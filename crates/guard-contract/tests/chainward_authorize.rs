//! ChainWard's live verdict route, checked by the contract itself.
//!
//! `fixtures/chainward-authorize.json` holds real responses of ChainWard's
//! `POST /api/near/authorize` (saltxd/chainward, `apps/api/src/__tests__/nearAuthorize.test.ts`
//! writes it), signed with a throwaway key derived inside that test. Each response's `auth`
//! and `signature` go to `request_payment` exactly as an agent would pass them, through the
//! contract's own JSON argument types, canonical encoding and `env::ed25519_verify`.
//!
//! The pay case must be paid. The hold case must be refused with ChainWard's signed reason,
//! which the contract only reaches after the signature verified. A changed field must fail
//! as a bad signature. So these pass only if the route signs exactly the bytes the contract
//! checks.

use std::fmt::Write as _;

use ed25519_dalek::{Signer, SigningKey};
use guard_contract::oneclick::SignedQuote;
use guard_contract::{GuardContract, PaymentAuthArgs, Policy};
use near_sdk::json_types::{Base64VecU8, U128};
use near_sdk::serde::Deserialize;
use near_sdk::test_utils::VMContextBuilder;
use near_sdk::{bs58, env, testing_env, AccountId, NearToken};

#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct Fixture {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct Case {
    name: String,
    response: Response,
    canonical_hex: String,
}

/// The parts of the route's response an agent hands to the guard. The rest (ChainWard's
/// full verdict text and which checks ran) is for the agent's log.
#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct Response {
    auth: PaymentAuthArgs,
    signature: Base64VecU8,
    public_key: Base64VecU8,
}

fn load(name: &str) -> Case {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/chainward-authorize.json"
    );
    let raw = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
    let fixture: Fixture =
        near_sdk::serde_json::from_str(&raw).expect("the fixture is the route's response shape");
    fixture
        .cases
        .into_iter()
        .find(|case| case.name == name)
        .unwrap_or_else(|| panic!("no `{name}` case in the fixture"))
}

fn owner() -> AccountId {
    "owner.near".parse().unwrap()
}

/// Stands in for 1Click's key so the test can sign a quote matching the fixture.
fn oneclick_key() -> SigningKey {
    SigningKey::from_bytes(&[3u8; 32])
}

const BASE_ASSET: &str = "nep141:base-0xtest.omft.near";

/// A guard at the fixture's `guard_id`, trusting the fixture's ChainWard key, with block
/// time one minute after the verdict was signed.
fn guard_for(case: &Case) -> GuardContract {
    let issued_at = case.response.auth.issued_at.0;
    testing_env!(VMContextBuilder::new()
        .current_account_id(case.response.auth.guard_id.parse().unwrap())
        .predecessor_account_id(owner())
        .account_balance(NearToken::from_near(10))
        .block_timestamp((issued_at + 60) * 1_000_000_000)
        .build());
    let policy = Policy {
        per_tx_cap: U128(10_000_000),
        daily_cap: U128(100_000_000),
        per_counterparty_cap: U128(50_000_000),
        allowlist: vec![],
        denylist: vec![],
        max_verdict_age_sec: 300,
    };
    let mut guard = GuardContract::new(owner(), case.response.public_key.clone(), policy);
    guard.set_oneclick_pubkeys(vec![oneclick_key()
        .verifying_key()
        .to_bytes()
        .to_vec()
        .into()]);
    guard.set_asset_chain(BASE_ASSET.to_string(), "base".to_string());
    guard
}

/// A 1Click quote matching `auth`, signed the way 1Click signs: ed25519 over
/// `base58(sha256(payload))`.
fn quote_for(auth: &PaymentAuthArgs) -> SignedQuote {
    let payload = format!(
        concat!(
            r#"{{"amountIn":"{}","deadline":"2099-01-01T00:00:00.000Z","#,
            r#""depositAddress":"{}","depositType":"INTENTS","destinationAsset":"{}","#,
            r#""dry":false,"originAsset":"nep245:origin","recipient":"{}","#,
            r#""recipientType":"DESTINATION_CHAIN"}}"#
        ),
        auth.amount.0, auth.deposit_address, BASE_ASSET, auth.destination,
    );
    let message = bs58::encode(env::sha256(payload.as_bytes())).into_string();
    let signature = oneclick_key().sign(message.as_bytes()).to_bytes();
    SignedQuote {
        payload,
        signature: format!("ed25519:{}", bs58::encode(signature).into_string()),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn core(auth: &PaymentAuthArgs) -> guard_auth::PaymentAuth {
    guard_auth::PaymentAuth {
        guard_id: auth.guard_id.clone(),
        deposit_address: auth.deposit_address.clone(),
        destination: auth.destination.clone(),
        chain: auth.chain.clone(),
        amount: auth.amount.0,
        verdict: auth.verdict.clone(),
        reason: auth.reason.clone(),
        issued_at: auth.issued_at.0,
        quote_expiry: auth.quote_expiry.0,
        nonce: auth.nonce.0,
    }
}

#[test]
fn the_route_signs_shape_valid_auths_over_the_same_canonical_bytes() {
    for name in ["pay", "hold-sanctioned"] {
        let case = load(name);
        let auth = core(&case.response.auth);
        assert_eq!(guard_auth::validate(&auth), None, "`{name}` is shape-valid");
        assert_eq!(
            hex(&guard_auth::canonical_bytes(&auth)),
            case.canonical_hex,
            "`{name}`: the route's encoder and guard-auth disagree on the bytes"
        );
    }
}

#[test]
fn a_chainward_pay_verdict_is_paid() {
    let case = load("pay");
    let mut guard = guard_for(&case);
    let auth = case.response.auth.clone();
    let quote = quote_for(&auth);

    let result = guard.request_payment(auth.clone(), case.response.signature.clone(), quote);

    assert!(result.paid);
    assert_eq!(result.amount, auth.amount);
    assert_eq!(result.deposit_address, auth.deposit_address);
    assert_eq!(result.destination, auth.destination);
    assert_eq!(result.reason, auth.reason);
    assert!(guard.is_nonce_used(auth.nonce), "the nonce is now spent");
    println!(
        "ChainWard pay verdict accepted by request_payment: {}",
        auth.reason
    );
}

#[test]
#[should_panic(
    expected = "verdict: hold, On the US sanctions list (OFAC): This address is on the US Treasury OFAC SDN list."
)]
fn a_chainward_hold_verdict_is_refused_with_its_signed_reason() {
    // The verdict gate runs after the signature check, so this message (not "bad
    // signature") proves the signature verified, and the reason echoed is ChainWard's.
    let case = load("hold-sanctioned");
    let mut guard = guard_for(&case);
    let auth = case.response.auth.clone();
    let quote = quote_for(&auth);
    let _ = guard.request_payment(auth, case.response.signature.clone(), quote);
}

#[test]
#[should_panic(expected = "bad signature")]
fn the_route_signature_does_not_cover_a_changed_verdict() {
    // Turn the signed hold into a pay: the bytes change, so ChainWard's signature fails.
    let case = load("hold-sanctioned");
    let mut guard = guard_for(&case);
    let mut forged = case.response.auth.clone();
    forged.verdict = "pay".to_string();
    let quote = quote_for(&forged);
    let _ = guard.request_payment(forged, case.response.signature.clone(), quote);
}
