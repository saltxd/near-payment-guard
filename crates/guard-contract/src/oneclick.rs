//! The cross-chain settlement leg: verifying 1Click's quote signature in-contract.
//!
//! A payment to a counterparty on Base or BNB Chain goes through NEAR Intents / 1Click.
//! You ask 1Click for a route; it returns a **deposit address**, and money sent there
//! surfaces at a **destination** (an EVM address) on the destination chain. 1Click signs
//! that binding, so the guard does not have to trust the agent about where a deposit
//! address leads: it verifies 1Click's own signature and reads the destination out of the
//! signed bytes.
//!
//! ## The scheme, as 1Click's SDK implements it
//!
//! `@defuse-protocol/one-click-sdk-typescript` (`src/quote-signature.ts`, ISC, NEAR
//! Foundation) signs, for a quote response:
//!
//! ```text
//! dataString = json-stable-stringify({ ...signedRequest, ...signedQuote, timestamp })
//! message    = utf8( base58( sha256( utf8(dataString) ) ) )   // the BASE58 TEXT, not the digest
//! signature  = ed25519_sign(oneClickManagerKey, message)
//! ```
//!
//! The one subtlety worth stating twice: the signed message is the UTF-8 of the base58
//! *text* of the hash, never the raw 32 bytes. Both 1Click's SDK and the prior art note it.
//!
//! ## Why this verifies cheaply, with no JSON rebuilt in-contract
//!
//! The caller hands the guard the exact string 1Click signed ([`SignedQuote::payload`]).
//! The guard hashes those bytes with `env::sha256`, base58-encodes the digest, and checks
//! the ed25519 signature with `env::ed25519_verify` against a manager key. Only *after* the
//! signature authenticates the bytes does it parse them with `serde_json` to read the terms.
//! It never reconstructs the canonical JSON, so the whole "is json-stable-stringify
//! reproducible in a contract" question is moot. This is the approach the audited prior art
//! takes (Peerfolio / beneviolabs `autonomous-trading-account`, `contracts/trading-account/
//! src/quote.rs`, MIT); the signature/decode shape here follows it, and the production
//! manager key below is cross-checked against the one that project compiles in.
//!
//! Proven end to end against a real production quote in the tests: see
//! `fixtures/1click-quote.json` and `ops/near/quote-signature.md`.

use near_sdk::serde::Deserialize;
use near_sdk::serde_json::Value;
use near_sdk::{bs58, env, near};

/// Raw ed25519 public keys 1Click signs quotes with.
///
/// 1Click's SDK hardcodes exactly one,
/// `ed25519:reYaWhvwu8Jzo3WUM3zhn6VrhuMEF4eADL17qtRVifc`, and it is not published anywhere
/// a contract could fetch it, so a rotation is a code change. These bytes are the base58
/// decode of that key (verified against both the SDK and Peerfolio's compiled-in constant).
/// The guard stores its own copy in state so the owner can rotate without a redeploy; this
/// is the default it is seeded with and the value the real-fixture test checks against.
pub const ONE_CLICK_MANAGER_KEYS: &[[u8; 32]] = &[[
    12, 183, 233, 73, 227, 135, 30, 207, 40, 74, 80, 184, 231, 116, 171, 41, 179, 247, 178, 54, 62,
    57, 140, 239, 29, 242, 233, 68, 87, 183, 233, 67,
]];

/// Length of a raw ed25519 signature, in bytes.
const SIGNATURE_LEN: usize = 64;

/// A 1Click quote, exactly as 1Click signed it, handed to the guard by the agent.
///
/// `payload` is the finished `json-stable-stringify({ ...request, ...quote, timestamp })`
/// string; the guard verifies and parses it but never rebuilds it. `signature` is the
/// response's `signature`, either `ed25519:<base58>` or the bare base58 (the prefix is
/// optional on the way in).
#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct SignedQuote {
    /// The exact JSON string 1Click signed.
    pub payload: String,
    /// The ed25519 signature over `message(payload)`, base58, `ed25519:` prefix optional.
    pub signature: String,
}

/// The fields of a signed quote the guard reads. 1Click signs more than these; the rest are
/// ignored. `serde` rejects a duplicate field, so a second `recipient` cannot slip past.
#[derive(Deserialize, Debug, Clone)]
#[serde(crate = "near_sdk::serde", rename_all = "camelCase")]
pub struct QuoteTerms {
    /// A dry quote has no deposit address and must never be settled.
    pub dry: bool,
    /// The asset deposited, e.g. `nep245:...` — what the guard `mt_transfer`s.
    pub origin_asset: String,
    /// The asset delivered at the destination; its id carries the destination chain.
    pub destination_asset: String,
    /// The EVM address the funds surface at. Checksummed by 1Click; compare case-folded.
    pub recipient: String,
    /// `DESTINATION_CHAIN` for an off-NEAR payout.
    pub recipient_type: String,
    /// `INTENTS` for a funds-in-intents deposit.
    pub deposit_type: String,
    /// Amount to deposit, in the origin asset's smallest unit (decimal string).
    pub amount_in: String,
    /// The intents deposit address to pay. Present only on a live (non-dry) quote.
    pub deposit_address: Option<String>,
    /// The quote's deposit deadline (ISO-8601 UTC). Present only on a live quote.
    pub deadline: Option<String>,
    /// Redirect vectors. 1Click drops them from the payload when unset; a null is unset too.
    pub virtual_chain_recipient: Option<Value>,
    /// See [`QuoteTerms::virtual_chain_recipient`].
    pub virtual_chain_refund_recipient: Option<Value>,
    /// See [`QuoteTerms::virtual_chain_recipient`].
    pub custom_recipient_msg: Option<Value>,
}

/// Verifies that one of `keys` signed `quote` the way 1Click's SDK signs, and returns its
/// parsed terms.
///
/// `Err` carries a short, stable reason. The signature is checked *before* the payload is
/// parsed, so no attacker-chosen byte is trusted until 1Click's key has vouched for it.
pub fn verify_quote(quote: &SignedQuote, keys: &[[u8; 32]]) -> Result<QuoteTerms, String> {
    let signature = decode_signature(&quote.signature)?;

    // 1Click signs the base58 TEXT of the payload's SHA-256, not the hash bytes.
    let digest = env::sha256(quote.payload.as_bytes());
    let message = bs58::encode(digest).into_string();

    let signed = keys
        .iter()
        .any(|key| env::ed25519_verify(&signature, message.as_bytes(), key));
    if !signed {
        return Err("bad quote signature".to_string());
    }

    near_sdk::serde_json::from_str(&quote.payload)
        .map_err(|e| format!("invalid quote payload: {e}"))
}

/// Decodes `ed25519:<base58>` (or bare `<base58>`) into a 64-byte signature.
fn decode_signature(signature: &str) -> Result<[u8; SIGNATURE_LEN], String> {
    let encoded = signature.strip_prefix("ed25519:").unwrap_or(signature);
    let bytes = bs58::decode(encoded)
        .into_vec()
        .map_err(|_| "quote signature is not base58".to_string())?;
    bytes
        .try_into()
        .map_err(|_| "quote signature is not 64 bytes".to_string())
}

impl QuoteTerms {
    /// True if any redirect vector is present and not null. Such a quote can send funds past
    /// the signed `recipient`, so the guard refuses it (the prior art, PR #186, does the same).
    pub fn has_redirect_vector(&self) -> bool {
        !is_unset(&self.virtual_chain_recipient)
            || !is_unset(&self.virtual_chain_refund_recipient)
            || !is_unset(&self.custom_recipient_msg)
    }

    /// Maps `destination_asset` to `"base"` or `"bsc"`, or `None` if it is neither.
    ///
    /// 1Click's asset ids put the chain in the id: Base assets read `nep141:base-…` or
    /// `nep141:base.…`; BNB Chain assets carry the `:56_` chain-id segment. This is the
    /// weakest link in the binding because the id format is 1Click's, not a standard; the
    /// owner-set allowlist in the contract is what actually bounds which assets are payable,
    /// and this is a cross-check on top of it. See `ops/near/quote-signature.md`.
    pub fn destination_chain(&self) -> Option<&'static str> {
        let asset = &self.destination_asset;
        if asset.contains(":base-") || asset.contains(":base.") {
            Some("base")
        } else if asset.contains(":56_") || asset.contains(":bsc-") || asset.contains(":bsc.") {
            Some("bsc")
        } else {
            None
        }
    }
}

/// A JSON optional is "unset" when it is absent (`None`) or explicitly `null`.
fn is_unset(value: &Option<Value>) -> bool {
    matches!(value, None | Some(Value::Null))
}

/// Parses a 1Click deadline (`YYYY-MM-DDTHH:MM:SS[.fff]Z`, UTC) to Unix seconds.
///
/// Deliberately strict and dependency-free: it accepts only the exact zoned UTC shape
/// 1Click emits and returns `None` on anything else, so a surprising format fails closed
/// (the guard refuses the payment) rather than being read as some other instant. Fractional
/// seconds are accepted and truncated to whole seconds.
pub fn parse_deadline_seconds(deadline: &str) -> Option<u64> {
    let bytes = deadline.as_bytes();
    // Shortest valid form "YYYY-MM-DDTHH:MM:SSZ" is 20 bytes.
    if bytes.len() < 20 {
        return None;
    }
    if bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b'T' {
        return None;
    }
    if bytes[13] != b':' || bytes[16] != b':' {
        return None;
    }
    if *bytes.last()? != b'Z' {
        return None;
    }
    // After "SS" (index 19) only an optional ".<digits>" is allowed before the trailing Z.
    let tail = &deadline[19..deadline.len() - 1];
    if !tail.is_empty() {
        let mut chars = tail.chars();
        if chars.next() != Some('.') {
            return None;
        }
        if !tail[1..].chars().all(|c| c.is_ascii_digit()) || tail.len() < 2 {
            return None;
        }
    }

    let year: i64 = deadline.get(0..4)?.parse().ok()?;
    let month: u32 = deadline.get(5..7)?.parse().ok()?;
    let day: u32 = deadline.get(8..10)?.parse().ok()?;
    let hour: u64 = deadline.get(11..13)?.parse().ok()?;
    let minute: u64 = deadline.get(14..16)?.parse().ok()?;
    let second: u64 = deadline.get(17..19)?.parse().ok()?;

    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        return None;
    }
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }

    let days = days_from_civil(year, month, day);
    if days < 0 {
        return None;
    }
    Some(days as u64 * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// Days since 1970-01-01 for a proleptic-Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let m = m as i64;
    let d = d as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

/// Whether `year` is a leap year in the proleptic Gregorian calendar.
fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Number of days in `month` of `year` (`month` is 1..=12).
fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use near_sdk::serde_json;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    /// The recorded real-quote fixture, verified in `ops/near/quote-signature.md`.
    const FIXTURE: &str = include_str!("../../../fixtures/1click-quote.json");

    #[derive(Deserialize)]
    #[serde(crate = "near_sdk::serde")]
    struct Fixture {
        #[serde(rename = "managerPublicKey")]
        manager_public_key: String,
        #[serde(rename = "signatureBase58")]
        signature_base58: String,
        #[serde(rename = "signedPayload")]
        signed_payload: String,
        expected: Expected,
    }

    #[derive(Deserialize)]
    #[serde(crate = "near_sdk::serde")]
    struct Expected {
        #[serde(rename = "depositAddress")]
        deposit_address: String,
        #[serde(rename = "recipientLowercase")]
        recipient_lowercase: String,
        #[serde(rename = "amountIn")]
        amount_in: String,
        deadline: String,
        chain: String,
    }

    fn fixture() -> Fixture {
        serde_json::from_str(FIXTURE).expect("fixture is valid JSON")
    }

    /// `env::sha256` / `env::ed25519_verify` are host functions; give the tests a VM.
    fn vm() {
        testing_env!(VMContextBuilder::new().build());
    }

    fn pubkey_bytes(ed25519_key: &str) -> [u8; 32] {
        let bare = ed25519_key.strip_prefix("ed25519:").unwrap_or(ed25519_key);
        bs58::decode(bare)
            .into_vec()
            .unwrap()
            .try_into()
            .expect("32-byte key")
    }

    #[test]
    fn production_manager_key_matches_the_published_base58() {
        // The compiled-in constant must be exactly base58(reYaWhvwu8…).
        assert_eq!(
            ONE_CLICK_MANAGER_KEYS[0],
            pubkey_bytes("ed25519:reYaWhvwu8Jzo3WUM3zhn6VrhuMEF4eADL17qtRVifc"),
        );
    }

    #[test]
    fn a_real_1click_signature_verifies_against_the_production_key() {
        // The crown jewel: a genuine production 1Click signature, verified with exactly the
        // host primitives the contract uses. If this passes, the signed payload string is
        // provably the one 1Click signed — a wrong string could not carry a valid signature.
        vm();
        let f = fixture();
        let quote = SignedQuote {
            payload: f.signed_payload.clone(),
            signature: f.signature_base58.clone(),
        };
        let keys = [pubkey_bytes(&f.manager_public_key)];
        let terms = verify_quote(&quote, &keys).expect("real signature must verify");

        assert_eq!(
            terms.deposit_address.as_deref(),
            Some(f.expected.deposit_address.as_str())
        );
        assert_eq!(
            terms.recipient.to_ascii_lowercase(),
            f.expected.recipient_lowercase
        );
        assert_eq!(terms.amount_in, f.expected.amount_in);
        assert_eq!(
            terms.deadline.as_deref(),
            Some(f.expected.deadline.as_str())
        );
        assert_eq!(terms.destination_chain(), Some(f.expected.chain.as_str()));
        assert!(!terms.dry);
        assert!(!terms.has_redirect_vector());
        assert_eq!(terms.recipient_type, "DESTINATION_CHAIN");
        assert_eq!(terms.deposit_type, "INTENTS");
    }

    #[test]
    fn the_production_constant_also_verifies_the_fixture() {
        // Same proof, but against the hardcoded default the guard seeds itself with.
        vm();
        let f = fixture();
        let quote = SignedQuote {
            payload: f.signed_payload,
            signature: f.signature_base58,
        };
        assert!(verify_quote(&quote, ONE_CLICK_MANAGER_KEYS).is_ok());
    }

    #[test]
    fn a_tampered_payload_fails_the_signature() {
        // Flip the deposit address in the signed string: the SHA-256 changes, so 1Click's
        // signature no longer covers it. This is scenario 5 for the cross-chain leg.
        vm();
        let f = fixture();
        let tampered = f.signed_payload.replace(
            &f.expected.deposit_address,
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        assert_ne!(
            tampered, f.signed_payload,
            "the replace must have changed something"
        );
        let quote = SignedQuote {
            payload: tampered,
            signature: f.signature_base58,
        };
        let err = verify_quote(&quote, ONE_CLICK_MANAGER_KEYS).unwrap_err();
        assert_eq!(err, "bad quote signature");
    }

    #[test]
    fn a_signature_from_the_wrong_key_fails() {
        vm();
        let f = fixture();
        let quote = SignedQuote {
            payload: f.signed_payload,
            signature: f.signature_base58,
        };
        let impostor = SigningKey::from_bytes(&[9u8; 32])
            .verifying_key()
            .to_bytes();
        let err = verify_quote(&quote, &[impostor]).unwrap_err();
        assert_eq!(err, "bad quote signature");
    }

    #[test]
    fn a_malformed_signature_is_refused() {
        vm();
        let f = fixture();
        for bad in ["ed25519:", "not-base58-!!!", "ed25519:abc"] {
            let quote = SignedQuote {
                payload: f.signed_payload.clone(),
                signature: bad.to_string(),
            };
            assert!(
                verify_quote(&quote, ONE_CLICK_MANAGER_KEYS).is_err(),
                "{bad}"
            );
        }
    }

    // --- Synthetic quotes signed by a throwaway "manager" key ---
    //
    // The fixture proves we match 1Click's real scheme. These prove the field-level checks,
    // which need quotes we can edit and re-sign at will.

    fn test_manager() -> SigningKey {
        SigningKey::from_bytes(&[3u8; 32])
    }

    /// Signs `payload` the way 1Click does, with `key`, returning a ready [`SignedQuote`].
    fn sign_quote(payload: &str, key: &SigningKey) -> SignedQuote {
        let digest = env::sha256(payload.as_bytes());
        let message = bs58::encode(digest).into_string();
        let sig = key.sign(message.as_bytes()).to_bytes();
        SignedQuote {
            payload: payload.to_string(),
            signature: format!("ed25519:{}", bs58::encode(sig).into_string()),
        }
    }

    #[test]
    fn a_synthetic_quote_round_trips() {
        vm();
        let key = test_manager();
        let payload = r#"{"amountIn":"5","depositAddress":"d.near","depositType":"INTENTS","destinationAsset":"nep141:base-0xabc.omft.near","dry":false,"originAsset":"nep245:v2_1.omni.hot.tg:56_x","recipient":"0xAbCd","recipientType":"DESTINATION_CHAIN"}"#;
        let quote = sign_quote(payload, &key);
        let terms = verify_quote(&quote, &[key.verifying_key().to_bytes()]).unwrap();
        assert_eq!(terms.amount_in, "5");
        assert_eq!(terms.recipient.to_ascii_lowercase(), "0xabcd");
        assert_eq!(terms.destination_chain(), Some("base"));
        assert!(!terms.has_redirect_vector());
    }

    #[test]
    fn a_redirect_vector_is_detected() {
        vm();
        let key = test_manager();
        let payload = r#"{"amountIn":"5","customRecipientMsg":{"to":"evil"},"depositAddress":"d.near","depositType":"INTENTS","destinationAsset":"nep141:base-0xabc.omft.near","dry":false,"originAsset":"o","recipient":"0xabcd","recipientType":"DESTINATION_CHAIN"}"#;
        let quote = sign_quote(payload, &key);
        let terms = verify_quote(&quote, &[key.verifying_key().to_bytes()]).unwrap();
        assert!(
            terms.has_redirect_vector(),
            "customRecipientMsg must be caught"
        );
    }

    #[test]
    fn an_explicit_null_redirect_is_not_a_redirect() {
        vm();
        let key = test_manager();
        let payload = r#"{"amountIn":"5","depositAddress":"d.near","depositType":"INTENTS","destinationAsset":"nep141:base-0xabc.omft.near","dry":false,"originAsset":"o","recipient":"0xabcd","recipientType":"DESTINATION_CHAIN","virtualChainRecipient":null}"#;
        let quote = sign_quote(payload, &key);
        let terms = verify_quote(&quote, &[key.verifying_key().to_bytes()]).unwrap();
        assert!(!terms.has_redirect_vector(), "an explicit null is unset");
    }

    #[test]
    fn a_duplicate_field_is_rejected_by_the_parser() {
        // Two `recipient`s: serde refuses it, so a second value cannot shadow the signed one
        // after the signature has passed over the whole string.
        vm();
        let key = test_manager();
        let payload = r#"{"amountIn":"5","depositType":"INTENTS","destinationAsset":"nep141:base-0xabc.omft.near","dry":false,"originAsset":"o","recipient":"0xabcd","recipient":"0xdead","recipientType":"DESTINATION_CHAIN"}"#;
        let quote = sign_quote(payload, &key);
        assert!(verify_quote(&quote, &[key.verifying_key().to_bytes()]).is_err());
    }

    #[test]
    fn bsc_asset_maps_to_bsc() {
        let terms: QuoteTerms = serde_json::from_str(
            r#"{"amountIn":"5","depositType":"INTENTS","destinationAsset":"nep245:v2_1.omni.hot.tg:56_2w93Gq","dry":false,"originAsset":"o","recipient":"0xabcd","recipientType":"DESTINATION_CHAIN"}"#,
        )
        .unwrap();
        assert_eq!(terms.destination_chain(), Some("bsc"));
    }

    #[test]
    fn deadline_parses_the_fixture_and_rejects_junk() {
        // Oracle values computed independently (Python datetime, UTC).
        assert_eq!(
            parse_deadline_seconds("2026-11-04T07:55:04.000Z"),
            Some(1_793_778_904)
        );
        assert_eq!(
            parse_deadline_seconds("2026-11-04T07:55:04Z"),
            Some(1_793_778_904)
        );
        assert_eq!(parse_deadline_seconds("1970-01-01T00:00:00.000Z"), Some(0));
        assert_eq!(
            parse_deadline_seconds("2000-02-29T00:00:00.000Z"),
            Some(951_782_400)
        );
        assert_eq!(
            parse_deadline_seconds("2027-01-01T00:00:00.000Z"),
            Some(1_798_761_600)
        );

        // Fail closed on anything but the exact zoned-UTC shape.
        assert_eq!(
            parse_deadline_seconds("2026-11-04T07:55:04"),
            None,
            "no zone"
        );
        assert_eq!(
            parse_deadline_seconds("2026-11-04T07:55:04+00:00"),
            None,
            "offset, not Z"
        );
        assert_eq!(parse_deadline_seconds("2026-11-04"), None, "date only");
        assert_eq!(
            parse_deadline_seconds("2026-02-30T00:00:00Z"),
            None,
            "Feb 30"
        );
        assert_eq!(
            parse_deadline_seconds("2026-13-01T00:00:00Z"),
            None,
            "month 13"
        );
        assert_eq!(
            parse_deadline_seconds("2026-11-04T24:00:00Z"),
            None,
            "hour 24"
        );
        assert_eq!(
            parse_deadline_seconds("2026-11-04T07:55:04.Z"),
            None,
            "empty fraction"
        );
        assert_eq!(parse_deadline_seconds(""), None);
    }
}
