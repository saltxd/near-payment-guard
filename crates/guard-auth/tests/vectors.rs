//! Cross-language agreement against the shared fixture.
//!
//! This is the Day 1 gate. The TypeScript signer produced
//! `vectors/canonical-vectors.json`; this Rust verifier, written independently from
//! `docs/canonical-bytes.md`, must reproduce every byte of it.
//!
//! If these pass, the signer that will run in ChainWard's API and the verifier that
//! will run inside the guard contract agree on what a signature means.

use ed25519_dalek::{Signature, VerifyingKey};
use guard_auth::{canonical_bytes, validate, PaymentAuth, ValidationFailure};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Deserialize)]
struct AuthJson {
    guard_id: String,
    deposit_address: String,
    destination: String,
    chain: String,
    amount: String,
    verdict: String,
    reason: String,
    issued_at: String,
    quote_expiry: String,
    nonce: String,
}

impl AuthJson {
    /// Integers arrive as strings: u128 does not fit a JSON number and u64 loses
    /// precision above 2^53 in any JavaScript producer.
    fn to_auth(&self) -> PaymentAuth {
        PaymentAuth {
            guard_id: self.guard_id.clone(),
            deposit_address: self.deposit_address.clone(),
            destination: self.destination.clone(),
            chain: self.chain.clone(),
            amount: self.amount.parse().expect("amount is a u128"),
            verdict: self.verdict.clone(),
            reason: self.reason.clone(),
            issued_at: self.issued_at.parse().expect("issued_at is a u64"),
            quote_expiry: self.quote_expiry.parse().expect("quote_expiry is a u64"),
            nonce: self.nonce.parse().expect("nonce is a u128"),
        }
    }
}

#[derive(Debug, Deserialize)]
struct EncodingVector {
    name: String,
    description: String,
    auth: AuthJson,
    canonical_hex: String,
    canonical_len: usize,
    canonical_sha256: String,
}

#[derive(Debug, Deserialize)]
struct DistinctnessVector {
    name: String,
    description: String,
    a: AuthJson,
    b: AuthJson,
}

#[derive(Debug, Deserialize)]
struct VerificationVector {
    name: String,
    description: String,
    message_hex: String,
    public_key_hex: String,
    signature_hex: String,
    expect_valid: bool,
}

#[derive(Debug, Deserialize)]
struct ValidationVector {
    name: String,
    description: String,
    auth: AuthJson,
    expect_failure: Option<String>,
}

/// `[value, is_valid]` pairs for the exhaustive agreement checks.
#[derive(Debug, Deserialize)]
struct Differential {
    account_id: Vec<(String, bool)>,
    deposit_address: Vec<(String, bool)>,
}

#[derive(Debug, Deserialize)]
struct Vectors {
    version: u8,
    domain: String,
    encoding: Vec<EncodingVector>,
    distinctness: Vec<DistinctnessVector>,
    verification: Vec<VerificationVector>,
    validation: Vec<ValidationVector>,
    differential: Differential,
}

fn load() -> Vectors {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/canonical-vectors.json"
    );
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read {path}: {e}. Run `npm run vectors:generate`."));
    serde_json::from_str(&raw).expect("vectors file is valid JSON in the expected shape")
}

/// Mirrors the signature check the contract performs with `env::ed25519_verify`.
///
/// nearcore implements that host function with dalek's `verify_strict`, so this
/// uses `verify_strict` too. A non-strict verifier would accept the malleated
/// signature in the `malleable-s-plus-l` vector, which would give one
/// authorization two valid signatures.
fn verify_strict(message: &[u8], signature_hex: &str, public_key_hex: &str) -> bool {
    let sig_bytes = match hex::decode(signature_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let key_bytes = match hex::decode(public_key_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig_array: [u8; 64] = match sig_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let key_array: [u8; 32] = match key_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let key = match VerifyingKey::from_bytes(&key_array) {
        Ok(k) => k,
        Err(_) => return false,
    };
    key.verify_strict(message, &Signature::from_bytes(&sig_array))
        .is_ok()
}

#[test]
fn header_matches_the_spec() {
    let vectors = load();
    assert_eq!(vectors.version, guard_auth::VERSION, "VERSION");
    assert_eq!(vectors.domain, guard_auth::DOMAIN, "DOMAIN");
}

#[test]
fn encoding_matches_the_typescript_signer() {
    let vectors = load();
    assert!(!vectors.encoding.is_empty(), "no encoding vectors");

    for vector in &vectors.encoding {
        let bytes = canonical_bytes(&vector.auth.to_auth());

        assert_eq!(
            hex::encode(&bytes),
            vector.canonical_hex,
            "\nvector `{}`: {}\nRust and TypeScript disagree on the bytes",
            vector.name,
            vector.description,
        );
        assert_eq!(
            bytes.len(),
            vector.canonical_len,
            "vector `{}`: length",
            vector.name
        );
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            vector.canonical_sha256,
            "vector `{}`: sha256",
            vector.name,
        );
    }

    println!(
        "{} encoding vectors agree byte for byte",
        vectors.encoding.len()
    );
}

#[test]
fn distinct_inputs_never_collide() {
    let vectors = load();
    assert!(!vectors.distinctness.is_empty(), "no distinctness vectors");

    for vector in &vectors.distinctness {
        let a = canonical_bytes(&vector.a.to_auth());
        let b = canonical_bytes(&vector.b.to_auth());
        assert_ne!(
            hex::encode(&a),
            hex::encode(&b),
            "\nvector `{}`: {}\nthese two authorizations encode identically, so one signature covers both",
            vector.name,
            vector.description,
        );
    }

    println!(
        "{} distinctness vectors stay distinct",
        vectors.distinctness.len()
    );
}

#[test]
fn signature_verification_agrees() {
    let vectors = load();
    assert!(!vectors.verification.is_empty(), "no verification vectors");

    let mut accepted = 0usize;
    for vector in &vectors.verification {
        let message = hex::decode(&vector.message_hex).expect("message_hex is hex");
        let actual = verify_strict(&message, &vector.signature_hex, &vector.public_key_hex);
        assert_eq!(
            actual, vector.expect_valid,
            "\nvector `{}`: {}\nexpected verify={} but Rust said {}",
            vector.name, vector.description, vector.expect_valid, actual,
        );
        if vector.expect_valid {
            accepted += 1;
        }
    }

    assert!(
        accepted >= 2,
        "the suite must contain real signatures that do verify"
    );
    println!(
        "{} verification vectors agree ({} accepted, {} refused)",
        vectors.verification.len(),
        accepted,
        vectors.verification.len() - accepted,
    );
}

#[test]
fn validation_agrees_including_the_reason() {
    let vectors = load();
    assert!(!vectors.validation.is_empty(), "no validation vectors");

    for vector in &vectors.validation {
        let actual = validate(&vector.auth.to_auth());
        let actual_code = actual.map(ValidationFailure::code);
        let expected_code = vector.expect_failure.as_deref();

        assert_eq!(
            actual_code, expected_code,
            "\nvector `{}`: {}\nRust and TypeScript disagree on WHY this is accepted or refused",
            vector.name, vector.description,
        );
    }

    let refusals = vectors
        .validation
        .iter()
        .filter(|v| v.expect_failure.is_some())
        .count();
    assert!(refusals >= 10, "the suite must exercise many refusals");
    println!(
        "{} validation vectors agree ({} accepted, {} refused with a matching reason)",
        vectors.validation.len(),
        vectors.validation.len() - refusals,
        refusals,
    );
}

/// Exhaustive agreement on the rules each language implements differently.
///
/// TypeScript runs a regex; Rust runs a hand-rolled scan, because a contract should
/// not carry a regex engine. Two different programs for one rule is exactly where a
/// signer and a verifier drift apart, and a drift here is not cosmetic: if the signer
/// accepts what the verifier refuses, ChainWard mints authorizations the guard will
/// never honour; the other way round is a hole.
#[test]
fn hand_rolled_rules_agree_exhaustively_with_the_regex() {
    let vectors = load();

    let base = PaymentAuth {
        guard_id: "g.near".to_string(),
        deposit_address: "d.near".to_string(),
        destination: "0x0000000000000000000000000000000000000001".to_string(),
        chain: "base".to_string(),
        amount: 1,
        verdict: "pay".to_string(),
        reason: "ok".to_string(),
        issued_at: 1_762_000_000,
        quote_expiry: 1_762_000_900,
        nonce: 7,
    };

    assert!(
        vectors.differential.account_id.len() > 1000,
        "the account-id sweep should be exhaustive, got {}",
        vectors.differential.account_id.len(),
    );

    for (value, expected_valid) in &vectors.differential.account_id {
        let auth = PaymentAuth {
            guard_id: value.clone(),
            ..base.clone()
        };
        let actual_valid = validate(&auth).is_none();
        assert_eq!(
            actual_valid, *expected_valid,
            "account id {value:?}: TypeScript says valid={expected_valid}, Rust says {actual_valid}",
        );
    }

    for (value, expected_valid) in &vectors.differential.deposit_address {
        let auth = PaymentAuth {
            deposit_address: value.clone(),
            ..base.clone()
        };
        let actual_valid = validate(&auth).is_none();
        assert_eq!(
            actual_valid, *expected_valid,
            "deposit address {value:?}: TypeScript says valid={expected_valid}, Rust says {actual_valid}",
        );
    }

    let accepted = vectors
        .differential
        .account_id
        .iter()
        .filter(|(_, v)| *v)
        .count();
    println!(
        "{} account ids and {} deposit addresses agree exhaustively ({} accepted)",
        vectors.differential.account_id.len(),
        vectors.differential.deposit_address.len(),
        accepted,
    );
}

/// Pins the Rust encoder to the spec document directly, not only to the generated file.
///
/// Without this, both implementations could drift together: the generator would
/// emit whatever TypeScript produces and Rust would agree with it. This constant
/// was assembled by hand from the byte table in docs/canonical-bytes.md section 7.
#[test]
fn worked_example_matches_the_hand_assembled_spec_bytes() {
    let expected = concat!(
        "00000021", // u32(33), DOMAIN length
        "636861696e776172642e6e6561722d7061796d656e742d67756172642e61757468", // the domain
        "01",       // VERSION
        "00000006",
        "672e6e656172", // "g.near"
        "00000006",
        "642e6e656172", // "d.near"
        "0000002a",     // u32(42)
        "3078",         // "0x"
        "303030303030303030303030303030303030303030303030303030303030303030303030303030", // 39 zeros
        "31",                                                                             // "1"
        "00000004",
        "62617365",                         // "base"
        "00000000000000000000000000000001", // u128(1)
        "00000003",
        "706179", // "pay"
        "00000002",
        "6f6b",                             // "ok"
        "000000006905fc80",                 // u64(1762000000)
        "0000000069060004",                 // u64(1762000900)
        "00000000000000000000000000000007", // u128(7)
    );

    let auth = PaymentAuth {
        guard_id: "g.near".to_string(),
        deposit_address: "d.near".to_string(),
        destination: "0x0000000000000000000000000000000000000001".to_string(),
        chain: "base".to_string(),
        amount: 1,
        verdict: "pay".to_string(),
        reason: "ok".to_string(),
        issued_at: 1_762_000_000,
        quote_expiry: 1_762_000_900,
        nonce: 7,
    };

    let bytes = canonical_bytes(&auth);
    assert_eq!(bytes.len(), 173, "spec section 7 states 173 bytes");
    assert_eq!(hex::encode(&bytes), expected);
}
