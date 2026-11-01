//! Canonical byte encoding and shape validation for guard payment authorizations.
//!
//! This is the Rust half of a two-language agreement. The TypeScript half is
//! `ts/src/canonical.ts` and `ts/src/validate.ts`. Both are written from
//! `docs/canonical-bytes.md`; `vectors/canonical-vectors.json` proves they agree.
//!
//! The crate is deliberately dependency-free and has no `near-sdk` import. It is
//! compiled into a contract that holds money, so everything here is code a reviewer
//! can read in full, and `cargo test` runs without a NEAR toolchain.

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod canonical;
mod validate;

pub use canonical::{canonical_bytes, DOMAIN, VERSION};
pub use validate::{validate, ValidationFailure, LIMITS};

/// A payment authorization, in the field order the canonical encoding uses.
///
/// `chain` and `verdict` are `String` rather than enums on purpose: this struct must
/// be able to hold the invalid values an attacker supplies, so that `validate` can
/// refuse them with a specific reason. Converting to an enum is the contract's job,
/// after validation has passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentAuth {
    /// NEAR account id of the guard contract this authorization is for.
    ///
    /// Present so a verdict cannot be replayed against a different guard; see
    /// `docs/canonical-bytes.md` section 4.
    pub guard_id: String,
    /// The only address the guard will pay.
    pub deposit_address: String,
    /// Lowercase `0x`-prefixed EVM address the money must surface at.
    pub destination: String,
    /// `"base"` or `"bsc"`.
    pub chain: String,
    /// Exact amount this authorization covers, in the asset's smallest unit.
    pub amount: u128,
    /// `"pay"`, `"hold"` or `"unknown"`.
    pub verdict: String,
    /// The one fact the verdict rests on. May be empty.
    pub reason: String,
    /// Unix seconds when ChainWard signed.
    pub issued_at: u64,
    /// Unix seconds, the 1Click quote deadline.
    pub quote_expiry: u64,
    /// Replay protection.
    pub nonce: u128,
}
