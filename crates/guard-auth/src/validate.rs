//! Shape validation.
//!
//! Shape only: the rules that make two parties agree on a byte string. Semantics
//! (freshness, caps, nonce reuse, whether the verdict is `"pay"`) belong to the
//! contract. See `docs/canonical-bytes.md` section 5 for where that line sits.
//!
//! Every rule here is mirrored in `ts/src/validate.ts` and pinned by the
//! `validation` family in `vectors/canonical-vectors.json`.

use crate::PaymentAuth;

/// Field length bounds, in bytes. From `docs/canonical-bytes.md` section 5.
pub struct Limits {
    /// Minimum `guard_id` length.
    pub guard_id_min: usize,
    /// Maximum `guard_id` length.
    pub guard_id_max: usize,
    /// Minimum `deposit_address` length.
    pub deposit_address_min: usize,
    /// Maximum `deposit_address` length.
    pub deposit_address_max: usize,
    /// Maximum `reason` length.
    pub reason_max: usize,
}

/// The bounds this crate enforces.
pub const LIMITS: Limits = Limits {
    guard_id_min: 2,
    guard_id_max: 64,
    deposit_address_min: 1,
    deposit_address_max: 128,
    reason_max: 256,
};

/// Why an authorization failed shape validation.
///
/// The string forms are part of the specification: tests assert on them and the
/// contract echoes them, so renaming one is a breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationFailure {
    /// `guard_id` is not a valid NEAR account id, or is out of bounds.
    GuardIdInvalid,
    /// `deposit_address` is empty, oversized, or not printable ASCII.
    DepositAddressInvalid,
    /// `destination` is not a lowercase `0x`-prefixed 40-digit hex address.
    DestinationInvalid,
    /// `chain` is not `"base"` or `"bsc"`.
    ChainInvalid,
    /// `verdict` is not `"pay"`, `"hold"` or `"unknown"`.
    VerdictInvalid,
    /// `reason` is oversized or contains a control character.
    ReasonInvalid,
}

impl ValidationFailure {
    /// The stable machine-readable code, matching `ValidationFailure` in TypeScript.
    pub fn code(self) -> &'static str {
        match self {
            Self::GuardIdInvalid => "guard_id_invalid",
            Self::DepositAddressInvalid => "deposit_address_invalid",
            Self::DestinationInvalid => "destination_invalid",
            Self::ChainInvalid => "chain_invalid",
            Self::VerdictInvalid => "verdict_invalid",
            Self::ReasonInvalid => "reason_invalid",
        }
    }
}

impl core::fmt::Display for ValidationFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.code())
    }
}

/// NEAR account id rule, implemented without a regex crate.
///
/// Equivalent to `^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$` over a
/// 2..=64 byte string: dot-separated parts, each part non-empty, each part made of
/// lowercase alphanumeric runs joined by single `-` or `_`, with no leading,
/// trailing or doubled separator.
///
/// Stated as a scan: the string must be non-empty, start and end with an
/// alphanumeric, and never contain two separators in a row.
fn is_valid_account_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    if !(LIMITS.guard_id_min..=LIMITS.guard_id_max).contains(&bytes.len()) {
        return false;
    }

    let is_alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let is_separator = |b: u8| b == b'-' || b == b'_' || b == b'.';

    // A multi-byte character has every byte >= 0x80, so it is neither alphanumeric
    // nor a separator and is rejected here rather than slipping through on length.
    let mut previous_was_separator = true; // a leading separator is invalid
    for &byte in bytes {
        if is_alnum(byte) {
            previous_was_separator = false;
        } else if is_separator(byte) {
            if previous_was_separator {
                return false;
            }
            previous_was_separator = true;
        } else {
            return false;
        }
    }

    // A trailing separator is invalid.
    !previous_was_separator
}

/// Every byte in `0x21..=0x7E`: printable ASCII, no space and no DEL.
fn is_printable_ascii_no_space(value: &str) -> bool {
    value.as_bytes().iter().all(|b| (0x21..=0x7e).contains(b))
}

/// Lowercase `0x`-prefixed EVM address. Section 5.2 explains why case is not forgiven.
fn is_lowercase_evm_address(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 42 {
        return false;
    }
    if &bytes[0..2] != b"0x" {
        return false;
    }
    bytes[2..]
        .iter()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}

/// C0 (`U+0000..U+001F`), DEL (`U+007F`) and C1 (`U+0080..U+009F`).
fn has_control_character(value: &str) -> bool {
    value
        .chars()
        .any(|c| c <= '\u{001f}' || c == '\u{007f}' || ('\u{0080}'..='\u{009f}').contains(&c))
}

/// Returns the first failing rule, or `None` when the authorization is shape-valid.
///
/// Rules run in the field order of the canonical encoding, so a given input always
/// reports the same failure in both languages.
pub fn validate(auth: &PaymentAuth) -> Option<ValidationFailure> {
    if !is_valid_account_id(&auth.guard_id) {
        return Some(ValidationFailure::GuardIdInvalid);
    }

    // `str::len()` is already the UTF-8 byte count, which is what the spec means.
    let deposit_len = auth.deposit_address.len();
    if !(LIMITS.deposit_address_min..=LIMITS.deposit_address_max).contains(&deposit_len)
        || !is_printable_ascii_no_space(&auth.deposit_address)
    {
        return Some(ValidationFailure::DepositAddressInvalid);
    }

    if !is_lowercase_evm_address(&auth.destination) {
        return Some(ValidationFailure::DestinationInvalid);
    }

    if auth.chain != "base" && auth.chain != "bsc" {
        return Some(ValidationFailure::ChainInvalid);
    }

    if auth.verdict != "pay" && auth.verdict != "hold" && auth.verdict != "unknown" {
        return Some(ValidationFailure::VerdictInvalid);
    }

    if auth.reason.len() > LIMITS.reason_max || has_control_character(&auth.reason) {
        return Some(ValidationFailure::ReasonInvalid);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_id_rule_matches_the_documented_regex() {
        assert!(is_valid_account_id("g.near"));
        assert!(is_valid_account_id("guard.chainward.near"));
        assert!(is_valid_account_id("a_b-c.near"));
        assert!(
            is_valid_account_id(&"f".repeat(64)),
            "implicit 64-hex account"
        );
        assert!(is_valid_account_id("ab"));

        assert!(!is_valid_account_id("a"), "below the minimum");
        assert!(!is_valid_account_id(&"a".repeat(65)), "above the maximum");
        assert!(!is_valid_account_id("Guard.near"), "uppercase");
        assert!(!is_valid_account_id("a..near"), "doubled separator");
        assert!(!is_valid_account_id("a--b.near"), "doubled separator");
        assert!(!is_valid_account_id(".near"), "leading separator");
        assert!(!is_valid_account_id("near."), "trailing separator");
        assert!(
            !is_valid_account_id("a-.near"),
            "separator run across a dot"
        );
        assert!(!is_valid_account_id("guard\u{00e9}.near"), "non-ASCII");
    }

    #[test]
    fn reason_limit_is_in_bytes_not_characters() {
        let sixty_five_emoji = "\u{1F600}".repeat(65); // 65 chars, 260 bytes
        assert_eq!(sixty_five_emoji.chars().count(), 65);
        assert_eq!(sixty_five_emoji.len(), 260, "UTF-8 bytes, not characters");
        assert!(sixty_five_emoji.len() > LIMITS.reason_max);
    }

    #[test]
    fn evm_address_must_be_lowercase() {
        assert!(is_lowercase_evm_address(&format!("0x{}", "a".repeat(40))));
        assert!(!is_lowercase_evm_address(&format!("0x{}", "A".repeat(40))));
        assert!(!is_lowercase_evm_address(&format!("0X{}", "a".repeat(40))));
        assert!(!is_lowercase_evm_address(&format!("0x{}", "g".repeat(40))));
        assert!(!is_lowercase_evm_address(&format!("0x{}", "a".repeat(39))));
    }
}
