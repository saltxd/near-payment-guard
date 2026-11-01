//! The canonical byte encoding.
//!
//! See `docs/canonical-bytes.md` sections 2 and 3. The encoder does not validate and
//! does not transform: call [`crate::validate`] separately, before signing and before
//! verifying.

use crate::PaymentAuth;

/// Domain separation tag. These bytes are not valid as any other signed message.
pub const DOMAIN: &str = "chainward.near-payment-guard.auth";

/// Format version. An unknown version is a refusal, never a field to skip.
pub const VERSION: u8 = 1;

/// Appends `u32(len(bytes))` followed by the UTF-8 bytes of `value`.
///
/// The length is the UTF-8 byte count. In Rust `str::len()` is already the byte
/// count, which is the trap the TypeScript side has to work for: there,
/// `String.length` counts UTF-16 code units and is wrong outside the BMP.
fn push_str(out: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    debug_assert!(
        u32::try_from(bytes.len()).is_ok(),
        "string too long to length-prefix",
    );
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Produces the exact bytes that get signed and verified.
///
/// Field order is part of the specification. Changing it is a [`VERSION`] bump,
/// not an edit.
pub fn canonical_bytes(auth: &PaymentAuth) -> Vec<u8> {
    // Pre-size to the common case to avoid repeated reallocation inside a contract.
    let mut out = Vec::with_capacity(256);

    push_str(&mut out, DOMAIN);
    out.push(VERSION);
    push_str(&mut out, &auth.guard_id);
    push_str(&mut out, &auth.deposit_address);
    push_str(&mut out, &auth.destination);
    push_str(&mut out, &auth.chain);
    out.extend_from_slice(&auth.amount.to_be_bytes());
    push_str(&mut out, &auth.verdict);
    push_str(&mut out, &auth.reason);
    out.extend_from_slice(&auth.issued_at.to_be_bytes());
    out.extend_from_slice(&auth.quote_expiry.to_be_bytes());
    out.extend_from_slice(&auth.nonce.to_be_bytes());

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> PaymentAuth {
        PaymentAuth {
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
        }
    }

    #[test]
    fn domain_is_thirty_three_bytes() {
        assert_eq!(DOMAIN.len(), 33);
    }

    #[test]
    fn message_opens_with_the_length_prefixed_domain_and_version() {
        let bytes = canonical_bytes(&base());
        assert_eq!(&bytes[0..4], &[0, 0, 0, 33]);
        assert_eq!(&bytes[4..37], DOMAIN.as_bytes());
        assert_eq!(bytes[37], VERSION);
    }

    #[test]
    fn integers_are_fixed_width_so_zero_is_not_empty() {
        let mut zero = base();
        zero.amount = 0;
        assert_eq!(canonical_bytes(&zero).len(), canonical_bytes(&base()).len());
    }

    #[test]
    fn maximum_integers_do_not_truncate() {
        let mut max = base();
        max.amount = u128::MAX;
        max.nonce = u128::MAX;
        max.issued_at = u64::MAX;
        max.quote_expiry = u64::MAX;
        let hex_bytes = canonical_bytes(&max);
        assert_eq!(
            hex_bytes.iter().filter(|b| **b == 0xff).count(),
            16 + 16 + 8 + 8
        );
    }

    #[test]
    fn utf8_length_is_counted_in_bytes_not_characters() {
        let mut auth = base();
        auth.reason = "\u{1F600}".to_string(); // 1 character, 4 UTF-8 bytes
        let bytes = canonical_bytes(&auth);
        let needle = [0x00, 0x00, 0x00, 0x04, 0xf0, 0x9f, 0x98, 0x80];
        assert!(bytes.windows(needle.len()).any(|w| w == needle));
    }

    #[test]
    fn length_prefixes_prevent_field_boundary_collisions() {
        let mut a = base();
        a.guard_id = "ab.near".to_string();
        a.deposit_address = "c.near".to_string();

        let mut b = base();
        b.guard_id = "a.near".to_string();
        b.deposit_address = "bc.near".to_string();

        assert_ne!(canonical_bytes(&a), canonical_bytes(&b));
    }

    #[test]
    fn encoder_does_not_normalize_unicode() {
        let mut nfc = base();
        nfc.reason = "caf\u{00e9}".to_string();
        let mut nfd = base();
        nfd.reason = "cafe\u{0301}".to_string();
        assert_ne!(canonical_bytes(&nfc), canonical_bytes(&nfd));
    }
}
