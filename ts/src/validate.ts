/**
 * Shape validation for a payment authorization.
 *
 * Shape only: the rules that make two parties agree on a byte string. Semantics
 * (freshness, caps, nonce reuse, whether the verdict is "pay") belong to the
 * contract. See docs/canonical-bytes.md section 5 for where that line sits and why.
 *
 * Every rule here is mirrored in crates/guard-auth/src/validate.rs and pinned by
 * the `validation` family in vectors/canonical-vectors.json.
 */

import { LIMITS, type PaymentAuth, type ValidationFailure } from "./types.ts";

const UTF8 = new TextEncoder();

const byteLength = (value: string): number => UTF8.encode(value).length;

/**
 * NEAR account id rule: 2..=64 bytes, dot-separated parts, each part made of
 * lowercase alphanumeric runs joined by single `-` or `_`, with no leading,
 * trailing or doubled separator. A 64-character hex implicit account is one part.
 */
const NEAR_ACCOUNT_ID = /^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$/;

const isValidAccountId = (value: string): boolean => {
  // Length is in bytes. The charset below is ASCII-only, so any multi-byte
  // character fails the pattern rather than slipping through on char count.
  const length = byteLength(value);
  if (length < LIMITS.guardIdMin || length > LIMITS.guardIdMax) return false;
  return NEAR_ACCOUNT_ID.test(value);
};

/** Printable ASCII, no space and no DEL: every byte in 0x21..=0x7E. */
const isPrintableAsciiNoSpace = (value: string): boolean => {
  for (const char of value) {
    const code = char.codePointAt(0) ?? 0;
    if (code < 0x21 || code > 0x7e) return false;
  }
  return true;
};

/** Lowercase 0x-prefixed EVM address. Section 5.2 explains why case is not forgiven. */
const EVM_ADDRESS_LOWERCASE = /^0x[0-9a-f]{40}$/;

/** C0 (0x00-0x1F), DEL (0x7F) and C1 (0x80-0x9F) are refused in human-readable text. */
const hasControlCharacter = (value: string): boolean => {
  for (const char of value) {
    const code = char.codePointAt(0) ?? 0;
    if (code <= 0x1f || code === 0x7f || (code >= 0x80 && code <= 0x9f)) return true;
  }
  return false;
};

/**
 * Returns the first failing rule, or null when the authorization is shape-valid.
 *
 * Rules are checked in the field order of the canonical encoding, so a given input
 * always reports the same failure in both languages.
 */
export const validate = (auth: PaymentAuth): ValidationFailure | null => {
  if (!isValidAccountId(auth.guardId)) return "guard_id_invalid";

  const depositLength = byteLength(auth.depositAddress);
  if (
    depositLength < LIMITS.depositAddressMin ||
    depositLength > LIMITS.depositAddressMax ||
    !isPrintableAsciiNoSpace(auth.depositAddress)
  ) {
    return "deposit_address_invalid";
  }

  if (!EVM_ADDRESS_LOWERCASE.test(auth.destination)) return "destination_invalid";

  if (auth.chain !== "base" && auth.chain !== "bsc") return "chain_invalid";

  if (auth.verdict !== "pay" && auth.verdict !== "hold" && auth.verdict !== "unknown") {
    return "verdict_invalid";
  }

  if (byteLength(auth.reason) > LIMITS.reasonMax || hasControlCharacter(auth.reason)) {
    return "reason_invalid";
  }

  return null;
};

/** Throws on a shape-invalid authorization. Use before signing. */
export const assertValid = (auth: PaymentAuth): void => {
  const failure = validate(auth);
  if (failure !== null) {
    throw new Error(`payment authorization failed shape validation: ${failure}`);
  }
};
