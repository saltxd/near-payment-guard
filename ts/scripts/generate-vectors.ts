/**
 * Generates vectors/canonical-vectors.json, the shared fixture that both the
 * TypeScript and the Rust test suites read.
 *
 *   npm run vectors:generate   write the file
 *   npm run vectors:check      regenerate and fail if it differs from the committed file
 *
 * CI runs the check, so the committed vectors cannot drift from this generator,
 * and the Rust suite cannot drift from the committed vectors.
 */

import { writeFileSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import path from "node:path";

import { canonicalBytes, toHex } from "../src/canonical.ts";
import { validate } from "../src/validate.ts";
import { signBytes, testKeyPairFromPhrase, verifyBytes } from "../src/sign.ts";
import { DOMAIN, VERSION, type PaymentAuth } from "../src/types.ts";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const OUT_PATH = path.resolve(HERE, "../../vectors/canonical-vectors.json");

/**
 * Documented in docs/canonical-bytes.md section 8. Deterministic so the vectors
 * regenerate byte-identically; throwaway so it protects nothing. This key signs
 * test fixtures and nothing else.
 */
const TEST_SEED_PHRASE = "chainward near-payment-guard test vectors v1";
const SECOND_SEED_PHRASE = "chainward near-payment-guard wrong key v1";

const signer = testKeyPairFromPhrase(TEST_SEED_PHRASE);
const otherSigner = testKeyPairFromPhrase(SECOND_SEED_PHRASE);

const U64_MAX = 2n ** 64n - 1n;
const U128_MAX = 2n ** 128n - 1n;
/** The ed25519 group order, for the S-malleability vector. RFC 8032. */
const ED25519_L = 2n ** 252n + 27742317777372353535851937790883648493n;

const BASE: PaymentAuth = {
  guardId: "g.near",
  depositAddress: "d.near",
  destination: "0x0000000000000000000000000000000000000001",
  chain: "base",
  amount: 1n,
  verdict: "pay",
  reason: "ok",
  issuedAt: 1762000000n,
  quoteExpiry: 1762000900n,
  nonce: 7n,
};

/** A realistic authorization, shaped like a genuine 1Click quote to Base USDC. */
const REALISTIC: PaymentAuth = {
  guardId: "guard.chainward.near",
  depositAddress: "a4f1c0d9e8b7a6958473621f0e9d8c7b6a5948372615f4e3d2c1b0a998877665",
  destination: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
  chain: "base",
  amount: 25000000n,
  verdict: "pay",
  reason: "paid by 14 unrelated funders over 90 days",
  issuedAt: 1762012800n,
  quoteExpiry: 1762013700n,
  nonce: 42n,
};

const auth = (patch: Partial<PaymentAuth>): PaymentAuth => ({ ...BASE, ...patch });

// --- JSON shape -------------------------------------------------------------
// snake_case keys matching the Rust struct and the contract's JSON args.
// All integers are strings: u128 does not fit a JSON number, and u64 loses
// precision above 2^53 in any JavaScript consumer.

interface AuthJson {
  guard_id: string;
  deposit_address: string;
  destination: string;
  chain: string;
  amount: string;
  verdict: string;
  reason: string;
  issued_at: string;
  quote_expiry: string;
  nonce: string;
}

const toJson = (a: PaymentAuth): AuthJson => ({
  guard_id: a.guardId,
  deposit_address: a.depositAddress,
  destination: a.destination,
  chain: a.chain,
  amount: a.amount.toString(),
  verdict: a.verdict,
  reason: a.reason,
  issued_at: a.issuedAt.toString(),
  quote_expiry: a.quoteExpiry.toString(),
  nonce: a.nonce.toString(),
});

const sha256Hex = (bytes: Uint8Array): string =>
  createHash("sha256").update(Buffer.from(bytes)).digest("hex");

const encodingVector = (name: string, description: string, a: PaymentAuth) => {
  const bytes = canonicalBytes(a);
  return {
    name,
    description,
    auth: toJson(a),
    canonical_hex: toHex(bytes),
    canonical_len: bytes.length,
    // Test metadata only. Nothing signs or verifies this; see spec section 6.
    canonical_sha256: sha256Hex(bytes),
  };
};

const distinctnessVector = (
  name: string,
  description: string,
  a: PaymentAuth,
  b: PaymentAuth,
) => ({ name, description, a: toJson(a), b: toJson(b) });

const verificationVector = (
  name: string,
  description: string,
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
  expectValid: boolean,
) => {
  const actual = verifyBytes(message, signature, publicKey);
  if (actual !== expectValid) {
    throw new Error(
      `verification vector "${name}" expected valid=${expectValid} but the TS verifier said ${actual}`,
    );
  }
  return {
    name,
    description,
    message_hex: toHex(message),
    public_key_hex: toHex(publicKey),
    signature_hex: toHex(signature),
    expect_valid: expectValid,
  };
};

const validationVector = (name: string, description: string, a: PaymentAuth) => ({
  name,
  description,
  auth: toJson(a),
  expect_failure: validate(a),
});

// --- byte helpers for the adversarial verification vectors ------------------

const withTrailing = (bytes: Uint8Array, ...extra: number[]): Uint8Array =>
  Uint8Array.from([...bytes, ...extra]);

const flipBit = (bytes: Uint8Array, index: number): Uint8Array => {
  const out = Uint8Array.from(bytes);
  out[index] = (out[index] ?? 0) ^ 0x01;
  return out;
};

const leToBigint = (bytes: Uint8Array): bigint => {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) value = (value << 8n) | BigInt(bytes[i] ?? 0);
  return value;
};

const bigintToLe = (value: bigint, width: number): Uint8Array => {
  const out = new Uint8Array(width);
  let rest = value;
  for (let i = 0; i < width; i += 1) {
    out[i] = Number(rest & 0xffn);
    rest >>= 8n;
  }
  return out;
};

/** Returns R || (S + L), the classic malleated form a non-strict verifier accepts. */
const malleateS = (signature: Uint8Array): Uint8Array => {
  const out = Uint8Array.from(signature);
  out.set(bigintToLe(leToBigint(signature.subarray(32)) + ED25519_L, 32), 32);
  return out;
};

// --- the vectors ------------------------------------------------------------

const encoding = [
  encodingVector("worked-example", "The byte-by-byte example in spec section 7.", BASE),
  encodingVector("realistic-base-usdc", "A realistic authorization paying USDC on Base.", REALISTIC),
  encodingVector("realistic-bsc", "The same shape on BNB Chain.", { ...REALISTIC, chain: "bsc" }),
  encodingVector("empty-reason", "An empty string is a 4-byte length of zero, not an absent field.", auth({ reason: "" })),
  encodingVector("verdict-hold", "A refusal carries the same shape as an approval.", auth({ verdict: "hold", reason: "sanctions list match" })),
  encodingVector("verdict-unknown", "Unknown is a verdict, not an error.", auth({ verdict: "unknown", reason: "payer hidden behind a relayer" })),
  encodingVector("amount-max-u128", "u128::MAX must not truncate or wrap.", auth({ amount: U128_MAX })),
  encodingVector("nonce-max-u128", "u128::MAX in the last field, where a truncation bug would hide.", auth({ nonce: U128_MAX })),
  encodingVector("timestamps-max-u64", "u64::MAX in both time fields.", auth({ issuedAt: U64_MAX, quoteExpiry: U64_MAX })),
  encodingVector("numerics-all-zero", "Zero is fixed-width, not empty: 16 zero bytes, not none.", auth({ amount: 0n, issuedAt: 0n, quoteExpiry: 0n, nonce: 0n })),
  encodingVector("unicode-astral-reason", "An astral-plane character: 2 UTF-16 code units, 4 UTF-8 bytes. Catches a length taken from String.length.", auth({ reason: "drained \u{1F600}" })),
  encodingVector("unicode-nfc-reason", "Precomposed U+00E9.", auth({ reason: "café wallet" })),
  encodingVector("unicode-nfd-reason", "Decomposed e + U+0301. Must encode differently from the NFC form.", auth({ reason: "café wallet" })),
  encodingVector("unicode-mixed-scripts", "Non-Latin text in the human-readable field.", auth({ reason: "расчет 付款 مدفوع" })),
  encodingVector("reason-max-length", "Exactly 256 bytes, the limit.", auth({ reason: "a".repeat(256) })),
  encodingVector("guard-id-implicit-64hex", "A free implicit NEAR account, 64 hex characters.", auth({ guardId: "f".repeat(64) })),
  encodingVector("deposit-address-max-length", "Exactly 128 bytes, the limit.", auth({ depositAddress: "b".repeat(128) })),
  encodingVector("destination-all-f", "Every hex digit at its maximum.", auth({ destination: "0x" + "f".repeat(40) })),
];

const distinctness = [
  distinctnessVector(
    "field-boundary-shift",
    "Moving a character across the guard_id/deposit_address seam. Without length prefixes these concatenate identically; this is the vector that proves rule 1.",
    auth({ guardId: "ab.near", depositAddress: "c.near" }),
    auth({ guardId: "a.near", depositAddress: "bc.near" }),
  ),
  distinctnessVector(
    "field-boundary-shift-destination",
    "The same attack at the deposit_address/destination seam.",
    auth({ depositAddress: "x", destination: "0x" + "a".repeat(40) }),
    auth({ depositAddress: "x0", destination: "x" + "a".repeat(40) }),
  ),
  distinctnessVector(
    "swapped-field-values",
    "Two string fields with their values exchanged.",
    auth({ guardId: "one.near", depositAddress: "two.near" }),
    auth({ guardId: "two.near", depositAddress: "one.near" }),
  ),
  distinctnessVector(
    "swapped-timestamps",
    "issued_at and quote_expiry exchanged. Same bytes, different meaning, so the order is load-bearing.",
    auth({ issuedAt: 1762000000n, quoteExpiry: 1762000900n }),
    auth({ issuedAt: 1762000900n, quoteExpiry: 1762000000n }),
  ),
  distinctnessVector(
    "swapped-amount-and-nonce",
    "The two u128 fields exchanged.",
    auth({ amount: 5n, nonce: 9n }),
    auth({ amount: 9n, nonce: 5n }),
  ),
  distinctnessVector(
    "nfc-vs-nfd",
    "Unicode is not normalized (rule 5). These must stay different byte strings.",
    auth({ reason: "café" }),
    auth({ reason: "café" }),
  ),
  distinctnessVector(
    "empty-vs-one-byte-reason",
    "An empty field is distinguishable from a one-byte field.",
    auth({ reason: "" }),
    auth({ reason: " " }),
  ),
  distinctnessVector(
    "amount-off-by-one",
    "The smallest possible change to the amount.",
    auth({ amount: 1000000n }),
    auth({ amount: 1000001n }),
  ),
  distinctnessVector(
    "destination-last-digit",
    "One hex digit of the payee.",
    auth({ destination: "0x" + "a".repeat(39) + "b" }),
    auth({ destination: "0x" + "a".repeat(39) + "c" }),
  ),
  distinctnessVector(
    "chain-base-vs-bsc",
    "The same destination string on a different chain is a different payee.",
    auth({ chain: "base" }),
    auth({ chain: "bsc" }),
  ),
  distinctnessVector(
    "verdict-pay-vs-hold",
    "The field the whole design turns on.",
    auth({ verdict: "pay" }),
    auth({ verdict: "hold" }),
  ),
  distinctnessVector(
    "different-guard-same-everything",
    "The cross-guard replay from spec section 4: identical authorization, different guard.",
    auth({ guardId: "alice.near" }),
    auth({ guardId: "bob.near" }),
  ),
];

// Signatures used by the verification family.
const baseBytes = canonicalBytes(BASE);
const baseSig = signBytes(baseBytes, signer.privateKey);
const realisticBytes = canonicalBytes(REALISTIC);
const realisticSig = signBytes(realisticBytes, signer.privateKey);

/** A message whose domain string is swapped, to prove domain separation. */
const foreignDomainMessage = (() => {
  const bytes = Uint8Array.from(baseBytes);
  // DOMAIN sits at bytes 4..37 and is the same length as this replacement.
  const replacement = new TextEncoder().encode("chainward.near-payment-guard.OTHR");
  bytes.set(replacement, 4);
  return bytes;
})();

/** The same message with the version byte bumped to 2. */
const bumpedVersionMessage = (() => {
  const bytes = Uint8Array.from(baseBytes);
  bytes[37] = VERSION + 1;
  return bytes;
})();

const verification = [
  verificationVector("valid-signature", "The happy path: a real signature over the worked example.", baseBytes, baseSig, signer.publicKeyBytes, true),
  verificationVector("valid-signature-realistic", "A real signature over the realistic authorization.", realisticBytes, realisticSig, signer.publicKeyBytes, true),
  verificationVector("trailing-zero-byte", "One zero byte appended. A verifier that ignores trailing data accepts a message the signer never produced.", withTrailing(baseBytes, 0x00), baseSig, signer.publicKeyBytes, false),
  verificationVector("trailing-newline", "A trailing newline, the shape a careless file read introduces.", withTrailing(baseBytes, 0x0a), baseSig, signer.publicKeyBytes, false),
  verificationVector("trailing-sixteen-bytes", "A whole extra u128 appended, as if a field were added.", withTrailing(baseBytes, ...new Array<number>(16).fill(0)), baseSig, signer.publicKeyBytes, false),
  verificationVector("truncated-last-byte", "The last byte of the nonce removed.", baseBytes.subarray(0, baseBytes.length - 1), baseSig, signer.publicKeyBytes, false),
  verificationVector("truncated-to-empty", "An empty message against a real signature.", new Uint8Array(0), baseSig, signer.publicKeyBytes, false),
  verificationVector("flipped-bit-in-destination", "One bit of the payee address changed.", flipBit(baseBytes, 70), baseSig, signer.publicKeyBytes, false),
  verificationVector("flipped-bit-in-amount", "One bit of the amount changed.", flipBit(baseBytes, 127), baseSig, signer.publicKeyBytes, false),
  verificationVector("flipped-bit-in-signature", "One bit of the signature changed.", baseBytes, flipBit(baseSig, 10), signer.publicKeyBytes, false),
  verificationVector("signature-for-different-message", "A genuine ChainWard signature, presented against another authorization. The attack spec section 4 is about.", realisticBytes, baseSig, signer.publicKeyBytes, false),
  verificationVector("wrong-public-key", "A real signature checked against a different key.", baseBytes, baseSig, otherSigner.publicKeyBytes, false),
  verificationVector("all-zero-signature", "64 zero bytes.", baseBytes, new Uint8Array(64), signer.publicKeyBytes, false),
  verificationVector("all-ff-signature", "64 bytes of 0xff: a non-canonical S far above the group order.", baseBytes, new Uint8Array(64).fill(0xff), signer.publicKeyBytes, false),
  verificationVector("malleable-s-plus-l", "R || (S + L). A non-strict verifier accepts this, giving one authorization two valid signatures. Node (OpenSSL) and dalek both refuse it; whether nearcore's host function is equally strict is confirmed when the contract wires it up.", baseBytes, malleateS(baseSig), signer.publicKeyBytes, false),
  verificationVector("foreign-domain", "The same fields under a different domain string. Proves a signature here is not reusable elsewhere.", foreignDomainMessage, baseSig, signer.publicKeyBytes, false),
  verificationVector("bumped-version-byte", "Version 2 bytes against a version 1 signature.", bumpedVersionMessage, baseSig, signer.publicKeyBytes, false),
];

const validation = [
  validationVector("valid-worked-example", "The baseline: shape-valid.", BASE),
  validationVector("valid-realistic", "A realistic authorization is shape-valid.", REALISTIC),
  validationVector("valid-implicit-guard-id", "A 64-hex implicit account is a valid single-part account id.", auth({ guardId: "0".repeat(64) })),
  validationVector("valid-separators-in-guard-id", "Single - and _ separators inside a part.", auth({ guardId: "a_b-c.near" })),
  validationVector("valid-empty-reason", "An empty reason is allowed.", auth({ reason: "" })),
  validationVector("valid-reason-at-limit", "256 bytes exactly.", auth({ reason: "a".repeat(256) })),
  validationVector("valid-reason-non-ascii", "Non-ASCII human text is allowed in reason.", auth({ reason: "риск \u{1F600}" })),
  validationVector("valid-deposit-address-at-limit", "128 bytes exactly.", auth({ depositAddress: "b".repeat(128) })),

  validationVector("guard-id-too-short", "One character is below the 2-byte minimum.", auth({ guardId: "a" })),
  validationVector("guard-id-too-long", "65 bytes is above the 64-byte maximum.", auth({ guardId: "a".repeat(65) })),
  validationVector("guard-id-uppercase", "NEAR account ids are lowercase.", auth({ guardId: "Guard.near" })),
  validationVector("guard-id-doubled-dot", "An empty part between separators.", auth({ guardId: "a..near" })),
  validationVector("guard-id-leading-dot", "A leading separator.", auth({ guardId: ".near" })),
  validationVector("guard-id-trailing-dot", "A trailing separator.", auth({ guardId: "near." })),
  validationVector("guard-id-separator-run", "Two separators in a row inside a part.", auth({ guardId: "a--b.near" })),
  validationVector("guard-id-non-ascii", "A multi-byte character must fail the charset rule, not pass on character count.", auth({ guardId: "guardé.near" })),
  validationVector("guard-id-astral", "An astral-plane character in an account id.", auth({ guardId: "guard\u{1F600}.near" })),

  validationVector("deposit-address-empty", "Empty is below the 1-byte minimum.", auth({ depositAddress: "" })),
  validationVector("deposit-address-too-long", "129 bytes is above the limit.", auth({ depositAddress: "b".repeat(129) })),
  validationVector("deposit-address-with-space", "A space is outside printable 0x21..0x7E.", auth({ depositAddress: "has space" })),
  validationVector("deposit-address-with-tab", "A tab is a control character.", auth({ depositAddress: "has\ttab" })),
  validationVector("deposit-address-non-ascii", "Non-ASCII in the one address the guard will pay.", auth({ depositAddress: "café.near" })),

  validationVector("destination-uppercase", "EIP-55 checksum casing. Section 5.2: accepting this bypasses the per-counterparty cap.", auth({ destination: "0x" + "A".repeat(40) })),
  validationVector("destination-mixed-case", "A realistic checksummed address.", auth({ destination: "0x833589FcD6eDb6E08f4c7C32D4f71b54bdA02913" })),
  validationVector("destination-too-short", "39 hex digits.", auth({ destination: "0x" + "a".repeat(39) })),
  validationVector("destination-too-long", "41 hex digits.", auth({ destination: "0x" + "a".repeat(41) })),
  validationVector("destination-no-prefix", "42 hex characters with no 0x.", auth({ destination: "a".repeat(42) })),
  validationVector("destination-uppercase-prefix", "0X instead of 0x.", auth({ destination: "0X" + "a".repeat(40) })),
  validationVector("destination-not-hex", "Characters outside [0-9a-f].", auth({ destination: "0x" + "g".repeat(40) })),
  validationVector("destination-empty", "An empty payee.", auth({ destination: "" })),

  validationVector("chain-uppercase", "Chain names are a closed lowercase set.", auth({ chain: "BASE" as PaymentAuth["chain"] })),
  validationVector("chain-unsupported", "A chain the guard does not serve.", auth({ chain: "ethereum" as PaymentAuth["chain"] })),
  validationVector("chain-empty", "An empty chain.", auth({ chain: "" as PaymentAuth["chain"] })),

  validationVector("verdict-uppercase", "Verdict labels are lowercase.", auth({ verdict: "PAY" as PaymentAuth["verdict"] })),
  validationVector("verdict-unknown-word", "A label outside the closed set.", auth({ verdict: "yes" as PaymentAuth["verdict"] })),
  validationVector("verdict-empty", "An empty verdict.", auth({ verdict: "" as PaymentAuth["verdict"] })),

  validationVector("reason-too-long", "257 bytes.", auth({ reason: "a".repeat(257) })),
  validationVector("reason-astral-over-byte-limit", "65 astral characters are 260 UTF-8 bytes, though only 65 characters. The limit is in bytes.", auth({ reason: "\u{1F600}".repeat(65) })),
  validationVector("reason-newline", "A C0 control character.", auth({ reason: "line\nbreak" })),
  validationVector("reason-nul", "A NUL byte.", auth({ reason: "nul\u0000here" })),
  validationVector("reason-del", "U+007F.", auth({ reason: "del\u007f" })),
  validationVector("reason-c1-control", "A C1 control character.", auth({ reason: "c1\u0085here" })),

  validationVector("first-failure-wins", "Several fields are invalid at once. Rules run in canonical field order, so both languages must report guard_id_invalid.", auth({ guardId: "BAD", destination: "nope", chain: "ethereum" as PaymentAuth["chain"] })),
];

// --- differential: exhaustive agreement on the hand-rolled rules ------------
//
// The two account-id implementations are genuinely different programs: TypeScript
// runs a regex, Rust runs a hand-rolled scan with no regex crate (a contract should
// not carry one). Agreeing on the 43 validation vectors above shows they agree on
// 43 inputs, which is not the same as agreeing. A signer that accepts what the
// verifier refuses mints unusable authorizations; a verifier that accepts what the
// signer refuses is a hole.
//
// So: enumerate every string up to length 4 over an alphabet chosen to hit every
// branch, and pin the answer for each. Exhaustive at these lengths, which is where
// separator and boundary bugs live.

const DIFFERENTIAL_ALPHABET = ["a", "1", "-", "_", ".", "A", "é"] as const;

const enumerateStrings = (maxLength: number): string[] => {
  const out: string[] = [];
  let frontier: string[] = [""];
  for (let length = 1; length <= maxLength; length += 1) {
    const next: string[] = [];
    for (const prefix of frontier) {
      for (const char of DIFFERENTIAL_ALPHABET) next.push(prefix + char);
    }
    out.push(...next);
    frontier = next;
  }
  return out;
};

/** Longer shapes that length <= 4 cannot express. */
const LONGER_ACCOUNT_IDS = [
  "a".repeat(64),
  "a".repeat(65),
  "f".repeat(64),
  "guard.chainward.near",
  "a_b-c.near",
  "a-b_c.d1.near",
  "sub.sub.sub.near",
  "a.b.c.d.e.f.g",
  "a-.b.near",
  "a._b.near",
  "a__b.near",
  "a.-b.near",
  "1234567890.near",
  "é".repeat(32),
  "a\u{1F600}b.near",
];

const differentialAccountIds = [...enumerateStrings(4), ...LONGER_ACCOUNT_IDS].map((value) => {
  // Isolate the guard_id rule: everything else in the auth is known-good.
  const failure = validate(auth({ guardId: value }));
  return [value, failure === null] as const;
});

/** The deposit_address rule, over the same alphabet plus bytes around the 0x21..0x7E edges. */
const differentialDepositAddresses = [
  ...enumerateStrings(2),
  " ",
  "\t",
  "\n",
  "\u0000",
  "\u007f",
  "\u0080",
  "!",
  "~",
  "0x",
  "a".repeat(128),
  "a".repeat(129),
  "é",
  "\u{1F600}",
].map((value) => {
  const failure = validate(auth({ depositAddress: value }));
  return [value, failure === null] as const;
});

// --- write ------------------------------------------------------------------

const document = {
  $comment: "Generated by `npm run vectors:generate`. Do not edit by hand.",
  spec: "docs/canonical-bytes.md",
  version: VERSION,
  domain: DOMAIN,
  test_signer: {
    warning:
      "THROWAWAY TEST KEY. Derived at test time, signs fixtures only, protects nothing. The production verdict key is generated separately and lives only in a k8s secret; it is never in this repository.",
    seed_phrase: TEST_SEED_PHRASE,
    seed_derivation: "sha256(utf8(seed_phrase)) -> 32-byte ed25519 seed",
    public_key_hex: toHex(signer.publicKeyBytes),
    second_key_seed_phrase: SECOND_SEED_PHRASE,
    second_public_key_hex: toHex(otherSigner.publicKeyBytes),
  },
  counts: {
    encoding: encoding.length,
    distinctness: distinctness.length,
    verification: verification.length,
    validation: validation.length,
    differential_account_id: differentialAccountIds.length,
    differential_deposit_address: differentialDepositAddresses.length,
    total:
      encoding.length +
      distinctness.length +
      verification.length +
      validation.length +
      differentialAccountIds.length +
      differentialDepositAddresses.length,
  },
  encoding,
  distinctness,
  verification,
  validation,
  differential: {
    note:
      "Exhaustive agreement checks for the two rules implemented differently in each language " +
      "(a regex in TypeScript, a hand-rolled scan in Rust). Each entry is [value, is_valid]. " +
      "Every string up to length 4 over the alphabet a 1 - _ . A é, plus longer shapes.",
    alphabet: [...DIFFERENTIAL_ALPHABET],
    max_enumerated_length: 4,
    account_id: differentialAccountIds,
    deposit_address: differentialDepositAddresses,
  },
};

/**
 * Serializes with every non-ASCII character escaped as \uXXXX.
 *
 * The file's entire job is to pin down bytes, so it must survive editors, diff
 * tools and terminals that would otherwise normalize or re-encode it. JSON parsers
 * reconstruct the escapes, including surrogate pairs, so Rust reads the same string.
 */
const toAsciiJson = (value: unknown): string =>
  JSON.stringify(value, null, 2).replace(/[\u0080-￿]/g, (char) =>
    `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`,
  ) + "\n";

const rendered = toAsciiJson(document);

if (process.argv.includes("--check")) {
  const committed = readFileSync(OUT_PATH, "utf8");
  if (committed !== rendered) {
    console.error(
      `vectors/canonical-vectors.json is out of date.\nRun: npm run vectors:generate`,
    );
    process.exit(1);
  }
  console.log(`vectors are up to date (${document.counts.total} vectors)`);
} else {
  writeFileSync(OUT_PATH, rendered);
  console.log(`wrote ${OUT_PATH}`);
  console.log(
    `  encoding ${encoding.length}, distinctness ${distinctness.length}, ` +
      `verification ${verification.length}, validation ${validation.length}, ` +
      `differential ${differentialAccountIds.length + differentialDepositAddresses.length} ` +
      `= ${document.counts.total} vectors`,
  );
}
