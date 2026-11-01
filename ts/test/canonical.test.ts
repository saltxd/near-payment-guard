/**
 * Spec-conformance tests for the canonical encoding.
 *
 * These assert against values derived BY HAND from docs/canonical-bytes.md, not
 * against whatever the encoder happens to produce. That is the whole point: if the
 * encoder and the test are both written from the code, they agree on the bug too.
 */

import { test, describe } from "node:test";
import assert from "node:assert/strict";

import { canonicalBytes, toHex } from "../src/canonical.ts";
import { validate } from "../src/validate.ts";
import type { PaymentAuth } from "../src/types.ts";

/** The worked example from docs/canonical-bytes.md section 7. */
const WORKED_EXAMPLE: PaymentAuth = {
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

/**
 * Hand-assembled from the byte table in docs/canonical-bytes.md section 7.
 * Every row of that table, in order, concatenated. Do not regenerate this from
 * the implementation; if it disagrees with the implementation, one of them is
 * wrong and the spec decides which.
 */
const WORKED_EXAMPLE_HEX = [
  "00000021", // u32(33), DOMAIN length
  "636861696e776172642e6e6561722d7061796d656e742d67756172642e61757468", // "chainward.near-payment-guard.auth"
  "01", // u8(1), VERSION
  "00000006", // u32(6)
  "672e6e656172", // "g.near"
  "00000006", // u32(6)
  "642e6e656172", // "d.near"
  "0000002a", // u32(42)
  "3078" + "30".repeat(39) + "31", // "0x0000...0001"
  "00000004", // u32(4)
  "62617365", // "base"
  "00000000000000000000000000000001", // u128(1)
  "00000003", // u32(3)
  "706179", // "pay"
  "00000002", // u32(2)
  "6f6b", // "ok"
  "000000006905fc80", // u64(1762000000)
  "0000000069060004", // u64(1762000900)
  "00000000000000000000000000000007", // u128(7)
].join("");

describe("canonical encoding: the worked example", () => {
  test("matches the byte table in the spec", () => {
    assert.equal(toHex(canonicalBytes(WORKED_EXAMPLE)), WORKED_EXAMPLE_HEX);
  });

  test("is 173 bytes, as the spec states", () => {
    assert.equal(canonicalBytes(WORKED_EXAMPLE).length, 173);
    assert.equal(WORKED_EXAMPLE_HEX.length / 2, 173);
  });

  test("starts with the length-prefixed domain and the version byte", () => {
    const bytes = canonicalBytes(WORKED_EXAMPLE);
    // u32(33) big-endian
    assert.deepEqual(Array.from(bytes.subarray(0, 4)), [0, 0, 0, 0x21]);
    assert.equal(
      Buffer.from(bytes.subarray(4, 37)).toString("utf8"),
      "chainward.near-payment-guard.auth",
    );
    assert.equal(bytes[37], 1, "version byte");
  });
});

describe("canonical encoding: primitives behave as specified", () => {
  test("integers are fixed width, so zero is not empty", () => {
    const zeroAmount = canonicalBytes({ ...WORKED_EXAMPLE, amount: 0n });
    const oneAmount = canonicalBytes(WORKED_EXAMPLE);
    assert.equal(
      zeroAmount.length,
      oneAmount.length,
      "u128(0) must occupy the same 16 bytes as u128(1)",
    );
  });

  test("u128 maximum round-trips without truncation", () => {
    const max = 2n ** 128n - 1n;
    const hex = toHex(canonicalBytes({ ...WORKED_EXAMPLE, amount: max }));
    assert.ok(hex.includes("f".repeat(32)), "u128::MAX must appear as 16 bytes of 0xff");
  });

  test("u64 maximum round-trips without truncation", () => {
    const max = 2n ** 64n - 1n;
    const hex = toHex(canonicalBytes({ ...WORKED_EXAMPLE, issuedAt: max }));
    assert.ok(hex.includes("f".repeat(16)), "u64::MAX must appear as 8 bytes of 0xff");
  });

  test("out-of-range integers are refused, not silently wrapped", () => {
    assert.throws(() => canonicalBytes({ ...WORKED_EXAMPLE, amount: 2n ** 128n }), /u128/);
    assert.throws(() => canonicalBytes({ ...WORKED_EXAMPLE, amount: -1n }), /u128/);
    assert.throws(() => canonicalBytes({ ...WORKED_EXAMPLE, issuedAt: 2n ** 64n }), /u64/);
  });

  test("string length is the UTF-8 byte count, not the UTF-16 code unit count", () => {
    // "\u{1F600}".length is 2 in JavaScript, but 4 bytes in UTF-8.
    const auth = { ...WORKED_EXAMPLE, reason: "\u{1F600}" };
    const bytes = canonicalBytes(auth);
    const hex = toHex(bytes);
    assert.ok(hex.includes("00000004f09f9880"), "emoji must encode as u32(4) + f0 9f 98 80");
  });
});

describe("canonical encoding: injectivity (spec rule 1)", () => {
  const hex = (a: PaymentAuth) => toHex(canonicalBytes(a));

  test("moving a character across a field boundary changes the bytes", () => {
    // Without length prefixes these two would concatenate identically.
    const a = hex({ ...WORKED_EXAMPLE, guardId: "ab.near", depositAddress: "c.near" });
    const b = hex({ ...WORKED_EXAMPLE, guardId: "a.near", depositAddress: "bc.near" });
    assert.notEqual(a, b);
  });

  test("swapping two field values changes the bytes", () => {
    const a = hex({ ...WORKED_EXAMPLE, guardId: "one.near", depositAddress: "two.near" });
    const b = hex({ ...WORKED_EXAMPLE, guardId: "two.near", depositAddress: "one.near" });
    assert.notEqual(a, b);
  });

  test("an empty field is distinguishable from a short one", () => {
    const a = hex({ ...WORKED_EXAMPLE, reason: "" });
    const b = hex({ ...WORKED_EXAMPLE, reason: "\u0000" });
    assert.notEqual(a, b);
  });

  test("Unicode is NOT normalized: NFC and NFD stay different", () => {
    // Rule 5: the encoder does not transform. "é" precomposed vs "e" + combining acute.
    const nfc = hex({ ...WORKED_EXAMPLE, reason: "caf\u00e9" });
    const nfd = hex({ ...WORKED_EXAMPLE, reason: "cafe\u0301" });
    assert.notEqual(nfc, nfd, "the encoder must not normalize");
  });

  test("changing only the chain changes the bytes", () => {
    assert.notEqual(hex(WORKED_EXAMPLE), hex({ ...WORKED_EXAMPLE, chain: "bsc" }));
  });

  test("changing only the verdict changes the bytes", () => {
    assert.notEqual(hex(WORKED_EXAMPLE), hex({ ...WORKED_EXAMPLE, verdict: "hold" }));
  });
});

describe("validate: shape rules (spec section 5)", () => {
  const check = (patch: Partial<PaymentAuth>) => validate({ ...WORKED_EXAMPLE, ...patch });

  test("the worked example is valid", () => {
    assert.equal(validate(WORKED_EXAMPLE), null);
  });

  test("guard_id must be a valid NEAR account id", () => {
    assert.equal(check({ guardId: "a" }), "guard_id_invalid", "too short");
    assert.equal(check({ guardId: "a".repeat(65) }), "guard_id_invalid", "too long");
    assert.equal(check({ guardId: "UPPER.near" }), "guard_id_invalid", "uppercase");
    assert.equal(check({ guardId: "a..near" }), "guard_id_invalid", "doubled dot");
    assert.equal(check({ guardId: ".near" }), "guard_id_invalid", "leading dot");
    assert.equal(check({ guardId: "near." }), "guard_id_invalid", "trailing dot");
    assert.equal(check({ guardId: "a-.near" }), "guard_id_invalid", "separator before dot");
    assert.equal(check({ guardId: "guard\u00e9.near" }), "guard_id_invalid", "non-ASCII");
    assert.equal(check({ guardId: "f".repeat(64) }), null, "implicit 64-hex account is valid");
    assert.equal(check({ guardId: "guard.chainward.near" }), null);
    assert.equal(check({ guardId: "a_b-c.near" }), null);
  });

  test("deposit_address must be printable ASCII without spaces", () => {
    assert.equal(check({ depositAddress: "" }), "deposit_address_invalid");
    assert.equal(check({ depositAddress: "a".repeat(129) }), "deposit_address_invalid");
    assert.equal(check({ depositAddress: "has space" }), "deposit_address_invalid");
    assert.equal(check({ depositAddress: "caf\u00e9.near" }), "deposit_address_invalid");
    assert.equal(check({ depositAddress: "tab\there" }), "deposit_address_invalid");
    assert.equal(check({ depositAddress: "0xAbCd" }), null, "mixed case is allowed here");
  });

  test("destination must be a lowercase 0x EVM address", () => {
    assert.equal(check({ destination: "0x" + "a".repeat(39) }), "destination_invalid", "39 digits");
    assert.equal(check({ destination: "0x" + "a".repeat(41) }), "destination_invalid", "41 digits");
    assert.equal(check({ destination: "0x" + "A".repeat(40) }), "destination_invalid", "uppercase");
    assert.equal(check({ destination: "0X" + "a".repeat(40) }), "destination_invalid", "0X prefix");
    assert.equal(check({ destination: "a".repeat(42) }), "destination_invalid", "no 0x prefix");
    assert.equal(check({ destination: "0x" + "g".repeat(40) }), "destination_invalid", "not hex");
    assert.equal(check({ destination: "0x" + "0123456789abcdef".repeat(2) + "01234567" }), null);
  });

  test("chain and verdict are closed sets", () => {
    assert.equal(check({ chain: "BASE" as never }), "chain_invalid");
    assert.equal(check({ chain: "ethereum" as never }), "chain_invalid");
    assert.equal(check({ chain: "" as never }), "chain_invalid");
    assert.equal(check({ verdict: "PAY" as never }), "verdict_invalid");
    assert.equal(check({ verdict: "yes" as never }), "verdict_invalid");
    assert.equal(check({ chain: "bsc" }), null);
    assert.equal(check({ verdict: "hold" }), null);
    assert.equal(check({ verdict: "unknown" }), null);
  });

  test("reason is bounded and free of control characters", () => {
    assert.equal(check({ reason: "" }), null, "empty is allowed");
    assert.equal(check({ reason: "a".repeat(256) }), null, "256 bytes is the limit");
    assert.equal(check({ reason: "a".repeat(257) }), "reason_invalid");
    assert.equal(check({ reason: "line\nbreak" }), "reason_invalid", "C0 control");
    assert.equal(check({ reason: "nul\u0000" }), "reason_invalid");
    assert.equal(check({ reason: "del\u007f" }), "reason_invalid");
    assert.equal(check({ reason: "c1\u0085" }), "reason_invalid", "C1 control");
    assert.equal(check({ reason: "sanctions list match \u{1F600}" }), null, "non-ASCII text is fine");
    // 256 is a BYTE limit, not a character limit.
    assert.equal(check({ reason: "\u{1F600}".repeat(65) }), "reason_invalid", "65 emoji = 260 bytes");
  });

  test("validation is independent of encoding: invalid input still encodes", () => {
    // Spec rule 5 and section 5: the encoder is dumb, validate() is a separate call.
    const bad = { ...WORKED_EXAMPLE, destination: "0x" + "A".repeat(40) };
    assert.equal(validate(bad), "destination_invalid");
    assert.doesNotThrow(() => canonicalBytes(bad));
  });
});
