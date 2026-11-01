/**
 * Verifies the TypeScript side against the COMMITTED vector file.
 *
 * canonical.test.ts checks TypeScript against the spec. The Rust suite checks Rust
 * against this file. This closes the triangle: if someone hand-edits
 * vectors/canonical-vectors.json to make the Rust suite pass, this fails.
 */

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalBytes, toHex, fromHex } from "../src/canonical.ts";
import { validate } from "../src/validate.ts";
import { verifyBytes } from "../src/sign.ts";
import { DOMAIN, VERSION, type PaymentAuth } from "../src/types.ts";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const VECTORS_PATH = path.resolve(HERE, "../../vectors/canonical-vectors.json");

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

interface VectorFile {
  version: number;
  domain: string;
  counts: Record<string, number>;
  encoding: ReadonlyArray<{
    name: string;
    auth: AuthJson;
    canonical_hex: string;
    canonical_len: number;
    canonical_sha256: string;
  }>;
  distinctness: ReadonlyArray<{ name: string; a: AuthJson; b: AuthJson }>;
  verification: ReadonlyArray<{
    name: string;
    message_hex: string;
    public_key_hex: string;
    signature_hex: string;
    expect_valid: boolean;
  }>;
  validation: ReadonlyArray<{ name: string; auth: AuthJson; expect_failure: string | null }>;
  differential: {
    account_id: ReadonlyArray<readonly [string, boolean]>;
    deposit_address: ReadonlyArray<readonly [string, boolean]>;
  };
}

const raw = readFileSync(VECTORS_PATH, "utf8");
const vectors = JSON.parse(raw) as VectorFile;

const toAuth = (json: AuthJson): PaymentAuth => ({
  guardId: json.guard_id,
  depositAddress: json.deposit_address,
  destination: json.destination,
  chain: json.chain as PaymentAuth["chain"],
  amount: BigInt(json.amount),
  verdict: json.verdict as PaymentAuth["verdict"],
  reason: json.reason,
  issuedAt: BigInt(json.issued_at),
  quoteExpiry: BigInt(json.quote_expiry),
  nonce: BigInt(json.nonce),
});

describe("the committed vector file", () => {
  test("is pure ASCII, so no editor can re-encode it", () => {
    assert.ok(!/[^\x00-\x7f]/.test(raw), "non-ASCII found; regenerate the vectors");
  });

  test("declares the same domain and version as the implementation", () => {
    assert.equal(vectors.domain, DOMAIN);
    assert.equal(vectors.version, VERSION);
  });

  test("has every family populated", () => {
    assert.ok(vectors.encoding.length >= 15, "encoding");
    assert.ok(vectors.distinctness.length >= 10, "distinctness");
    assert.ok(vectors.verification.length >= 15, "verification");
    assert.ok(vectors.validation.length >= 30, "validation");
    assert.ok(vectors.differential.account_id.length >= 1000, "differential");
  });

  test("vector names are unique within each family", () => {
    for (const family of ["encoding", "distinctness", "verification", "validation"] as const) {
      const names = vectors[family].map((v) => v.name);
      assert.equal(new Set(names).size, names.length, `duplicate name in ${family}`);
    }
  });
});

describe("encoding vectors", () => {
  for (const vector of vectors.encoding) {
    test(vector.name, () => {
      const bytes = canonicalBytes(toAuth(vector.auth));
      assert.equal(toHex(bytes), vector.canonical_hex);
      assert.equal(bytes.length, vector.canonical_len);
      assert.equal(
        createHash("sha256").update(Buffer.from(bytes)).digest("hex"),
        vector.canonical_sha256,
      );
    });
  }
});

describe("distinctness vectors", () => {
  for (const vector of vectors.distinctness) {
    test(vector.name, () => {
      assert.notEqual(
        toHex(canonicalBytes(toAuth(vector.a))),
        toHex(canonicalBytes(toAuth(vector.b))),
      );
    });
  }
});

describe("verification vectors", () => {
  for (const vector of vectors.verification) {
    test(vector.name, () => {
      assert.equal(
        verifyBytes(
          fromHex(vector.message_hex),
          fromHex(vector.signature_hex),
          fromHex(vector.public_key_hex),
        ),
        vector.expect_valid,
      );
    });
  }

  test("at least two vectors are genuinely valid signatures", () => {
    assert.ok(vectors.verification.filter((v) => v.expect_valid).length >= 2);
  });
});

describe("validation vectors", () => {
  for (const vector of vectors.validation) {
    test(vector.name, () => {
      assert.equal(validate(toAuth(vector.auth)), vector.expect_failure);
    });
  }
});

describe("differential sweep", () => {
  const base = toAuth(vectors.encoding[0]!.auth);

  test("every enumerated account id still matches the committed answer", () => {
    for (const [value, expected] of vectors.differential.account_id) {
      assert.equal(
        validate({ ...base, guardId: value }) === null,
        expected,
        `account id ${JSON.stringify(value)}`,
      );
    }
  });

  test("every enumerated deposit address still matches the committed answer", () => {
    for (const [value, expected] of vectors.differential.deposit_address) {
      assert.equal(
        validate({ ...base, depositAddress: value }) === null,
        expected,
        `deposit address ${JSON.stringify(value)}`,
      );
    }
  });
});
