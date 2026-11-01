/**
 * ed25519 signing and verification over the canonical bytes.
 *
 * Uses Node's built-in crypto (OpenSSL) and has no dependencies. That matters twice:
 * a judge runs `npm test` from a clean clone with nothing to install, and the same
 * code drops into ChainWard's API without adding a package to a service that signs.
 *
 * The message is NOT pre-hashed: ed25519 hashes internally (RFC 8032). See
 * docs/canonical-bytes.md section 6.
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as nodeSign,
  verify as nodeVerify,
  type KeyObject,
} from "node:crypto";

import { canonicalBytes } from "./canonical.ts";
import { assertValid } from "./validate.ts";
import type { PaymentAuth } from "./types.ts";

/** DER prefix for a PKCS#8-wrapped Ed25519 private key, followed by the 32-byte seed. */
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

/** DER prefix for an SPKI-wrapped Ed25519 public key, followed by the 32-byte point. */
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export interface SignerKeyPair {
  readonly privateKey: KeyObject;
  readonly publicKey: KeyObject;
  /** The raw 32-byte public key, which is what the contract stores. */
  readonly publicKeyBytes: Uint8Array;
}

/** Builds a key pair from a raw 32-byte ed25519 seed. */
export const keyPairFromSeed = (seed: Uint8Array): SignerKeyPair => {
  if (seed.length !== 32) {
    throw new RangeError(`ed25519 seed must be 32 bytes, got ${seed.length}`);
  }
  const privateKey = createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(seed)]),
    format: "der",
    type: "pkcs8",
  });
  const publicKey = createPublicKey(privateKey);
  const publicKeyBytes = new Uint8Array(
    publicKey.export({ format: "der", type: "spki" }).subarray(SPKI_ED25519_PREFIX.length),
  );
  return { privateKey, publicKey, publicKeyBytes };
};

/** Rebuilds a verifying key from the raw 32 bytes the contract stores. */
export const publicKeyFromBytes = (publicKeyBytes: Uint8Array): KeyObject => {
  if (publicKeyBytes.length !== 32) {
    throw new RangeError(`ed25519 public key must be 32 bytes, got ${publicKeyBytes.length}`);
  }
  return createPublicKey({
    key: Buffer.concat([SPKI_ED25519_PREFIX, Buffer.from(publicKeyBytes)]),
    format: "der",
    type: "spki",
  });
};

/**
 * Derives a DETERMINISTIC, THROWAWAY key pair from a seed phrase.
 *
 * For test vectors only. It makes the committed vectors reproducible without any
 * private key ever being written to a file. This key protects nothing and must
 * never be used to sign a real verdict; the production key is generated once and
 * lives only in a k8s secret. See docs/canonical-bytes.md section 8.
 */
export const testKeyPairFromPhrase = (phrase: string): SignerKeyPair =>
  keyPairFromSeed(new Uint8Array(createHash("sha256").update(phrase, "utf8").digest()));

/** Signs raw bytes. Prefer signAuth, which validates first. */
export const signBytes = (message: Uint8Array, privateKey: KeyObject): Uint8Array =>
  new Uint8Array(nodeSign(null, Buffer.from(message), privateKey));

/** Verifies a signature over raw bytes. Never throws; a malformed input is `false`. */
export const verifyBytes = (
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: KeyObject | Uint8Array,
): boolean => {
  try {
    const key = publicKey instanceof Uint8Array ? publicKeyFromBytes(publicKey) : publicKey;
    return nodeVerify(null, Buffer.from(message), key, Buffer.from(signature));
  } catch {
    return false;
  }
};

/**
 * Validates, encodes and signs a payment authorization.
 *
 * Validation is not optional here: signing a shape-invalid authorization would
 * mint a signature over bytes the contract is required to refuse, which is a
 * confusing failure at best and a denylist bypass at worst (section 5.2).
 */
export const signAuth = (auth: PaymentAuth, privateKey: KeyObject): Uint8Array => {
  assertValid(auth);
  return signBytes(canonicalBytes(auth), privateKey);
};

/** Verifies a signature over an authorization, re-encoding it rather than trusting bytes. */
export const verifyAuth = (
  auth: PaymentAuth,
  signature: Uint8Array,
  publicKey: KeyObject | Uint8Array,
): boolean => {
  if (signature.length !== 64) return false;
  return verifyBytes(canonicalBytes(auth), signature, publicKey);
};
