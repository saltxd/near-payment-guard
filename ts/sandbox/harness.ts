/**
 * Helpers shared by the near-workspaces sandbox scenarios.
 *
 * These build the two signed artifacts the guard checks, using the same signer the production
 * API would use (`../src/sign.ts`):
 *
 * - the ChainWard **verdict**, signed over the canonical bytes (`signAuth`), and
 * - a synthetic 1Click **quote**, signed exactly as 1Click's SDK signs:
 *   `ed25519( base58( sha256( utf8(payload) ) ) )`.
 *
 * The quote is synthetic (signed by a throwaway key the sandbox registers as 1Click's) rather
 * than the committed real fixture, because the scenarios need to vary the deposit address,
 * recipient, amount and chain at will. The Rust suite proves the exact same verification path
 * against the genuine production signature (`fixtures/1click-quote.json`).
 *
 * No runtime dependencies: base58 is a few lines, sha256 and ed25519 come from `node:crypto` via
 * the existing signer, so a judge installs nothing beyond near-workspaces to run this.
 */

import { createHash, type KeyObject } from "node:crypto";

import { signBytes } from "../src/sign.ts";
import type { PaymentAuth } from "../src/types.ts";

/** 1Click destination asset ids the sandbox registers, and the chains they settle on. */
export const BASE_ASSET = "nep141:base-0xtest.omft.near";
export const BSC_ASSET = "nep245:v2_1.omni.hot.tg:56_usdc";

/** A deposit deadline comfortably in the future, for quotes that should pass the deadline check. */
export const FAR_FUTURE = "2099-01-01T00:00:00.000Z";

/** A 1Click quote as the contract's `oneclick::SignedQuote` expects it. */
export interface SignedQuote {
  readonly payload: string;
  readonly signature: string;
}

/** Base64, for the `Base64VecU8` arguments the contract takes (keys and signatures). */
export const b64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString("base64");

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/** Base58 (Bitcoin alphabet) encode, matching `near_sdk::bs58` on the contract side. */
export const base58 = (bytes: Uint8Array): string => {
  if (bytes.length === 0) {
    return "";
  }
  const digits: number[] = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i += 1) {
      carry += (digits[i] as number) << 8;
      digits[i] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let out = "";
  for (let i = 0; i < bytes.length && bytes[i] === 0; i += 1) {
    out += "1";
  }
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    out += BASE58_ALPHABET[digits[i] as number];
  }
  return out;
};

const sha256 = (data: Uint8Array): Uint8Array =>
  new Uint8Array(createHash("sha256").update(Buffer.from(data)).digest());

/**
 * Signs a quote payload the way 1Click's SDK does: ed25519 over the UTF-8 of
 * `base58(sha256(payload))` (the base58 *text*, not the raw digest). See
 * `crates/guard-contract/src/oneclick.rs` and `ops/near/quote-signature.md`.
 */
export const signQuote = (payload: string, oneclickPrivateKey: KeyObject): SignedQuote => {
  const digest = sha256(Buffer.from(payload, "utf8"));
  const message = Buffer.from(base58(digest), "utf8");
  const signature = signBytes(message, oneclickPrivateKey);
  return { payload, signature: `ed25519:${base58(signature)}` };
};

/** The subset of 1Click quote fields the guard reads; the rest are filled with sane defaults. */
export interface QuoteFields {
  readonly amountIn: string;
  readonly depositAddress: string;
  readonly recipient: string;
  readonly destinationAsset?: string;
  readonly deadline?: string;
  readonly originAsset?: string;
  readonly dry?: boolean;
  readonly depositType?: string;
  readonly recipientType?: string;
  /** Extra top-level keys, e.g. a `customRecipientMsg` redirect vector, to be merged in. */
  readonly extra?: Record<string, unknown>;
}

/**
 * Builds the exact JSON string a quote is signed over and the contract re-parses. Field order is
 * irrelevant: the contract hashes whatever string this produces and verifies that, then parses
 * it, so the quote is self-consistent.
 */
export const buildQuotePayload = (q: QuoteFields): string =>
  JSON.stringify({
    amountIn: q.amountIn,
    deadline: q.deadline ?? FAR_FUTURE,
    depositAddress: q.depositAddress,
    depositType: q.depositType ?? "INTENTS",
    destinationAsset: q.destinationAsset ?? BASE_ASSET,
    dry: q.dry ?? false,
    originAsset: q.originAsset ?? "nep245:v2_1.omni.hot.tg:56_origin",
    recipient: q.recipient,
    recipientType: q.recipientType ?? "DESTINATION_CHAIN",
    ...(q.extra ?? {}),
  });

/** The contract's `PaymentAuthArgs`: snake_case keys, big integers as decimal strings. */
export interface PaymentAuthArgs {
  readonly guard_id: string;
  readonly deposit_address: string;
  readonly destination: string;
  readonly chain: string;
  readonly amount: string;
  readonly verdict: string;
  readonly reason: string;
  readonly issued_at: string;
  readonly quote_expiry: string;
  readonly nonce: string;
}

/** Projects a signer-side `PaymentAuth` onto the contract's JSON argument shape. */
export const toAuthArgs = (auth: PaymentAuth): PaymentAuthArgs => ({
  guard_id: auth.guardId,
  deposit_address: auth.depositAddress,
  destination: auth.destination,
  chain: auth.chain,
  amount: auth.amount.toString(),
  verdict: auth.verdict,
  reason: auth.reason,
  issued_at: auth.issuedAt.toString(),
  quote_expiry: auth.quoteExpiry.toString(),
  nonce: auth.nonce.toString(),
});

/** Unix seconds now, for `issued_at` / `quote_expiry`. */
export const nowSeconds = (): number => Math.floor(Date.now() / 1000);
