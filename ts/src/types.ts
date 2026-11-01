/**
 * Types for the payment authorization that ChainWard signs and the guard verifies.
 *
 * Integers are carried as `bigint`, never `number`. `amount` and `nonce` are u128,
 * which `number` cannot hold; `issued_at` and `quote_expiry` are u64, which `number`
 * cannot hold above 2^53. Using `bigint` for all four removes the question of which
 * ones are safe.
 *
 * See docs/canonical-bytes.md section 3.
 */

export type Chain = "base" | "bsc";

export type VerdictLabel = "pay" | "hold" | "unknown";

/** A payment authorization, in the field order the canonical encoding uses. */
export interface PaymentAuth {
  /** NEAR account id of the guard contract this authorization is for. */
  readonly guardId: string;
  /** The only address the guard will pay. */
  readonly depositAddress: string;
  /** Lowercase 0x-prefixed EVM address the money must surface at. */
  readonly destination: string;
  readonly chain: Chain;
  /** Exact amount this authorization covers, in the asset's smallest unit. u128. */
  readonly amount: bigint;
  readonly verdict: VerdictLabel;
  /** The one fact the verdict rests on. May be empty. */
  readonly reason: string;
  /** Unix seconds when ChainWard signed. u64. */
  readonly issuedAt: bigint;
  /** Unix seconds, the 1Click quote deadline. u64. */
  readonly quoteExpiry: bigint;
  /** Replay protection. u128. */
  readonly nonce: bigint;
}

/**
 * Stable machine-readable reasons a `PaymentAuth` fails shape validation.
 * These strings are part of the spec: tests assert on them, so renaming one
 * is a breaking change. See docs/canonical-bytes.md section 5.
 */
export type ValidationFailure =
  | "guard_id_invalid"
  | "deposit_address_invalid"
  | "destination_invalid"
  | "chain_invalid"
  | "verdict_invalid"
  | "reason_invalid";

export const DOMAIN = "chainward.near-payment-guard.auth";
export const VERSION = 1;

/** Field length bounds from docs/canonical-bytes.md section 5. */
export const LIMITS = {
  guardIdMin: 2,
  guardIdMax: 64,
  depositAddressMin: 1,
  depositAddressMax: 128,
  reasonMax: 256,
} as const;
