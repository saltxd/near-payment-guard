# Architecture

The guard is a NEAR contract that holds an owner's funds and pays out only when two independent signatures agree: ChainWard's verdict that a destination is safe to pay, and 1Click's quote that a NEAR deposit address leads to that destination. The agent that asks for a payment holds a function-call key that can call one method, `request_payment`, and neither signing key.

## Who does what

```mermaid
sequenceDiagram
    autonumber
    actor Owner as Owner (full-access key)
    participant Guard as Guard contract (NEAR)
    actor Agent as Agent (function-call key)
    participant OneClick as 1Click quote service
    participant ChainWard as ChainWard API
    participant Intents as NEAR Intents (intents.near)
    participant Dest as Destination on Base / BNB Chain

    Owner->>Guard: new(owner, chainward_pubkey, policy)
    Owner->>Guard: set_oneclick_pubkeys, set_asset_chain, deposit
    Owner->>Agent: FunctionCall key: receiver = guard, method = request_payment

    Agent->>OneClick: quote for amount to destination
    OneClick-->>Agent: SignedQuote (deposit address, recipient, asset, amount, deadline)
    Agent->>ChainWard: POST /api/near/authorize (destination, chain, amount, guard, deposit address, quote expiry)
    ChainWard-->>Agent: authorization (verdict, reason, nonce, issued_at) + ed25519 signature

    Agent->>Guard: request_payment(auth, signature, quote)
    Note over Guard: checks below, in order; any failure refuses and nothing moves
    Guard->>Intents: mt_transfer to the quote's deposit address (1 yoctoNEAR attached)
    Intents->>Dest: swap delivers to the recipient 1Click signed for
```

The guard reads the destination out of the quote it verified, never from a free caller argument, and pays only the deposit address named inside both signed payloads. A function-call key cannot attach a deposit, so the agent cannot move funds any other way.

## What `request_payment` checks, in order

Each line is the refusal the contract returns. `tests` in `ts/test/architecture-doc.test.ts` read the contract source and fail if this list drifts from it.

1. Caller: `owner only` (the owner, or the agent's function-call key on the owner's account).
2. Shape, identical to the signer's view: `invalid authorization: <code>`.
3. Audience: `wrong guard`, the verdict was issued for a different guard contract.
4. ChainWard's signature over the canonical bytes: `bad signature`.
5. Freshness: `quote expired`, `issued after expiry`, `verdict too old`.
6. The verdict itself: `verdict: <verdict>, <reason>` unless ChainWard said pay. The reason is ChainWard-signed, so it is safe to echo.
7. 1Click's signature over the quote (refused with the quote verifier's own error), then the binding between the two signatures:
   - `quote is dry`
   - `quote carries a redirect vector`
   - `quote deposit address does not match the verdict`
   - `quote recipient does not match the verdict destination`
   - `destination asset not registered`
   - `quote destination asset is not on the verdict's chain`
   - `quote amount does not match the verdict`
   - `quote has no parseable deadline`
   - `quote deadline has passed`
8. Replay: `nonce already used`. A nonce is honoured once.
9. Policy, membership first, then the amount caps, keyed on the EVM destination:
   - `destination on denylist`
   - `destination not on allowlist` (only when an allowlist is set)
   - `amount exceeds per-transaction cap`
   - `daily cap exceeded` (rolling 24 hours)
   - `counterparty cap exceeded` (rolling 24 hours, per destination)
10. Record the spend, then release the funds with one `mt_transfer` of the guard's balance inside NEAR Intents to the quote's deposit address.

## The two signatures

| Signature | Signed by | Answers |
|---|---|---|
| Quote signature | 1Click | "Money sent to this deposit address lands at this recipient, on this chain, before this deadline" |
| Verdict signature | ChainWard | "This destination is safe to pay, and here is the one fact why" |

Neither party can forge the other's half, and the agent holds neither key. The byte format ChainWard signs is specified in [canonical-bytes.md](canonical-bytes.md); the TypeScript signer and the Rust verifier are tested against the same committed vectors.
