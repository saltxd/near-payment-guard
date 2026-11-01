# NEAR Payment Guard

**Let an AI agent pay a stranger, safely, by checking the stranger first.**

Built at NEAR HACKATHON. Track: AI Security & Defense.

> **Status: day 1 of 10.** The canonical signing format and its cross-language test
> vectors are complete and green. The contract, the API route and the demo are not
> written yet. Every section below marked **[NOT BUILT YET]** is a placeholder with the
> intended shape, not a description of working code. Nothing in this README claims
> something runs unless you can run it from the steps given.

---

## The problem

To let an AI agent pay for things, you give it a wallet key. That key is all or
nothing: the agent can send every coin in the account, to anyone, forever. So people
either do not let agents pay at all, or they fund a small hot wallet and hope.

The usual answer is a spending limit. A limit caps how much you lose. It does not ask
whether the payment should have happened.

Two things go wrong in practice, and ChainWard has measured both on Base:

- **The agent is tricked into paying the wrong address.** Address poisoning put a
  look-alike of our own treasury in front of us two minutes after a real payout. A
  fresh agent cannot tell the look-alike from the real one.
- **The agent pays a counterparty that should not be paid.** A sanctioned address, a
  token that just rug-pulled, a seller whose "demand" turns out to be its own wallets.

## What this is

A NEAR contract that **holds the money** and releases it only when a policy **and** a
fresh, signed risk verdict both say yes. The agent never holds a key that can move
funds.

The agent's key is a NEAR **function-call access key**, which by protocol cannot
attach a deposit and cannot call any other contract. So a fully compromised agent
cannot steal: the worst it can do is burn its own gas allowance asking for a payment
that gets refused. That is enforced by the protocol, not by our code.

### How this differs from the prior art

Spending caps and allowlists are a commodity: Safe spending limits plus Zodiac,
ERC-4337 session keys, NEAR multisig, Sputnik DAO, Coinbase's agentic wallet, Cobo
Pact. On NEAR, **Peerfolio / beneviolabs `autonomous-trading-account`** is closest by
far: production, audited, the same 1Click path, and it already verifies the quote
signature.

The honest one-line claim, and the only one we make:

> Every existing guard limits **how much** an agent spends, or restricts it to paying
> **you**. This one lets an agent pay **a stranger**, because it checks the stranger
> first.

## Architecture

```
  owner (human, full-access key)
     |  deploys, funds, sets policy, registers the ChainWard public key,
     |  adds a FunctionCall key for the agent (receiver = guard,
     |  method_names = ["request_payment"], small gas allowance)
     v
  +------------------------- guard contract (NEAR) --------------------------+
  |  holds the funds                                                          |
  |  policy: per-tx cap, rolling 24h cap, per-counterparty cap, allow/deny     |
  |  verifies: ed25519 signature, freshness, nonce (replay), audience          |
  |  pays ONLY the deposit_address named inside the signed payload             |
  +---------------------------------------------------------------------------+
     ^                                        |
     | request_payment(auth, signature)       | on pass: transfer
     |                                        v
  agent (function-call key only)        NEAR Intents / 1Click deposit address
     |                                        |
     | GET a signed authorization             v
     v                                  destination on Base / BNB Chain
  api.chainward.ai
```

Two independent signatures, each answering a different question:

| Signature | Signed by | Answers |
|---|---|---|
| Quote signature | 1Click | "Money sent to this deposit address lands at this destination, on this chain, before this deadline" |
| Verdict signature | ChainWard | "This destination is safe to pay, and here is the one fact why" |

Neither party can forge the other's half, and the agent holds neither key. The guard
reads the destination out of the quote blob it verified, never from a caller argument.

---

## Run it yourself

### 1. The part that works today: cross-language signing agreement

The verdict is signed off-chain in TypeScript and verified on-chain in Rust. If those
two disagree by one byte, the guard either refuses everything or pays the wrong
person. So the first thing built was the proof that they agree.

```bash
git clone https://github.com/saltxd/near-payment-guard
cd near-payment-guard

# TypeScript: the signer, and conformance to the written spec
npm install
npm test

# Rust: the verifier, against the same committed vectors
cargo test -- --nocapture
```

**What you should see.** `npm test` reports `pass 118`, `fail 0`. `cargo test` reports
`10 passed` then `7 passed`, and the vector tests print how many fixtures agreed (the
lines arrive in whatever order the tests finish):

```
18 encoding vectors agree byte for byte
12 distinctness vectors stay distinct
17 verification vectors agree (2 accepted, 15 refused)
43 validation vectors agree (8 accepted, 35 refused with a matching reason)
2815 account ids and 69 deposit addresses agree exhaustively (96 accepted)
```

That is 2974 fixtures, every one of them produced by the TypeScript signer and
reproduced by the Rust verifier.

Both suites read the same committed file, `vectors/canonical-vectors.json`. Neither
language can quietly disagree with the other: CI regenerates that file and fails if it
differs, so it cannot be edited until both sides pass.

Judges needing no account, no keys, no funds and no network for this step is the point.

### 2. The signing format itself

[`docs/canonical-bytes.md`](docs/canonical-bytes.md) is the specification: the byte
layout, why it is not JSON or Borsh, the shape rules and where validation stops and
contract semantics begin. Section 7 works a complete 173-byte message out by hand, and
that hand-derived value is asserted in both test suites, so neither implementation can
drift from the document.

### 3. **[NOT BUILT YET]** The guard contract

Planned for days 2 to 5. The nine demo scenarios below will run in a `near-workspaces`
sandbox with one command.

| # | Scenario | Expected |
|---|---|---|
| 1 | Agent pays a clean address inside policy | PAID, guard balance drops |
| 2 | Agent tries to pay a sanctioned address | REFUSED, "verdict: hold, sanctions list match" |
| 3 | Agent replays scenario 1's authorization | REFUSED, "nonce already used" |
| 4 | Agent edits the destination, keeps the signature | REFUSED, "bad signature" |
| 5 | Agent swaps in its own deposit address | REFUSED, "bad signature" |
| 6 | Agent presents a verdict issued 10 minutes ago | REFUSED, "verdict too old" |
| 7 | Agent makes many small payments to drain the budget | PAID until the 24h cap, then REFUSED |
| 8 | Agent calls any other method with its key | REFUSED by the protocol, not by our code |
| 9 | Compromised agent tries to transfer out directly | IMPOSSIBLE, the key cannot attach a deposit |

Scenarios 8 and 9 are the ones that make the point: they fail at the protocol layer.

### 4. **[NOT BUILT YET]** The verdict API

Planned for day 6: `POST /api/near/authorize` on ChainWard's existing API, returning a
verdict plus an ed25519 signature over the canonical bytes.

### 5. **[NOT BUILT YET]** Testnet deployment and video

Planned for day 9.

---

## Disclosures

### Existing product on another chain

This project is built by **[ChainWard](https://chainward.ai)**, which is an existing,
live product on **Base**, not something created for this hackathon. ChainWard monitors
on-chain agent activity and sells risk checks: counterparty checks, sanctions and OFAC
screening, token rug checks and wallet screening, available over HTTP and x402.

**What that means for this entry, stated plainly:** the risk verdict this guard
consumes comes from checks that already existed and already run in production. What is
new here, and what was built during the hackathon window, is everything in this
repository: the NEAR contract, the canonical signing format, the verdict signing route
and the demo. The guard is a new consumer of an existing engine. We would rather say so
than let a judge discover it.

### Libraries, templates and prior art

- **near-sdk-rs** for the contract **[to be added, day 2]**
- **near-workspaces** for the sandbox test suite **[to be added, day 8]**
- **ed25519-dalek** — test-only, to cross-check signatures. The contract itself calls
  `env::ed25519_verify`, a host function needing no crate
- **Node's built-in `node:crypto`** for signing. The TypeScript side has **no runtime
  dependencies**
- **serde / serde_json / hex / sha2** — Rust dev-dependencies, for reading the fixture
- **TypeScript** — the only npm dev-dependency, for typechecking
- **No project template was used.** The repository layout is our own
- **Prior art we read and are not pretending does not exist:** Peerfolio /
  beneviolabs `autonomous-trading-account`, whose quote-signature verification and
  rejection of `virtualChainRecipient` we follow. It confines payouts to the owner;
  that difference is our contribution, and it is described above rather than glossed

### AI-generated code

**Most of the code in this repository was written by an AI agent (Claude), directed,
reviewed and accepted by a human.** That applies to the Rust crate, the TypeScript
signer, the test suites, the vector generator, the CI configuration and this README.

The human author set the design, chose the threat model, decided the trade-offs
recorded in `docs/canonical-bytes.md`, and accepted or rejected each change. The
specification was written before the implementations, and both implementations were
written from the specification, which is also why the cross-language vectors exist: on
work of this shape, agreement between two independently written implementations is
worth more than a reviewer's confidence in either one.

### Security and limits

Stated here because the README should not oversell the thing it documents.

- **The guard protects the funds it holds. It does not make the agent's judgment
  good.** A verdict is a reading of on-chain history, not a promise about the future.
- A verdict can be **wrong**. It can miss a counterparty with no history, and it can
  flag a clean one. `unknown` is a real answer and the guard treats it as a refusal.
- The **production verdict signing key** is generated once and lives only in a
  Kubernetes secret. It is not in this repository in any form, and it is a new key, not
  one reused from anything in production.
- The test vectors are signed by a **throwaway key derived at test time** from a
  documented seed phrase. Its public key is
  `0ae07b938297a1f89184061a591c7624b93666ce5d2a141a79a48032b4609716`. It signs fixtures
  and nothing else. No private key is written to any file in this repository.

---

## Repository layout

```
docs/canonical-bytes.md       the signing format specification
vectors/canonical-vectors.json the shared fixture both languages read (generated, committed)

crates/guard-auth/            Rust: canonical encoder + shape validation, zero dependencies
  src/canonical.rs            the byte layout
  src/validate.rs             the shape rules
  tests/vectors.rs            cross-language agreement against the fixture

ts/src/canonical.ts           TypeScript: the same byte layout
ts/src/validate.ts            the same shape rules
ts/src/sign.ts                ed25519 signing, no dependencies
ts/scripts/generate-vectors.ts the fixture generator
ts/test/                      spec conformance + fixture verification

contracts/guard/              [NOT BUILT YET] the NEAR contract, day 2
```

## License

MIT. See [LICENSE](LICENSE).
