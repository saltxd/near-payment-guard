# NEAR Payment Guard

**Let an AI agent pay a stranger, safely, by checking the stranger first.**

Built at NEAR HACKATHON. Track: AI Security & Defense.

> **Status: in progress.** The canonical signing format and its cross-language vectors, the
> guard contract (policy, signed-verdict gate, nonce/replay, rolling caps, the owner-registered
> chain allowlist, and the 1Click quote-signature binding), and the nine-scenario
> `near-workspaces` sandbox demo are complete and green, and so are the verdict API route and the
> demo video renderer. A testnet deploy is not built (section 5 says why). Nothing here claims
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

[`docs/architecture.md`](docs/architecture.md) draws the same flow as a sequence diagram and lists
every refusal `request_payment` can return, in the order the contract checks them (a test keeps
the list in step with the contract).

---

## Run it yourself

**You need:** Node 22.18 or newer (CI runs 22.18, 24 and 26), a stable Rust toolchain with a
C compiler and `git` on the PATH (a stock `node:22` Docker image has them; a minimal one does
not), and, for step 3, the wasm target: `rustup target add wasm32-unknown-unknown`. No NEAR
account, keys or funds are needed for steps 1 to 3. Steps 1 and 2 need no network once the
packages are installed; step 3 downloads one binary (see below).

**Machines that can run step 3 and the demo:** macOS on Apple Silicon, or Linux on x86_64 with
glibc 2.39 or newer (Ubuntu 24.04, Debian 13). The sandbox binary (`neard`) is published only
for those two. On Linux arm64 `npm ci` itself stops with `Unsupported platform: Linux arm64`
(in an arm64 Docker host, add `--platform linux/amd64`). On an older Linux such as Debian 12
or Ubuntu 22.04 the binary downloads but will not start (`GLIBC_2.39 not found`), the demo
exits with an error, and `npm run test:sandbox` reports its nine scenarios as skipped, not
passed. Steps 1 and 2 work anywhere Node and Rust do.

### 1. Cross-language signing agreement

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

**What you should see.** `npm test` reports `pass 129`, `fail 0`. `cargo test` runs four
suites and reports `10 passed`, `7 passed`, `70 passed` and `4 passed`, 91 in all: the
signing crate's unit tests, its vector tests, the guard contract's unit tests, and the check
of ChainWard's verdict route (section 4). The vector tests print how many fixtures agreed (the
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

### 3. The guard contract: the nine scenarios in a sandbox

```bash
npm run test:sandbox
```

This compiles both contracts, lowers them to NEAR-deployable wasm, fetches the matching
`near-sandbox` (neard) binary if needed, and runs the nine scenarios against the real compiled
guard in a local [`near-workspaces`](https://github.com/near/near-workspaces-js) sandbox. Each
prints a human line, so the output reads as a story. (Needs a Rust toolchain with the
`wasm32-unknown-unknown` target; if the sandbox binary cannot start, the scenarios skip cleanly
rather than fail.)

| # | Scenario | Expected |
|---|---|---|
| 1 | Agent pays a clean address inside policy | PAID, released via `mt_transfer` to the intents account |
| 2 | Agent tries to pay a sanctioned address | REFUSED, "verdict: hold, sanctions list match" |
| 3 | Agent replays scenario 1's authorization | REFUSED, "nonce already used" |
| 4 | Agent edits the destination, keeps the signature | REFUSED, "bad signature" |
| 5 | Agent swaps in its own deposit address | REFUSED, "bad signature" |
| 6 | Agent presents a verdict issued 10 minutes ago | REFUSED, "verdict too old" |
| 7 | Agent makes many small payments to drain the budget | PAID until the 24h cap, then REFUSED |
| 8 | Agent calls any other method with its key | REFUSED by the protocol, not by our code |
| 9 | Compromised agent tries to transfer out directly | IMPOSSIBLE, the key cannot attach a deposit |

Scenario 1 asks for the payment through the agent's restricted function-call key, exactly as a
real agent would. Scenarios 8 and 9 are the ones that make the point: they fail at the NEAR
protocol layer, before any of our code runs.

For the same nine moments as a narrated walkthrough (a story to watch or record, rather than test
output), run `npm run demo`.

**Two sandbox details, disclosed.** NEAR Intents has no testnet, so the guard is pointed at a
local `intents-stub` (`crates/intents-stub/`) that receives the `mt_transfer`; and the 1Click leg
uses synthetic quotes signed by a throwaway key the sandbox registers as 1Click's, so the scenarios
can vary the deposit address, recipient, amount and chain. The Rust suite proves the identical
quote-signature verification against a genuine production 1Click signature
(`fixtures/1click-quote.json`).

### 4. The verdict API

`POST /api/near/authorize` is part of ChainWard's existing API (saltxd/chainward PR #111). It
runs ChainWard's counterparty, sanctions and look-alike checks on the destination and returns
the verdict plus an ed25519 signature over the canonical bytes. `GET /api/near/public-key`
returns the key to register in the contract.

The proof that the route and the contract agree is `crates/guard-contract/tests/chainward_authorize.rs`
(run by `cargo test` above). It feeds real responses of the route, recorded in
`fixtures/chainward-authorize.json` and signed with a throwaway test key, into `request_payment`
exactly as an agent would: the pay case is paid, the hold case is refused with ChainWard's
signed reason, and any changed field fails as a bad signature.

On the live API the signing key is not provisioned yet, so both routes currently answer
`503 NOT_CONFIGURED`. The demo above needs neither.

### 5. The demo video, and testnet

`npm run video` records `npm run demo` and renders it to `out/video/demo.mp4` (1280x720, about 48 seconds): the
demo's own output, line for line, with only the sandbox's waits between scenarios shortened. It needs Google Chrome
(headless, to draw the frames) and ffmpeg with libx264. The frame timing is unit-tested in `ts/test/video-plan.test.ts`.

**[NOT BUILT]** A testnet deployment. NEAR Intents has no testnet, so the sandbox above is the faithful demo; a testnet
copy of the guard would show the same refusals against a stub.

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

- **near-sdk-rs** (`=5.29.1`) for the contract. The on-chain wasm is built with `--cfg near`
  and lowered with `wasm-opt` to the feature set NEAR's VM accepts — the same two things
  `cargo-near` does internally; we do them directly (`.cargo/config.toml`,
  `scripts/build-contracts.mjs`) so the only toolchain needed is cargo + npm
- **near-workspaces** (`5.0.0`) for the sandbox suite, plus **near-sandbox**: that release bundles
  neard 2.6.2, which is too old for near-sdk 5.29.1's host imports, so `scripts/ensure-sandbox.mjs`
  fetches the matching neard (2.13.4) from NEAR's official release bucket
- **binaryen** (`wasm-opt`) — dev-only, to lower post-MVP wasm features (bulk-memory, sign-ext,
  reference-types, multivalue) that NEAR's VM rejects at deploy time
- **near-api-js** — dev-only, used in the sandbox to add the agent's restricted function-call key
- **ed25519-dalek** — test-only, to cross-check signatures. The contract itself calls
  `env::ed25519_verify`, a host function needing no crate
- **Node's built-in `node:crypto`** for signing. The signer has **no runtime dependencies**; the
  npm dependencies above are all dev-only, for typechecking and the sandbox demo
- **serde / serde_json / hex / sha2** — Rust dev-dependencies, for reading the fixture
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
docs/architecture.md         the payment flow as a sequence diagram, and every refusal in contract order
vectors/canonical-vectors.json the shared fixture both languages read (generated, committed)

crates/guard-auth/            Rust: canonical encoder + shape validation, zero dependencies
  src/canonical.rs            the byte layout
  src/validate.rs             the shape rules
  tests/vectors.rs            cross-language agreement against the fixture
crates/guard-contract/        Rust: the guard contract (near-sdk)
  src/lib.rs                  policy, the signed-verdict gate, nonce/replay, rolling caps, asset allowlist
  src/oneclick.rs             the 1Click quote-signature verification and binding
crates/intents-stub/          Rust: a test-only stand-in for intents.near (sandbox only)

ts/src/canonical.ts           TypeScript: the same byte layout
ts/src/validate.ts            the same shape rules
ts/src/sign.ts                ed25519 signing, no dependencies
ts/scripts/generate-vectors.ts the fixture generator
ts/test/                      spec conformance + fixture verification
ts/sandbox/                   the nine-scenario near-workspaces demo (npm run test:sandbox)
ts/video/                     the demo video: frame plan (tested) and renderer (npm run video)

scripts/build-contracts.mjs   cargo build + wasm-opt lowering into out/
scripts/ensure-sandbox.mjs    fetch the neard version near-sdk 5.29.1 needs
fixtures/1click-quote.json    a real captured 1Click quote with its signature
```

## License

MIT. See [LICENSE](LICENSE).
