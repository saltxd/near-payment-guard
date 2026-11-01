# Canonical bytes: what the guard actually signs and verifies

**Status:** v1, frozen for the build. Changing anything here is a version bump, never an edit.

ChainWard signs a payment authorization **off-chain in TypeScript**. The guard contract verifies it
**on-chain in Rust**. Those are two programs, two languages, two teams of bugs. If they disagree by a
single byte about what "the message" is, one of two things happens, and both are bad:

- the verifier rejects authorizations the signer meant to issue, and the guard is simply broken; or
- the verifier accepts bytes the signer never meant to authorize, and the guard pays the wrong person.

So the byte layout is not an implementation detail. It is the security boundary. This document is the
single definition of it. The Rust and the TypeScript implementations are both written **from this
document**, and a shared vector file (`vectors/canonical-vectors.json`) proves they landed in the
same place.

---

## 1. Design rules

Five rules, in priority order. Everything below follows from them.

1. **Injective.** Two different authorizations must never produce the same bytes. If they can, a
   signature over one is a signature over the other, and the whole scheme is decorative.
2. **Domain separated.** These bytes must not be valid as anything else — not a NEAR transaction, not
   a NEP-413 message, not a future v2 of this struct. A signing key used here must be useless
   everywhere else.
3. **No parsing on the verify path.** The contract never *decodes* a byte string into fields. It
   receives typed fields, re-encodes them itself, and verifies the signature over its own encoding.
   A decoder is an attack surface (trailing bytes, overlong lengths, ambiguous framing); an encoder
   is not. This single decision deletes an entire bug class.
4. **Fixed width where possible, length-prefixed where not.** No delimiters, no escaping, no
   terminators. Never `a + b` where `a` and `b` are variable length and nothing says where the seam is.
5. **Bytes as given.** No Unicode normalization, no case folding, no trimming at the encoding layer.
   Normalization is a *validation* decision (section 5), made once, before signing. The encoder is dumb
   on purpose: a transform in the encoder is a transform that can differ between two languages.

### Why not JSON, Borsh or protobuf

- **JSON** is not canonical. Key order, whitespace, unicode escaping (`é` vs the raw byte),
  number formatting and float coercion all vary by serializer. `json-stable-stringify` fixes *some*
  of that by convention, enforced by nobody. Signing non-canonical JSON is how you get two valid
  encodings of one object.
- **Borsh** is canonical and is already in the NEAR stack, which makes it tempting. It is rejected
  for one reason: on the TypeScript side it means a dependency, a schema declaration kept in sync by
  hand, and a second place for the field order to be wrong. Our encoding is ~40 lines in each
  language with no dependency at all, and a stranger can verify it with `xxd`.
- **protobuf** has the same canonicality caveats as JSON for signing (field ordering and default-value
  omission are encoder choices), plus a toolchain.

The cost of this decision is that we own the encoder. That is the point: it is small enough to read
in full, and section 7 proves both copies agree.

---

## 2. Primitives

| Notation | Encoding | Width |
|---|---|---|
| `u8(n)` | the single byte `n` | 1 byte |
| `u32(n)` | `n` big-endian, unsigned | 4 bytes |
| `u64(n)` | `n` big-endian, unsigned | 8 bytes |
| `u128(n)` | `n` big-endian, unsigned | 16 bytes |
| `str(s)` | `u32(byte_length(utf8(s)))` followed by the UTF-8 bytes of `s` | 4 + N bytes |

**Big-endian everywhere.** NEAR, Rust and JavaScript all default to little-endian in various places;
picking one and writing it down is worth more than picking the fast one. These messages are ~200 bytes.

**`byte_length` is the UTF-8 byte count, not the character count and not `String.length`.** In
JavaScript `"😀".length` is 2 (UTF-16 code units) while its UTF-8 length is 4. Getting this wrong
produces an encoder that works on every ASCII test and fails on the first non-ASCII input. Vector
`unicode-astral-reason` exists specifically to catch it.

**No length prefix on fixed-width integers**, because their width is already known. A `u128` is
always exactly 16 bytes, including `u128(0)`, which is sixteen zero bytes and not an empty string.

---

## 3. The message

```
canonical_bytes(auth) :=
      str(DOMAIN)
   || u8(VERSION)
   || str(auth.guard_id)
   || str(auth.deposit_address)
   || str(auth.destination)
   || str(auth.chain)
   || u128(auth.amount)
   || str(auth.verdict)
   || str(auth.reason)
   || u64(auth.issued_at)
   || u64(auth.quote_expiry)
   || u128(auth.nonce)
```

where

```
DOMAIN  = "chainward.near-payment-guard.auth"   (33 bytes, ASCII)
VERSION = 1
```

`||` is concatenation. There is nothing else: no header, no total length, no trailing padding, no
terminator.

### The fields

| # | Field | Type | What it is |
|---|---|---|---|
| 1 | `guard_id` | string | The NEAR account id of the guard contract this authorization is for. **See section 4.** |
| 2 | `deposit_address` | string | The only address the guard will pay. |
| 3 | `destination` | string | The EVM address the money must surface at, after the cross-chain leg. |
| 4 | `chain` | string | `"base"` or `"bsc"`. The chain `destination` lives on. |
| 5 | `amount` | u128 | The exact amount this authorization covers. Not a maximum. |
| 6 | `verdict` | string | `"pay"`, `"hold"` or `"unknown"`. |
| 7 | `reason` | string | The one fact the verdict rests on. Carried so a refusal can say *why*. |
| 8 | `issued_at` | u64 | Unix seconds, when ChainWard signed. Freshness is measured from here. |
| 9 | `quote_expiry` | u64 | Unix seconds, the 1Click quote deadline. |
| 10 | `nonce` | u128 | Replay protection. The guard records it and refuses it twice. |

Field order is the order above and is part of the specification. Reordering is a version bump.

### Why DOMAIN is length-prefixed

It is a compile-time constant, so a bare constant would be unambiguous today. It is prefixed anyway
so that **one rule covers every string in the message** — a reader does not have to remember an
exception, and a future `DOMAIN` of a different length cannot collide with this one.

### Why VERSION is separate from DOMAIN

`DOMAIN` carries no version, and `VERSION` is its own byte, so bumping the format is a one-constant
change. A v2 message can never collide with a v1 message: byte 37 differs.

---

## 4. `guard_id`: a deliberate addition to the design document

**`guard_id` is not in `PaymentAuth` as written in `ops/near/design.md` section 4. It is added here,
and this section is the argument for it.** If the argument is rejected, delete field 1 and bump the
version; nothing else changes.

The nonce store lives in the guard contract, so it is **per contract**. ChainWard intends to sign
verdicts for many customers' guards from one key. Without `guard_id`:

1. Owner A's agent calls `request_payment`. The authorization and its signature are transaction
   arguments, so they are **public on-chain forever**.
2. Owner B's agent reads them off the explorer and replays them verbatim against **guard B**.
3. Guard B checks the signature: valid, it is a real ChainWard signature. Nonce: unused *here*.
   Freshness: still inside the window. Policy: within B's caps. It pays.
4. Owner B's funds have just been sent to owner A's counterparty, and owner B's agent chose nothing.

Every other check passes honestly. The signature is genuine. The flaw is that the message never said
*which guard it was for*, so it was for all of them. This is the classic missing-audience bug, and
the fix is the standard one: name the audience inside the signed bytes.

The guard verifies `auth.guard_id == env::current_account_id()`. A verdict for another contract is
refused before the signature is even checked.

The cost is 4 + ~30 bytes, about 0.0003 TGas. The alternative — a separate signing key per customer —
is key management we would rather not own.

---

## 5. Validation, and where the line is

Encoding and validation are different jobs, and conflating them is how canonical formats rot. The
rule for this repo:

> **The canonical layer validates *shape*. The contract validates *semantics*.**

Shape is what makes two parties agree on a byte string. Semantics is what makes a payment a good idea.

### Shape (this layer, identical in both languages)

Checked by `validate()` before signing and again before verifying. Each failure has a **stable
machine-readable code**, so a test can assert *why* something was refused rather than merely that it
was.

| Field | Rule | Failure code |
|---|---|---|
| `guard_id` | 2..=64 bytes, and a valid NEAR account id (section 5.1) | `guard_id_invalid` |
| `deposit_address` | 1..=128 bytes, every byte in `0x21..=0x7E` (printable ASCII, no space) | `deposit_address_invalid` |
| `destination` | exactly `0x` + 40 **lowercase** hex digits (section 5.2) | `destination_invalid` |
| `chain` | exactly `"base"` or `"bsc"` | `chain_invalid` |
| `verdict` | exactly `"pay"`, `"hold"` or `"unknown"` | `verdict_invalid` |
| `reason` | 0..=256 bytes, valid UTF-8, no C0/C1 control characters and no `U+007F` | `reason_invalid` |

`amount`, `nonce`, `issued_at` and `quote_expiry` have no shape rules: every value in their range
encodes unambiguously. `amount == 0` and `issued_at == 0` are *shape*-valid and are the contract's
problem.

An authorization that fails `validate()` is never signed and never verified. The encoder itself will
still happily encode it — the encoder is dumb by rule 5 — so **validation is a separate call, and
both the signer and the verifier must make it.** A verifier that encodes without validating is a
verifier that accepts an uppercase `destination` its denylist will never match.

### 5.1 NEAR account id

NEAR's documented rule, implemented in both languages:

- 2..=64 bytes
- lowercase alphanumeric, plus the separators `-`, `_` and `.`
- matches `^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$`

In words: dot-separated parts, each part non-empty, each part made of alphanumeric runs joined by
single `-` or `_`, with no leading, trailing or doubled separator. A 64-character hex implicit
account satisfies this as a single part.

This rule is why `guard_id` cannot contain non-ASCII: a multi-byte character fails the charset check
with `guard_id_invalid`, not with a length surprise.

### 5.2 Why `destination` must be lowercase

EIP-55 lets the same EVM address be written in 2^40 different ways, all "correct". If the signed
bytes allow any of them, then:

- a denylist entry stored one way silently fails to match the same address written another way, and
- the per-counterparty rolling cap in the policy engine counts `0xAbC…` and `0xabc…` as two
  different counterparties, so the cap is bypassed by changing the case of a letter.

Both are live bugs in a system that compares addresses as strings, which the contract does. The fix
is to make one spelling the only valid spelling, at the layer both parties agree on. Normalization
happens **in the caller**, before `validate()`; the signer refuses anything else rather than quietly
lowercasing it, so a mismatch surfaces as an error rather than as a signature over bytes the caller
did not expect.

### Semantics (the contract, not this layer)

Not checked here, listed so the boundary is explicit: `verdict == "pay"`, `now - issued_at <=
max_verdict_age_sec`, `now < quote_expiry`, `issued_at <= quote_expiry`, nonce unused, `amount`
against the per-tx / 24h / per-counterparty caps, allowlist and denylist, `guard_id` equal to the
running contract, and `deposit_address` matching the verified 1Click quote.

---

## 6. Signing

**Algorithm: ed25519 (RFC 8032), over `canonical_bytes(auth)` directly. The message is not pre-hashed.**

ed25519 hashes the message internally, so there is no separate digest step and no choice of hash to
get wrong. The `canonical_sha256` field in the vector file is **test metadata only** — a short value
to eyeball when a diff is long. Nothing signs or verifies it.

On-chain this is `env::ed25519_verify(&sig, &bytes, &pubkey) -> bool` (near-sdk ≥ 5.0.0, NEP-364).

**Strict verification.** The Rust tests here call ed25519-dalek's `verify_strict`, which rejects
non-canonical `S` values and small-order public keys. The TypeScript side uses Node's built-in
`crypto.verify`, which is OpenSSL and enforces `S < L`. Both therefore reject the malleated
signature in vector `malleable-s-plus-l`, which is measured rather than assumed: a verifier that
accepts both `S` and `S + L` treats one authorization as having two valid signatures.

> **To confirm on day 3, not assumed here:** nearcore is understood to implement
> `env::ed25519_verify` with `verify_strict`, but that has not been read in the nearcore source
> during this work. It is checked once the contract actually calls the host function. The vector
> passes either way — dalek 2.x rejects a non-canonical `S` in plain `verify` as well — so this is a
> claim to verify, not a risk to the test.

**Message size and gas.** Worst case under section 5 is roughly 600 bytes. At
`wasm_ed25519_verify_base` 210,000,000,000 and `wasm_ed25519_verify_byte` 9,000,000, that is
0.21 TGas + 0.0054 TGas ≈ 0.22 TGas against a 300 TGas limit. Free, for practical purposes.

> Note for the design doc: `design.md` section 4 step 3 states the per-byte cost as "0.009 TGas per
> byte". The raw parameter is 9,000,000 gas, which is 0.000009 TGas per byte — the label is off by
> 1000x. The total it quotes (~0.212 TGas for 200 bytes) is correct, so only the unit is wrong and
> no conclusion changes.

**Keys.** The production signing key is generated once and lives only in a k8s secret. It is never in
this repository in any form. The public key is published here, in the README and in the contract.
Test vectors are signed by a throwaway key **derived at test time** from the documented seed phrase in
section 7; no private key is written to any file in this repo.

---

## 7. Worked example

Short, synthetic values, chosen so the whole message can be checked by hand with nothing but this
page. This is vector `worked-example` in `vectors/canonical-vectors.json`.

```json
{
  "guard_id": "g.near",
  "deposit_address": "d.near",
  "destination": "0x0000000000000000000000000000000000000001",
  "chain": "base",
  "amount": "1",
  "verdict": "pay",
  "reason": "ok",
  "issued_at": "1762000000",
  "quote_expiry": "1762000900",
  "nonce": "7"
}
```

| Part | Bytes (hex) | Len | Note |
|---|---|---|---|
| `u32(33)` | `00000021` | 4 | DOMAIN length |
| DOMAIN | `636861696e776172642e6e6561722d7061796d656e742d67756172642e61757468` | 33 | `chainward.near-payment-guard.auth` |
| `u8(1)` | `01` | 1 | VERSION |
| `u32(6)` | `00000006` | 4 | |
| `guard_id` | `672e6e656172` | 6 | `g.near` |
| `u32(6)` | `00000006` | 4 | |
| `deposit_address` | `642e6e656172` | 6 | `d.near` |
| `u32(42)` | `0000002a` | 4 | |
| `destination` | `3078` + `30`×39 + `31` | 42 | ASCII of `0x00…01` |
| `u32(4)` | `00000004` | 4 | |
| `chain` | `62617365` | 4 | `base` |
| `u128(1)` | `00000000000000000000000000000001` | 16 | note the 15 leading zero bytes |
| `u32(3)` | `00000003` | 4 | |
| `verdict` | `706179` | 3 | `pay` |
| `u32(2)` | `00000002` | 4 | |
| `reason` | `6f6b` | 2 | `ok` |
| `u64(1762000000)` | `000000006905fc80` | 8 | |
| `u64(1762000900)` | `0000000069060004` | 8 | |
| `u128(7)` | `00000000000000000000000000000007` | 16 | |

**Total: 173 bytes.**

Concatenated:

```
00000021636861696e776172642e6e6561722d7061796d656e742d67756172642e617574680100
000006672e6e65617200000006642e6e6561720000002a30783030303030303030303030303030
30303030303030303030303030303030303030303030303030303031000000046261736500000
000000000000000000000000000010000000370617900000002 6f6b000000006905fc80000000
0069060004 00000000000000000000000000000007
```

(line-wrapped and spaced for reading only; the real value is in the vector file, unbroken)

---

## 8. The vector file

`vectors/canonical-vectors.json` is **generated** by `npm run vectors:generate` and **committed**.
Both test suites read the committed file. CI regenerates it and fails if the result differs, so the
committed vectors cannot silently drift from the TypeScript implementation, and the Rust suite cannot
silently drift from the committed vectors.

Four families, because they answer four different questions:

| Family | Question | Shape |
|---|---|---|
| `encoding` | Do both languages produce the same bytes for this input? | auth → expected hex |
| `distinctness` | Are these two different inputs guaranteed to produce different bytes? | auth A, auth B → must differ |
| `verification` | Does a signature check succeed or fail, and for the right reason? | message hex + pubkey + sig → expected result |
| `validation` | Is this input accepted or refused by `validate()`, with which code? | auth → expected failure code or `null` |

`distinctness` is the family that proves rule 1. It is not a restatement of `encoding`: two vectors
having different expected hex only shows that *this* implementation separated them. A distinctness
vector states the adversarial intent — "these two must never collide" — so the property survives a
future refactor that changes the layout.

**Test signer.** Vectors are signed by an ed25519 key derived at test time as:

```
seed = SHA-256("chainward near-payment-guard test vectors v1")
```

Deterministic, so vectors regenerate byte-identically; throwaway, so it protects nothing. The public
key is in the vector file. The private key is in no file. **This key signs test fixtures and nothing
else; it is not the ChainWard verdict key and never will be.**

---

## 9. Known limits

Honest, because the README promises the same.

- **This layer says nothing about whether a payment is a good idea.** It makes "what was signed"
  unambiguous. The verdict's quality is the API's problem and the policy's problem.
- **`validate()` is not a guarantee that the strings refer to real things.** A shape-valid
  `destination` is 42 characters of lowercase hex; whether an account exists there is not knowable
  from the string.
- **`reason` is attacker-influenced text that a UI may display.** It is signed by ChainWard, so it
  cannot be forged, but it is still carried through to logs and interfaces. Control characters are
  refused for that reason; anything that renders it should still treat it as untrusted text.
- **Version 1 has no forward compatibility and is not meant to.** An unknown version is a refusal,
  not a field to skip. Signed formats that skip unknown fields are signed formats where the signer
  and verifier disagree about what was agreed.
