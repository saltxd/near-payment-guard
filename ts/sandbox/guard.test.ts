/**
 * The primary demo: the nine scenarios from design.md section 6, run against the compiled guard
 * wasm in a local near-workspaces sandbox. A judge runs one command and watches the story:
 *
 *     npm run test:sandbox
 *
 * It builds the contracts (`pretest:sandbox` -> `npm run build:contract`) and runs this file.
 * Each scenario deploys a fresh guard, then asks it to pay through the agent's restricted
 * function-call key, exactly as a real agent would. Scenarios 8 and 9 are the ones that make the
 * point: they fail at the NEAR protocol layer, before any of our code runs.
 *
 * NEAR Intents has no testnet, so the guard is pointed at a local `intents-stub` that receives the
 * `mt_transfer` and the 1Click leg uses synthetic quotes signed by a throwaway key the sandbox
 * registers as 1Click's. The Rust suite proves the identical verification path against a genuine
 * production 1Click signature (`fixtures/1click-quote.json`).
 *
 * If the near-sandbox binary cannot start in this environment, every scenario skips cleanly with a
 * message rather than failing.
 */

import { after, before, test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { KeyPair, Worker, parseNEAR } from "near-workspaces";
import type { NearAccount } from "near-workspaces";
import nearApi from "near-api-js";

import { testKeyPairFromPhrase, signAuth } from "../src/sign.ts";
import type { PaymentAuth } from "../src/types.ts";
import {
  BASE_ASSET,
  BSC_ASSET,
  FAR_FUTURE,
  b64,
  buildQuotePayload,
  nowSeconds,
  signQuote,
  toAuthArgs,
  type SignedQuote,
} from "./harness.ts";

const { functionCallAccessKey } = nearApi.transactions;

const HERE = dirname(fileURLToPath(import.meta.url));
const WASM_DIR = join(HERE, "..", "..", "out");
const GUARD_WASM = join(WASM_DIR, "guard_contract.wasm");
const STUB_WASM = join(WASM_DIR, "intents_stub.wasm");

/** 300 TGas: request_payment verifies two signatures and forwards 30 TGas to the intents call. */
const GAS = 300_000_000_000_000n;

/** The throwaway keys the sandbox uses; they protect nothing and sign only test artifacts. */
const verdictKp = testKeyPairFromPhrase("near-payment-guard sandbox verdict key — throwaway");
const oneclickKp = testKeyPairFromPhrase("near-payment-guard sandbox 1Click key — throwaway");

interface PolicyJson {
  per_tx_cap: string;
  daily_cap: string;
  per_counterparty_cap: string;
  allowlist: string[];
  denylist: string[];
  max_verdict_age_sec: number;
}

const DEFAULT_POLICY: PolicyJson = {
  per_tx_cap: "1000",
  daily_cap: "10000",
  per_counterparty_cap: "5000",
  allowlist: [],
  denylist: [],
  max_verdict_age_sec: 300,
};

interface PaymentResult {
  paid: boolean;
  amount: string;
  deposit_address: string;
  destination: string;
  reason: string;
  nonce: string;
}

let worker: Worker | undefined;
let root: NearAccount;
let intents: NearAccount;
let skipReason: string | undefined;
let guardCounter = 0;

before(async () => {
  if (!existsSync(GUARD_WASM) || !existsSync(STUB_WASM)) {
    skipReason = `contract wasm not found under ${WASM_DIR}. Build it first: npm run build:contract`;
    return;
  }
  // Everything environmental (starting neard, deploying the intents stub) is wrapped here: on any
  // failure the scenarios skip cleanly. Per-scenario guard deploys and all assertions live in the
  // tests, so a contract bug fails loudly rather than being masked by a skip.
  try {
    worker = await Worker.init();
    root = worker.rootAccount;
    intents = await root.createSubAccount("intents");
    await intents.deploy(STUB_WASM);
    await intents.call(intents, "new", {});
  } catch (error) {
    skipReason = `near-sandbox could not start in this environment (${
      (error as Error).message
    }). The suite is written and compiles; run it where the sandbox binary is available.`;
  }
});

after(async () => {
  await worker?.tearDown();
});

/** Skips the current scenario (returning `undefined`) if the sandbox is unavailable. */
const guard = (t: TestContext): boolean => {
  if (skipReason) {
    t.skip(skipReason);
    return false;
  }
  return true;
};

interface Deployment {
  owner: NearAccount;
  guard: NearAccount;
  agentKey: KeyPair;
}

/** Deploys a fresh guard owned by a fresh account, with the agent's restricted key in place. */
const deployGuard = async (policy: PolicyJson = DEFAULT_POLICY): Promise<Deployment> => {
  const owner = await root.createSubAccount(`o${guardCounter++}`, {
    initialBalance: BigInt(parseNEAR("40")),
  });
  const guardAccount = await owner.createSubAccount("guard", {
    initialBalance: BigInt(parseNEAR("15")),
  });
  await guardAccount.deploy(GUARD_WASM);
  await owner.call(guardAccount, "new", {
    owner_id: owner.accountId,
    chainward_pubkey: b64(verdictKp.publicKeyBytes),
    policy,
  });
  await owner.call(guardAccount, "set_oneclick_pubkeys", {
    pubkeys: [b64(oneclickKp.publicKeyBytes)],
  });
  await owner.call(guardAccount, "set_asset_chain", { asset_id: BASE_ASSET, chain: "base" });
  await owner.call(guardAccount, "set_asset_chain", { asset_id: BSC_ASSET, chain: "bsc" });
  await owner.call(guardAccount, "set_intents_account", { account_id: intents.accountId });

  // The agent's key: added to the owner's own account, able to call only request_payment on the
  // guard, and (being a function-call key) unable to attach a deposit or call anything else.
  const agentKey = KeyPair.fromRandom("ed25519");
  await owner
    .batch(owner)
    .addKey(
      agentKey.getPublicKey(),
      functionCallAccessKey(guardAccount.accountId, ["request_payment"], BigInt(parseNEAR("5"))),
    )
    .transact();

  return { owner, guard: guardAccount, agentKey };
};

/** A shape-valid, in-policy "pay" verdict for `guardId`, with the given overrides. */
const makeAuth = (guardId: string, overrides: Partial<PaymentAuth> = {}): PaymentAuth => ({
  guardId,
  depositAddress: "f7252e9f85ccdfd9ee2a1004ef84a517a1e4fa4eb3509cc0517281e761d55f64",
  destination: `0x${"a".repeat(40)}`,
  chain: "base",
  amount: 100n,
  verdict: "pay",
  reason: "no adverse history",
  issuedAt: BigInt(nowSeconds()),
  quoteExpiry: BigInt(nowSeconds() + 900),
  nonce: 1n,
  ...overrides,
});

/** The verdict signature, base64 for `Base64VecU8`. */
const signVerdict = (auth: PaymentAuth): string => b64(signAuth(auth, verdictKp.privateKey));

/** A synthetic 1Click quote that matches `auth`, signed by the test 1Click key. */
const quoteFor = (auth: PaymentAuth): SignedQuote =>
  signQuote(
    buildQuotePayload({
      amountIn: auth.amount.toString(),
      depositAddress: auth.depositAddress,
      recipient: auth.destination,
      destinationAsset: auth.chain === "bsc" ? BSC_ASSET : BASE_ASSET,
    }),
    oneclickKp.privateKey,
  );

/** The agent asks the guard to pay, using its restricted key, with the given quote. */
const requestPayment = (
  d: Deployment,
  auth: PaymentAuth,
  signature: string,
  quote: SignedQuote,
): Promise<PaymentResult> =>
  d.owner.call<PaymentResult>(
    d.guard,
    "request_payment",
    { auth: toAuthArgs(auth), signature, quote },
    { signWithKey: d.agentKey, gas: GAS },
  );

/** Asserts that `fn` rejects and the error text contains `needle`; returns the message. */
const expectReject = async (fn: () => Promise<unknown>, needle: string): Promise<string> => {
  try {
    await fn();
  } catch (error) {
    const message = String((error as Error).message ?? error);
    assert.ok(message.includes(needle), `expected "${needle}" in rejection, got:\n${message}`);
    return message;
  }
  assert.fail(`expected a rejection containing "${needle}", but the call resolved`);
};

test("Scenario 1: agent pays a clean address inside policy -> PAID", async (t) => {
  if (!guard(t)) return;
  const d = await deployGuard();
  const auth = makeAuth(d.guard.accountId);
  const before = await intents.view<number>("transfers");

  const result = await requestPayment(d, auth, signVerdict(auth), quoteFor(auth));

  assert.equal(result.paid, true);
  assert.equal(result.amount, "100");
  assert.equal(result.deposit_address, auth.depositAddress);
  assert.equal(await intents.view<number>("transfers"), before + 1, "the guard released via mt_transfer");
  assert.equal(await d.guard.view<string>("get_spent_24h"), "100");
  console.log(`  PAID ${result.amount} to ${result.destination} via mt_transfer -> ${intents.accountId}`);
});

test("Scenario 2: agent tries to pay a sanctioned address -> REFUSED (hold)", async (t) => {
  if (!guard(t)) return;
  const d = await deployGuard();
  // ChainWard signs a genuine "hold" with the reason; the guard echoes the signed reason.
  const auth = makeAuth(d.guard.accountId, { verdict: "hold", reason: "sanctions list match" });
  const message = await expectReject(
    () => requestPayment(d, auth, signVerdict(auth), quoteFor(auth)),
    "verdict: hold, sanctions list match",
  );
  console.log(`  REFUSED: ${firstPanic(message)}`);
});

test("Scenario 3: agent replays a spent authorization -> REFUSED (nonce used)", async (t) => {
  if (!guard(t)) return;
  const d = await deployGuard();
  const auth = makeAuth(d.guard.accountId, { nonce: 7n });
  const signature = signVerdict(auth);
  const quote = quoteFor(auth);

  const first = await requestPayment(d, auth, signature, quote);
  assert.equal(first.paid, true, "the first use is honoured");

  const message = await expectReject(
    () => requestPayment(d, auth, signature, quote),
    "nonce already used",
  );
  console.log(`  PAID once, then REFUSED on replay: ${firstPanic(message)}`);
});

test("Scenario 4: agent edits the destination, keeps the signature -> REFUSED (bad signature)", async (t) => {
  if (!guard(t)) return;
  const d = await deployGuard();
  const auth = makeAuth(d.guard.accountId);
  const signature = signVerdict(auth); // signed over the ORIGINAL destination
  const tampered = { ...auth, destination: `0x${"b".repeat(40)}` };
  const message = await expectReject(
    () => requestPayment(d, tampered, signature, quoteFor(tampered)),
    "bad signature",
  );
  console.log(`  REFUSED: ${firstPanic(message)}`);
});

test("Scenario 5: agent swaps in its own deposit address -> REFUSED (bad signature)", async (t) => {
  if (!guard(t)) return;
  const d = await deployGuard();
  const auth = makeAuth(d.guard.accountId);
  const signature = signVerdict(auth); // signed over the ORIGINAL deposit address
  const redirected = { ...auth, depositAddress: "attacker-deposit.near" };
  const message = await expectReject(
    () => requestPayment(d, redirected, signature, quoteFor(redirected)),
    "bad signature",
  );
  console.log(`  REFUSED (the deposit address is inside the signed bytes): ${firstPanic(message)}`);
});

test("Scenario 6: agent presents a verdict issued 10 minutes ago -> REFUSED (too old)", async (t) => {
  if (!guard(t)) return;
  const d = await deployGuard();
  const past = nowSeconds() - 600; // older than max_verdict_age_sec (300)
  const auth = makeAuth(d.guard.accountId, {
    issuedAt: BigInt(past),
    quoteExpiry: BigInt(nowSeconds() + 900), // quote itself not yet expired
  });
  const message = await expectReject(
    () => requestPayment(d, auth, signVerdict(auth), quoteFor(auth)),
    "verdict too old",
  );
  console.log(`  REFUSED: ${firstPanic(message)}`);
});

test("Scenario 7: agent drains the budget with small payments -> PAID until the 24h cap", async (t) => {
  if (!guard(t)) return;
  const d = await deployGuard({
    ...DEFAULT_POLICY,
    per_tx_cap: "60",
    daily_cap: "100",
    per_counterparty_cap: "1000",
  });
  const pay = async (amount: bigint, nonce: bigint) => {
    const auth = makeAuth(d.guard.accountId, { amount, nonce });
    return requestPayment(d, auth, signVerdict(auth), quoteFor(auth));
  };

  assert.equal((await pay(60n, 1n)).paid, true);
  assert.equal((await pay(40n, 2n)).paid, true); // window now at the cap, 100
  const message = await expectReject(() => pay(1n, 3n), "daily cap exceeded");
  assert.equal(await d.guard.view<string>("get_spent_24h"), "100", "nothing over the cap was paid");
  console.log(`  PAID 60 + 40 to the cap, then REFUSED: ${firstPanic(message)}`);
});

test("Scenario 8: agent calls another method with its key -> REFUSED by the protocol", async (t) => {
  if (!guard(t)) return;
  const d = await deployGuard();
  // The agent's key is restricted to request_payment. set_policy is a different method, so the
  // NEAR runtime rejects the transaction before the contract runs at all.
  const message = await expectReject(
    () =>
      d.owner.call(
        d.guard,
        "set_policy",
        { policy: DEFAULT_POLICY },
        { signWithKey: d.agentKey, gas: GAS },
      ),
    "", // any rejection; asserted below to be protocol-level, not a contract panic
  );
  assert.ok(
    !message.includes("Smart contract panicked"),
    `expected a protocol-level rejection, not a contract panic:\n${message}`,
  );
  assert.match(
    message,
    /method|access key|not allowed|MethodNameMismatch/i,
    `expected an access-key/method rejection:\n${message}`,
  );
  console.log(`  REFUSED by the protocol (not our code): ${firstLine(message)}`);
});

test("Scenario 9: compromised agent tries to move value out directly -> IMPOSSIBLE", async (t) => {
  if (!guard(t)) return;
  const d = await deployGuard();

  // A function-call key cannot sign a Transfer action: the protocol requires a full-access key.
  const transferMsg = await expectReject(
    () => d.owner.batch(root).transfer(BigInt(parseNEAR("1"))).transact(d.agentKey),
    "",
  );
  assert.ok(
    !transferMsg.includes("Smart contract panicked"),
    `expected a protocol-level rejection, not a contract panic:\n${transferMsg}`,
  );
  assert.match(
    transferMsg,
    /full access|RequiresFullAccess|not allowed|only.*function call/i,
    `expected a full-access requirement:\n${transferMsg}`,
  );

  // And it cannot attach a deposit to its one permitted method either.
  const auth = makeAuth(d.guard.accountId);
  const depositMsg = await expectReject(
    () =>
      d.owner.call(
        d.guard,
        "request_payment",
        { auth: toAuthArgs(auth), signature: signVerdict(auth), quote: quoteFor(auth) },
        { signWithKey: d.agentKey, gas: GAS, attachedDeposit: 1n },
      ),
    "",
  );
  assert.ok(
    !depositMsg.includes("Smart contract panicked"),
    `expected a protocol-level rejection, not a contract panic:\n${depositMsg}`,
  );
  console.log(`  IMPOSSIBLE: the key cannot transfer out or attach a deposit (${firstLine(transferMsg)})`);
});

/** The contract panic text out of a near-workspaces error, for a readable log line. */
const firstPanic = (message: string): string => {
  const match = message.match(/Smart contract panicked: ([^\n"]+)/);
  return match?.[1]?.trim() ?? firstLine(message);
};

const firstLine = (message: string): string => (message.split("\n")[0] ?? message).trim();
