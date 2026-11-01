/**
 * A narrated walkthrough of the guard, against a local near-workspaces sandbox.
 *
 *     npm run demo
 *
 * Same nine moments as the test suite (design.md section 6), but written as a story a human can
 * watch or record rather than a test runner's output: each line says what the agent tried and what
 * the guard did, with the reason. No testnet, no funds, no account -- everything runs in a local
 * sandbox. The testnet/video version (which needs the user's NEAR account) is a later step.
 *
 * This reuses the same signer the production API would (`../src/sign.ts`) and the same quote/auth
 * helpers as the test suite (`./harness.ts`); the 1Click leg uses synthetic quotes signed by a
 * throwaway key and the release goes to a local intents stub, both disclosed in the README.
 */

import { KeyPair, Worker, parseNEAR } from "near-workspaces";
import type { NearAccount } from "near-workspaces";
import nearApi from "near-api-js";

import { testKeyPairFromPhrase, signAuth } from "../src/sign.ts";
import type { PaymentAuth } from "../src/types.ts";
import {
  BASE_ASSET,
  BSC_ASSET,
  b64,
  buildQuotePayload,
  nowSeconds,
  signQuote,
  toAuthArgs,
  type SignedQuote,
} from "./harness.ts";

const { functionCallAccessKey } = nearApi.transactions;

const GAS = 300_000_000_000_000n;
const GUARD_WASM = new URL("../../out/guard_contract.wasm", import.meta.url).pathname;
const STUB_WASM = new URL("../../out/intents_stub.wasm", import.meta.url).pathname;

const verdictKp = testKeyPairFromPhrase("near-payment-guard demo verdict key — throwaway");
const oneclickKp = testKeyPairFromPhrase("near-payment-guard demo 1Click key — throwaway");

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
  destination: string;
  reason: string;
}

let counter = 0;

// near-workspaces logs raw receipts and contract logs to the console on every call. Keep those out
// of the narrative: print our own lines through the saved originals, and silence the console while a
// sandbox call runs.
const origLog = console.log.bind(console);
const line = (text = "") => origLog(text);
const origOut = process.stdout.write.bind(process.stdout);
const origErr = process.stderr.write.bind(process.stderr);
const mute = (() => true) as typeof process.stdout.write;
async function quiet<T>(fn: () => Promise<T>): Promise<T> {
  // near-workspaces writes receipts and failure dumps straight to stdout/stderr, so silence both at
  // the stream level while a sandbox call runs; the narrative is printed between calls.
  process.stdout.write = mute;
  process.stderr.write = mute;
  try {
    return await fn();
  } finally {
    process.stdout.write = origOut;
    process.stderr.write = origErr;
  }
}

const panicReason = (error: unknown): string => {
  const message = String((error as Error).message ?? error);
  return (
    message.match(/Smart contract panicked: ([^\n"]+)/)?.[1]?.trim() ??
    (message.split("\n")[0] ?? message).trim()
  );
};

async function main(): Promise<void> {
  line("Starting a local NEAR sandbox (no testnet, no funds, no account)...");
  const worker = await quiet(() => Worker.init());
  try {
    const root = worker.rootAccount;
    const intents = await quiet(async () => {
      const account = await root.createSubAccount("intents");
      await account.deploy(STUB_WASM);
      await account.call(account, "new", {});
      return account;
    });

    const deployGuard = (
      policy: PolicyJson = DEFAULT_POLICY,
    ): Promise<{ owner: NearAccount; guard: NearAccount; agentKey: KeyPair }> =>
      quiet(async () => {
      const owner = await root.createSubAccount(`o${counter++}`, {
        initialBalance: BigInt(parseNEAR("40")),
      });
      const guard = await owner.createSubAccount("guard", {
        initialBalance: BigInt(parseNEAR("15")),
      });
      await guard.deploy(GUARD_WASM);
      await owner.call(guard, "new", {
        owner_id: owner.accountId,
        chainward_pubkey: b64(verdictKp.publicKeyBytes),
        policy,
      });
      await owner.call(guard, "set_oneclick_pubkeys", { pubkeys: [b64(oneclickKp.publicKeyBytes)] });
      await owner.call(guard, "set_asset_chain", { asset_id: BASE_ASSET, chain: "base" });
      await owner.call(guard, "set_asset_chain", { asset_id: BSC_ASSET, chain: "bsc" });
      await owner.call(guard, "set_intents_account", { account_id: intents.accountId });
      const agentKey = KeyPair.fromRandom("ed25519");
      await owner
        .batch(owner)
        .addKey(
          agentKey.getPublicKey(),
          functionCallAccessKey(guard.accountId, ["request_payment"], BigInt(parseNEAR("5"))),
        )
        .transact();
      return { owner, guard, agentKey };
      });

    const auth = (guardId: string, overrides: Partial<PaymentAuth> = {}): PaymentAuth => ({
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

    const sign = (a: PaymentAuth): string => b64(signAuth(a, verdictKp.privateKey));
    const quoteFor = (a: PaymentAuth): SignedQuote =>
      signQuote(
        buildQuotePayload({
          amountIn: a.amount.toString(),
          depositAddress: a.depositAddress,
          recipient: a.destination,
          destinationAsset: a.chain === "bsc" ? BSC_ASSET : BASE_ASSET,
        }),
        oneclickKp.privateKey,
      );
    const ask = (
      owner: NearAccount,
      guard: NearAccount,
      agentKey: KeyPair,
      a: PaymentAuth,
      signature = sign(a),
      quote = quoteFor(a),
    ): Promise<PaymentResult> =>
      quiet(() =>
        owner.call<PaymentResult>(
          guard,
          "request_payment",
          { auth: toAuthArgs(a), signature, quote },
          { signWithKey: agentKey, gas: GAS },
        ),
      );

    line("");
    line("The guard holds the money. The agent holds only a function-call key that can call");
    line("request_payment and nothing else. It never holds a key that can move funds.");
    line("");

    // 1
    {
      const { owner, guard, agentKey } = await deployGuard();
      const a = auth(guard.accountId);
      const r = await ask(owner, guard, agentKey, a);
      line(`1. Agent pays a clean address inside policy`);
      line(`   -> PAID ${r.amount} to ${r.destination}, released via mt_transfer (${r.reason})`);
    }

    // 2
    {
      const { owner, guard, agentKey } = await deployGuard();
      const a = auth(guard.accountId, { verdict: "hold", reason: "sanctions list match" });
      line(`2. Agent tries to pay a sanctioned address (ChainWard signs a hold)`);
      try {
        await ask(owner, guard, agentKey, a);
        line(`   -> UNEXPECTED: paid`);
      } catch (e) {
        line(`   -> REFUSED: ${panicReason(e)}`);
      }
    }

    // 3
    {
      const { owner, guard, agentKey } = await deployGuard();
      const a = auth(guard.accountId, { nonce: 42n });
      const signature = sign(a);
      const quote = quoteFor(a);
      const r = await ask(owner, guard, agentKey, a, signature, quote);
      line(`3. Agent replays the same authorization`);
      line(`   -> first use PAID ${r.amount}; replay...`);
      try {
        await ask(owner, guard, agentKey, a, signature, quote);
        line(`   -> UNEXPECTED: paid twice`);
      } catch (e) {
        line(`   -> REFUSED: ${panicReason(e)}`);
      }
    }

    // 4
    {
      const { owner, guard, agentKey } = await deployGuard();
      const a = auth(guard.accountId);
      const signature = sign(a); // over the original destination
      const tampered = { ...a, destination: `0x${"b".repeat(40)}` };
      line(`4. Agent edits the destination but keeps the signature`);
      try {
        await ask(owner, guard, agentKey, tampered, signature);
        line(`   -> UNEXPECTED: paid`);
      } catch (e) {
        line(`   -> REFUSED: ${panicReason(e)}`);
      }
    }

    // 5
    {
      const { owner, guard, agentKey } = await deployGuard();
      const a = auth(guard.accountId);
      const signature = sign(a); // over the original deposit address
      const redirected = { ...a, depositAddress: "attacker-deposit.near" };
      line(`5. Agent swaps in its own deposit address`);
      try {
        await ask(owner, guard, agentKey, redirected, signature);
        line(`   -> UNEXPECTED: paid`);
      } catch (e) {
        line(`   -> REFUSED: ${panicReason(e)} (the deposit address is inside the signed bytes)`);
      }
    }

    // 6
    {
      const { owner, guard, agentKey } = await deployGuard();
      const a = auth(guard.accountId, {
        issuedAt: BigInt(nowSeconds() - 600),
        quoteExpiry: BigInt(nowSeconds() + 900),
      });
      line(`6. Agent presents a verdict issued 10 minutes ago`);
      try {
        await ask(owner, guard, agentKey, a);
        line(`   -> UNEXPECTED: paid`);
      } catch (e) {
        line(`   -> REFUSED: ${panicReason(e)}`);
      }
    }

    // 7
    {
      const { owner, guard, agentKey } = await deployGuard({
        ...DEFAULT_POLICY,
        per_tx_cap: "60",
        daily_cap: "100",
        per_counterparty_cap: "1000",
      });
      line(`7. Agent makes many small payments to drain the budget (daily cap 100)`);
      const r1 = await ask(owner, guard, agentKey, auth(guard.accountId, { amount: 60n, nonce: 1n }));
      const r2 = await ask(owner, guard, agentKey, auth(guard.accountId, { amount: 40n, nonce: 2n }));
      line(`   -> PAID ${r1.amount}, PAID ${r2.amount} (window now at the cap)`);
      try {
        await ask(owner, guard, agentKey, auth(guard.accountId, { amount: 1n, nonce: 3n }));
        line(`   -> UNEXPECTED: paid over the cap`);
      } catch (e) {
        line(`   -> REFUSED: ${panicReason(e)}`);
      }
    }

    // 8
    {
      const { owner, guard, agentKey } = await deployGuard();
      line(`8. Agent calls another method (set_policy) with its restricted key`);
      try {
        await quiet(() =>
          owner.call(
            guard,
            "set_policy",
            { policy: DEFAULT_POLICY },
            { signWithKey: agentKey, gas: GAS },
          ),
        );
        line(`   -> UNEXPECTED: allowed`);
      } catch (e) {
        line(`   -> REFUSED by the NEAR protocol, not our code: ${panicReason(e)}`);
      }
    }

    // 9
    {
      const { owner, agentKey } = await deployGuard();
      line(`9. Compromised agent tries to transfer funds out directly`);
      try {
        await quiet(() => owner.batch(root).transfer(BigInt(parseNEAR("1"))).transact(agentKey));
        line(`   -> UNEXPECTED: transferred`);
      } catch (e) {
        line(`   -> IMPOSSIBLE: a function-call key cannot sign a transfer (${panicReason(e)})`);
      }
    }

    line("");
    line("The guard paid only when a signed ChainWard verdict AND the policy both said yes, and");
    line("paid only the address 1Click signed. Everything else was refused, most of it by NEAR.");
  } finally {
    await quiet(() => worker.tearDown());
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
