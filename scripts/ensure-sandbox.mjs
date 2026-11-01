#!/usr/bin/env node
/**
 * Ensures the `near-sandbox` binary near-workspaces runs is new enough for near-sdk 5.29.1.
 *
 * near-workspaces 5.0.0 bundles neard 2.6.2 (protocol 77), but near-sdk 5.29.1 emits host-function
 * imports (e.g. global contracts) that only exist in a newer protocol, so the guard wasm fails to
 * link on 2.6.2 with "UnknownImportError". This fetches the neard version near-sandbox's own current
 * release pins (2.13.4, protocol 86) from NEAR's official release bucket -- the same bucket
 * near-sandbox downloads from -- and drops it where near-workspaces looks for it.
 *
 * Best-effort: on any failure (offline, unsupported platform) it logs and exits 0, and the sandbox
 * suite then skips cleanly rather than failing.
 */

import { execFileSync } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const WANT = "2.13.4"; // the neard version near-sandbox's current release pins; protocol 86
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const BIN = join(ROOT, "node_modules", "near-sandbox", "bin", "near-sandbox");

const platformTriple = () => {
  if (process.platform === "darwin" && process.arch === "arm64") return "Darwin-arm64";
  if (process.platform === "linux" && process.arch === "x64") return "Linux-x86_64";
  throw new Error(`no near-sandbox build for ${process.platform} ${process.arch}`);
};

const currentVersion = () => {
  if (!existsSync(BIN)) return null;
  try {
    const out = execFileSync(BIN, ["--version"], { encoding: "utf8" });
    return out.match(/release (\d+\.\d+\.\d+)/)?.[1] ?? null;
  } catch {
    return null;
  }
};

try {
  const current = currentVersion();
  if (current === WANT) {
    console.log(`near-sandbox ${WANT} already in place`);
    process.exit(0);
  }
  const triple = platformTriple();
  const url = `https://s3-us-west-1.amazonaws.com/build.nearprotocol.com/nearcore/${triple}/${WANT}/near-sandbox.tar.gz`;
  console.log(`near-sandbox is ${current ?? "missing"}; fetching ${WANT} (near-sdk 5.29.1 needs protocol >= 83)`);
  console.log(`  ${url}`);

  const response = await fetch(url);
  if (!response.ok) throw new Error(`download failed: HTTP ${response.status}`);

  const scratch = mkdtempSync(join(tmpdir(), "near-sandbox-"));
  try {
    const tarball = join(scratch, "near-sandbox.tar.gz");
    writeFileSync(tarball, Buffer.from(await response.arrayBuffer()));
    execFileSync("tar", ["xzf", tarball, "-C", scratch]);
    const extracted = join(scratch, triple, "near-sandbox");
    mkdirSync(dirname(BIN), { recursive: true });
    copyFileSync(extracted, BIN);
    chmodSync(BIN, 0o755);
    console.log(`installed near-sandbox ${WANT}`);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
} catch (error) {
  console.warn(`WARN: could not ensure near-sandbox ${WANT}: ${error.message}`);
  console.warn("The sandbox suite will skip cleanly if the binary is incompatible.");
  process.exit(0);
}
