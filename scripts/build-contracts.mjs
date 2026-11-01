#!/usr/bin/env node
/**
 * Builds the guard and intents-stub contracts to NEAR-deployable wasm.
 *
 * Two steps:
 *   1. `cargo build --target wasm32-unknown-unknown --release` for both crates.
 *   2. `wasm-opt` lowers the post-MVP WebAssembly features that NEAR's VM rejects. Modern
 *      rustc/LLVM emit bulk-memory, sign-extension, nontrapping-fptoint, reference-types and
 *      multivalue even with `-C target-cpu=mvp`; NEAR accepts only an MVP-ish set, so a raw
 *      cargo build is refused at deploy time with "PrepareError: Deserialization". Lowering is
 *      exactly what `cargo-near` does under the hood (it also shells out to binaryen); we do it
 *      directly so the only toolchain a judge needs is cargo + npm.
 *
 * Output: out/guard_contract.wasm and out/intents_stub.wasm, which the sandbox suite reads.
 */

import { execFileSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const RELEASE = join(ROOT, "target", "wasm32-unknown-unknown", "release");
const OUT = join(ROOT, "out");
const WASM_OPT = join(ROOT, "node_modules", ".bin", "wasm-opt");

const CRATES = [
  { pkg: "guard-contract", file: "guard_contract.wasm" },
  { pkg: "intents-stub", file: "intents_stub.wasm" },
];

const run = (cmd, args) => execFileSync(cmd, args, { cwd: ROOT, stdio: "inherit" });

run("cargo", [
  "build",
  "-p",
  "guard-contract",
  "-p",
  "intents-stub",
  "--target",
  "wasm32-unknown-unknown",
  "--release",
]);

mkdirSync(OUT, { recursive: true });
const LOWERING = [
  "-Oz",
  "--signext-lowering",
  "--llvm-memory-copy-fill-lowering",
  "--llvm-nontrapping-fptoint-lowering",
  "--disable-reference-types",
  "--disable-multivalue",
  "--strip-target-features",
];
for (const { file } of CRATES) {
  run(WASM_OPT, [join(RELEASE, file), "-o", join(OUT, file), ...LOWERING]);
}

console.log(`\nBuilt and lowered ${CRATES.length} contracts into ${OUT}`);
