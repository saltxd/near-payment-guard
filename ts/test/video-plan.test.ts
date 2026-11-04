/**
 * The demo video's frame plan: which lines of `npm run demo` are on screen, and for how
 * long. The recording waits ~15 s between scenarios while the sandbox works; the video
 * keeps the order and the text exactly, and only shortens the waits.
 */

import { test, describe } from "node:test";
import assert from "node:assert/strict";

import { planFrames, type TimedLine } from "../video/plan.ts";

const opts = { startMarker: "Starting a local NEAR sandbox", minSeconds: 0.8, maxSeconds: 2.5, holdEndSeconds: 4, maxLines: 6 };

const transcript: TimedLine[] = [
  { t: 0.1, line: "> near-payment-guard@0.1.0 predemo" },
  { t: 0.6, line: "Built and lowered 2 contracts" },
  { t: 5.1, line: "Starting a local NEAR sandbox (no testnet, no funds, no account)..." },
  { t: 9.7, line: "" },
  { t: 27.3, line: "1. Agent pays a clean address inside policy" },
  { t: 27.3, line: "   -> PAID 100" },
  { t: 42.4, line: "2. Agent tries to pay a sanctioned address" },
  { t: 44.2, line: "   -> REFUSED: verdict: hold, sanctions list match" },
];

describe("planFrames", () => {
  test("drops the build noise before the start marker", () => {
    const frames = planFrames(transcript, opts);
    for (const f of frames) for (const l of f.lines) assert.ok(!l.includes("predemo") && !l.includes("Built and lowered"));
    assert.equal(frames[0]?.lines[0], "Starting a local NEAR sandbox (no testnet, no funds, no account)...");
  });

  test("shows every line after the marker, in order, exactly as printed", () => {
    const frames = planFrames(transcript, opts);
    const last = frames.at(-1)!.lines;
    assert.deepEqual(last.slice(-2), ["2. Agent tries to pay a sanctioned address", "   -> REFUSED: verdict: hold, sanctions list match"]);
    const seen = frames.flatMap((f) => f.lines.slice(-1));
    assert.ok(seen.indexOf("   -> PAID 100") < seen.indexOf("   -> REFUSED: verdict: hold, sanctions list match"));
  });

  test("lines printed at the same moment appear in the same frame", () => {
    const frames = planFrames(transcript, opts);
    const withPaid = frames.find((f) => f.lines.includes("   -> PAID 100"))!;
    assert.ok(withPaid.lines.includes("1. Agent pays a clean address inside policy"));
    assert.equal(frames.filter((f) => f.lines.at(-1) === "1. Agent pays a clean address inside policy").length, 0);
  });

  test("shortens long waits and never shows a frame for less than the minimum", () => {
    const frames = planFrames(transcript, opts);
    for (const f of frames.slice(0, -1)) {
      assert.ok(f.seconds <= opts.maxSeconds, `frame held ${f.seconds}s`);
      assert.ok(f.seconds >= opts.minSeconds, `frame held ${f.seconds}s`);
    }
    assert.equal(frames.at(-1)!.seconds, opts.holdEndSeconds);
  });

  test("keeps only the last maxLines lines on screen, like a terminal scrolling", () => {
    const frames = planFrames(transcript, { ...opts, maxLines: 2 });
    for (const f of frames) assert.ok(f.lines.length <= 2);
    assert.deepEqual(frames.at(-1)!.lines, ["2. Agent tries to pay a sanctioned address", "   -> REFUSED: verdict: hold, sanctions list match"]);
  });

  test("refuses a transcript without the start marker instead of rendering nothing", () => {
    assert.throws(() => planFrames(transcript.slice(0, 2), opts), /start marker/);
  });
});
