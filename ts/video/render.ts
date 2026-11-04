/**
 * Render the demo video: record `npm run demo` with timestamps (or read a recording), plan the
 * frames (ts/video/plan.ts), draw each frame as a terminal-style page, screenshot it with
 * headless Chrome, and stitch the frames into out/video/demo.mp4 with ffmpeg.
 *
 *   npm run video                                   # record, then render
 *   node ts/video/render.ts out/video/demo-transcript.jsonl   # render an existing recording
 *
 * Needs Google Chrome and ffmpeg (with libx264) on the machine. The text on screen is the
 * demo's own output; only the sandbox's waits between scenarios are shortened.
 */

import { spawn, execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { planFrames, type TimedLine } from "./plan.ts";

const OUT = resolve("out/video");
const CHROME = process.env.CHROME ?? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const WIDTH = 1280;
const HEIGHT = 720;

async function record(path: string): Promise<TimedLine[]> {
  const lines: TimedLine[] = [];
  const t0 = Date.now();
  await new Promise<void>((done, fail) => {
    const child = spawn("npm", ["run", "demo"], { stdio: ["ignore", "pipe", "inherit"] });
    let buf = "";
    child.stdout.on("data", (chunk: Buffer) => {
      buf += chunk.toString();
      let nl: number;
      while ((nl = buf.indexOf("\n")) >= 0) {
        lines.push({ t: (Date.now() - t0) / 1000, line: buf.slice(0, nl) });
        buf = buf.slice(nl + 1);
      }
    });
    child.on("exit", (code) => (code === 0 ? done() : fail(new Error(`npm run demo exited ${code}`))));
  });
  writeFileSync(path, lines.map((l) => JSON.stringify(l)).join("\n") + "\n");
  return lines;
}

const escape = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

function lineClass(line: string): string {
  if (/->\s+(PAID|first use PAID)/.test(line)) return "paid";
  if (/->\s+(REFUSED|IMPOSSIBLE)/.test(line)) return "refused";
  if (/^\d\. /.test(line)) return "step";
  return "";
}

function page(lines: string[]): string {
  const body = lines.map((l) => `<div class="${lineClass(l)}">${escape(l) || "&nbsp;"}</div>`).join("");
  return `<!doctype html><html><head><meta charset="utf-8"><style>
  html,body{margin:0;width:${WIDTH}px;height:${HEIGHT}px;background:#0d1117;overflow:hidden}
  .bar{height:44px;display:flex;align-items:center;padding:0 22px;background:#161b22;color:#c9d1d9;
       font:600 18px -apple-system,Helvetica,Arial,sans-serif;border-bottom:1px solid #30363d}
  .bar span{color:#8b949e;font-weight:400;margin-left:12px}
  .term{position:absolute;left:0;right:0;top:45px;bottom:41px;padding:12px 28px;box-sizing:border-box;color:#c9d1d9;
        font:20px/1.45 Menlo,Monaco,monospace;display:flex;flex-direction:column;justify-content:flex-end;overflow:hidden}
  .term div{white-space:pre-wrap;word-break:break-word}
  .step{color:#ffffff;font-weight:700;margin-top:6px}
  .paid{color:#3fb950}
  .refused{color:#f0883e}
  .foot{position:absolute;left:0;right:0;bottom:0;height:40px;display:flex;align-items:center;padding:0 22px;
        color:#8b949e;font:15px -apple-system,Helvetica,Arial,sans-serif;border-top:1px solid #30363d}
</style></head><body>
<div class="bar">NEAR Payment Guard<span>an AI agent tries to pay, nine ways</span></div>
<div class="term">${body}</div>
<div class="foot">Local NEAR sandbox: no testnet, no funds, no account. Output of npm run demo; only the waits are shortened.</div>
</body></html>`;
}

async function main(): Promise<void> {
  mkdirSync(OUT, { recursive: true });
  const given = process.argv[2];
  const transcript: TimedLine[] = given
    ? readFileSync(given, "utf8").trim().split("\n").map((l) => JSON.parse(l) as TimedLine)
    : await record(join(OUT, "demo-transcript.jsonl"));

  const frames = planFrames(transcript, {
    startMarker: "Starting a local NEAR sandbox",
    minSeconds: 1.2,
    maxSeconds: 2.8,
    holdEndSeconds: 6,
    maxLines: 15,
  });

  const work = mkdtempSync(join(tmpdir(), "guard-video-"));
  const profile = mkdtempSync(join(tmpdir(), "guard-chrome-"));
  const list: string[] = [];
  try {
    frames.forEach((f, i) => {
      const html = join(work, `f${String(i).padStart(3, "0")}.html`);
      const png = html.replace(/\.html$/, ".png");
      writeFileSync(html, page(f.lines));
      execFileSync(CHROME, [
        "--headless=new", "--disable-gpu", "--hide-scrollbars", "--force-device-scale-factor=1",
        `--window-size=${WIDTH},${HEIGHT}`, `--user-data-dir=${profile}`, `--screenshot=${png}`, `file://${html}`,
      ], { stdio: "ignore" });
      list.push(`file '${png}'`, `duration ${f.seconds.toFixed(2)}`);
    });
    list.push(list[list.length - 2]!); // the concat demuxer needs the last file repeated to honour its duration
    const listPath = join(work, "frames.txt");
    writeFileSync(listPath, list.join("\n") + "\n");
    const mp4 = join(OUT, "demo.mp4");
    const total = frames.reduce((sum, f) => sum + f.seconds, 0);
    execFileSync("ffmpeg", [
      "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", listPath,
      "-vf", "fps=30,format=yuv420p", "-c:v", "libx264", "-crf", "20", "-movflags", "+faststart", "-t", total.toFixed(2), mp4,
    ], { stdio: "inherit" });
    console.log(`${frames.length} frames, ${total.toFixed(1)} s planned -> ${mp4}`);
  } finally {
    rmSync(work, { recursive: true, force: true });
    rmSync(profile, { recursive: true, force: true });
  }
}

await main();
