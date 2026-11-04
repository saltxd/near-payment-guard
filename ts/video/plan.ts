/**
 * Frame plan for the demo video, from a timed transcript of `npm run demo`.
 *
 * The video shows the demo's own output, line for line and in order. Only the waits change:
 * the sandbox spends ~15 s setting up each scenario, so every pause is clamped between
 * minSeconds and maxSeconds, and the last frame is held for holdEndSeconds.
 */

export interface TimedLine {
  /** Seconds since the recording started. */
  t: number;
  /** The line exactly as printed, without its newline. */
  line: string;
}

export interface Frame {
  /** The lines on screen, oldest first (at most maxLines). */
  lines: string[];
  /** How long this frame stays on screen. */
  seconds: number;
}

export interface PlanOptions {
  /** The first line to show is the first one containing this text; everything before it is build noise. */
  startMarker: string;
  minSeconds: number;
  maxSeconds: number;
  holdEndSeconds: number;
  /** Lines kept on screen, like a terminal that scrolls. */
  maxLines: number;
}

/** Lines printed within this many seconds of each other appear together. */
const SAME_MOMENT = 0.05;

export function planFrames(transcript: readonly TimedLine[], opts: PlanOptions): Frame[] {
  const start = transcript.findIndex((l) => l.line.includes(opts.startMarker));
  if (start < 0) throw new Error(`start marker not found in the transcript: "${opts.startMarker}"`);

  const steps: { t: number; lines: string[] }[] = [];
  for (const l of transcript.slice(start)) {
    const last = steps.at(-1);
    if (last && l.t - last.t <= SAME_MOMENT) last.lines.push(l.line);
    else steps.push({ t: l.t, lines: [l.line] });
  }

  const shown: string[] = [];
  return steps.map((step, i) => {
    shown.push(...step.lines);
    const next = steps[i + 1];
    const seconds = next
      ? Math.min(opts.maxSeconds, Math.max(opts.minSeconds, next.t - step.t))
      : opts.holdEndSeconds;
    return { lines: shown.slice(-opts.maxLines), seconds };
  });
}
