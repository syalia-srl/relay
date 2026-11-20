/**
 * Per-sender counters and the watermark rule (ROOMS.md 4.5). The state maps a device
 * id to `{n, seq}`: the last counter accepted from it and that message's sequence.
 */

/** Whether a message with counter `n` from `device` is a replay: not above the last one accepted. */
export function isReplay(state, device, n) {
  const last = state[device];
  return last !== undefined && n <= last.n;
}

/**
 * Accept message `{device, n, seq}` into `state` (changed in place). Returns the gap
 * it reveals, `{device, after_n, before_n, cause}`, or null. `cause` is `missing`
 * when the relay still holds the range (watermark at most the last sequence plus
 * one) and `expired` when retention deleted part of it.
 */
export function accept(state, watermark, message) {
  const last = state[message.device];
  let gap = null;
  if (last !== undefined && message.n > last.n + 1) {
    gap = {
      device: message.device,
      after_n: last.n,
      before_n: message.n,
      cause: watermark <= last.seq + 1 ? "missing" : "expired",
    };
  }
  state[message.device] = { n: message.n, seq: message.seq };
  return gap;
}

/** The vectors' form: what a receiver does with each message, in sequence order. */
export function count(state, watermark, messages) {
  const after = structuredClone(state);
  const results = [];
  const gaps = [];
  for (const message of messages) {
    if (isReplay(after, message.device, message.n)) {
      results.push("drop");
      continue;
    }
    const gap = accept(after, watermark, message);
    if (gap) gaps.push(gap);
    results.push("accept");
  }
  return { results, gaps, state: after };
}
