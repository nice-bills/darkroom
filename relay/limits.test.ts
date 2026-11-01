import { expect, test } from "bun:test";
import { admit, COOLDOWN_MS, redact } from "./limits";

const fresh = () => ({ busy: false, day: "", runs: 0, lastEnd: 0 });
const NOW = Date.parse("2026-11-05T12:00:00Z");

test("one run at a time", () => {
  expect(admit({ ...fresh(), busy: true }, NOW, 5)).toBe("A room is already running");
});

test("cooldown after a run", () => {
  expect(admit({ ...fresh(), lastEnd: NOW - 1 }, NOW, 5)).toBe("Try again in a minute");
  expect(admit({ ...fresh(), lastEnd: NOW - COOLDOWN_MS }, NOW, 5)).toBeNull();
});

test("daily cap resets the next day", () => {
  const state = { ...fresh(), day: "2026-11-05", runs: 5 };
  expect(admit(state, NOW, 5)).toBe("Today's demo runs are used up");
  expect(admit(state, NOW + 86_400_000, 5)).toBeNull();
  expect(state.runs).toBe(0);
});

test("keys never reach the stream", () => {
  expect(redact("key abc end", ["abc"])).toBe("key [redacted] end");
});
