import { expect, test } from "bun:test";
import { admit, COOLDOWN_MS, PER_CLIENT_DAILY, redact } from "./limits";

const fresh = () => ({ busy: false, day: "", runs: 0, lastEnd: 0, clients: new Map<string, number>() });
const NOW = Date.parse("2026-11-05T12:00:00Z");

test("one run at a time", () => {
  expect(admit({ ...fresh(), busy: true }, NOW, 5, "a")).toBe("A room is already running");
});

test("cooldown after a run", () => {
  expect(admit({ ...fresh(), lastEnd: NOW - 1 }, NOW, 5, "a")).toBe("Try again in a minute");
  expect(admit({ ...fresh(), lastEnd: NOW - COOLDOWN_MS }, NOW, 5, "a")).toBeNull();
});

test("daily cap resets the next day", () => {
  const state = { ...fresh(), day: "2026-11-05", runs: 5 };
  expect(admit(state, NOW, 5, "a")).toBe("Today's demo runs are used up");
  expect(admit(state, NOW + 86_400_000, 5, "a")).toBeNull();
  expect(state.runs).toBe(0);
});

test("one client cannot use up the day", () => {
  const state = fresh();
  admit(state, NOW, 20, "a");
  state.clients.set("a", PER_CLIENT_DAILY);
  expect(admit(state, NOW, 20, "a")).toBe("You have used today's runs");
  expect(admit(state, NOW, 20, "b")).toBeNull();
});

test("keys never reach the stream", () => {
  expect(redact("key abc end", ["abc"])).toBe("key [redacted] end");
});
