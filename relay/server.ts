#!/usr/bin/env bun
// Lets a judge run a real room without an account. GET /status, POST /run {"flow": ...} streams
// each step as text. Takes no other input, so a caller cannot reach the keys or pick a target.
import { spawn } from "node:child_process";
import { admit, FLOWS, redact, type Flow, type State } from "./limits";

const DAILY_LIMIT = Number(process.env.RELAY_DAILY_LIMIT ?? 20);
const RUN_LIMIT_MS = 10 * 60_000;
const SECRET_NAMES = ["NEAR_PRIVATE_KEY", "LLM_API_KEY", "OUTLAYER_PAYMENT_KEY"];
const secrets = SECRET_NAMES.map((name) => process.env[name]).filter((value): value is string => Boolean(value));
const state: State = { busy: false, day: "", runs: 0, lastEnd: 0 };
const cors = { "Access-Control-Allow-Origin": process.env.RELAY_ORIGIN ?? "*" };
const json = (body: object, status = 200) => Response.json(body, { status, headers: cors });

function run(flow: Flow) {
  state.busy = true;
  state.runs += 1;
  const child = spawn(FLOWS[flow][0], [], {
    env: { ...process.env, ...(flow === "chain" ? { DOOR: "chain" } : {}) },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const timer = setTimeout(() => child.kill(), RUN_LIMIT_MS);
  const finish = () => {
    clearTimeout(timer);
    state.busy = false;
    state.lastEnd = Date.now();
  };
  const encoder = new TextEncoder();
  return new ReadableStream({
    start(controller) {
      let open = true;
      const send = (text: string) => {
        if (open) controller.enqueue(encoder.encode(redact(text, secrets)));
      };
      child.stdout.on("data", (chunk) => send(chunk.toString()));
      child.stderr.on("data", (chunk) => send(chunk.toString()));
      child.on("error", (error) => send(`failed to start: ${error.message}\n`));
      child.on("close", (code) => {
        finish();
        send(code === 0 ? "\n== finished\n" : `\n== stopped, exit ${code}\n`);
        if (open) controller.close();
        open = false;
      });
      // A closed tab must not stop a run: it would leave a room half done.
      this.cancel = () => {
        open = false;
      };
    },
  });
}

Bun.serve({
  port: Number(process.env.PORT ?? 8787),
  idleTimeout: 0,
  async fetch(request) {
    const { pathname } = new URL(request.url);
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: { ...cors, "Access-Control-Allow-Methods": "GET, POST", "Access-Control-Allow-Headers": "content-type" } });
    }
    if (request.method === "GET" && pathname === "/status") {
      return json({ busy: state.busy, runs_today: state.runs, daily_limit: DAILY_LIMIT });
    }
    if (request.method === "POST" && pathname === "/run") {
      const body = await request.json().catch(() => ({}));
      if (!Object.hasOwn(FLOWS, body.flow)) return json({ error: "flow must be private, escrow or chain" }, 400);
      const refused = admit(state, Date.now(), DAILY_LIMIT);
      if (refused) return json({ error: refused }, 429);
      return new Response(run(body.flow), {
        headers: { ...cors, "Content-Type": "text/plain; charset=utf-8", "X-Content-Type-Options": "nosniff" },
      });
    }
    return json({ error: "Not found" }, 404);
  },
});
console.log("relay ready");
