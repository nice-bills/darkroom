#!/usr/bin/env bun
// Lets a judge run a real room without an account. GET /status, POST /run {"flow": ...} streams
// each step as text. Takes no other input, so a caller cannot reach the keys or pick a target.
import { spawn } from "node:child_process";
import { admit, FLOWS, redact, type Flow, type State } from "./limits";

const DAILY_LIMIT = Number(process.env.RELAY_DAILY_LIMIT ?? 20);
const RUN_LIMIT_MS = 20 * 60_000;
const SECRET_NAMES = ["NEAR_PRIVATE_KEY", "OUTLAYER_PAYMENT_KEY", "OUTLAYER_CREDENTIALS_B64"];
const secrets = SECRET_NAMES.map((name) => process.env[name]).filter((value): value is string => Boolean(value));
const state: State = { busy: false, day: "", runs: 0, lastEnd: 0, clients: new Map() };
const cors = { "Access-Control-Allow-Origin": process.env.RELAY_ORIGIN ?? "*" };
const json = (body: object, status = 200) => Response.json(body, { status, headers: cors });

function run(flow: Flow, client: string) {
  state.busy = true;
  state.runs += 1;
  state.clients.set(client, (state.clients.get(client) ?? 0) + 1);
  const child = spawn(FLOWS[flow][0], [], {
    env: { ...process.env, ...(flow === "chain" ? { DOOR: "chain" } : {}) },
    stdio: ["ignore", "pipe", "pipe"],
    detached: true,
  });
  // The whole group: a script's children hold the pipes open, and would leave `busy` set.
  const stop = () => {
    try {
      process.kill(-child.pid!);
    } catch {}
  };
  const timer = setTimeout(stop, RUN_LIMIT_MS);
  const encoder = new TextEncoder();
  let viewer: ReadableStreamDefaultController<Uint8Array> | null = null;
  const send = (text: string) => {
    try {
      viewer?.enqueue(encoder.encode(redact(text, secrets)));
    } catch {
      viewer = null;
    }
  };
  return new ReadableStream<Uint8Array>({
    start(controller) {
      viewer = controller;
      child.stdout!.on("data", (chunk) => send(chunk.toString()));
      child.stderr!.on("data", (chunk) => send(chunk.toString()));
      child.on("error", (error) => send(`failed to start: ${error.message}\n`));
      child.on("close", (code) => {
        clearTimeout(timer);
        state.busy = false;
        state.lastEnd = Date.now();
        send(code === 0 ? "\n== finished\n" : `\n== stopped, exit ${code}\n`);
        try {
          viewer?.close();
        } catch {}
        viewer = null;
      });
    },
    // A closed tab must not stop a run: it would leave a room half done.
    cancel() {
      viewer = null;
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
      const body = await request.json().catch(() => null);
      if (!Object.hasOwn(FLOWS, body?.flow)) return json({ error: "flow must be private, escrow or chain" }, 400);
      // Render puts the real client first.
      const client = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "local";
      const refused = admit(state, Date.now(), DAILY_LIMIT, client);
      if (refused) return json({ error: refused }, 429);
      return new Response(run(body.flow, client), {
        headers: { ...cors, "Content-Type": "text/plain; charset=utf-8", "X-Content-Type-Options": "nosniff" },
      });
    }
    return json({ error: "Not found" }, 404);
  },
});
console.log("relay ready");
