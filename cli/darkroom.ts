#!/usr/bin/env bun
// darkroom seller list | buyer open, fetch, cancel, refund | status | verify. See the README.
import { createHash, randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { checkRoomKey, newBuyerKey, openDelivery, sealMandate, sealToRoom } from "./crypto";
import { call, rpc, view } from "./near";

const env = (name: string) => {
  const value = process.env[name];
  if (!value) throw new Error(`Set ${name}, see .env.example`);
  return value;
};
const USDC = 1_000_000;
// Mirrors the contract. Paying takes minutes, so it must not start at the edge of the window.
const PAY_WINDOW_BLOCKS = 6000;
const PAY_MARGIN_BLOCKS = 1000;
const KEY_DIR = join(homedir(), ".darkroom");
const keyPath = (listing: number, account: string) => join(KEY_DIR, `${listing}-${account}.json`);
const paymentPath = (ctRef: string) => join(KEY_DIR, `paid-${ctRef}.tx`);
const sellerSeedPath = (listing: number) => join(KEY_DIR, `seller-${listing}.seed`);
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function sellerList(o: Record<string, any>) {
  const contract = env("DARKROOM_CONTRACT");
  const profile = `l-${randomBytes(4).toString("hex")}`;
  const secret = readFileSync(o["secret-file"], "utf8");
  const salt = randomBytes(32);
  const commitment = createHash("sha256").update(salt).update(secret).digest("hex");
  const row: Record<string, string> = {
    DARKROOM_SECRET: secret,
    DARKROOM_SALT: salt.toString("hex"),
    DARKROOM_RESERVE_USDC: String(o.reserve),
    DARKROOM_TITLE: o["private-title"] ?? o.title,
  };
  const privateSettlement = Boolean(o.private);
  const payeeSeed = randomBytes(32).toString("hex");
  if (privateSettlement) {
    row.DARKROOM_PAYEE_SEED = payeeSeed;
    // Before anything else: without this the seller cannot spend what they are paid.
    mkdirSync(KEY_DIR, { recursive: true, mode: 0o700 });
    writeFileSync(join(KEY_DIR, `seed-${profile}`), payeeSeed, { mode: 0o600 });
  }
  // Encrypted on this machine by the outlayer CLI. Only this build, started by the contract or
  // the relayer, can read the row, and the room checks the commitment and the chain itself.
  const stored = spawnSync(
    "outlayer",
    ["secrets", "set", JSON.stringify(row), "--profile", profile, "--project", env("DARKROOM_PROJECT"),
     "--access", "allow-all", "--build", env("DARKROOM_WASM_HASH"), "--via", `${contract},${env("DARKROOM_RELAYER")}`],
    { encoding: "utf8" },
  );
  if (stored.status !== 0) throw new Error(`outlayer secrets set failed:\n${stored.stderr.slice(-400)}`);
  const id = await view(contract, "listing_count", {});
  const args = { profile, title: o.title, max_rooms: Number(o["max-rooms"] ?? 3), commitment, target: o.target ?? null, private_settlement: privateSettlement, bond: privateSettlement ? String(Number(o.bond ?? 1) * USDC) : "0" };
  call(o.as, contract, "list", args, "0.01 NEAR");
  if (privateSettlement) writeFileSync(sellerSeedPath(id), payeeSeed, { mode: 0o600 });
  console.log(`listed as ${id}, commitment ${commitment}`);
}

/// Proving needs Node: snarkjs crashes under Bun. Output on stdout is the result.
function gloam(...args: string[]) {
  const run = spawnSync("node", ["cli/gloam.ts", ...args], { encoding: "utf8" });
  if (run.status !== 0) throw new Error(`gloam ${args[0]} failed:\n${run.stderr.slice(-600)}`);
  return run.stdout;
}

/// One authenticated run in a worker. The caller is the relayer, which is trusted with nothing.
async function callRoom(input: object, secretsRef?: object) {
  const url = `${env("OUTLAYER_API")}/call/${env("DARKROOM_PROJECT")}`;
  const response = await fetch(url, {
    method: "POST",
    headers: { "X-Payment-Key": env("OUTLAYER_PAYMENT_KEY"), "Content-Type": "application/json" },
    body: JSON.stringify({
      input,
      secrets_ref: secretsRef,
      resource_limits: { max_instructions: 10_000_000_000, max_execution_seconds: 90 },
    }),
  });
  const body: any = await response.json();
  if (body.status !== "completed") throw new Error(`room run failed: ${body.error ?? JSON.stringify(body)}`);
  console.log(`room run ${body.call_id}, ${body.time_ms} ms`);
  return body.output;
}

async function waitForStatus(listing: number, buyer: string, wanted: string) {
  const contract = env("DARKROOM_CONTRACT");
  for (let i = 0; i < 30; i++) {
    const room = await view(contract, "get_room", { listing_id: listing, buyer });
    if (room?.status === wanted) return;
    await sleep(1000);
  }
  throw new Error(`Room never reached ${wanted}`);
}

async function buyerOpen(o: Record<string, any>) {
  const contract = env("DARKROOM_CONTRACT");
  const token = env("DARKROOM_TOKEN");
  const listing = Number(o.listing);
  const amount = BigInt(o.budget) * BigInt(USDC);

  mkdirSync(KEY_DIR, { recursive: true, mode: 0o700 });
  const path = keyPath(listing, o.as);
  // Resumable: a failure between funding and opening must not strand the budget.
  const key = existsSync(path) ? JSON.parse(readFileSync(path, "utf8")) : newBuyerKey();
  writeFileSync(path, JSON.stringify(key), { mode: 0o600 });

  const { private_settlement: isPrivate, bond } = await view(contract, "get_listing", { listing_id: listing });
  let room = await view(contract, "get_room", { listing_id: listing, buyer: o.as });
  if (!room) {
    const open: Record<string, unknown> = { listing_id: listing, buyer_pubkey: key.pubkey, protected_value: Number(o.protects ?? 0) };
    if (isPrivate) {
      const roomKey = await readRoomKey();
      open.sealed_mandate = sealMandate(roomKey, amount, BigInt(o.protects ?? 0), `${listing}-${o.as}`);
      open.protected_value = 0;
    }
    const transfer = isPrivate ? bond : amount.toString();
    call(o.as, token, "ft_transfer_call", { receiver_id: contract, amount: transfer, msg: JSON.stringify(open) }, "1 yoctoNEAR");
    await sleep(2000);
    room = await view(contract, "get_room", { listing_id: listing, buyer: o.as });
    if (!room) throw new Error("Funding was refused and returned: check the listing, or your balance");
    console.log(isPrivate ? `bond posted, limit of ${o.budget} USDC sealed to the room` : `escrowed ${o.budget} USDC`);
  }
  if (room.status === "Funded") {
    console.log("the room is starting");
    if (o.door === "chain") {
      const output = call(o.as, contract, "open_room", { listing_id: listing }, "0.1 NEAR");
      console.log(`open_room tx ${output.match(/Transaction ID: (\S+)/)?.[1]}`);
    } else {
      call(o.as, contract, "start_room", { listing_id: listing }, "0 NEAR");
      await relay(listing, o.as);
    }
  } else if (room.status === "Running" && o.door !== "chain") {
    await relay(listing, o.as);
  }
  await printStatus(listing, o.as);
}

/// Runs the room and posts its signed verdict. Anyone can do this: changing a byte breaks the
/// signature, and a relayer that does nothing only triggers `refund_stale`.
async function relay(listing: number, buyer: string) {
  const contract = env("DARKROOM_CONTRACT");
  await waitForStatus(listing, buyer, "Running");
  const { seller, profile } = await view(contract, "get_listing", { listing_id: listing });
  const verdict = await callRoom(
    { op: "negotiate", listing_id: listing, buyer },
    { profile, account_id: seller },
  );
  const output = call(buyer, contract, "settle_signed", {
    listing_id: listing, buyer, deal: verdict.deal, price: verdict.price,
    ct_ref: verdict.ct_ref, ct_hash: verdict.ct_hash, sig: verdict.sig,
  }, "0 NEAR");
  console.log(`settle_signed tx ${output.match(/Transaction ID: (\S+)/)?.[1]}`);
}

/// After the pay window, a buyer who took a price and never paid loses the bond to the seller.
function sellerForfeit(o: Record<string, any>) {
  call(o.as, env("DARKROOM_CONTRACT"), "forfeit", { listing_id: Number(o.listing), buyer: o.buyer }, "0 NEAR");
  console.log("bond claimed. Call again after the grace period to take it");
}

function buyerCancel(o: Record<string, any>) {
  call(o.as, env("DARKROOM_CONTRACT"), "cancel", { listing_id: Number(o.listing) }, "0 NEAR");
  console.log("cancelled, budget refunded");
}

function buyerRefund(o: Record<string, any>) {
  call(o.as, env("DARKROOM_CONTRACT"), "refund_stale", { listing_id: Number(o.listing), buyer: o.as }, "0 NEAR");
  console.log("stale room refunded");
}

async function waitForOutcome(listing: number, buyer: string) {
  const contract = env("DARKROOM_CONTRACT");
  for (let i = 0; i < 90; i++) {
    const room = await view(contract, "get_room", { listing_id: listing, buyer });
    if (!room) throw new Error("No room for this account on this listing");
    if (room.status !== "Running") return room;
    await sleep(2000);
  }
  throw new Error("Room still running after 3 minutes");
}

async function printStatus(listing: number, buyer: string) {
  const room = await waitForOutcome(listing, buyer);
  if (room.status === "Funded") console.log("funded, not started: run buyer open again, or buyer cancel");
  else if (room.status === "NoDeal") console.log("no deal: any escrow is refunded, and you learned nothing else");
  else if (room.status.Deal && room.mandate) console.log("deal, price sealed to you. Run: buyer pay");
  else if (room.status.Deal) console.log(`deal at ${Number(room.status.Deal.price) / USDC} USDC. Run: buyer fetch`);
  else console.log(JSON.stringify(room.status));
}

/// Refuses a key the enclave did not sign. Published, so a buyer needs no relayer to read it.
async function readRoomKey() {
  const contract = env("DARKROOM_CONTRACT");
  const keys = JSON.parse(new TextDecoder().decode(await readPublic("room-keys")));
  return checkRoomKey(contract, keys, await view(contract, "get_enclave_key", {}));
}

async function readPublic(key: string) {
  const url = `${env("OUTLAYER_API")}/public/storage/get?project=${encodeURIComponent(env("DARKROOM_PROJECT"))}`
    + `&key=${encodeURIComponent(key)}&format=raw`;
  for (let i = 0; i < 60; i++) {
    const response = await fetch(url);
    if (response.ok) return new Uint8Array(await response.arrayBuffer());
    await sleep(2000);
  }
  throw new Error(`${key} is not published yet. It is safe to retry`);
}

/// Reads the sealed price, which the room releases only after the chain records the deal, then
/// pays through Gloam. The payment's hash stays off NEAR, so nothing there points to it.
async function buyerPay(o: Record<string, any>) {
  const contract = env("DARKROOM_CONTRACT");
  const listing = Number(o.listing);
  const room = await view(contract, "get_room", { listing_id: listing, buyer: o.as });
  if (!room?.mandate || !room.status?.Deal) throw new Error("No private deal on this listing");
  const ctRef = room.status.Deal.ct_ref;
  const height = (await rpc("block", { finality: "final" })).header.height;
  if (height > room.opened_at + PAY_WINDOW_BLOCKS - PAY_MARGIN_BLOCKS) {
    throw new Error("Too little of the pay window is left. Paying now could lose the bond");
  }
  if (o.door === "chain") call(o.as, contract, "request_terms", { listing_id: listing }, "0.1 NEAR");
  else await callRoom({ op: "terms", listing_id: listing, buyer: o.as });
  const { secret } = JSON.parse(readFileSync(keyPath(listing, o.as), "utf8"));
  const terms = JSON.parse(new TextDecoder().decode(openDelivery(secret, await readPublic(`terms:${ctRef}`))));
  console.log(`sealed terms: ${Number(terms.price) / USDC} USDC`);
  const tx = gloam("pay", terms.pay_to, String(terms.price), ctRef, o.as).trim();
  writeFileSync(paymentPath(ctRef), tx, { mode: 0o600 });
  console.log("paid. The payment is final. Run: buyer fetch");
}

function buyerReclaim(o: Record<string, any>) {
  console.log(gloam("reclaim", `${o.listing}-${o.as}`, o.as, o.to));
}

async function sellerPaid(o: Record<string, any>) {
  const seed = readFileSync(sellerSeedPath(Number(o.listing)), "utf8");
  console.log(gloam("balance", seed, `${o.listing}-${o.buyer}`).trim());
}

async function buyerFetch(o: Record<string, any>) {
  const contract = env("DARKROOM_CONTRACT");
  const listing = Number(o.listing);
  const room = await view(contract, "get_room", { listing_id: listing, buyer: o.as });
  if (!room?.status?.Deal) throw new Error("No deal on this listing");
  const ctRef = room.status.Deal.ct_ref;
  const { secret } = JSON.parse(readFileSync(keyPath(listing, o.as), "utf8"));
  const tx = o.tx ?? (existsSync(paymentPath(ctRef)) ? readFileSync(paymentPath(ctRef), "utf8") : undefined);
  const sealedTx = tx ? sealToRoom(await readRoomKey(), new TextEncoder().encode(tx.trim())) : undefined;
  let paidSig: string | undefined;
  if (o.door === "chain") call(o.as, contract, "reveal", { listing_id: listing, sealed_tx: sealedTx ?? null }, "0.1 NEAR");
  else paidSig = (await callRoom({ op: "reveal", listing_id: listing, buyer: o.as, ...(sealedTx ? { sealed_tx: sealedTx } : {}) })).paid_sig;
  process.stdout.write(new TextDecoder().decode(openDelivery(secret, await readPublic(`reveal:${ctRef}`))));
  // After the secret is out: a failure here costs at most the bond, never what was paid for.
  if (paidSig) {
    try {
      call(o.as, contract, "confirm_paid", { listing_id: listing, buyer: o.as, sig: paidSig }, "0 NEAR");
    } catch (error: any) {
      console.error(`Bond not returned: ${error.message.slice(-160)}`);
    }
  }
}

function wasmManifest(wasm: Buffer) {
  const marker = wasm.indexOf("outlayer.manifest");
  if (marker < 0) throw new Error("wasm has no outlayer.manifest section");
  const start = wasm.indexOf("{", marker);
  let depth = 0;
  for (let i = start; i < wasm.length; i++) {
    if (wasm[i] === 0x7b) depth++;
    if (wasm[i] === 0x7d && --depth === 0) return JSON.parse(wasm.subarray(start, i + 1).toString());
  }
  throw new Error("manifest is not valid JSON");
}

/// Checks everything checkable from the chain and a local build. The TDX quote itself is only
/// exposed in the OutLayer dashboard for on-chain runs.
async function verify(o: Record<string, any>) {
  const contract = env("DARKROOM_CONTRACT");
  const wasm = readFileSync(o.wasm);
  const hash = createHash("sha256").update(wasm).digest("hex");
  const manifest = wasmManifest(wasm);
  let failed = false;
  const check = (ok: boolean, label: string) => {
    console.log(`${ok ? "ok  " : "FAIL"} ${label}`);
    failed ||= !ok;
  };

  console.log(`local wasm sha256 ${hash}`);
  check(manifest.callers?.direct === "deny", "manifest refuses direct calls");
  check(manifest.signing_keys?.[0]?.path === "verdict", "verdicts are signed by the enclave key");
  check(manifest.connector_id !== undefined, "connector_id set, so the egress allowlist is enforced");
  console.log(`     egress allowed: ${manifest.capabilities?.network?.join(", ")}`);

  const tx = await rpc("tx", { tx_hash: o.tx, sender_account_id: o.signer, wait_until: "FINAL" });
  const logs: string[] = tx.receipts_outcome.flatMap((receipt: any) => receipt.outcome.logs);
  const event = (name: string) => logs
    .filter((log) => log.startsWith("EVENT_JSON:"))
    .map((log) => JSON.parse(log.slice("EVENT_JSON:".length)))
    .find((e) => e.event === name);
  const requested = event("execution_requested");
  check(Boolean(requested), "transaction started an OutLayer run");
  if (requested) {
    const data = JSON.parse(requested.data[0].request_data);
    check(data.predecessor_id === contract, "the run was requested by the contract");
    check(data.code_source?.WasmUrl?.hash === hash, "the run used exactly this wasm");
    console.log(`     request id ${data.request_id}. TDX quote: https://app.outlayer.ai/executions`);
  }
  if (failed) process.exit(1);
}

/// Recomputes the task hash from the attestation and compares it to the hash inside the TDX
/// quote, so swapping the wasm, input or output breaks the match, then checks the quote itself.
async function verifyCall(o: Record<string, any>) {
  const response = await fetch(`${env("OUTLAYER_API")}/attestations/by-call/${o.call}`, {
    headers: { "X-Payment-Key": env("OUTLAYER_PAYMENT_KEY") },
  });
  const a: any = await response.json();
  const quote = Buffer.from(a.tdx_quote, a.tdx_quote.startsWith("BAAC") ? "base64" : "hex");
  const le64 = (value: number) => {
    const bytes = Buffer.alloc(8);
    bytes.writeBigInt64LE(BigInt(value));
    return bytes;
  };
  const text = (value: string | null | undefined) => Buffer.from(value ?? "");
  const hash = createHash("sha256");
  for (const part of [
    text(a.task_type), le64(a.task_id), text(a.repo_url), text(a.commit_hash), text(a.build_target),
    text(a.wasm_hash), text(a.input_hash), text(a.output_hash),
    a.block_height == null ? Buffer.alloc(0) : le64(a.block_height),
    text(a.caller_account_id), text(a.project_id), text(a.secrets_ref), le64(a.timestamp), text(a.attached_usd),
  ]) hash.update(part);
  const computed = hash.digest("hex");
  const inQuote = quote.subarray(568, 600).toString("hex");
  const expected = process.env.DARKROOM_WASM_HASH;
  if (expected && a.wasm_hash !== expected) {
    console.log(`FAIL the run used ${a.wasm_hash}, not the published ${expected}`);
    process.exit(1);
  }
  console.log(`quote: version ${quote.readUInt16LE(0)}, tee type 0x${quote.readUInt32LE(4).toString(16)}`);
  console.log(`worker measurement ${a.worker_measurement}`);
  console.log(`wasm ${a.executed_wasm_sha256}, project ${a.project_id}`);
  console.log(`${computed === inQuote ? "ok  " : "FAIL"} quote commits to this wasm, input and output`);
  if (computed !== inQuote) process.exit(1);

  // Intel's signature chain and the approved worker builds, from outside OutLayer's API.
  const file = join(tmpdir(), `darkroom-quote-${o.call}.hex`);
  writeFileSync(file, quote.toString("hex"));
  const tool = spawnSync("tools/verify-quote/target/release/verify-quote", [file], { encoding: "utf8" });
  if (tool.status !== 0) {
    console.log(`FAIL Intel signature check: ${tool.stderr.slice(-300) || "build tools/verify-quote first"}`);
    process.exit(1);
  }
  const report = JSON.parse(tool.stdout);
  const current = report.tcb_status === "UpToDate";
  console.log(`${current ? "ok  " : "FAIL"} Intel signature chain verifies, TCB ${report.tcb_status}`);
  if (!current) process.exit(1);
  if (!report.report_data.startsWith(inQuote)) throw new Error("verified report differs from the parsed quote");
  const approved: any[] = await view(env("OUTLAYER_REGISTER"), "get_approved_measurements", {});
  const known = approved.some((m) => m.mrtd === report.mr_td && m.rtmr0 === report.rtmr0
    && m.rtmr1 === report.rtmr1 && m.rtmr2 === report.rtmr2);
  console.log(`${known ? "ok  " : "FAIL"} worker build ${known ? "is" : "is not"} on OutLayer's on-chain approved list (${approved.length} builds)`);
  if (!known) process.exit(1);
}

/// Checks that a model really runs in a TEE, before its URL is compiled into the room. Needs no
/// account. A fresh nonce must come back inside quotes Intel signed, so a report cannot be replayed.
async function verifyModel(o: Record<string, any>) {
  const nonce = randomBytes(32).toString("hex");
  const base = o.url ?? "https://cloud-api.near.ai/v1";
  const params = new URLSearchParams({ model: o.model, signing_algo: "ecdsa", nonce });
  const report: any = await (await fetch(`${base}/attestation/report?${params}`)).json();
  const quoteChecks = (label: string, a: any) => {
    const file = join(tmpdir(), `darkroom-model-${nonce}.hex`);
    writeFileSync(file, a.intel_quote);
    const tool = spawnSync("tools/verify-quote/target/release/verify-quote", [file], { encoding: "utf8" });
    if (tool.status !== 0) throw new Error(`${label}: Intel check failed: ${tool.stderr.slice(-300)}`);
    const { tcb_status, report_data } = JSON.parse(tool.stdout);
    const bound = report_data.startsWith(a.signing_address.slice(2).toLowerCase()) && report_data.endsWith(nonce);
    if (!bound) throw new Error(`${label}: quote is not bound to this signer and nonce`);
    console.log(`ok   ${label}: Intel signature verifies, TCB ${tcb_status}, bound to our nonce`);
  };
  quoteChecks("gateway", report.gateway_attestation);
  const models: any[] = report.model_attestations ?? [];
  const inTee = models.filter((a) => a.intel_quote && a.nvidia_payload);
  if (inTee.length === 0 || inTee.length !== models.length) {
    console.log(`FAIL ${o.model} has no model quote: a third party serves it, so it would see the secret`);
    process.exit(1);
  }
  for (const a of inTee) {
    quoteChecks(`model ${a.model_name} ${a.signing_address}`, a);
    const gpu = await fetch("https://nras.attestation.nvidia.com/v3/attest/gpu", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: typeof a.nvidia_payload === "string" ? a.nvidia_payload : JSON.stringify(a.nvidia_payload),
    });
    // The service answers with signed claims. A 200 alone can carry a failed result.
    const claims = gpu.ok ? JSON.parse(atob((await gpu.json())[0][1].split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))) : {};
    const passed = claims["x-nvidia-overall-att-result"] === true;
    console.log(`${passed ? "ok  " : "FAIL"} NVIDIA attestation result: ${passed}`);
    if (!passed) process.exit(1);
  }
}

async function main() {
  const [group, verb] = process.argv.slice(2);
  const { values } = parseArgs({
    args: process.argv.slice(2),
    allowPositionals: true,
    options: Object.fromEntries(
      ["as", "buyer", "bond", "tx", "to", "model", "url", "title", "private-title", "target", "secret-file", "reserve", "max-rooms", "listing", "budget", "protects", "door", "tx", "wasm", "signer", "call"]
        .map((name) => [name, { type: "string" as const }])
        .concat([["private", { type: "boolean" as const }]] as any),
    ),
  });
  if (group === "seller" && verb === "list") return sellerList(values);
  if (group === "seller" && verb === "forfeit") return sellerForfeit(values);
  if (group === "seller" && verb === "paid") return sellerPaid(values);
  if (group === "buyer" && verb === "pay") return buyerPay(values);
  if (group === "buyer" && verb === "reclaim") return buyerReclaim(values);
  if (group === "buyer" && verb === "open") return buyerOpen(values);
  if (group === "buyer" && verb === "fetch") return buyerFetch(values);
  if (group === "buyer" && verb === "cancel") return buyerCancel(values);
  if (group === "buyer" && verb === "refund") return buyerRefund(values);
  if (group === "status") return printStatus(Number(values.listing), values.as!);
  if (group === "verify-model") return verifyModel(values);
  if (group === "verify" && values.call) return verifyCall(values);
  if (group === "verify") return verify(values);
  console.log(`usage:
  darkroom seller list --as <account> --title <public label> --secret-file <path> --reserve <usdc>
      [--private-title <claim only agents see>] [--target <only allowed buyer>] [--max-rooms <n>]
      [--private] [--bond <usdc, below the reserve>]   pay through Gloam: NEAR sees no price, payee or limit
  darkroom seller paid --listing <id> --buyer <account>
  darkroom buyer reclaim --as <account> --listing <id> --to <Tempo address>
  darkroom seller forfeit --as <account> --listing <id> --buyer <account>
  darkroom buyer pay --as <account> --listing <id> [--door chain]
  darkroom buyer open --as <account> --listing <id> --budget <usdc> [--protects <usdc at risk>] [--door chain]
  darkroom buyer fetch --as <account> --listing <id> [--door chain] [--tx <Tempo payment>]
  darkroom buyer cancel --as <account> --listing <id>
  darkroom buyer refund --as <account> --listing <id>
  darkroom status --as <account> --listing <id>
  darkroom verify --tx <hash> --signer <account> --wasm <path to room.wasm>
  darkroom verify --call <https call id>
  darkroom verify-model --model <id> [--url <api base>]`);
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
