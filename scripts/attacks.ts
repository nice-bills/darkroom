#!/usr/bin/env bun
// Attacks the live deployment with real transactions and real worker calls. No model runs.
//   set -a; source .env; source .darkroom.env; set +a; bun scripts/attacks.ts <settle_signed tx>
// The tx must be a relayed public deal: its real signature is the material replayed here.
import { randomBytes } from "node:crypto";
import { call, rpc, view } from "../cli/near";

const contract = process.env.DARKROOM_CONTRACT!;
const token = process.env.DARKROOM_TOKEN!;
const root = process.env.NEAR_ACCOUNT_ID!;
const buyer = `buyer.${root}`;
const attacker = `seller.${root}`;
const [settleTx] = process.argv.slice(2);
const commitment = "ab".repeat(32);
const pubkey = "ab".repeat(32);
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
let failed = 0;

async function refused(label: string, wanted: string, attack: () => unknown) {
  await sleep(1200);
  try {
    await attack();
    console.log(`FAIL ${label}: it went through`);
    failed++;
  } catch (error: any) {
    const ok = String(error.message).includes(wanted);
    console.log(`${ok ? "ok  " : "FAIL"} ${label}: ${ok ? wanted : String(error.message).slice(-200)}`);
    if (!ok) failed++;
  }
}

async function room(input: object) {
  const response = await fetch(`${process.env.OUTLAYER_API}/call/${process.env.DARKROOM_PROJECT}`, {
    method: "POST",
    headers: { "X-Payment-Key": process.env.OUTLAYER_PAYMENT_KEY!, "Content-Type": "application/json" },
    body: JSON.stringify({ input, resource_limits: { max_instructions: 1_000_000_000, max_memory_mb: 128, max_execution_seconds: 30 } }),
  });
  const body: any = await response.json();
  if (body.status !== "completed") throw new Error(body.error ?? JSON.stringify(body));
  return body.output;
}

async function list(target: string | null, isPrivate: boolean) {
  const id = await view(contract, "listing_count", {});
  call(root, contract, "list", {
    profile: `attack-${randomBytes(3).toString("hex")}`, title: "Attack fixture", max_rooms: 3, commitment,
    target, private_settlement: isPrivate, bond: isPrivate ? "1000000" : "0",
  }, "0.01 NEAR");
  await sleep(1500);
  return id;
}

const fund = (from: string, msg: object, amount: string) =>
  call(from, token, "ft_transfer_call", { receiver_id: contract, amount, msg: JSON.stringify(msg) }, "1 yoctoNEAR");

const tx = await rpc("tx", { tx_hash: settleTx, sender_account_id: buyer, wait_until: "FINAL" });
const real = JSON.parse(atob(tx.transaction.actions[0].FunctionCall.args));
if (!real.deal) throw new Error("Pass the settle_signed tx of a deal");

const listing = await list(null, false);
fund(buyer, { listing_id: listing, buyer_pubkey: pubkey, protected_value: 50_000 }, "5000000");
await sleep(2500);
call(buyer, contract, "start_room", { listing_id: listing }, "0 NEAR");
const forged = { listing_id: listing, buyer, deal: true, price: 5_000_000, ct_ref: "r", ct_hash: "h" };

await refused("forged signature", "Bad signature", () => call(attacker, contract, "settle_signed", { ...forged, sig: "cd".repeat(64) }, "0 NEAR"));
await refused("real signature moved to another room", "Bad signature", () => call(attacker, contract, "settle_signed", { ...real, listing_id: listing, buyer }, "0 NEAR"));
await refused("real signature with a changed price", "Bad signature", () => call(attacker, contract, "settle_signed", { ...real, listing_id: listing, buyer, price: 1_000_000 }, "0 NEAR"));
await refused("replay on a settled room", "Room is not running", () => call(attacker, contract, "settle_signed", real, "0 NEAR"));
await refused("refund before a room is stale", "Room is not stale yet", () => call(attacker, contract, "refund_stale", { listing_id: listing, buyer }, "0 NEAR"));
await refused("reveal with no deal", "no ct_ref", () => room({ op: "reveal", listing_id: listing, buyer }));
await refused("second run of a settled room", "room is not running", () => room({ op: "negotiate", listing_id: real.listing_id, buyer: real.buyer }));
await refused("relayer lies about the cap", "unknown field", () => room({ op: "negotiate", listing_id: listing, buyer, cap: 999 }));

const targeted = await list(buyer, false);
const before = await view(token, "ft_balance_of", { account_id: attacker });
try {
  fund(attacker, { listing_id: targeted, buyer_pubkey: pubkey, protected_value: 1 }, "1000000");
} catch {
  // ft_transfer_call may fail outright or refund through its resolver. Both are checked below.
}
await sleep(3000);
const kept = (await view(contract, "get_room", { listing_id: targeted, buyer: attacker })) === null
  && (await view(token, "ft_balance_of", { account_id: attacker })) === before;
console.log(`${kept ? "ok  " : "FAIL"} a non-target buyer gets no room and keeps the funds`);
if (!kept) failed++;

const hidden = await list(null, true);
const sealed = "ef".repeat(96);
await refused("private room paying less than the bond", "no room", async () => {
  fund(buyer, { listing_id: hidden, buyer_pubkey: pubkey, protected_value: 0, sealed_mandate: sealed }, "2");
  await sleep(3000);
  if ((await view(contract, "get_room", { listing_id: hidden, buyer })) === null) throw new Error("no room, funds returned");
});
fund(buyer, { listing_id: hidden, buyer_pubkey: pubkey, protected_value: 0, sealed_mandate: sealed }, "1000000");
await sleep(2500);
await refused("terms before a deal", "no ct_ref", () => room({ op: "terms", listing_id: hidden, buyer }));
await refused("a huge profile to fill the contract", "Profile too long", () => call(attacker, contract, "list", {
  profile: "p".repeat(100), title: "t", max_rooms: 1, commitment, target: null, private_settlement: false, bond: "0",
}, "0.01 NEAR"));
await refused("a listing with no storage deposit", "Attach 0.01 NEAR", () => call(attacker, contract, "list", {
  profile: "p", title: "t", max_rooms: 1, commitment, target: null, private_settlement: false, bond: "0",
}, "0 NEAR"));
await refused("the chain door into a private room", "Private listings run through the relayer", () => call(attacker, contract, "open_room", { listing_id: hidden }, "0.1 NEAR"));
await refused("paid signature with no deal", "No bond to return", () => call(attacker, contract, "confirm_paid", { listing_id: hidden, buyer, sig: "cd".repeat(64) }, "0 NEAR"));
await refused("taking a bond with no deal", "No bond to take", () => call(attacker, contract, "forfeit", { listing_id: hidden, buyer }, "0 NEAR"));

console.log(failed ? `${failed} ATTACKS NOT REFUSED` : "ALL ATTACKS REFUSED");
process.exit(failed ? 1 : 0);
