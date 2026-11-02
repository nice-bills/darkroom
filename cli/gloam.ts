// Private settlement through Gloam on Tempo testnet. Run with Node: snarkjs crashes under Bun.
//   pay <address> <price> <ct_ref> <account>  shields, cashes out, prints the payment's hash
//   balance <seed> <ct_ref>                   what a room's one-time address holds
//   reclaim <ct_ref> <account> <address>      cashes out the rest of the shielded amount
import * as G from "@gloamtrade/sdk";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import os, { homedir } from "node:os";
import { join } from "node:path";
import { createPublicClient, createWalletClient, http, parseAbi } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

const cpus = os.cpus();
// snarkjs starts a prover per CPU the host reports, which a small container cannot hold in memory.
os.cpus = () => cpus.slice(0, 1);
const net = G.GLOAM_NETWORKS.tempo;
const asset = G.TEMPO_PATHUSD;
const DIR = join(homedir(), ".darkroom");
/// Shielding is a public token transfer, so it is always the top bucket, never the price.
const SHIELD_WEI = 200_000_000n;
const CACHE = join(DIR, "circuits");
const client = createPublicClient({ chain: net.chain, transport: http(net.rpcUrl) });
const erc20 = parseAbi(["function approve(address,uint256) returns (bool)", "function balanceOf(address) view returns (uint256)"]);
const UNSHIELD_ABI = parseAbi(["function unshield(bytes,bytes32,bytes32,address,address,uint256)"]);
const wait = (hash) => client.waitForTransactionReceipt({ hash });
const log = (text) => process.stderr.write(`${text}\n`);

/// A new address per deal, so two deals of one account do not link on Tempo.
function wallet(account) {
  const file = join(DIR, `tempo-${account}.key`);
  if (!existsSync(file)) writeFileSync(file, generatePrivateKey(), { mode: 0o600 });
  const signer = privateKeyToAccount(readFileSync(file, "utf8").trim());
  return createWalletClient({ account: signer, chain: net.chain, transport: http(net.rpcUrl) });
}

async function funded(account) {
  const payer = wallet(account);
  await client.request({ method: "tempo_fundAddress", params: [payer.account.address] });
  await new Promise((resolve) => setTimeout(resolve, 3000));
  return payer;
}

/// The SDK's artifact URLs do not load under Node, so they are fetched to files once.
async function prover(circuit) {
  mkdirSync(CACHE, { recursive: true });
  const urls = G.circuitArtifactUrls(circuit, net.chainId);
  const local = async (url) => {
    const file = join(CACHE, url.split("/").slice(-2).join("-"));
    if (!existsSync(file)) writeFileSync(file, Buffer.from(await (await fetch(url)).arrayBuffer()));
    return file;
  };
  return G.artifactProver({ wasm: await local(urls.wasm), zkey: await local(urls.zkey) });
}

async function pathFor(commitment) {
  const tree = await G.syncTree(client, { pool: net.pool, fromBlock: net.deployBlock });
  return tree.pathForCommitment(commitment);
}

/// Through Gloam's relay when it is up, so our address is not beside the payment. The proof binds
/// the transfer, so the relay can only send or refuse. If it refuses, we send it ourselves.
async function submit(sender, intent, abi) {
  const send = async () => {
    const up = (await G.relayStatus().catch(() => [])).some((n) => n.chainId === net.chainId && n.enabled && !n.lowBalance);
    if (up) {
      try {
        const hash = await G.relayIntent(intent);
        log("sent through the Gloam relay");
        return hash;
      } catch (error) {
        log(`relay refused: ${error.message}`);
      }
    }
    const { exec } = intent;
    return sender.writeContract({ address: net.pool, abi, functionName: exec.fn, args: exec.args });
  };
  const hash = await send();
  const receipt = await wait(hash);
  if (receipt.status !== "success") throw new Error(`transaction reverted: ${hash}`);
  return hash;
}

/// Mirrors `payee_key` in enclave/core/src/gloam.rs.
const payeeKey = (seedHex, ctRef) => `0x${createHash("sha256")
  .update("darkroom-payee")
  .update(Buffer.from(seedHex, "hex"))
  .update(ctRef)
  .digest("hex")}`;

const seen = (commitment) => client.readContract({ address: net.pool, abi: G.POOL_STATE_ABI, functionName: "commitmentSeen", args: [commitment] });
const spent = (nullifier) => client.readContract({ address: net.pool, abi: G.POOL_STATE_ABI, functionName: "isSpent", args: [nullifier] });
const bigints = (_key, value) => (typeof value === "bigint" ? { $big: value.toString() } : value);
const revive = (_key, value) => (value?.$big ? BigInt(value.$big) : value);

/// Every step is written down before its money moves, and each is checked against the chain on
/// a rerun, so a failure at any point resumes and never makes a second note over the first.
async function pay(payee, priceText, ctRef, account) {
  const price = BigInt(priceText);
  const file = join(DIR, `pay-${ctRef}.json`);
  const state = existsSync(file) ? JSON.parse(readFileSync(file, "utf8"), revive) : {};
  const save = () => writeFileSync(file, JSON.stringify(state, bigints), { mode: 0o600 });
  if (state.tx) return console.log(state.tx);
  const payer = await funded(`${account}-${ctRef}`);

  if (!state.shield) {
    const shield = await G.buildShieldBoundIntent({
      chainId: net.chainId, poolAddress: net.pool, asset, amountWei: SHIELD_WEI, prover: await prover("shield"),
    });
    state.shield = { note: shield.note, exec: shield.exec };
    save();
  }
  if (!(await seen(state.shield.note.commitment))) {
    await wait(await payer.writeContract({ address: asset, abi: erc20, functionName: "approve", args: [net.pool, SHIELD_WEI] }));
    const shielded = await wait(await payer.writeContract({
      address: state.shield.exec.poolAddress,
      abi: parseAbi(["function shieldBound(address,uint256,bytes32,bytes)"]),
      functionName: state.shield.exec.fn,
      args: state.shield.exec.args,
    }));
    if (shielded.status !== "success") throw new Error("shield reverted");
    log(`shield tx ${shielded.transactionHash}`);
  }

  // A cash out spends a whole note, so first split off exactly the price.
  if (!state.split) {
    const split = await G.buildPrivateSendIntent({
      secretHex: state.shield.note.secret, amountInWei: SHIELD_WEI, amountPayWei: price, asset,
      path: await pathFor(state.shield.note.commitment), prove: await prover("transfer"),
      poolAddress: net.pool, chainId: net.chainId,
    });
    state.split = { note: split.paymentNote, change: split.changeNote, args: G.transferCallArgs(split) };
    save();
  }
  if (!(await seen(state.split.note.commitment))) {
    log(`split tx ${await submit(payer, { chainId: net.chainId, exec: { fn: "transfer", args: state.split.args } }, G.POOL_TRANSFER_ABI)}`);
  }

  const nullifier = G.fieldToBytes32(await G.noteNullifierPoseidon(G.hexToField(state.split.note.secret), G.hexToField(state.split.note.commitment)));
  if (await spent(nullifier)) throw new Error(`The payment landed but its hash was lost. Find it on Tempo for ${payee}, then pass buyer fetch --tx`);
  const cashOut = await G.buildUnshieldIntent({
    secretHex: state.split.note.secret, amountWei: price, asset, to: payee,
    path: await pathFor(state.split.note.commitment), prove: await prover("unshield"),
    poolAddress: net.pool, chainId: net.chainId,
  });
  state.tx = await submit(payer, cashOut, UNSHIELD_ABI);
  save();
  console.log(state.tx);
}

/// Takes what is left of the shielded amount back out, to any address.
async function reclaim(ctRef, account, to) {
  const { split } = JSON.parse(readFileSync(join(DIR, `pay-${ctRef}.json`), "utf8"), revive);
  const amountWei = BigInt(split.change.amountWei);
  const intent = await G.buildUnshieldIntent({
    secretHex: split.change.secret, amountWei, asset, to,
    path: await pathFor(split.change.commitment), prove: await prover("unshield"),
    poolAddress: net.pool, chainId: net.chainId,
  });
  console.log(await submit(wallet(`${account}-${ctRef}`), intent, UNSHIELD_ABI));
}

/// What a room's one-time address holds. Only the holder of the seed can spend it.
async function balance(seedHex, ctRef) {
  const { address } = privateKeyToAccount(payeeKey(seedHex, ctRef));
  const held = await client.readContract({ address: asset, abi: erc20, functionName: "balanceOf", args: [address] });
  console.log(`${address} holds ${held}`);
}

mkdirSync(DIR, { recursive: true, mode: 0o700 });
const [command, ...args] = process.argv.slice(2);
await ({ pay, balance, reclaim })[command](...args);
process.exit(0);
