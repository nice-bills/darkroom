// Private settlement through Gloam on Tempo testnet. Run with Node: snarkjs crashes under Bun.
//   pay <address> <price> <ct_ref> <account>  shields, cashes out, prints the payment's hash
//   balance <seed> <ct_ref>                   what a room's one-time address holds
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
  const up = (await G.relayStatus().catch(() => [])).some((n) => n.chainId === net.chainId && n.enabled && !n.lowBalance);
  if (up) {
    try {
      const hash = await G.relayIntent(intent);
      await wait(hash);
      log("sent through the Gloam relay");
      return hash;
    } catch (error) {
      log(`relay refused: ${error.message}`);
    }
  }
  const { exec } = intent;
  const receipt = await wait(await sender.writeContract({ address: net.pool, abi, functionName: exec.fn, args: exec.args }));
  return receipt.transactionHash;
}

/// Mirrors `payee_key` in enclave/core/src/gloam.rs.
const payeeKey = (seedHex, ctRef) => `0x${createHash("sha256")
  .update("darkroom-payee")
  .update(Buffer.from(seedHex, "hex"))
  .update(ctRef)
  .digest("hex")}`;

async function pay(payee, priceText, ctRef, account) {
  const price = BigInt(priceText);
  const notes = join(DIR, `notes-${ctRef}.json`);
  const saved = (name, note) => writeFileSync(join(DIR, `${name}-${ctRef}.json`), JSON.stringify(note), { mode: 0o600 });
  const payer = await funded(`${account}-${ctRef}`);
  // Resumable: a note that is only in memory is money lost if the next step fails.
  let note = existsSync(notes) ? JSON.parse(readFileSync(notes, "utf8")) : null;
  if (!note) {
    const shield = await G.buildShieldBoundIntent({
      chainId: net.chainId, poolAddress: net.pool, asset, amountWei: SHIELD_WEI, prover: await prover("shield"),
    });
    saved("shielded", { secret: shield.note.secret, commitment: shield.note.commitment });
    await wait(await payer.writeContract({ address: asset, abi: erc20, functionName: "approve", args: [net.pool, SHIELD_WEI] }));
    const shielded = await wait(await payer.writeContract({
      address: shield.exec.poolAddress,
      abi: parseAbi(["function shieldBound(address,uint256,bytes32,bytes)"]),
      functionName: shield.exec.fn,
      args: shield.exec.args,
    }));
    log(`shield tx ${shielded.transactionHash}`);
    // A cash out spends a whole note, so first split off exactly the price.
    const split = await G.buildPrivateSendIntent({
      secretHex: shield.note.secret, amountInWei: SHIELD_WEI, amountPayWei: price, asset,
      path: await pathFor(shield.note.commitment), prove: await prover("transfer"),
      poolAddress: net.pool, chainId: net.chainId,
    });
    note = { secret: split.paymentNote.secret, commitment: split.paymentNote.commitment };
    saved("notes", note);
    saved("change", split.changeNote);
    const hash = await submit(payer, { chainId: net.chainId, exec: { fn: "transfer", args: G.transferCallArgs(split) } }, G.POOL_TRANSFER_ABI);
    log(`split tx ${hash}`);
  }
  const cashOut = await G.buildUnshieldIntent({
    secretHex: note.secret, amountWei: price, asset, to: payee,
    path: await pathFor(note.commitment), prove: await prover("unshield"),
    poolAddress: net.pool, chainId: net.chainId,
  });
  const abi = parseAbi(["function unshield(bytes,bytes32,bytes32,address,address,uint256)"]);
  console.log(await submit(payer, cashOut, abi));
}

/// What a room's one-time address holds. Only the holder of the seed can spend it.
async function balance(seedHex, ctRef) {
  const { address } = privateKeyToAccount(payeeKey(seedHex, ctRef));
  const held = await client.readContract({ address: asset, abi: erc20, functionName: "balanceOf", args: [address] });
  console.log(`${address} holds ${held}`);
}

mkdirSync(DIR, { recursive: true, mode: 0o700 });
const [command, ...args] = process.argv.slice(2);
await ({ pay, balance })[command](...args);
process.exit(0);
