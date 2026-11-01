// Private settlement through Gloam on Tempo testnet. Run with Node: snarkjs crashes under Bun.
//   keygen                                prints a receive key, tag and sweep key
//   pay <tag> <price> <ct_ref> <account>  shields, pays the tag, prints a sealed ticket
//   sweep <ticket> <key file> <ct_ref> <account>
import * as G from "@gloamtrade/sdk";
import { createHash, randomBytes } from "node:crypto";
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
const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const DIR = join(homedir(), ".darkroom");
/// Shielding is a public token transfer, so it is always the top bucket, never the price.
const SHIELD_WEI = 200_000_000n;
const CACHE = join(DIR, "circuits");
const client = createPublicClient({ chain: net.chain, transport: http(net.rpcUrl) });
const erc20 = parseAbi(["function approve(address,uint256) returns (bool)"]);
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
async function submit(sender, args) {
  const up = (await G.relayStatus().catch(() => [])).some((n) => n.chainId === net.chainId && n.enabled && !n.lowBalance);
  if (up) {
    try {
      const hash = await G.relayIntent({ chainId: net.chainId, exec: { fn: "transfer", args } });
      await wait(hash);
      log("sent through the Gloam relay");
      return hash;
    } catch (error) {
      log(`relay refused: ${error.message}`);
    }
  }
  const receipt = await wait(await sender.writeContract({ address: net.pool, abi: G.POOL_TRANSFER_ABI, functionName: "transfer", args }));
  return receipt.transactionHash;
}

async function keygen() {
  const key = await G.generateReceiveKey();
  const key_hex = Buffer.from(key.privateJwk.d, "base64url").toString("hex");
  console.log(JSON.stringify({ tag: key.tag, jwk: key.privateJwk, key_hex, sweep_hex: randomBytes(32).toString("hex") }));
}

async function pay(tag, priceText, ctRef, account) {
  const price = BigInt(priceText);
  const payer = await funded(account);
  const shield = await G.buildShieldBoundIntent({
    chainId: net.chainId, poolAddress: net.pool, asset, amountWei: SHIELD_WEI, prover: await prover("shield"),
  });
  await wait(await payer.writeContract({ address: asset, abi: erc20, functionName: "approve", args: [net.pool, SHIELD_WEI] }));
  const shielded = await wait(await payer.writeContract({
    address: shield.exec.poolAddress,
    abi: parseAbi(["function shieldBound(address,uint256,bytes32,bytes)"]),
    functionName: shield.exec.fn,
    args: shield.exec.args,
  }));
  log(`shield tx ${shielded.transactionHash}`);

  const send = await G.buildPrivateSendIntent({
    secretHex: shield.note.secret, amountInWei: SHIELD_WEI, amountPayWei: price, asset,
    path: await pathFor(shield.note.commitment), prove: await prover("transfer"),
    poolAddress: net.pool, chainId: net.chainId,
  });
  const sent = await submit(payer, G.transferCallArgs(send));
  log(`pay tx ${sent}`);
  // The rest of the shielded amount. Without this file those funds cannot be spent.
  writeFileSync(join(DIR, `change-${send.changeNote.commitment}.json`), JSON.stringify(send.changeNote), { mode: 0o600 });
  const note = G.encodeNotePackage({
    pool: net.pool, asset, amountWei: send.paymentNote.amountWei, secret: send.paymentNote.secret,
    commitment: send.paymentNote.commitment, note: ctRef, chainId: net.chainId,
  });
  console.log(await G.sealToReceiveTag(note, tag));
}

/// Mirrors `sweep_secret` in enclave/core/src/gloam.rs.
const sweepSecret = (sweepHex, nullifier, ctRef) => {
  const digest = createHash("sha256")
    .update("darkroom-sweep")
    .update(Buffer.from(sweepHex, "hex"))
    .update(Buffer.from(nullifier.toString(16).padStart(64, "0"), "hex"))
    .update(ctRef)
    .digest("hex");
  return BigInt(`0x${digest}`) % FIELD;
};

async function sweep(ticket, keyFile, ctRef, account) {
  const keys = JSON.parse(readFileSync(keyFile, "utf8"));
  const opened = G.decodeNotePackage(await G.openSealedTicket(ticket, { privateJwk: keys.jwk, tag: keys.tag }));
  const secretIn = G.hexToField(opened.secret);
  const nullifier = await G.noteNullifierPoseidon(secretIn, G.hexToField(opened.commitment));
  const secretPay = sweepSecret(keys.sweep_hex, nullifier, ctRef);
  const secretChange = sweepSecret(keys.sweep_hex, nullifier, `${ctRef}:change`);
  const amount = BigInt(opened.amountWei);
  const pay0 = await G.noteCommitmentPoseidon(secretPay, amount, asset);
  const change = await G.noteCommitmentPoseidon(secretChange, 0n, asset);
  const path = await pathFor(opened.commitment);
  const prove = await prover("transfer");
  const { proofBytes } = await prove({
    root: path.root.toString(), nullifier: nullifier.toString(),
    newCommitment0: pay0.toString(), newCommitment1: change.toString(),
    secretIn: secretIn.toString(), amountIn: amount.toString(), asset: BigInt(asset).toString(),
    pathElements: path.pathElements.map(String), pathIndices: path.pathIndices.map(String),
    secretPay: secretPay.toString(), amountPay: amount.toString(),
    secretChange: secretChange.toString(), amountChange: "0",
  });
  const word = (value) => `0x${value.toString(16).padStart(64, "0")}`;
  const sender = await funded(account);
  const swept = await submit(sender, [proofBytes, word(path.root), word(nullifier), [word(pay0), word(change)]]);
  console.log(`swept ${amount} into a note only this seller can spend, tx ${swept}`);
}

mkdirSync(DIR, { recursive: true, mode: 0o700 });
const [command, ...args] = process.argv.slice(2);
await ({ keygen, pay, sweep })[command](...args);
process.exit(0);
