//! Runs the real room.wasm outside OutLayer. `near:storage` and `outlayer:encryption-keys` are
//! implemented here to the semantics of OutLayer's published WIT, with real ciphers.
//!   harness <room.wasm>   needs a build with DARKROOM_LLM_URL and DARKROOM_RPC_URL on
//!                         http://127.0.0.1:18099, and DARKROOM_CONTRACT=room.testnet
//! Wasmtime is pinned to the worker's major version on purpose: a newer one accepts things the
//! worker traps on, such as a 4,096-byte+ `blocking-write-and-flush`.
//! This proves the wasm links against those interfaces and works. It proves nothing about a TEE.
use anyhow::{bail, ensure, Context, Result};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use darkroom_core::{gloam, open_delivery, seal_to_buyer, secret_commitment, to_hex, verdict_message, Verdict, USDC};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::bindings::Command;
use wasmtime_wasi::pipe::{MemoryInputPipe, MemoryOutputPipe};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiView};
use wasmtime_wasi_http::{WasiHttpCtx, WasiHttpView};

/// What `max_instructions` allows in the contract.
const FUEL: u64 = 10_000_000_000;
const FINDING: &str = "Vault::on_withdraw has no #[private] guard. Full drain.";
const CONTRACT_SEAL_KEY: [u8; 32] = [7; 32];
const BUYER_SECRET: [u8; 32] = [9; 32];
const VERDICT_KEY: [u8; 32] = [5; 32];
const SALT: &str = "0102";
const CONTRACT: &str = "room.testnet";
const ASSET: &str = "0x20c0000000000000000000000000000000000000";

#[derive(Default)]
struct Chain {
    private: HashMap<String, Vec<u8>>,
    public: HashMap<String, Vec<u8>>,
    /// What the contract's views answer.
    room: Value,
    listing: Value,
    /// When set, the second RPC answers `get_room` with this instead.
    lying_room: Option<Value>,
    room_reads: u32,
    /// What Tempo answers for any transaction.
    receipt: Option<Value>,
    /// When set, every second receipt read answers this instead.
    lying_receipt: Option<Value>,
    receipt_reads: u32,
}

struct Guest {
    wasi: WasiCtx,
    http: WasiHttpCtx,
    table: ResourceTable,
}

impl WasiView for Guest {
    fn ctx(&mut self) -> &mut WasiCtx {
        &mut self.wasi
    }
    fn table(&mut self) -> &mut ResourceTable {
        &mut self.table
    }
}

impl WasiHttpView for Guest {
    fn ctx(&mut self) -> &mut WasiHttpCtx {
        &mut self.http
    }
    fn table(&mut self) -> &mut ResourceTable {
        &mut self.table
    }
}

fn hmac_of(data: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&CONTRACT_SEAL_KEY).unwrap();
    mac.update(b"mac");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Format 0x01 from encryption-keys.wit: marker, 24-byte nonce, ciphertext and tag.
fn wit_encrypt(plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; 24];
    getrandom::getrandom(&mut nonce).unwrap();
    let cipher = XChaCha20Poly1305::new((&CONTRACT_SEAL_KEY).into());
    let sealed = cipher.encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad }).unwrap();
    [&[1u8][..], &nonce, &sealed].concat()
}

fn wit_decrypt(ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let failed = || "decryption failed".to_string();
    if ciphertext.len() < 41 || ciphertext[0] != 1 {
        return Err(failed());
    }
    let cipher = XChaCha20Poly1305::new((&CONTRACT_SEAL_KEY).into());
    let payload = Payload { msg: &ciphertext[25..], aad };
    cipher.decrypt(XNonce::from_slice(&ciphertext[1..25]), payload).map_err(|_| failed())
}

fn checked_path(path: &str, vault: &Option<String>) -> Result<(), String> {
    if path == "sealed" && vault.is_none() { Ok(()) } else { Err(format!("undeclared key {path}")) }
}

fn link_outlayer(linker: &mut Linker<Guest>, chain: &Arc<Mutex<Chain>>) -> Result<()> {
    let mut keys = linker.instance("outlayer:encryption-keys/api@0.1.0")?;
    keys.func_wrap("encrypt", |_, (path, vault, plain, aad): (String, Option<String>, Vec<u8>, Vec<u8>)| {
        Ok((checked_path(&path, &vault).map(|()| wit_encrypt(&plain, &aad)),))
    })?;
    keys.func_wrap("decrypt", |_, (path, vault, ct, aad): (String, Option<String>, Vec<u8>, Vec<u8>)| {
        Ok((checked_path(&path, &vault).and_then(|()| wit_decrypt(&ct, &aad)),))
    })?;
    keys.func_wrap("mac", |_, (path, vault, data): (String, Option<String>, Vec<u8>)| {
        Ok((checked_path(&path, &vault).map(|()| hmac_of(&data)),))
    })?;

    let mut signing = linker.instance("outlayer:signing-keys/api@0.1.0")?;
    let key = ed25519_dalek::SigningKey::from_bytes(&VERDICT_KEY);
    let public = key.verifying_key().to_bytes().to_vec();
    signing.func_wrap("public-key", move |_, (path, _vault): (String, Option<String>)| {
        Ok((if path == "verdict" { Ok::<_, String>(public.clone()) } else { Err(format!("undeclared {path}")) },))
    })?;
    signing.func_wrap("sign", move |_, (path, _vault, message): (String, Option<String>, Vec<u8>)| {
        use ed25519_dalek::Signer;
        Ok((if path == "verdict" { Ok::<_, String>(key.sign(&message).to_bytes().to_vec()) } else { Err(format!("undeclared {path}")) },))
    })?;

    let mut storage = linker.instance("near:storage/api@0.2.0")?;
    let c = chain.clone();
    storage.func_wrap("set-if-absent-raw", move |_, (key, value): (String, Vec<u8>)| {
        let mut chain = c.lock().unwrap();
        let inserted = !chain.private.contains_key(&key);
        if inserted {
            chain.private.insert(key, value);
        }
        Ok(((inserted, String::new()),))
    })?;
    let c = chain.clone();
    storage.func_wrap("set-raw", move |_, (key, value): (String, Vec<u8>)| {
        c.lock().unwrap().private.insert(key, value);
        Ok((String::new(),))
    })?;
    let c = chain.clone();
    storage.func_wrap("get-raw", move |_, (key,): (String,)| {
        // An empty value means no record, as the WIT says.
        Ok(((c.lock().unwrap().private.get(&key).cloned().unwrap_or_default(), String::new()),))
    })?;
    let c = chain.clone();
    let shared = chain.clone();
    storage.func_wrap("get-worker", move |_, (key, _project): (String, Option<String>)| {
        Ok(((shared.lock().unwrap().private.get(&key).cloned().unwrap_or_default(), String::new()),))
    })?;
    storage.func_wrap("set-worker", move |_, (key, value, encrypted): (String, Vec<u8>, Option<bool>)| {
        let mut chain = c.lock().unwrap();
        if encrypted == Some(false) {
            chain.public.insert(key, value);
        } else {
            chain.private.insert(key, value);
        }
        Ok((String::new(),))
    })?;
    Ok(())
}

struct Room {
    engine: Engine,
    component: Component,
    linker: Linker<Guest>,
}

impl Room {
    fn new(wasm: &str, chain: &Arc<Mutex<Chain>>) -> Result<Self> {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.async_support(true);
        config.wasm_component_model(true);
        let engine = Engine::new(&config)?;
        let component = Component::from_file(&engine, wasm)?;
        let mut linker = Linker::new(&engine);
        wasmtime_wasi::add_to_linker_async(&mut linker)?;
        wasmtime_wasi_http::add_only_http_to_linker_async(&mut linker)?;
        link_outlayer(&mut linker, chain)?;
        Ok(Room { engine, component, linker })
    }

    /// Returns stdout and the instructions used, or the guest's failure.
    async fn run(&self, input: &Value, api_key: &str) -> Result<(String, u64)> {
        let stdout = MemoryOutputPipe::new(4096);
        let stderr = MemoryOutputPipe::new(4096);
        let wasi = WasiCtxBuilder::new()
            .stdin(MemoryInputPipe::new(input.to_string()))
            .stdout(stdout.clone())
            .stderr(stderr.clone())
            .env("DARKROOM_SECRET", std::env::var("HARNESS_SECRET").context("HARNESS_SECRET")?)
            .env("DARKROOM_RESERVE_USDC", "2")
            .env("DARKROOM_TITLE", "Critical drain in the decoy vault")
            .env("DARKROOM_PAYEE_SEED", "03".repeat(32))
            .env("DARKROOM_ROOM_KEY", "04".repeat(32))
            .env("DARKROOM_SALT", std::env::var("HARNESS_SALT").unwrap_or(SALT.to_string()))
            .env("LLM_API_KEY", api_key)
            .build();
        let guest = Guest { wasi, http: WasiHttpCtx::new(), table: ResourceTable::new() };
        let mut store = Store::new(&self.engine, guest);
        store.set_fuel(FUEL)?;
        store.fuel_async_yield_interval(Some(1_000_000))?;
        let command = Command::instantiate_async(&mut store, &self.component, &self.linker).await?;
        let outcome = command.wasi_cli_run().call_run(&mut store).await;
        let used = FUEL - store.get_fuel()?;
        let out = String::from_utf8(stdout.contents().to_vec())?;
        match outcome {
            Ok(Ok(())) => Ok((out, used)),
            Ok(Err(())) => bail!("guest failed: {}", String::from_utf8_lossy(&stderr.contents())),
            Err(trap) => bail!("trap: {trap:?}"),
        }
    }
}

/// One local server for both: RPC views from `chain`, and an OpenAI-shaped model from a script.
fn mock_services(chain: Arc<Mutex<Chain>>, replies: Arc<Mutex<VecDeque<String>>>) -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:18099")?;
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            loop {
                line.clear();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
            }
            let mut body = vec![];
            loop {
                line.clear();
                reader.read_line(&mut line).unwrap();
                let size = usize::from_str_radix(line.trim(), 16).unwrap_or(0);
                let mut chunk = vec![0u8; size + 2];
                reader.read_exact(&mut chunk).unwrap();
                if size == 0 {
                    break;
                }
                body.extend_from_slice(&chunk[..size]);
            }
            let request: Value = serde_json::from_slice(&body).unwrap();
            let answer = if request["method"] == "eth_getTransactionReceipt" {
                let mut chain = chain.lock().unwrap();
                chain.receipt_reads += 1;
                let lie = chain.lying_receipt.clone().filter(|_| chain.receipt_reads % 2 == 0);
                json!({ "result": lie.or(chain.receipt.clone()) }).to_string()
            } else if request["method"] == "query" {
                let mut chain = chain.lock().unwrap();
                let view = if request["params"]["method_name"] == "get_room" {
                    chain.room_reads += 1;
                    match &chain.lying_room {
                        Some(lie) if chain.room_reads % 2 == 0 => lie.clone(),
                        _ => chain.room.clone(),
                    }
                } else {
                    chain.listing.clone()
                };
                json!({ "result": { "result": view.to_string().into_bytes() } }).to_string()
            } else {
                let text = replies.lock().unwrap().pop_front().unwrap_or_default();
                json!({ "choices": [{ "message": { "content": text } }] }).to_string()
            };
            let head = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", answer.len());
            let mut stream = reader.into_inner();
            stream.write_all(head.as_bytes()).unwrap();
            stream.write_all(answer.as_bytes()).unwrap();
        }
    });
    Ok(())
}

fn buyer_pubkey() -> String {
    let secret = x25519_dalek::StaticSecret::from(BUYER_SECRET);
    to_hex(x25519_dalek::PublicKey::from(&secret).as_bytes())
}

fn check(label: &str, ok: bool) -> Result<()> {
    println!("{} {label}", if ok { "ok  " } else { "FAIL" });
    ensure!(ok, "{label}");
    Ok(())
}

fn negotiate_input(listing: u64) -> Value {
    json!({ "op": "negotiate", "listing_id": listing, "buyer": "buyer.testnet" })
}

fn reveal_input(listing: u64) -> Value {
    json!({ "op": "reveal", "listing_id": listing, "buyer": "buyer.testnet" })
}

/// Over 4,096 bytes, so every prompt to the model is too.
fn long_secret() -> String {
    format!("{FINDING}\n{}", "Reproduction detail line.\n".repeat(250))
}

async fn flow(wasm: &str) -> Result<()> {
    let secret = long_secret();
    std::env::set_var("HARNESS_SECRET", &secret);
    let salt: Vec<u8> = vec![1, 2];
    let chain = Arc::new(Mutex::new(Chain {
        room: json!({ "cap": (50 * USDC).to_string(), "protected_value": 50_000, "status": "Running", "buyer_pubkey": buyer_pubkey() }),
        listing: json!({ "title": "Security finding", "commitment": secret_commitment(&salt, &secret) }),
        ..Default::default()
    }));
    let replies = Arc::new(Mutex::new(VecDeque::new()));
    mock_services(chain.clone(), replies.clone())?;
    let room = Room::new(wasm, &chain)?;
    println!("ok   wasm linked against OutLayer's storage, encryption and signing interfaces");
    let key = "test-key";

    let (out, _) = room.run(&json!({ "op": "public_key" }), key).await?;
    let public = ed25519_dalek::SigningKey::from_bytes(&VERDICT_KEY).verifying_key();
    check("public_key op returns the signing key", out.contains(&to_hex(&public.to_bytes())))?;

    chain.lock().unwrap().room["status"] = json!("Funded");
    check("a room that is not Running is refused", room.run(&negotiate_input(0), key).await.is_err())?;
    chain.lock().unwrap().room["status"] = json!("Running");

    let good = chain.lock().unwrap().listing["commitment"].clone();
    chain.lock().unwrap().listing["commitment"] = json!("00");
    check("another listing's secret is refused", room.run(&negotiate_input(0), key).await.is_err())?;
    chain.lock().unwrap().listing["commitment"] = good;

    chain.lock().unwrap().room_reads = 0;
    chain.lock().unwrap().lying_room = Some(json!({ "status": "Funded" }));
    check("one lying RPC is refused", room.run(&negotiate_input(0), key).await.is_err())?;
    chain.lock().unwrap().lying_room = None;

    let fake = json!({ "op": "reveal", "listing_id": 0, "buyer": "buyer.testnet" });
    check("reveal before any deal is refused", room.run(&fake, key).await.is_err())?;
    check("nothing public yet", chain.lock().unwrap().public.is_empty())?;

    replies.lock().unwrap().extend([
        r#"{"ask":10,"accept_bid":false,"note":"n"}"#.to_string(),
        r#"{"accept":true,"bid":10,"note":"n"}"#.to_string(),
    ]);
    let (out, used) = room.run(&negotiate_input(0), key).await?;
    println!("     negotiate: {} chars, {used} instructions of {FUEL}", out.len());
    let verdict: Value = serde_json::from_str(&out)?;
    check("deal at 10 USDC", verdict["deal"] == true && verdict["price"] == 10 * USDC)?;
    check("stdout under 900 bytes", out.len() <= 900)?;
    check("stdout carries no secret", !out.contains("drain"))?;

    let text = |name: &str| verdict[name].as_str().unwrap().to_string();
    let plain = Verdict { deal: true, price: 10 * USDC, ct_ref: text("ct_ref"), ct_hash: text("ct_hash"), sig: String::new() };
    let message = verdict_message(CONTRACT, 0, "buyer.testnet", &plain);
    let sig: [u8; 64] = darkroom_core::from_hex(&text("sig")).map_err(|e| anyhow::anyhow!("{e}"))?.try_into().unwrap();
    let signature = ed25519_dalek::Signature::from_bytes(&sig);
    check("verdict signature verifies", public.verify_strict(message.as_bytes(), &signature).is_ok())?;

    replies.lock().unwrap().extend([r#"{"ask":10,"accept_bid":false,"note":"n"}"#.to_string()]);
    check("the room refuses to run twice", room.run(&negotiate_input(0), key).await.is_err())?;
    replies.lock().unwrap().clear();

    check("reveal is refused while Running", room.run(&reveal_input(0), key).await.is_err())?;
    chain.lock().unwrap().room["status"] = json!({ "Deal": { "price": "10000000", "ct_ref": text("ct_ref"), "ct_hash": "00" } });
    check("reveal refuses a hash that does not match", room.run(&reveal_input(0), key).await.is_err())?;
    chain.lock().unwrap().room["status"] = json!({ "Deal": { "price": "10000000", "ct_ref": "9-other", "ct_hash": text("ct_hash") } });
    check("reveal refuses another room's deal", room.run(&reveal_input(0), key).await.is_err())?;

    chain.lock().unwrap().room["status"] = json!({ "Deal": { "price": "10000000", "ct_ref": text("ct_ref"), "ct_hash": text("ct_hash") } });
    let (out, used) = room.run(&reveal_input(0), key).await?;
    println!("     reveal: {out} ({used} instructions)");
    let delivery = chain.lock().unwrap().public["reveal:0-buyer.testnet"].clone();
    check("buyer decrypts the exact secret", open_delivery(BUYER_SECRET, &delivery).context("open")? == secret.as_bytes())?;
    check("another key cannot open it", open_delivery([8; 32], &delivery).is_none())?;
    check("sealed record is not plaintext", chain.lock().unwrap().private.values().all(|v| !String::from_utf8_lossy(v).contains("drain")))?;

    let before = chain.lock().unwrap().private.len();
    chain.lock().unwrap().room["status"] = json!("Running");
    replies.lock().unwrap().extend(["not json".to_string(), "not json".to_string()]);
    let (out, _) = room.run(&negotiate_input(1), key).await?;
    let verdict: Value = serde_json::from_str(&out)?;
    check("garbage from an agent is a signed no deal", verdict["deal"] == false && !verdict["sig"].as_str().unwrap().is_empty())?;
    check("no deal stores only the run mark", chain.lock().unwrap().private.len() == before + 1)?;
    private_flow(&room, &chain, &replies, &secret, key).await
}

/// Private settlement on the real wasm, against a mock of Tempo's receipts.
async fn private_flow(room: &Room, chain: &Arc<Mutex<Chain>>, replies: &Arc<Mutex<VecDeque<String>>>, secret: &str, key: &str) -> Result<()> {
    let ct_ref = "7-buyer.testnet";
    {
        let mut chain = chain.lock().unwrap();
        chain.listing["private_settlement"] = json!(true);
        chain.listing["bond"] = json!("1000000");
        chain.room["status"] = json!("Running");
    }
    let (out, _) = room.run(&json!({ "op": "public_key" }), key).await?;
    let keys: Value = serde_json::from_str(&out)?;
    let room_key: [u8; 32] = hex::decode(keys["mandate_key"].as_str().unwrap())?.try_into().unwrap();
    let numbers = [(50 * USDC).to_le_bytes().as_slice(), &50_000u64.to_le_bytes(), &sha2::Sha256::digest(ct_ref.as_bytes())].concat();
    let sealed = seal_to_buyer([4; 32], &room_key, &numbers).map_err(|e| anyhow::anyhow!("{e}"))?;
    {
        let mut chain = chain.lock().unwrap();
        chain.room["mandate"] = json!(hex::encode(sealed));
        chain.room["cap"] = json!("1000000");
    }
    replies.lock().unwrap().extend([
        r#"{"ask":5,"accept_bid":false,"note":"n"}"#.to_string(),
        r#"{"accept":true,"bid":5,"note":"n"}"#.to_string(),
    ]);
    let (out, _) = room.run(&negotiate_input(7), key).await?;
    let verdict: Value = serde_json::from_str(&out)?;
    check("a private verdict shows no price", verdict["deal"] == true && verdict["price"] == 0)?;
    check("terms are refused before the chain records the deal", room.run(&json!({ "op": "terms", "listing_id": 7, "buyer": "buyer.testnet" }), key).await.is_err())?;

    chain.lock().unwrap().room["status"] = json!({ "Deal": { "price": "0", "ct_ref": verdict["ct_ref"], "ct_hash": verdict["ct_hash"] } });
    room.run(&json!({ "op": "terms", "listing_id": 7, "buyer": "buyer.testnet" }), key).await?;
    let sealed = chain.lock().unwrap().public["terms:7-buyer.testnet"].clone();
    let terms: Value = serde_json::from_slice(&open_delivery(BUYER_SECRET, &sealed).context("terms")?)?;
    let payee = gloam::payee_address(&[3; 32], ct_ref).map_err(|e| anyhow::anyhow!("{e}"))?;
    check("the buyer alone reads the price and address", terms["price"] == 5 * USDC && terms["pay_to"] == format!("0x{payee}"))?;

    let leaked = |chain: &Arc<Mutex<Chain>>| chain.lock().unwrap().public.contains_key("reveal:7-buyer.testnet");
    let tx = format!("0x{}", "11".repeat(32));
    let reveal = json!({ "op": "reveal", "listing_id": 7, "buyer": "buyer.testnet", "tx": tx });
    check("no payment, no reveal", room.run(&reveal_input(7), key).await.is_err() && !leaked(chain))?;

    let receipt = |to: &str, amount: u64| json!({ "status": "0x1", "logs": [{
        "address": ASSET,
        "topics": ["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", format!("0x{:0>64}", "ab"), format!("0x{to:0>64}")],
        "data": format!("0x{amount:064x}"),
    }] });
    chain.lock().unwrap().receipt = Some(receipt(&payee, 4 * USDC));
    check("an underpayment is refused", room.run(&reveal, key).await.is_err() && !leaked(chain))?;
    chain.lock().unwrap().receipt = Some(receipt("beef", 5 * USDC));
    check("a payment to another address is refused", room.run(&reveal, key).await.is_err() && !leaked(chain))?;
    chain.lock().unwrap().receipt = Some(receipt(&payee, 5 * USDC));
    chain.lock().unwrap().lying_receipt = Some(receipt("beef", 5 * USDC));
    check("one lying Tempo RPC is refused", room.run(&reveal, key).await.is_err() && !leaked(chain))?;
    chain.lock().unwrap().lying_receipt = None;

    let (out, _) = room.run(&reveal, key).await?;
    check("the room signs that it saw the payment", serde_json::from_str::<Value>(&out)?["paid_sig"].as_str().is_some_and(|s| s.len() == 128))?;
    let delivery = chain.lock().unwrap().public["reveal:7-buyer.testnet"].clone();
    check("a final payment releases the exact secret", open_delivery(BUYER_SECRET, &delivery).context("open")? == secret.as_bytes())?;
    Ok(())
}

/// The production wasm against the real chain and model, with every failure shown in full.
/// Secret and salt must match the listing's commitment.
async fn live(wasm: &str, listing: u64, buyer: &str) -> Result<()> {
    let chain = Arc::new(Mutex::new(Chain::default()));
    let room = Room::new(wasm, &chain)?;
    let key = std::env::var("LLM_API_KEY").context("LLM_API_KEY")?;
    let input = json!({ "op": "negotiate", "listing_id": listing, "buyer": buyer });
    match room.run(&input, &key).await {
        Ok((out, used)) => println!("{out}\n{used} instructions"),
        Err(error) => println!("FAILED: {error:?}"),
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let wasm = args.get(1).context("usage: harness <room.wasm> [--live <listing> <buyer>]")?;
    if args.get(2).map(String::as_str) == Some("--live") {
        return live(wasm, args[3].parse()?, &args[4]).await;
    }
    flow(wasm).await?;
    println!("HARNESS PASSED");
    Ok(())
}
