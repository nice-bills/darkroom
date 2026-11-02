//! The room's logic, free of WASI and OutLayer so that tests and the red-team bench run the
//! same code as the enclave. `enclave/room` supplies the real `Host`.
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

pub mod gloam;

const SETTLEMENT_LEN: usize = 32;
const AGENT_TRIES: usize = 3;
const MAX_ASK_OVER_BID: u64 = 4;
/// Padded length of sealed private terms, so a price with more digits seals to the same size.
pub const TERMS_LEN: usize = 256;

pub type Error = Box<dyn std::error::Error>;

const SELLER_PROMPT: &str = include_str!("../../../agents/seller.md");
const BUYER_PROMPT: &str = include_str!("../../../agents/buyer.md");
const RUBRIC: &str = include_str!("../../../agents/rubric.md");

pub const USDC: u64 = 1_000_000;
/// Every price is one of these, in whole USDC. Mirrored in the contract. This bounds the
/// covert channel to log2(8) bits in the price plus one bit for deal or no deal.
pub const PRICE_BUCKETS: [u64; 8] = [1, 2, 5, 10, 20, 50, 100, 200];
pub const MAX_ROUNDS: usize = 3;
/// A yield lasts about 200 blocks. Past this the run stops talking and ends as no deal.
pub const TIME_BUDGET_SECS: u64 = 70;
pub const MAX_OUTPUT_BYTES: usize = 900;
const MAX_NOTE_CHARS: usize = 200;
const BUYER_SEAL_INFO: &[u8] = b"darkroom-reveal-v1";

/// Everything the room needs from outside itself.
pub trait Host {
    fn llm(&mut self, system: &str, user: &str) -> Result<String, Error>;
    /// Seal under the key only this project, called by the contract, can derive.
    fn seal(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error>;
    fn open(&mut self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error>;
    /// Keyed hash, so storage keys do not reveal names to the operator.
    fn mac(&mut self, data: &[u8]) -> Result<Vec<u8>, Error>;
    fn store(&mut self, key: &str, value: &[u8]) -> Result<(), Error>;
    fn load(&mut self, key: &str) -> Result<Option<Vec<u8>>, Error>;
    /// World-readable storage. Only ever receives ciphertext sealed to the buyer.
    fn publish(&mut self, key: &str, value: &[u8]) -> Result<(), Error>;
    /// Sets the key only if it is unset. False means an earlier run got there first.
    fn claim(&mut self, key: &str) -> Result<bool, Error>;
    /// Signs with a key that exists only inside runs of this project for this caller.
    fn sign(&mut self, message: &[u8]) -> Result<Vec<u8>, Error>;
    fn public_key(&mut self) -> Result<Vec<u8>, Error>;
    /// A view call on the escrow contract at final block.
    fn view(&mut self, method: &str, args: Value) -> Result<Value, Error>;
    /// One Tempo transaction's receipt, from two independent sources.
    fn receipts(&mut self, tx: &str) -> Result<[Value; 2], Error>;
    /// The account that started this run, if any.
    fn caller(&mut self) -> Option<String>;
    fn random32(&mut self) -> Result<[u8; 32], Error>;
    fn elapsed_secs(&mut self) -> u64;
}

/// Names a room and nothing else. Whoever starts a run is untrusted: every fact about the room
/// comes from the contract, and a buyer has no text path to the agents (docs/redteam.md).
#[derive(Deserialize, Debug, PartialEq)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Input {
    Negotiate { listing_id: u64, buyer: String },
    /// `sealed_tx` is a private deal's Tempo payment, sealed to the room, so NEAR shows no link.
    Reveal {
        listing_id: u64,
        buyer: String,
        #[serde(default)]
        sealed_tx: Option<String>,
    },
    /// Releases a private deal's price, once the chain has recorded the deal.
    Terms { listing_id: u64, buyer: String },
    PublicKey {},
}

/// The only thing a negotiation lets out. No free text.
#[derive(Serialize, Debug, PartialEq)]
pub struct Verdict {
    pub deal: bool,
    pub price: u64,
    pub ct_ref: String,
    pub ct_hash: String,
    /// Ed25519 over `verdict_message`, so anyone can relay this to the contract.
    pub sig: String,
}

impl Verdict {
    pub fn no_deal() -> Self {
        Verdict { deal: false, price: 0, ct_ref: String::new(), ct_hash: String::new(), sig: String::new() }
    }
}

/// The largest bucket at or below `usdc`, in whole USDC.
pub fn bucket_floor(usdc: u64) -> Option<u64> {
    PRICE_BUCKETS.iter().rev().copied().find(|bucket| *bucket <= usdc)
}

fn bucket_list() -> String {
    PRICE_BUCKETS.map(|b| b.to_string()).join(", ")
}

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn from_hex(text: &str) -> Result<Vec<u8>, Error> {
    if text.len() % 2 != 0 || !text.is_ascii() {
        return Err("bad hex".into());
    }
    (0..text.len()).step_by(2).map(|i| Ok(u8::from_str_radix(&text[i..i + 2], 16)?)).collect()
}

fn sha256_hex(data: &[u8]) -> String {
    to_hex(&Sha256::digest(data))
}

fn cipher_for(shared: &[u8; 32]) -> ChaCha20Poly1305 {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, shared)
        .expand(BUYER_SEAL_INFO, &mut key)
        .expect("32 bytes is a valid length");
    ChaCha20Poly1305::new(Key::from_slice(&key))
}

/// ECIES to the buyer's X25519 key: `ephemeral_pub || ciphertext`. The key is fresh per seal,
/// so the zero nonce never repeats under one key.
pub fn seal_to_buyer(seed: [u8; 32], buyer_pubkey: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let ephemeral = StaticSecret::from(seed);
    let shared = ephemeral.diffie_hellman(&PublicKey::from(*buyer_pubkey));
    let ciphertext = cipher_for(shared.as_bytes())
        .encrypt(Nonce::from_slice(&[0u8; 12]), plaintext)
        .map_err(|_| "seal failed")?;
    Ok([PublicKey::from(&ephemeral).as_bytes().as_slice(), &ciphertext].concat())
}

/// The buyer's side of `seal_to_buyer`.
pub fn open_delivery(secret: [u8; 32], sealed: &[u8]) -> Option<Vec<u8>> {
    let ephemeral: [u8; 32] = sealed.get(..32)?.try_into().ok()?;
    let shared = StaticSecret::from(secret).diffie_hellman(&PublicKey::from(ephemeral));
    cipher_for(shared.as_bytes()).decrypt(Nonce::from_slice(&[0u8; 12]), &sealed[32..]).ok()
}

/// The agents reply in free text. Only these numbers and a bounded note survive parsing.
fn parse_reply(reply: &str) -> Option<Value> {
    let start = reply.find('{')?;
    let end = reply.rfind('}')?;
    serde_json::from_str(reply.get(start..=end)?).ok()
}

fn note_of(reply: &Value) -> String {
    let note = reply.get("note").and_then(Value::as_str).unwrap_or("");
    // One line, so a note cannot forge a transcript entry.
    note.chars().filter(|c| !c.is_control()).take(MAX_NOTE_CHARS).collect()
}

/// Models sometimes answer in prose. Retries keep a stray format from sinking a good room,
/// and adds no trust: whatever comes back still has to parse, and Rust still decides.
fn ask_agent(host: &mut dyn Host, system: &str, user: &str) -> Result<Option<Value>, Error> {
    // A model can answer with prose or an empty refusal. That must not cost a real finding its deal.
    let reminded = format!("{user}\nReply with only the JSON object your instructions describe.");
    for attempt in 0..AGENT_TRIES {
        let prompt = if attempt == 0 { user } else { &reminded };
        if let Some(reply) = parse_reply(&host.llm(system, prompt)?) {
            return Ok(Some(reply));
        }
    }
    Ok(None)
}

pub struct Deal<'a> {
    pub cap: u64,
    pub listing_id: u64,
    pub buyer: &'a str,
    pub title: &'a str,
    pub protected_value: u64,
    pub secret: &'a str,
    pub reserve_usdc: u64,
    /// The seed of a private deal's one-time payee. Zero otherwise. Sealed with the secret,
    /// because the seller could delete their row once paid and strand the buyer.
    pub settlement: [u8; SETTLEMENT_LEN],
}

/// Rust decides every outcome. An agent can only propose, so a hijacked agent still cannot
/// exceed the cap, undercut the reserve, or put anything but a bucket in the verdict.
pub fn negotiate(host: &mut dyn Host, deal: &Deal) -> Result<Verdict, Error> {
    let cap_usdc = deal.cap / USDC;
    let buckets = bucket_list();
    let seller_system = SELLER_PROMPT
        .replace("{reserve}", &deal.reserve_usdc.to_string())
        .replace("{buckets}", &buckets)
        .replace("{rounds}", &MAX_ROUNDS.to_string());
    let buyer_system = BUYER_PROMPT
        .replace("{cap}", &cap_usdc.to_string())
        .replace("{protected_value}", &deal.protected_value.to_string())
        .replace("{buckets}", &buckets)
        .replace("{rubric}", RUBRIC)
        .replace("{rounds}", &MAX_ROUNDS.to_string());
    // An unguessable fence: the data cannot close its own block to pose as instructions.
    let fence = format!("data-{}", to_hex(&host.random32()?));
    let context = format!(
        "LISTING (claimed by the seller): {}\n<{fence}>\n{}\n</{fence}>",
        deal.title, deal.secret
    );

    let acceptable = |usdc: u64| usdc >= deal.reserve_usdc && usdc <= cap_usdc;
    let mut transcript = String::new();
    let mut last_bid: Option<u64> = None;
    let mut last_ask: Option<u64> = None;
    let mut agreed = None;

    for round in 1..=MAX_ROUNDS {
        if host.elapsed_secs() >= TIME_BUDGET_SECS {
            break;
        }
        let user = format!("{context}\nTRANSCRIPT:\n{transcript}");
        let Some(reply) = ask_agent(host, &seller_system, &user)? else { break };
        if reply.get("accept_bid").and_then(Value::as_bool) == Some(true) {
            if let Some(bid) = last_bid.filter(|bid| acceptable(*bid)) {
                agreed = Some(bid);
                break;
            }
        }
        let Some(ask) = reply.get("ask").and_then(Value::as_u64).and_then(bucket_floor) else { break };
        last_ask = Some(ask);
        transcript += &format!("round {round} seller asks {ask} USDC: {}\n", note_of(&reply));

        if host.elapsed_secs() >= TIME_BUDGET_SECS {
            break;
        }
        let user = format!("{context}\nTRANSCRIPT:\n{transcript}");
        // A buyer's agent that stops answering has withdrawn: a refusal must not close a deal.
        let Some(reply) = ask_agent(host, &buyer_system, &user)? else {
            last_bid = None;
            break;
        };
        if reply.get("accept").and_then(Value::as_bool) == Some(true) && acceptable(ask) {
            agreed = Some(ask);
            break;
        }
        let bid = reply.get("bid").and_then(Value::as_u64).and_then(bucket_floor);
        last_bid = bid;
        let bid_text = bid.map_or("nothing".to_string(), |b| format!("{b} USDC"));
        transcript += &format!("round {round} buyer bids {bid_text}: {}\n", note_of(&reply));
    }

    // Without this, agents hold firm until the rounds run out and good data never sells. A zero
    // bid is not a bid, so data the buyer's agent rejects still ends in no deal. The ask counts
    // only up to a few times the bid: opening high must not kill a fair deal. The cap stays out
    // of this sum and only filters, so the price does not trace the sealed cap.
    if let (None, Some(ask), Some(bid)) = (agreed, last_ask, last_bid) {
        // One bucket apart at the reserve has no price between them, so the ask closes it.
        let adjacent = PRICE_BUCKETS.windows(2).any(|pair| pair == [bid, ask]);
        // A bid above the ask must not lift the price past what the seller asked.
        let bid = bid.min(ask);
        let midpoint = bucket_floor((ask.min(bid.saturating_mul(MAX_ASK_OVER_BID)) + bid) / 2).filter(|mid| acceptable(*mid));
        agreed = midpoint.or(Some(ask).filter(|ask| adjacent && acceptable(*ask)));
    }

    let Some(usdc) = agreed else { return Ok(Verdict::no_deal()) };
    // Sealed to this project, not the buyer. The buyer must not be able to open anything until
    // the contract records the deal. Kept apart from the seller's secret row, which the seller
    // could delete after being paid.
    let ct_ref = format!("{}-{}", deal.listing_id, deal.buyer);
    let record = [(usdc * USDC).to_le_bytes().as_slice(), &deal.settlement, deal.secret.as_bytes()].concat();
    let sealed = host.seal(&record, ct_ref.as_bytes())?;
    let key = to_hex(&host.mac(ct_ref.as_bytes())?);
    host.store(&key, &sealed)?;
    Ok(Verdict { deal: true, price: usdc * USDC, ct_hash: sha256_hex(&sealed), ct_ref, sig: String::new() })
}

/// No chain check here: the manifest admits only the contract, which calls this after a deal.
/// Price, payee seed and secret, from the copy the chain's deal commits to.
fn open_record(host: &mut dyn Host, ct_ref: &str, ct_hash: &str) -> Result<(u64, Vec<u8>, Vec<u8>), Error> {
    let key = to_hex(&host.mac(ct_ref.as_bytes())?);
    let sealed = host.load(&key)?.ok_or("nothing sealed")?;
    if sha256_hex(&sealed) != ct_hash {
        return Err("sealed copy does not match the deal".into());
    }
    let record = host.open(&sealed, ct_ref.as_bytes())?;
    let (price, rest) = record.split_at_checked(8).ok_or("sealed record is short")?;
    let (settlement, secret) = rest.split_at_checked(SETTLEMENT_LEN).ok_or("sealed record is short")?;
    Ok((u64::from_le_bytes(price.try_into()?), settlement.to_vec(), secret.to_vec()))
}

type PaymentCheck<'a> = &'a dyn Fn(&mut dyn Host, u64, &[u8]) -> Result<(), Error>;

pub fn reveal(
    host: &mut dyn Host,
    ct_ref: &str,
    ct_hash: &str,
    buyer_pubkey: &str,
    payment: Option<PaymentCheck>,
) -> Result<Value, Error> {
    let buyer_key: [u8; 32] = from_hex(buyer_pubkey)?.try_into().map_err(|_| "bad buyer key")?;
    let (price, settlement, secret) = open_record(host, ct_ref, ct_hash)?;
    if let Some(check) = payment {
        check(host, price, &settlement)?;
    }
    let seed = host.random32()?;
    host.publish(&format!("reveal:{ct_ref}"), &seal_to_buyer(seed, &buyer_key, &secret)?)?;
    Ok(json!({ "revealed": true }))
}

/// Anthropic's Messages API or an OpenAI-compatible one, chosen by the compiled-in URL.
fn is_anthropic(url: &str) -> bool {
    url.starts_with("https://api.anthropic.com/")
}

pub fn llm_body(url: &str, model: &str, system: &str, user: &str) -> Value {
    if is_anthropic(url) {
        json!({
            "model": model,
            "max_tokens": 300,
            "thinking": { "type": "disabled" },
            "system": system,
            "messages": [{ "role": "user", "content": user }],
        })
    } else {
        json!({
            "model": model,
            "max_tokens": 600,
            "messages": [{ "role": "system", "content": system }, { "role": "user", "content": user }],
        })
    }
}

/// Header name and value carrying the key, plus any extra header.
pub fn llm_auth(url: &str, key: &str) -> Vec<(&'static str, String)> {
    if is_anthropic(url) {
        vec![("x-api-key", key.to_string()), ("anthropic-version", "2023-06-01".to_string())]
    } else {
        vec![("Authorization", format!("Bearer {key}"))]
    }
}

/// `None` covers a refusal, which parses as no move and so ends in no deal.
pub fn llm_text(url: &str, parsed: &Value) -> Option<String> {
    if is_anthropic(url) {
        let blocks = parsed["content"].as_array()?;
        blocks.iter().find(|b| b["type"] == "text")?["text"].as_str().map(str::to_string)
    } else {
        parsed["choices"][0]["message"]["content"].as_str().map(str::to_string)
    }
}

/// Exactly what the contract rebuilds and checks. Names the contract and the room, so a
/// signature cannot be replayed on another room or deployment.
pub fn verdict_message(contract: &str, listing_id: u64, buyer: &str, v: &Verdict) -> String {
    format!("darkroom-v1|{contract}|{listing_id}|{buyer}|{}|{}|{}|{}", v.deal, v.price, v.ct_ref, v.ct_hash)
}

/// What a listing publishes, so a run cannot pair one listing's price with another's secret.
pub fn secret_commitment(salt: &[u8], secret: &str) -> String {
    sha256_hex(&[salt, secret.as_bytes()].concat())
}

pub fn rpc_request(contract: &str, method: &str, args: &Value) -> Value {
    let encoded = base64::engine::general_purpose::STANDARD.encode(args.to_string());
    json!({
        "jsonrpc": "2.0", "id": "room", "method": "query",
        "params": {
            "request_type": "call_function", "finality": "final", "account_id": contract,
            "method_name": method, "args_base64": encoded,
        },
    })
}

/// Two independent readings of the chain must agree, so one lying RPC cannot fake a deal.
pub fn agreed(first: Value, second: Value) -> Result<Value, Error> {
    if first != second {
        return Err("rpc endpoints disagree".into());
    }
    Ok(first)
}

pub fn rpc_value(reply: &Value) -> Result<Value, Error> {
    let bytes = reply["result"]["result"].as_array().ok_or("rpc reply has no result")?;
    let bytes: Option<Vec<u8>> = bytes.iter().map(|b| b.as_u64().map(|b| b as u8)).collect();
    Ok(serde_json::from_slice(&bytes.ok_or("rpc result is not bytes")?)?)
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a str, Error> {
    value[name].as_str().ok_or_else(|| format!("chain data has no {name}").into())
}

fn negotiate_room(host: &mut dyn Host, contract: &str, listing_id: u64, buyer: &str, env: &dyn Fn(&str) -> Result<String, Error>) -> Result<Verdict, Error> {
    let room = host.view("get_room", json!({ "listing_id": listing_id, "buyer": buyer }))?;
    if room["status"] != "Running" {
        return Err("room is not running".into());
    }
    let listing = host.view("get_listing", json!({ "listing_id": listing_id }))?;
    let secret = env("DARKROOM_SECRET")?;
    let commitment = secret_commitment(&from_hex(&env("DARKROOM_SALT")?)?, &secret);
    if commitment != field(&listing, "commitment")? {
        return Err("secret does not match the listing".into());
    }
    // Only the door the contract recorded may run this room, so a second door gets no second run.
    let by_contract = host.caller().as_deref() == Some(contract);
    if by_contract != (room["door"] == "chain") {
        return Err("this room runs through its other door".into());
    }
    let private = listing["private_settlement"] == true;
    let reserve_usdc: u64 = env("DARKROOM_RESERVE_USDC")?.parse()?;
    // A bond above the price would pay a seller to stall.
    if private && field(&listing, "bond")?.parse::<u64>()? >= reserve_usdc * USDC {
        return Err("bond must stay below the reserve".into());
    }
    // Spent before any model runs: a second run could read a second price, which is more
    // covert-channel bits. A run that dies here ends in a timeout refund, not a retry.
    let ct_ref = format!("{listing_id}-{buyer}");
    // Salted by the commitment: listing numbers restart if the contract is ever redeployed.
    let mark = to_hex(&host.mac(format!("ran:{commitment}:{ct_ref}").as_bytes())?);
    if !host.claim(&mark)? {
        return Err("room already ran".into());
    }
    // The real claim comes from the encrypted row. The public title says nothing useful.
    let title = env("DARKROOM_TITLE")?;
    let mut settlement = [0u8; SETTLEMENT_LEN];
    let mut cap: u64 = field(&room, "cap")?.parse()?;
    let mut protected_value = room["protected_value"].as_u64().ok_or("room has no protected_value")?;
    if private {
        (cap, protected_value) = open_mandate(host, field(&room, "mandate")?, &ct_ref)?;
        settlement = from_hex(&env("DARKROOM_PAYEE_SEED")?)?.try_into().map_err(|_| "bad payee seed")?;
    }
    let deal = Deal {
        cap,
        listing_id,
        buyer,
        title: &title,
        protected_value,
        secret: &secret,
        reserve_usdc,
        settlement,
    };
    let mut verdict = negotiate(host, &deal)?;
    // The price stays in the room until the chain records the deal. A verdict is seen by whoever
    // relays it, and a relayer who liked the price could otherwise let the room go stale.
    if verdict.deal && private {
        verdict.price = 0;
    }
    verdict.sig = to_hex(&host.sign(verdict_message(contract, listing_id, buyer, &verdict).as_bytes())?);
    Ok(verdict)
}

/// The buyer's limit and value at risk, sealed so the chain sees neither. Numbers only, as with
/// `protected_value`: free text here would reach both agents. Names the room, so a sealed limit
/// copied into another room does not open.
fn open_mandate(host: &mut dyn Host, sealed: &str, ct_ref: &str) -> Result<(u64, u64), Error> {
    let plain = open_delivery(mandate_secret(host)?, &from_hex(sealed)?).ok_or("mandate was not sealed to this room")?;
    let plain: [u8; 48] = plain.try_into().map_err(|_| "bad mandate")?;
    if plain[16..] != Sha256::digest(ct_ref.as_bytes())[..] {
        return Err("mandate is for another room".into());
    }
    let cap = u64::from_le_bytes(plain[..8].try_into()?);
    let protected_value = u64::from_le_bytes(plain[8..16].try_into()?);
    Ok((cap, protected_value))
}

/// Stable across runs, and exists only inside them.
fn mandate_secret(host: &mut dyn Host) -> Result<[u8; 32], Error> {
    Ok(Sha256::digest(host.mac(b"darkroom-mandate-key")?).into())
}

/// The room's public key for mandates, signed so a relayer cannot swap in its own.
fn public_keys(host: &mut dyn Host, contract: &str) -> Result<Value, Error> {
    let mandate_key = to_hex(PublicKey::from(&StaticSecret::from(mandate_secret(host)?)).as_bytes());
    let signed = format!("darkroom-mandate-v1|{contract}|{mandate_key}");
    let keys = json!({
        "public_key": to_hex(&host.public_key()?),
        "mandate_key": mandate_key,
        "mandate_sig": to_hex(&host.sign(signed.as_bytes())?),
    });
    // Published, so a buyer who has no relayer can still read it.
    host.publish("room-keys", keys.to_string().as_bytes())?;
    Ok(keys)
}

fn reveal_room(
    host: &mut dyn Host,
    contract: &str,
    vault: &gloam::Vault,
    listing_id: u64,
    buyer: &str,
    sealed_tx: Option<&str>,
) -> Result<Value, Error> {
    let room = host.view("get_room", json!({ "listing_id": listing_id, "buyer": buyer }))?;
    let deal = &room["status"]["Deal"];
    let ct_ref = field(deal, "ct_ref")?;
    if ct_ref != format!("{listing_id}-{buyer}") {
        return Err("deal is for another room".into());
    }
    let listing = host.view("get_listing", json!({ "listing_id": listing_id }))?;
    let ct_hash = field(deal, "ct_hash")?;
    let buyer_key = field(&room, "buyer_pubkey")?;
    if listing["private_settlement"] != true {
        return reveal(host, ct_ref, ct_hash, buyer_key, None);
    }
    let sealed_tx = sealed_tx.ok_or("private deal needs its Tempo payment")?;
    let tx = open_delivery(mandate_secret(host)?, &from_hex(sealed_tx)?).ok_or("payment was not sealed to this room")?;
    let tx = std::str::from_utf8(&tx)?;
    let check = |host: &mut dyn Host, price: u64, seed: &[u8]| {
        gloam::check_payment(host, vault, seed, tx, ct_ref, price)
    };
    let mut out = reveal(host, ct_ref, ct_hash, buyer_key, Some(&check))?;
    // Returns the buyer's bond: only a run that saw the payment can sign this.
    let paid = format!("darkroom-paid-v1|{contract}|{listing_id}|{buyer}");
    out["paid_sig"] = json!(to_hex(&host.sign(paid.as_bytes())?));
    Ok(out)
}

/// Seals a recorded private deal's price and one-time address to the buyer, at a fixed size.
fn release_terms(host: &mut dyn Host, listing_id: u64, buyer: &str) -> Result<Value, Error> {
    let room = host.view("get_room", json!({ "listing_id": listing_id, "buyer": buyer }))?;
    let deal = &room["status"]["Deal"];
    let ct_ref = field(deal, "ct_ref")?;
    if ct_ref != format!("{listing_id}-{buyer}") {
        return Err("deal is for another room".into());
    }
    let buyer_key: [u8; 32] = from_hex(field(&room, "buyer_pubkey")?)?.try_into().map_err(|_| "bad buyer key")?;
    let (price, seed, _) = open_record(host, ct_ref, field(deal, "ct_hash")?)?;
    let terms = json!({ "price": price, "pay_to": format!("0x{}", gloam::payee_address(&seed, ct_ref)?) }).to_string();
    let terms = format!("{terms:<TERMS_LEN$}");
    let sealed = seal_to_buyer(host.random32()?, &buyer_key, terms.as_bytes())?;
    host.publish(&format!("terms:{ct_ref}"), &sealed)?;
    Ok(json!({ "released": true }))
}

/// Seals under the room key. Keystore keys differ per caller, and a deal must open from either
/// door, or a relayer who disappears strands a paid buyer.
pub fn room_seal(key: &[u8; 32], nonce: [u8; 12], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    let sealed = cipher_for(key).encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad }).map_err(|_| "seal failed")?;
    Ok([nonce.as_slice(), &sealed].concat())
}

pub fn room_open(key: &[u8; 32], sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    let (nonce, cipher) = sealed.split_at_checked(12).ok_or("sealed record is short")?;
    Ok(cipher_for(key).decrypt(Nonce::from_slice(nonce), Payload { msg: cipher, aad }).map_err(|_| "open failed")?)
}

pub fn room_mac(key: &[u8; 32], data: &[u8]) -> Vec<u8> {
    Sha256::new().chain_update(key).chain_update(data).finalize().to_vec()
}

/// One run: stdin JSON to stdout JSON. The secret, salt and reserve come from the environment.
pub fn run(
    host: &mut dyn Host,
    contract: &str,
    vault: &gloam::Vault,
    raw: &str,
    env: impl Fn(&str) -> Result<String, Error>,
) -> Result<String, Error> {
    let output = match serde_json::from_str(raw)? {
        Input::Negotiate { listing_id, buyer } => {
            serde_json::to_string(&negotiate_room(host, contract, listing_id, &buyer, &env)?)?
        }
        Input::Reveal { listing_id, buyer, sealed_tx } => reveal_room(host, contract, vault, listing_id, &buyer, sealed_tx.as_deref())?.to_string(),
        Input::Terms { listing_id, buyer } => release_terms(host, listing_id, &buyer)?.to_string(),
        Input::PublicKey {} => public_keys(host, contract)?.to_string(),
    };
    assert!(output.len() <= MAX_OUTPUT_BYTES);
    Ok(output)
}

/// An in-memory `Host`. Tests and the mock red-team mode script the agents through `replies`.
pub mod fake {
    use super::*;
    use std::collections::{HashMap, VecDeque};

    #[derive(Default)]
    pub struct FakeHost {
        pub replies: VecDeque<String>,
        pub prompts: Vec<String>,
        pub private: HashMap<String, Vec<u8>>,
        pub public: HashMap<String, Vec<u8>>,
        pub clock: u64,
        pub tick: u64,
        pub counter: u8,
        pub claimed: Vec<String>,
        /// Contract view results, keyed by method.
        pub chain: HashMap<String, Value>,
        /// What the two Tempo sources answer.
        pub receipt_pair: Option<[Value; 2]>,
        /// Who started the run. The default is a relayer.
        pub run_caller: Option<String>,
    }

    impl FakeHost {
        pub fn scripted(replies: &[&str]) -> Self {
            FakeHost { replies: replies.iter().map(|r| r.to_string()).collect(), ..Default::default() }
        }
    }

    impl Host for FakeHost {
        fn llm(&mut self, _system: &str, user: &str) -> Result<String, Error> {
            self.prompts.push(user.to_string());
            self.clock += self.tick;
            // As a model that has stopped answering: empty text, not a failed run.
            Ok(self.replies.pop_front().unwrap_or_default())
        }
        fn seal(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
            Ok([aad, b"|", plaintext].concat().iter().map(|b| b ^ 0x5a).collect())
        }
        fn open(&mut self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
            let plain: Vec<u8> = ciphertext.iter().map(|b| b ^ 0x5a).collect();
            let prefix = [aad, b"|"].concat();
            plain.strip_prefix(prefix.as_slice()).map(<[u8]>::to_vec).ok_or_else(|| "decryption failed".into())
        }
        fn mac(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
            Ok(Sha256::digest(data).to_vec())
        }
        fn store(&mut self, key: &str, value: &[u8]) -> Result<(), Error> {
            self.private.insert(key.to_string(), value.to_vec());
            Ok(())
        }
        fn load(&mut self, key: &str) -> Result<Option<Vec<u8>>, Error> {
            Ok(self.private.get(key).cloned())
        }
        fn publish(&mut self, key: &str, value: &[u8]) -> Result<(), Error> {
            self.public.insert(key.to_string(), value.to_vec());
            Ok(())
        }
        fn claim(&mut self, key: &str) -> Result<bool, Error> {
            if self.claimed.iter().any(|k| k == key) {
                return Ok(false);
            }
            self.claimed.push(key.to_string());
            Ok(true)
        }
        fn sign(&mut self, message: &[u8]) -> Result<Vec<u8>, Error> {
            Ok(Sha256::digest(message).to_vec())
        }
        fn public_key(&mut self) -> Result<Vec<u8>, Error> {
            Ok(vec![7; 32])
        }
        fn view(&mut self, method: &str, _args: Value) -> Result<Value, Error> {
            self.chain.get(method).cloned().ok_or_else(|| format!("no view {method}").into())
        }
        fn receipts(&mut self, _tx: &str) -> Result<[Value; 2], Error> {
            self.receipt_pair.clone().ok_or_else(|| "no receipt".into())
        }
        fn caller(&mut self) -> Option<String> {
            self.run_caller.clone()
        }
        fn random32(&mut self) -> Result<[u8; 32], Error> {
            self.counter += 1;
            Ok([self.counter; 32])
        }
        fn elapsed_secs(&mut self) -> u64 {
            self.clock
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakeHost;
    use super::*;

    const SECRET: &str = "call drain() twice";

    fn deal(cap_usdc: u64, reserve_usdc: u64) -> Deal<'static> {
        Deal {
            cap: cap_usdc * USDC,
            listing_id: 3,
            buyer: "buyer.testnet",
            title: "exploit for vault",
            protected_value: 50_000,
            secret: SECRET,
            reserve_usdc,
            settlement: [0; SETTLEMENT_LEN],
        }
    }

    fn seller(ask: u64, accept_bid: bool) -> String {
        format!(r#"{{"ask":{ask},"accept_bid":{accept_bid},"note":"n"}}"#)
    }

    fn buyer(accept: bool, bid: u64) -> String {
        format!(r#"{{"accept":{accept},"bid":{bid},"note":"n"}}"#)
    }

    fn talk(replies: &[String], d: &Deal) -> (FakeHost, Verdict) {
        let mut host = FakeHost::scripted(&replies.iter().map(String::as_str).collect::<Vec<_>>());
        let verdict = negotiate(&mut host, d).unwrap();
        (host, verdict)
    }

    #[test]
    fn buyer_accepts_ask() {
        let (_, v) = talk(&[seller(10, false), buyer(true, 10)], &deal(20, 5));
        assert!(v.deal);
        assert_eq!(v.price, 10 * USDC);
        assert_eq!(v.ct_ref, "3-buyer.testnet");
    }

    #[test]
    fn seller_accepts_bid_in_a_later_round() {
        let (_, v) = talk(&[seller(50, false), buyer(false, 10), seller(20, true)], &deal(20, 5));
        assert_eq!(v.price, 10 * USDC);
    }

    #[test]
    fn hijacked_agents_cannot_beat_cap_or_reserve() {
        let (_, over_cap) = talk(&[seller(100, false), buyer(true, 100), seller(100, false), buyer(true, 100), seller(100, false), buyer(true, 100)], &deal(20, 5));
        assert!(!over_cap.deal);
        let (_, under_reserve) = talk(&[seller(1, false), buyer(true, 1), seller(1, false), buyer(true, 1), seller(1, false), buyer(true, 1)], &deal(20, 5));
        assert!(!under_reserve.deal);
    }

    /// A buyer seals a limit of 50 USDC to the room's published key.
    fn make_private(host: &mut FakeHost) {
        let keys = public_keys(host, CONTRACT).unwrap();
        let key: [u8; 32] = from_hex(keys["mandate_key"].as_str().unwrap()).unwrap().try_into().unwrap();
        let ct_ref = format!("{}-buyer.testnet", 3);
        let numbers = [(50 * USDC).to_le_bytes().as_slice(), &50_000u64.to_le_bytes(), &Sha256::digest(ct_ref.as_bytes())].concat();
        let room = host.chain.get_mut("get_room").unwrap();
        room["mandate"] = json!(to_hex(&seal_to_buyer([4u8; 32], &key, &numbers).unwrap()));
        room["cap"] = json!("1000000");
        room["protected_value"] = json!(0);
        let listing = host.chain.get_mut("get_listing").unwrap();
        listing["private_settlement"] = json!(true);
        listing["bond"] = json!("1000000");
    }

    #[test]
    fn a_sealed_record_opens_only_under_its_name() {
        let sealed = room_seal(&[1; 32], [2; 12], b"secret", b"7-a").unwrap();
        assert_eq!(room_open(&[1; 32], &sealed, b"7-a").unwrap(), b"secret");
        assert!(room_open(&[1; 32], &sealed, b"8-a").is_err());
        assert!(room_open(&[3; 32], &sealed, b"7-a").is_err());
    }

    #[test]
    fn a_bond_at_the_reserve_is_refused() {
        let mut host = live_room(&script_deal());
        make_private(&mut host);
        host.chain.get_mut("get_listing").unwrap()["bond"] = json!((100 * USDC).to_string());
        let error = run(&mut host, CONTRACT, &VAULT, NEGOTIATE, env).unwrap_err().to_string();
        assert_eq!(error, "bond must stay below the reserve");
    }

    #[test]
    fn a_mandate_sealed_to_another_key_is_refused() {
        let mut host = live_room(&script_deal());
        make_private(&mut host);
        let sealed = seal_to_buyer([4u8; 32], &[8u8; 32], &[0u8; 48]).unwrap();
        host.chain.get_mut("get_room").unwrap()["mandate"] = json!(to_hex(&sealed));
        let error = run(&mut host, CONTRACT, &VAULT, NEGOTIATE, env).unwrap_err().to_string();
        assert_eq!(error, "mandate was not sealed to this room");
    }

    #[test]
    fn talks_one_bucket_apart_close_at_the_ask() {
        let (_, v) = talk(&[seller(2, false), buyer(false, 1), seller(2, false), buyer(false, 1), seller(2, false), buyer(false, 1)], &deal(50, 2));
        assert_eq!(v.price, 2 * USDC);
    }

    #[test]
    fn an_opening_ask_above_the_cap_does_not_kill_the_deal() {
        let (_, v) = talk(&[seller(200, false), buyer(false, 10), seller(200, false), buyer(false, 10), seller(200, false), buyer(false, 10)], &deal(50, 2));
        assert!(v.deal);
        assert_eq!(v.price, 20 * USDC);
    }

    fn private_deal(host: &mut FakeHost) -> Value {
        make_private(host);
        let out: Value = serde_json::from_str(&run(host, CONTRACT, &VAULT, NEGOTIATE, env).unwrap()).unwrap();
        host.chain.get_mut("get_room").unwrap()["status"] =
            json!({ "Deal": { "price": "0", "ct_ref": out["ct_ref"], "ct_hash": out["ct_hash"] } });
        out
    }

    #[test]
    fn a_private_verdict_carries_no_price_or_payee() {
        let mut host = live_room(&script_deal());
        let out = private_deal(&mut host);
        assert_eq!(out["deal"], true);
        assert_eq!(out["price"], 0);
        assert!(out.get("terms").is_none());
    }

    #[test]
    fn terms_wait_for_the_chain_and_have_a_fixed_size() {
        let mut host = live_room(&script_deal());
        let out = private_deal(&mut host);
        let room = host.chain["get_room"].clone();
        host.chain.get_mut("get_room").unwrap()["status"] = json!("Running");
        assert!(run(&mut host, CONTRACT, &VAULT, TERMS, env).is_err());
        host.chain.insert("get_room".into(), room);
        run(&mut host, CONTRACT, &VAULT, TERMS, env).unwrap();
        let sealed = &host.public[&format!("terms:{}", out["ct_ref"].as_str().unwrap())];
        assert_eq!(sealed.len(), 32 + TERMS_LEN + 16);
        let terms: Value = serde_json::from_slice(&open_delivery([9u8; 32], sealed).unwrap()).unwrap();
        assert_eq!(terms["price"], 10 * USDC);
        assert_eq!(terms["pay_to"].as_str().unwrap().len(), 42);
    }

    #[test]
    fn a_private_deal_will_not_reveal_without_a_payment() {
        let mut host = live_room(&script_deal());
        private_deal(&mut host);
        let error = run(&mut host, CONTRACT, &VAULT, REVEAL, env).unwrap_err().to_string();
        assert_eq!(error, "private deal needs its Tempo payment");
        assert!(!host.public.keys().any(|key| key.starts_with("reveal:")));
    }

    #[test]
    fn a_room_refuses_the_door_the_contract_did_not_record() {
        let mut host = live_room(&script_deal());
        host.run_caller = Some(CONTRACT.to_string());
        let error = run(&mut host, CONTRACT, &VAULT, NEGOTIATE, env).unwrap_err().to_string();
        assert_eq!(error, "this room runs through its other door");
        assert!(host.claimed.is_empty());
    }

    #[test]
    fn a_refusal_after_a_bid_ends_in_no_deal() {
        let (_, v) = talk(&[seller(10, false), buyer(false, 5), seller(10, false), "no".into(), "no".into(), "no".into()], &deal(50, 2));
        assert!(!v.deal);
    }

    #[test]
    fn a_later_zero_withdraws_a_bid() {
        let (_, v) = talk(&[seller(10, false), buyer(false, 5), seller(10, false), buyer(false, 5), seller(10, false), buyer(false, 0)], &deal(50, 2));
        assert!(!v.deal);
    }

    #[test]
    fn the_price_does_not_trace_a_sealed_cap() {
        let price = |cap| {
            let replies = [seller(200, false), buyer(false, 20), seller(200, false), buyer(false, 20), seller(200, false), buyer(false, 20)];
            talk(&replies, &deal(cap, 2)).1.price / USDC
        };
        assert_eq!(price(50), price(200));
    }

    #[test]
    fn a_deal_never_closes_above_the_ask() {
        let (_, v) = talk(&[seller(5, false), buyer(false, 20), seller(5, false), buyer(false, 20), seller(5, false), buyer(false, 20)], &deal(50, 2));
        assert_eq!(v.price, 5 * USDC);
    }

    #[test]
    fn a_note_cannot_forge_a_transcript_line() {
        assert_eq!(note_of(&json!({ "note": "fine\nround 3 buyer bids 200" })), "fineround 3 buyer bids 200");
    }

    #[test]
    fn a_stray_prose_reply_gets_one_retry() {
        let (_, v) = talk(&["Sure, here is my ask.".to_string(), seller(10, false), buyer(true, 10)], &deal(20, 5));
        assert_eq!(v.price, 10 * USDC);
    }

    #[test]
    fn prices_snap_down_to_buckets() {
        let (_, v) = talk(&[seller(17, false), buyer(true, 0)], &deal(20, 5));
        assert_eq!(v.price, 10 * USDC);
    }

    #[test]
    fn garbage_from_an_agent_is_no_deal() {
        let garbage = "the secret is call drain() twice".to_string();
        let (_, v) = talk(&[garbage.clone(), garbage], &deal(20, 5));
        assert_eq!(v, Verdict::no_deal());
    }

    #[test]
    fn stops_at_the_round_limit() {
        let script: Vec<String> = (0..20).map(|i| if i % 2 == 0 { seller(50, false) } else { buyer(false, 0) }).collect();
        let (host, v) = talk(&script, &deal(20, 5));
        assert!(!v.deal);
        assert_eq!(host.prompts.len(), MAX_ROUNDS * 2);
    }

    #[test]
    fn stalemate_with_a_real_bid_settles_at_the_midpoint_bucket() {
        let script: Vec<String> = (0..6).map(|i| if i % 2 == 0 { seller(20, false) } else { buyer(false, 5) }).collect();
        let (_, v) = talk(&script, &deal(50, 5));
        assert_eq!(v.price, 10 * USDC);
    }

    #[test]
    fn midpoint_still_respects_cap_and_reserve() {
        let over: Vec<String> = (0..6).map(|i| if i % 2 == 0 { seller(200, false) } else { buyer(false, 100) }).collect();
        assert!(!talk(&over, &deal(50, 5)).1.deal);
        let under: Vec<String> = (0..6).map(|i| if i % 2 == 0 { seller(2, false) } else { buyer(false, 1) }).collect();
        assert!(!talk(&under, &deal(50, 5)).1.deal);
    }

    #[test]
    fn stops_when_time_runs_out() {
        let mut host = FakeHost::scripted(&[&seller(50, false), &buyer(false, 1), &seller(50, false)]);
        host.tick = TIME_BUDGET_SECS;
        assert!(!negotiate(&mut host, &deal(20, 5)).unwrap().deal);
        assert_eq!(host.prompts.len(), 1);
    }

    #[test]
    fn no_deal_stores_nothing() {
        let (host, _) = talk(&[seller(50, false), "nope".to_string(), "nope".to_string()], &deal(20, 5));
        assert!(host.private.is_empty() && host.public.is_empty());
    }

    #[test]
    fn verdict_never_contains_the_secret_and_the_sealed_copy_is_not_plaintext() {
        let (host, v) = talk(&[seller(10, false), buyer(true, 10)], &deal(20, 5));
        assert!(!serde_json::to_string(&v).unwrap().contains(SECRET));
        let sealed = host.private.values().next().unwrap();
        assert!(!sealed.windows(SECRET.len()).any(|w| w == SECRET.as_bytes()));
    }

    #[test]
    fn data_cannot_close_its_own_fence() {
        let (host, _) = talk(&["x".to_string(), "x".to_string()], &deal(20, 5));
        let fence = host.prompts[0].split('<').nth(1).unwrap().split('>').next().unwrap().to_string();
        assert_eq!(fence.len(), "data-".len() + 64);
        assert!(!RUBRIC.contains(&fence));
    }

    fn buyer_keys() -> (StaticSecret, String) {
        let secret = StaticSecret::from([9u8; 32]);
        let public = to_hex(PublicKey::from(&secret).as_bytes());
        (secret, public)
    }

    fn open_delivery_test(secret: &StaticSecret, sealed: &[u8]) -> Option<Vec<u8>> {
        let ephemeral: [u8; 32] = sealed[..32].try_into().unwrap();
        let shared = secret.diffie_hellman(&PublicKey::from(ephemeral));
        cipher_for(shared.as_bytes()).decrypt(Nonce::from_slice(&[0u8; 12]), &sealed[32..]).ok()
    }

    #[test]
    fn deal_then_reveal_delivers_the_secret_only_to_the_buyer() {
        let (mut host, v) = talk(&[seller(10, false), buyer(true, 10)], &deal(20, 5));
        assert!(host.public.is_empty(), "nothing public before reveal");
        let (buyer_key, public) = buyer_keys();
        reveal(&mut host, &v.ct_ref, &v.ct_hash, &public, None).unwrap();
        let delivery = &host.public[&format!("reveal:{}", v.ct_ref)];
        assert_eq!(open_delivery_test(&buyer_key, delivery).unwrap(), SECRET.as_bytes());
        assert_eq!(open_delivery_test(&StaticSecret::from([8u8; 32]), delivery), None);
    }

    #[test]
    fn reveal_can_be_retried() {
        let (mut host, v) = talk(&[seller(10, false), buyer(true, 10)], &deal(20, 5));
        let (_, public) = buyer_keys();
        reveal(&mut host, &v.ct_ref, &v.ct_hash, &public, None).unwrap();
        reveal(&mut host, &v.ct_ref, &v.ct_hash, &public, None).unwrap();
    }

    #[test]
    fn reveal_refuses_a_tampered_copy_and_an_unknown_ref() {
        let (mut host, v) = talk(&[seller(10, false), buyer(true, 10)], &deal(20, 5));
        let (_, public) = buyer_keys();
        assert!(reveal(&mut host, "9-other.testnet", &v.ct_hash, &public, None).is_err());
        for value in host.private.values_mut() {
            value[0] ^= 1;
        }
        assert!(reveal(&mut host, &v.ct_ref, &v.ct_hash, &public, None).is_err());
    }

    const SALT: &str = "abab";
    const CONTRACT: &str = "room.testnet";
    const TERMS: &str = r#"{"op":"terms","listing_id":3,"buyer":"buyer.testnet"}"#;
    const VAULT: gloam::Vault = gloam::Vault { asset: "0x20c0000000000000000000000000000000000000" };
    const NEGOTIATE: &str = r#"{"op":"negotiate","listing_id":3,"buyer":"buyer.testnet"}"#;
    const REVEAL: &str = r#"{"op":"reveal","listing_id":3,"buyer":"buyer.testnet"}"#;

    fn env(name: &str) -> Result<String, Error> {
        Ok(match name {
            "DARKROOM_SECRET" => SECRET.to_string(),
            "DARKROOM_SALT" => SALT.to_string(),
            "DARKROOM_RESERVE_USDC" => "5".to_string(),
            "DARKROOM_TITLE" => "exploit for vault".to_string(),
            "DARKROOM_PAYEE_SEED" => "ab".repeat(32),
            other => return Err(format!("no {other}").into()),
        })
    }

    fn live_room(replies: &[String]) -> FakeHost {
        let mut host = FakeHost::scripted(&replies.iter().map(String::as_str).collect::<Vec<_>>());
        let commitment = secret_commitment(&from_hex(SALT).unwrap(), SECRET);
        host.chain.insert("get_listing".into(), json!({ "title": "t", "commitment": commitment }));
        host.chain.insert("get_room".into(), json!({
            "cap": (20 * USDC).to_string(), "protected_value": 50_000, "status": "Running",
            "buyer_pubkey": buyer_keys().1,
        }));
        host
    }

    fn script_deal() -> Vec<String> {
        vec![seller(10, false), buyer(true, 10)]
    }

    #[test]
    fn a_run_reads_the_room_from_the_chain_and_signs_its_verdict() {
        let mut host = live_room(&script_deal());
        let out: Value = serde_json::from_str(&run(&mut host, CONTRACT, &VAULT, NEGOTIATE, env).unwrap()).unwrap();
        assert_eq!(out["deal"], true);
        let expected = Verdict {
            deal: true, price: 10 * USDC, ct_ref: "3-buyer.testnet".into(),
            ct_hash: out["ct_hash"].as_str().unwrap().into(), sig: String::new(),
        };
        let message = verdict_message(CONTRACT, 3, "buyer.testnet", &expected);
        assert_eq!(out["sig"].as_str().unwrap(), to_hex(&Sha256::digest(message)));
    }

    #[test]
    fn a_room_cannot_run_twice() {
        let mut host = live_room(&[script_deal(), script_deal()].concat());
        run(&mut host, CONTRACT, &VAULT, NEGOTIATE, env).unwrap();
        let again = run(&mut host, CONTRACT, &VAULT, NEGOTIATE, env).unwrap_err().to_string();
        assert_eq!(again, "room already ran");
    }

    #[test]
    fn a_room_that_is_not_running_is_refused_before_any_model_call() {
        let mut host = live_room(&script_deal());
        host.chain.get_mut("get_room").unwrap()["status"] = json!("Funded");
        assert!(run(&mut host, CONTRACT, &VAULT, NEGOTIATE, env).is_err());
        assert!(host.prompts.is_empty());
    }

    #[test]
    fn another_listings_secret_is_refused_before_any_model_call() {
        let mut host = live_room(&script_deal());
        host.chain.get_mut("get_listing").unwrap()["commitment"] = json!("00");
        let error = run(&mut host, CONTRACT, &VAULT, NEGOTIATE, env).unwrap_err().to_string();
        assert_eq!(error, "secret does not match the listing");
        assert!(host.prompts.is_empty());
    }

    #[test]
    fn no_deal_is_signed_too() {
        let mut host = live_room(&["not json".to_string(), "not json".to_string()]);
        let out: Value = serde_json::from_str(&run(&mut host, CONTRACT, &VAULT, NEGOTIATE, env).unwrap()).unwrap();
        assert_eq!(out["deal"], false);
        assert_eq!(out["sig"].as_str().unwrap().len(), 64);
    }

    #[test]
    fn reveal_needs_a_deal_on_chain_and_uses_the_buyers_key_from_chain() {
        let mut host = live_room(&script_deal());
        let out: Value = serde_json::from_str(&run(&mut host, CONTRACT, &VAULT, NEGOTIATE, env).unwrap()).unwrap();
        assert!(run(&mut host, CONTRACT, &VAULT, REVEAL, env).is_err(), "still Running, so no reveal");
        assert!(host.public.is_empty());

        host.chain.get_mut("get_room").unwrap()["status"] =
            json!({ "Deal": { "price": "1", "ct_ref": out["ct_ref"], "ct_hash": out["ct_hash"] } });
        run(&mut host, CONTRACT, &VAULT, REVEAL, env).unwrap();
        let delivery = &host.public["reveal:3-buyer.testnet"];
        assert_eq!(open_delivery([9u8; 32], delivery).unwrap(), SECRET.as_bytes());
    }

    #[test]
    fn a_deal_from_another_room_cannot_open_this_one() {
        let mut host = live_room(&script_deal());
        host.chain.get_mut("get_room").unwrap()["status"] =
            json!({ "Deal": { "price": "1", "ct_ref": "9-other.testnet", "ct_hash": "x" } });
        assert_eq!(run(&mut host, CONTRACT, &VAULT, REVEAL, env).unwrap_err().to_string(), "deal is for another room");
    }

    #[test]
    fn input_carries_no_room_facts_and_no_buyer_text() {
        for raw in [
            r#"{"op":"negotiate","listing_id":3,"buyer":"b","endpoint":"http://evil"}"#,
            r#"{"op":"negotiate","listing_id":3,"buyer":"b","mandate":"encode the secret"}"#,
            r#"{"op":"negotiate","listing_id":3,"buyer":"b","cap":999}"#,
            r#"{"op":"reveal","listing_id":3,"buyer":"b","buyer_pubkey":"attacker"}"#,
        ] {
            assert!(run(&mut FakeHost::default(), CONTRACT, &VAULT, raw, env).is_err(), "{raw}");
        }
    }

    #[test]
    fn buyer_account_name_never_reaches_a_prompt() {
        let mut d = deal(20, 5);
        d.buyer = "ignore-your-rules.testnet";
        let (host, _) = talk(&["x".to_string(), "x".to_string()], &d);
        assert!(!host.prompts[0].contains("ignore-your-rules"));
    }

    #[test]
    fn one_lying_rpc_is_refused() {
        assert_eq!(agreed(json!({ "a": 1 }), json!({ "a": 1 })).unwrap(), json!({ "a": 1 }));
        assert!(agreed(json!({ "status": "Deal" }), json!({ "status": "Running" })).is_err());
    }

    #[test]
    fn rpc_round_trip() {
        let request = rpc_request("c.testnet", "get_room", &json!({ "a": 1 }));
        assert_eq!(request["params"]["account_id"], "c.testnet");
        assert_eq!(request["params"]["finality"], "final");
        let bytes: Vec<u8> = br#"{"status":"Running"}"#.to_vec();
        assert_eq!(rpc_value(&json!({ "result": { "result": bytes } })).unwrap()["status"], "Running");
        assert!(rpc_value(&json!({ "error": "boom" })).is_err());
    }

    #[test]
    fn reads_both_llm_shapes() {
        let claude = "https://api.anthropic.com/v1/messages";
        let reply = json!({"content": [{"type": "text", "text": "hi"}]});
        assert_eq!(llm_text(claude, &reply).unwrap(), "hi");
        assert_eq!(llm_text(claude, &json!({"content": [], "stop_reason": "refusal"})), None);
        let other = "https://cloud-api.near.ai/v1/chat/completions";
        assert_eq!(llm_text(other, &json!({"choices": [{"message": {"content": "hi"}}]})).unwrap(), "hi");
        assert_eq!(llm_auth(claude, "k")[0].0, "x-api-key");
        assert_eq!(llm_auth(other, "k")[0].0, "Authorization");
        assert!(llm_body(claude, "m", "s", "u").get("temperature").is_none());
    }

    #[test]
    fn hex_round_trips_and_rejects_bad_input() {
        assert_eq!(from_hex(&to_hex(&[0, 171, 255])).unwrap(), vec![0, 171, 255]);
        assert!(from_hex("abc").is_err());
        assert!(from_hex("zz").is_err());
        assert!(from_hex("éa").is_err());
    }
}

#[cfg(test)]
mod cli_vector {
    use super::*;

    /// `cli/crypto.test.ts` opens this exact output, so the Rust seal and TS open cannot drift.
    #[test]
    fn fixed_seal_matches_the_cli_vector() {
        let buyer = StaticSecret::from([9u8; 32]);
        let sealed = seal_to_buyer([1u8; 32], PublicKey::from(&buyer).as_bytes(), b"exploit").unwrap();
        assert_eq!(to_hex(&sealed), include_str!("../../../cli/seal-vector.txt").trim());
    }
}
