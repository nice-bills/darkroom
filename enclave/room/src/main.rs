use darkroom_core::gloam::Vault;
use darkroom_core::{agreed, llm_auth, llm_body, llm_text, room_mac, room_open, room_seal, rpc_request, rpc_value, run, Error, Host};
use outlayer::{signing_keys, storage};
use std::env;
use std::io::{self, Read, Write};
use std::time::Instant;

mod http;

/// Covered by the wasm sha256, so the worker refuses any other caller or egress host.
#[cfg(target_arch = "wasm32")]
#[used]
#[link_section = "outlayer.manifest"]
static OUTLAYER_MANIFEST: [u8; include_bytes!("../manifest.json").len()] =
    *include_bytes!("../manifest.json");

// Compile-time on purpose: input is caller-controlled, and a caller-chosen
// endpoint would receive the secret.
const LLM_URL: &str = env!("DARKROOM_LLM_URL");
const LLM_MODEL: &str = env!("DARKROOM_LLM_MODEL");
const RPC_URL: &str = env!("DARKROOM_RPC_URL");
const RPC_URL_2: &str = env!("DARKROOM_RPC_URL_2");
const CONTRACT: &str = env!("DARKROOM_CONTRACT");
const VAULT_RPC: &str = env!("DARKROOM_VAULT_RPC");
const VAULT_RPC_2: &str = env!("DARKROOM_VAULT_RPC_2");
const VAULT: Vault = Vault { asset: env!("DARKROOM_VAULT_ASSET") };
const VERDICT_KEY: &str = "verdict";
const ROOM_KEY: &str = "room-key";

struct Enclave {
    started: Instant,
}

/// Born inside the first run, in storage only wasm can read, so no person ever holds it. The
/// deploy script makes that first run, so two runs never race to create it.
fn room_key() -> Result<[u8; 32], Error> {
    if let Some(key) = storage::get_worker(ROOM_KEY)? {
        return key.try_into().map_err(|_| "bad room key".into());
    }
    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key)?;
    storage::set_worker(ROOM_KEY, &key)?;
    Ok(key)
}

impl Host for Enclave {
    fn llm(&mut self, system: &str, user: &str) -> Result<String, Error> {
        let body = llm_body(LLM_URL, LLM_MODEL, system, user);
        let key = env::var("LLM_API_KEY")?;
        let (status, reply) = http::post(LLM_URL, &llm_auth(LLM_URL, &key), body.to_string().as_bytes())?;
        if !(200..300).contains(&status) {
            return Err(format!("llm status {status}").into());
        }
        // A reply with no text ends the talks as no deal instead of failing the run.
        Ok(llm_text(LLM_URL, &serde_json::from_slice(&reply)?).unwrap_or_default())
    }

    fn seal(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce)?;
        room_seal(&room_key()?, nonce, plaintext, aad)
    }

    fn open(&mut self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
        room_open(&room_key()?, ciphertext, aad)
    }

    fn mac(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(room_mac(&room_key()?, data))
    }

    fn store(&mut self, key: &str, value: &[u8]) -> Result<(), Error> {
        // Worker storage belongs to the project, so either door can read it.
        Ok(storage::set_worker(key, value)?)
    }

    fn load(&mut self, key: &str) -> Result<Option<Vec<u8>>, Error> {
        Ok(storage::get_worker(key)?)
    }

    fn publish(&mut self, key: &str, value: &[u8]) -> Result<(), Error> {
        Ok(storage::set_worker_with_options(key, value, Some(false))?)
    }

    fn claim(&mut self, key: &str) -> Result<bool, Error> {
        Ok(storage::set_if_absent_raw(key, b"1")?)
    }

    fn sign(&mut self, message: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(signing_keys::sign(VERDICT_KEY, None, message)?)
    }

    fn public_key(&mut self) -> Result<Vec<u8>, Error> {
        Ok(signing_keys::public_key(VERDICT_KEY, None)?)
    }

    fn view(&mut self, method: &str, args: serde_json::Value) -> Result<serde_json::Value, Error> {
        let request = rpc_request(CONTRACT, method, &args).to_string();
        let read = |url: &str| -> Result<serde_json::Value, Error> {
            let (_, reply) = http::post(url, &[], request.as_bytes())?;
            rpc_value(&serde_json::from_slice(&reply)?)
        };
        agreed(read(RPC_URL)?, read(RPC_URL_2)?)
    }

    fn receipts(&mut self, tx: &str) -> Result<[serde_json::Value; 2], Error> {
        let request = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "eth_getTransactionReceipt", "params": [tx] }).to_string();
        let read = |url: &str| -> Result<serde_json::Value, Error> {
            let (_, reply) = http::post(url, &[], request.as_bytes())?;
            let reply: serde_json::Value = serde_json::from_slice(&reply)?;
            Ok(reply["result"].clone())
        };
        Ok([read(VAULT_RPC)?, read(VAULT_RPC_2)?])
    }

    fn caller(&mut self) -> Option<String> {
        outlayer::env::predecessor_account_id()
    }

    fn random32(&mut self) -> Result<[u8; 32], Error> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed)?;
        Ok(seed)
    }

    fn elapsed_secs(&mut self) -> u64 {
        self.started.elapsed().as_secs()
    }
}

fn main() -> Result<(), Error> {
    let mut raw = String::new();
    io::stdin().read_to_string(&mut raw)?;
    let mut host = Enclave { started: Instant::now() };
    let output = run(&mut host, CONTRACT, &VAULT, &raw, |name| Ok(env::var(name)?))?;
    let mut stdout = io::stdout();
    stdout.write_all(output.as_bytes())?;
    stdout.flush()?;
    Ok(())
}
