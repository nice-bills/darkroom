use darkroom_core::gloam::{vault_bool, vault_request, Vault};
use darkroom_core::{agreed, llm_auth, llm_body, llm_text, rpc_request, rpc_value, run, Error, Host};
use outlayer::{encryption_keys, signing_keys, storage};
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
const VAULT: Vault = Vault {
    pool: env!("DARKROOM_VAULT_POOL"),
    asset: env!("DARKROOM_VAULT_ASSET"),
    chain_id: 42431,
};
const SEAL_KEY: &str = "sealed";
const VERDICT_KEY: &str = "verdict";

struct Enclave {
    started: Instant,
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
        Ok(encryption_keys::encrypt(SEAL_KEY, None, plaintext, aad)?)
    }

    fn open(&mut self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(encryption_keys::decrypt(SEAL_KEY, None, ciphertext, aad)?)
    }

    fn mac(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(encryption_keys::mac(SEAL_KEY, None, data)?)
    }

    fn store(&mut self, key: &str, value: &[u8]) -> Result<(), Error> {
        Ok(storage::set_raw(key, value)?)
    }

    fn load(&mut self, key: &str) -> Result<Option<Vec<u8>>, Error> {
        Ok(storage::get_raw(key)?)
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

    fn vault_read(&mut self, selector: [u8; 4], word: [u8; 32]) -> Result<bool, Error> {
        let request = vault_request(VAULT.pool, selector, word).to_string();
        let read = |url: &str| -> Result<bool, Error> {
            let (_, reply) = http::post(url, &[], request.as_bytes())?;
            vault_bool(&serde_json::from_slice(&reply)?)
        };
        // A lagging source reads as a failed run, which the buyer retries. It never reveals early.
        let (one, two) = (read(VAULT_RPC)?, read(VAULT_RPC_2)?);
        if one != two {
            return Err("vault RPCs disagree".into());
        }
        Ok(one)
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
