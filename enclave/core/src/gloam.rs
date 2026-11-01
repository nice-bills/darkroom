//! Checks a private Gloam payment inside the room. A Gloam receipt cannot show who got paid, and a
//! payment is not final until the payee moves it, so the room checks both from the seller's key.
//! See docs/gloam-design.md.
use crate::{from_hex, to_hex, Error, Host};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use base64::Engine;
use hkdf::Hkdf;
use light_poseidon::{Poseidon, PoseidonHasher};
use num_bigint::BigUint;
use p256::elliptic_curve::sec1::FromEncodedPoint;
use p256::{EncodedPoint, PublicKey, SecretKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

const SEALED_PREFIX: &str = "gloam2t.";
const PACKAGE_PREFIX: &str = "gloam1.";
const HKDF_INFO: &[u8] = b"gloam-pay-to-tag-v1";
const IS_SPENT: [u8; 4] = [0xe5, 0x28, 0x5d, 0xcc];
const COMMITMENT_SEEN: [u8; 4] = [0x38, 0x22, 0x36, 0x09];

/// Which vault and token a deal settles in. Compiled into the room.
pub struct Vault<'a> {
    pub pool: &'a str,
    pub asset: &'a str,
    pub chain_id: u64,
}

fn b64url(text: &str) -> Result<Vec<u8>, Error> {
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(text)?)
}

/// Opens a `gloam2t.` ticket: P-256 ECDH, HKDF-SHA256, AES-256-GCM, as the Gloam SDK seals it.
pub fn open_ticket(key: &[u8], ticket: &str) -> Result<String, Error> {
    let raw = b64url(ticket.trim().strip_prefix(SEALED_PREFIX).ok_or("not a sealed ticket")?)?;
    let key_len = u16::from_be_bytes([*raw.first().ok_or("short ticket")?, *raw.get(1).ok_or("short ticket")?]) as usize;
    let spki = raw.get(2..2 + key_len).ok_or("short ticket")?;
    let nonce = raw.get(2 + key_len..2 + key_len + 12).ok_or("short ticket")?;
    let cipher = raw.get(2 + key_len + 12..).ok_or("short ticket")?;
    // A P-256 SPKI ends in the 65-byte uncompressed point.
    let point = EncodedPoint::from_bytes(spki.get(spki.len().wrapping_sub(65)..).ok_or("short key")?).map_err(|_| "bad key")?;
    let public = Option::<PublicKey>::from(PublicKey::from_encoded_point(&point)).ok_or("bad key")?;
    let secret = SecretKey::from_slice(key).map_err(|_| "bad receive key")?;
    let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
    let mut aes_key = [0u8; 32];
    Hkdf::<Sha256>::new(None, shared.raw_secret_bytes().as_slice())
        .expand(HKDF_INFO, &mut aes_key)
        .map_err(|_| "hkdf")?;
    let plain = Aes256Gcm::new_from_slice(&aes_key)?
        .decrypt(Nonce::from_slice(nonce), cipher)
        .map_err(|_| "ticket was sealed to another key")?;
    Ok(String::from_utf8(plain)?.trim_end().to_string())
}

fn field(value: &str) -> Result<Fr, Error> {
    let number = match value.strip_prefix("0x") {
        Some(hex) => BigUint::parse_bytes(hex.as_bytes(), 16),
        None => BigUint::parse_bytes(value.as_bytes(), 10),
    };
    Ok(Fr::from_be_bytes_mod_order(&number.ok_or("bad number")?.to_bytes_be()))
}

fn poseidon(inputs: &[Fr]) -> Result<Fr, Error> {
    Ok(Poseidon::<Fr>::new_circom(inputs.len())?.hash(inputs)?)
}

fn word(value: Fr) -> [u8; 32] {
    let bytes = value.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

/// The seller's sweep secret. The buyer knows the payment note but not `sweep_key`, so only the
/// seller can create this note. Its presence shows the seller took the money. A note is swept
/// once, and `ct_ref` is in the hash, so one payment cannot pay for two rooms.
pub fn sweep_secret(sweep_key: &[u8], nullifier: Fr, ct_ref: &str) -> Fr {
    let digest = Sha256::new()
        .chain_update(b"darkroom-sweep")
        .chain_update(sweep_key)
        .chain_update(word(nullifier))
        .chain_update(ct_ref)
        .finalize();
    Fr::from_be_bytes_mod_order(&digest)
}

/// Every check that must pass before a private deal may reveal.
pub fn check_payment(
    host: &mut dyn Host,
    vault: &Vault,
    key: &[u8],
    sweep: &[u8],
    ticket: &str,
    ct_ref: &str,
    price: u64,
) -> Result<(), Error> {
    let package = open_ticket(key, ticket)?;
    let encoded = package.strip_prefix(PACKAGE_PREFIX).ok_or("not a note package")?;
    let note: Value = serde_json::from_slice(&b64url(encoded)?)?;
    let text = |name: &str| note[name].as_str().ok_or_else(|| Error::from(format!("note has no {name}")));

    if !text("p")?.eq_ignore_ascii_case(vault.pool) {
        return Err("payment is in another vault".into());
    }
    if note["ch"].as_u64() != Some(vault.chain_id) {
        return Err("payment is on another chain".into());
    }
    if !text("a")?.eq_ignore_ascii_case(vault.asset) {
        return Err("payment is in another token".into());
    }
    if text("n")? != ct_ref {
        return Err("payment is for another room".into());
    }
    let amount: u128 = text("w")?.parse()?;
    if amount < price as u128 {
        return Err("payment is below the price".into());
    }

    let secret = field(text("k")?)?;
    let asset = field(vault.asset)?;
    let commitment = poseidon(&[secret, field(text("w")?)?, asset])?;
    if commitment != field(text("c")?)? {
        return Err("note does not match its commitment".into());
    }
    if !host.vault_read(COMMITMENT_SEEN, word(commitment))? {
        return Err("payment is not in the vault".into());
    }
    let nullifier = poseidon(&[secret, commitment])?;
    if !host.vault_read(IS_SPENT, word(nullifier))? {
        return Err("seller has not swept the payment".into());
    }
    let swept = sweep_secret(sweep, nullifier, ct_ref);
    if !host.vault_read(COMMITMENT_SEEN, word(poseidon(&[swept, field(text("w")?)?, asset])?))? {
        return Err("payment was spent, but not by the seller".into());
    }
    Ok(())
}

/// The JSON-RPC body for a one-word view on the vault. Latest block: Tempo finalizes each block.
pub fn vault_request(pool: &str, selector: [u8; 4], word: [u8; 32]) -> Value {
    let data = format!("0x{}{}", to_hex(&selector), to_hex(&word));
    serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "eth_call", "params": [{ "to": pool, "data": data }, "latest"] })
}

/// Reads a `bool` reply. Anything else is an error, never a false that looks like an answer.
pub fn vault_bool(reply: &Value) -> Result<bool, Error> {
    let result = reply["result"].as_str().ok_or_else(|| format!("vault read failed: {}", reply["error"]))?;
    let bytes: [u8; 32] = from_hex(result.trim_start_matches("0x"))?.try_into().map_err(|_| "bad vault reply")?;
    Ok(bytes[31] == 1 && bytes[..31].iter().all(|b| *b == 0))
}

/// What a sweep of this note creates, as hex. Used by tests and the harness.
pub fn swept_commitment_hex(sweep: &[u8], nullifier: &str, amount: &str, asset: &str, ct_ref: &str) -> Result<String, Error> {
    let swept = sweep_secret(sweep, field(nullifier)?, ct_ref);
    Ok(to_hex(&word(poseidon(&[swept, field(amount)?, field(asset)?])?)))
}

/// Field values as 32-byte hex, in the form the vault reads.
pub fn word_hex(value: &str) -> Result<String, Error> {
    Ok(to_hex(&word(field(value)?)))
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::fake::FakeHost;
    use std::collections::HashSet;

    pub const SWEEP: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

    pub fn fixture() -> Value {
        serde_json::from_str(include_str!("../gloam-fixture.json")).unwrap()
    }

    pub fn vault_of(f: &Value) -> (String, String) {
        let raw = open_ticket(&from_hex(f["key_hex"].as_str().unwrap()).unwrap(), f["ticket"].as_str().unwrap()).unwrap();
        let note: Value = serde_json::from_slice(&b64url(raw.strip_prefix(PACKAGE_PREFIX).unwrap()).unwrap()).unwrap();
        (note["p"].as_str().unwrap().to_string(), note["a"].as_str().unwrap().to_string())
    }

    /// What the chain says after an honest payment and sweep.
    pub fn honest_vault(f: &Value) -> HashSet<String> {
        let (_, asset) = vault_of(f);
        let n = field(f["nullifier"].as_str().unwrap()).unwrap();
        let swept = swept_commitment_hex(&from_hex(SWEEP).unwrap(), f["nullifier"].as_str().unwrap(), f["amount"].as_str().unwrap(), &asset, f["ct_ref"].as_str().unwrap()).unwrap();
        [to_hex(&word(field(f["commitment"].as_str().unwrap()).unwrap())), to_hex(&word(n)), swept].into_iter().collect()
    }

    fn check(host: &mut FakeHost, f: &Value, key: &str, ct_ref: &str, price: u64, chain: u64, asset: Option<&str>) -> Result<(), String> {
        let (pool, real_asset) = vault_of(f);
        let vault = Vault { pool: &pool, asset: asset.unwrap_or(&real_asset), chain_id: chain };
        check_payment(host, &vault, &from_hex(key).unwrap(), &from_hex(SWEEP).unwrap(), f["ticket"].as_str().unwrap(), ct_ref, price).map_err(|e| e.to_string())
    }

    fn host(words: HashSet<String>) -> FakeHost {
        FakeHost { vault_true: words, ..Default::default() }
    }

    const CHAIN: u64 = 42431;

    #[test]
    fn an_honest_payment_passes() {
        let f = fixture();
        let key = f["key_hex"].as_str().unwrap();
        check(&mut host(honest_vault(&f)), &f, key, "7-buyer.testnet", 5_000_000, CHAIN, None).unwrap();
    }

    #[test]
    fn a_ticket_sealed_to_someone_else_is_refused() {
        let f = fixture();
        let other = "11".repeat(32);
        let error = check(&mut host(honest_vault(&f)), &f, &other, "7-buyer.testnet", 1, CHAIN, None).unwrap_err();
        assert_eq!(error, "ticket was sealed to another key");
    }

    #[test]
    fn underpaying_is_refused() {
        let f = fixture();
        let key = f["key_hex"].as_str().unwrap();
        let error = check(&mut host(honest_vault(&f)), &f, key, "7-buyer.testnet", 5_000_001, CHAIN, None).unwrap_err();
        assert_eq!(error, "payment is below the price");
    }

    #[test]
    fn one_payment_cannot_open_two_rooms() {
        let f = fixture();
        let key = f["key_hex"].as_str().unwrap();
        let error = check(&mut host(honest_vault(&f)), &f, key, "8-buyer.testnet", 1, CHAIN, None).unwrap_err();
        assert_eq!(error, "payment is for another room");
    }

    #[test]
    fn another_chain_or_token_is_refused() {
        let f = fixture();
        let key = f["key_hex"].as_str().unwrap();
        assert_eq!(check(&mut host(honest_vault(&f)), &f, key, "7-buyer.testnet", 1, 1, None).unwrap_err(), "payment is on another chain");
        let wrong = "0x20c0000000000000000000000000000000000009";
        assert_eq!(check(&mut host(honest_vault(&f)), &f, key, "7-buyer.testnet", 1, CHAIN, Some(wrong)).unwrap_err(), "payment is in another token");
    }

    #[test]
    fn a_sweep_for_another_room_does_not_count() {
        let f = fixture();
        let key = f["key_hex"].as_str().unwrap();
        let (_, asset) = vault_of(&f);
        let mut words = honest_vault(&f);
        let right = swept_commitment_hex(&from_hex(SWEEP).unwrap(), f["nullifier"].as_str().unwrap(), f["amount"].as_str().unwrap(), &asset, "7-buyer.testnet").unwrap();
        let other = swept_commitment_hex(&from_hex(SWEEP).unwrap(), f["nullifier"].as_str().unwrap(), f["amount"].as_str().unwrap(), &asset, "8-buyer.testnet").unwrap();
        words.remove(&right);
        words.insert(other);
        let error = check(&mut host(words), &f, key, "7-buyer.testnet", 1, CHAIN, None).unwrap_err();
        assert_eq!(error, "payment was spent, but not by the seller");
    }

    #[test]
    fn vault_replies_parse_strictly() {
        let yes = format!("0x{}01", "00".repeat(31));
        assert!(vault_bool(&serde_json::json!({ "result": yes })).unwrap());
        assert!(!vault_bool(&serde_json::json!({ "result": format!("0x{}", "00".repeat(32)) })).unwrap());
        assert!(vault_bool(&serde_json::json!({ "error": { "code": -32000 } })).is_err());
        assert!(vault_bool(&serde_json::json!({ "result": "0x" })).is_err());
    }

    #[test]
    fn a_payment_that_never_landed_is_refused() {
        let f = fixture();
        let key = f["key_hex"].as_str().unwrap();
        let error = check(&mut host(HashSet::new()), &f, key, "7-buyer.testnet", 1, CHAIN, None).unwrap_err();
        assert_eq!(error, "payment is not in the vault");
    }

    #[test]
    fn an_unswept_payment_is_refused() {
        let f = fixture();
        let key = f["key_hex"].as_str().unwrap();
        let mut words = honest_vault(&f);
        words.remove(&to_hex(&word(field(f["nullifier"].as_str().unwrap()).unwrap())));
        let error = check(&mut host(words), &f, key, "7-buyer.testnet", 1, CHAIN, None).unwrap_err();
        assert_eq!(error, "seller has not swept the payment");
    }

    #[test]
    fn a_buyer_who_spends_the_payment_back_gets_nothing() {
        // Spent, but the seller's derived note is not there.
        let f = fixture();
        let key = f["key_hex"].as_str().unwrap();
        let spent_back: HashSet<String> = [
            to_hex(&word(field(f["commitment"].as_str().unwrap()).unwrap())),
            to_hex(&word(field(f["nullifier"].as_str().unwrap()).unwrap())),
        ].into_iter().collect();
        let error = check(&mut host(spent_back), &f, key, "7-buyer.testnet", 1, CHAIN, None).unwrap_err();
        assert_eq!(error, "payment was spent, but not by the seller");
    }
}
