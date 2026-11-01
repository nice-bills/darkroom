//! Confirms a private payment from Tempo. The buyer shields through Gloam, then cashes out to a
//! one-time address for this room. A cash out is final on arrival, so neither side can undo it,
//! and unlike a private note it needs nothing from the seller. See docs/gloam-design.md.
use crate::{from_hex, to_hex, Error, Host};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::SecretKey;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sha3::Keccak256;

const TRANSFER: &str = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

/// The token a deal settles in. Compiled into the room.
pub struct Vault<'a> {
    pub asset: &'a str,
}

/// The seller's key for one room. Rooms never share an address, so a payment cannot be claimed twice.
pub fn payee_key(seed: &[u8], ct_ref: &str) -> Result<SecretKey, Error> {
    let digest = Sha256::new().chain_update(b"darkroom-payee").chain_update(seed).chain_update(ct_ref).finalize();
    Ok(SecretKey::from_slice(&digest).map_err(|_| "bad payee key")?)
}

/// The room's one-time address, as lowercase hex with no prefix.
pub fn payee_address(seed: &[u8], ct_ref: &str) -> Result<String, Error> {
    let point = payee_key(seed, ct_ref)?.public_key().to_encoded_point(false);
    Ok(to_hex(&Keccak256::digest(&point.as_bytes()[1..])[12..]))
}

fn is_tx_hash(tx: &str) -> bool {
    tx.len() == 66 && tx.starts_with("0x") && tx[2..].bytes().all(|b| b.is_ascii_hexdigit())
}

/// What this transaction moved to `payee`, in the settlement token.
pub fn paid_to(receipt: &Value, asset: &str, payee: &str) -> Result<u128, Error> {
    if receipt["status"] != "0x1" {
        return Err("payment failed or is not final yet".into());
    }
    let topic = format!("0x{payee:0>64}");
    let mut total = 0u128;
    for log in receipt["logs"].as_array().ok_or("receipt has no logs")? {
        let text = |value: &Value| value.as_str().unwrap_or("").to_ascii_lowercase();
        let moved_here = text(&log["address"]) == asset.to_ascii_lowercase()
            && text(&log["topics"][0]) == TRANSFER
            && text(&log["topics"][2]) == topic;
        if moved_here {
            let data = log["data"].as_str().ok_or("log has no data")?.trim_start_matches("0x");
            let word: [u8; 32] = from_hex(data)?.try_into().map_err(|_| "bad transfer amount")?;
            if word[..16].iter().any(|b| *b != 0) {
                return Err("transfer amount out of range".into());
            }
            total += u128::from_be_bytes(word[16..].try_into()?);
        }
    }
    Ok(total)
}

/// The room reveals only if two sources agree the seller's address received the price.
pub fn check_payment(host: &mut dyn Host, vault: &Vault, seed: &[u8], tx: &str, ct_ref: &str, price: u64) -> Result<(), Error> {
    if !is_tx_hash(tx) {
        return Err("bad transaction hash".into());
    }
    let payee = payee_address(seed, ct_ref)?;
    let [one, two] = host.receipts(tx)?;
    let amount = paid_to(&one, vault.asset, &payee)?;
    if amount != paid_to(&two, vault.asset, &payee)? {
        return Err("Tempo RPCs disagree".into());
    }
    if amount < price as u128 {
        return Err("payment is below the price, or went elsewhere".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::FakeHost;
    use serde_json::json;

    const ASSET: &str = "0x20c0000000000000000000000000000000000000";
    const SEED: [u8; 32] = [7; 32];
    const VAULT: Vault = Vault { asset: ASSET };
    const TX: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";

    fn receipt(status: &str, token: &str, to: &str, amount: u64) -> Value {
        json!({ "status": status, "logs": [{
            "address": token,
            "topics": [TRANSFER, format!("0x{:0>64}", "abcd"), format!("0x{to:0>64}")],
            "data": format!("0x{amount:064x}"),
        }] })
    }

    fn check(one: Value, two: Value, tx: &str, price: u64) -> Result<(), String> {
        let mut host = FakeHost { receipt_pair: Some([one, two]), ..Default::default() };
        check_payment(&mut host, &VAULT, &SEED, tx, "7-buyer.testnet", price).map_err(|e| e.to_string())
    }

    fn good(amount: u64) -> Value {
        receipt("0x1", ASSET, &payee_address(&SEED, "7-buyer.testnet").unwrap(), amount)
    }

    #[test]
    fn payee_matches_a_known_ethereum_vector() {
        // The well-known address of private key 1, so this is real Ethereum derivation.
        let key = SecretKey::from_slice(&[[0u8; 31].as_slice(), &[1]].concat()).unwrap();
        let point = key.public_key().to_encoded_point(false);
        assert_eq!(to_hex(&Keccak256::digest(&point.as_bytes()[1..])[12..]), "7e5f4552091a69125d5dfcb7b8c2659029395bdf");
    }

    #[test]
    fn payee_key_matches_the_cli() {
        // cli/payee.test.ts holds the same vector, so the two cannot drift.
        assert_eq!(payee_address(&SEED, "7-buyer.testnet").unwrap(), "73092dd8c4f754c228860b37fd963cd933820fe1");
    }

    #[test]
    fn rooms_never_share_an_address() {
        assert_ne!(payee_address(&SEED, "7-a.testnet").unwrap(), payee_address(&SEED, "8-a.testnet").unwrap());
    }

    #[test]
    fn a_full_payment_passes() {
        check(good(5), good(5), TX, 5).unwrap();
    }

    #[test]
    fn underpaying_is_refused() {
        assert!(check(good(4), good(4), TX, 5).unwrap_err().contains("below the price"));
    }

    #[test]
    fn a_payment_to_another_address_is_refused() {
        let other = receipt("0x1", ASSET, "beef", 5);
        assert!(check(other.clone(), other, TX, 5).unwrap_err().contains("went elsewhere"));
    }

    #[test]
    fn another_room_s_payment_is_refused() {
        let other = receipt("0x1", ASSET, &payee_address(&SEED, "8-buyer.testnet").unwrap(), 5);
        assert!(check(other.clone(), other, TX, 5).unwrap_err().contains("went elsewhere"));
    }

    #[test]
    fn another_token_is_refused() {
        let payee = payee_address(&SEED, "7-buyer.testnet").unwrap();
        let fake = receipt("0x1", "0x20c0000000000000000000000000000000000009", &payee, 5);
        assert!(check(fake.clone(), fake, TX, 5).unwrap_err().contains("went elsewhere"));
    }

    #[test]
    fn a_failed_transaction_is_refused() {
        let payee = payee_address(&SEED, "7-buyer.testnet").unwrap();
        let failed = receipt("0x0", ASSET, &payee, 5);
        assert!(check(failed.clone(), failed, TX, 5).unwrap_err().contains("not final"));
    }

    #[test]
    fn a_missing_receipt_is_refused() {
        assert!(check(Value::Null, Value::Null, TX, 5).unwrap_err().contains("not final"));
    }

    #[test]
    fn one_lying_rpc_is_refused() {
        assert_eq!(check(good(5), good(0), TX, 5).unwrap_err(), "Tempo RPCs disagree");
    }

    #[test]
    fn a_malformed_hash_is_refused() {
        assert_eq!(check(good(5), good(5), "0x12", 5).unwrap_err(), "bad transaction hash");
    }

    #[test]
    fn an_oversized_amount_is_refused() {
        let mut log = good(5);
        log["logs"][0]["data"] = json!(format!("0x{}", "ff".repeat(32)));
        assert!(check(log.clone(), log, TX, 5).unwrap_err().contains("out of range"));
    }
}
