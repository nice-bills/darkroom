//! Stands in for `outlayer.testnet` to test escrow settlement on a real chain. It proves nothing
//! about the TEE. Set the next run's output, then `open_room` receives it as the callback value.
use near_sdk::serde_json::Value;
use near_sdk::{env, near, AccountId, PanicOnDefault};

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct MockOutlayer {
    next_output: String,
    last_input: String,
    runs: u64,
}

#[near]
impl MockOutlayer {
    #[init]
    pub fn new() -> Self {
        Self { next_output: "null".to_string(), last_input: String::new(), runs: 0 }
    }

    pub fn set_next_output(&mut self, output: Value) {
        self.next_output = output.to_string();
    }

    /// Same argument names as the real contract. The fake never reads the secrets row.
    #[payable]
    pub fn request_execution(&mut self, input_data: String, payer_account_id: AccountId) -> Value {
        self.last_input = input_data;
        self.runs += 1;
        if !env::attached_deposit().is_zero() {
            near_sdk::Promise::new(payer_account_id).transfer(env::attached_deposit()).detach();
        }
        near_sdk::serde_json::from_str(&self.next_output).unwrap_or(Value::Null)
    }

    pub fn last_input(&self) -> String {
        self.last_input.clone()
    }

    pub fn runs(&self) -> u64 {
        self.runs
    }
}
