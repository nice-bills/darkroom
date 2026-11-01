//! A NEP-141 token with free minting, so a judge needs no faucet. Testnet only, worth nothing.
use near_contract_standards::fungible_token::core::FungibleTokenCore;
use near_contract_standards::fungible_token::resolver::FungibleTokenResolver;
use near_contract_standards::fungible_token::FungibleToken;
use near_contract_standards::storage_management::{StorageBalance, StorageBalanceBounds, StorageManagement};
use near_sdk::json_types::U128;
use near_sdk::{env, near, AccountId, PanicOnDefault, PromiseOrValue};

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct TestToken {
    token: FungibleToken,
}

#[near]
impl TestToken {
    #[init]
    pub fn new() -> Self {
        Self { token: FungibleToken::new(b"t") }
    }

    /// Open to anyone: registers the caller if needed and mints.
    pub fn mint(&mut self, amount: U128) {
        let account = env::predecessor_account_id();
        if !self.token.accounts.contains_key(&account) {
            self.token.internal_register_account(&account);
        }
        self.token.internal_deposit(&account, amount.0);
    }

    pub fn ft_metadata(&self) -> near_sdk::serde_json::Value {
        near_sdk::serde_json::json!({"spec": "ft-1.0.0", "name": "Test USDC", "symbol": "tUSDC", "decimals": 6})
    }

    #[payable]
    pub fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
        self.token.ft_transfer(receiver_id, amount, memo)
    }

    #[payable]
    pub fn ft_transfer_call(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>, msg: String) -> PromiseOrValue<U128> {
        self.token.ft_transfer_call(receiver_id, amount, memo, msg)
    }

    pub fn ft_total_supply(&self) -> U128 {
        self.token.ft_total_supply()
    }

    pub fn ft_balance_of(&self, account_id: AccountId) -> U128 {
        self.token.ft_balance_of(account_id)
    }

    #[private]
    pub fn ft_resolve_transfer(&mut self, sender_id: AccountId, receiver_id: AccountId, amount: U128) -> U128 {
        self.token.ft_resolve_transfer(sender_id, receiver_id, amount)
    }

    #[payable]
    pub fn storage_deposit(&mut self, account_id: Option<AccountId>, registration_only: Option<bool>) -> StorageBalance {
        self.token.storage_deposit(account_id, registration_only)
    }

    pub fn storage_balance_bounds(&self) -> StorageBalanceBounds {
        self.token.storage_balance_bounds()
    }

    pub fn storage_balance_of(&self, account_id: AccountId) -> Option<StorageBalance> {
        self.token.storage_balance_of(account_id)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    #[test]
    fn mint_registers_and_credits() {
        let owner: AccountId = "buyer.testnet".parse().unwrap();
        testing_env!(VMContextBuilder::new().predecessor_account_id(owner.clone()).build());
        let mut token = TestToken::new();
        token.mint(U128(7));
        assert_eq!(token.ft_balance_of(owner), U128(7));
    }
}
