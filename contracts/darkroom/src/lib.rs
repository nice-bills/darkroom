//! Escrow for sealed negotiations: the buyer funds a room in NEP-141, OutLayer runs it,
//! and the callback settles. Anything but a valid verdict refunds the buyer.
//! shortcut: no storage deposits for listings and rooms, add before mainnet.
use near_sdk::json_types::U128;
use near_sdk::serde::Deserialize;
use near_sdk::serde_json::{self, json, Value};
use near_sdk::store::LookupMap;
use near_sdk::{
    env, is_promise_success, near, require, AccountId, Gas, NearToken, PanicOnDefault, Promise,
    PromiseError,
};

const OUTLAYER_GAS: Gas = Gas::from_tgas(100);
const CALLBACK_GAS: Gas = Gas::from_tgas(60);
const FT_TRANSFER_GAS: Gas = Gas::from_tgas(10);
const PAYOUT_CALLBACK_GAS: Gas = Gas::from_tgas(5);
const MIN_RUN_DEPOSIT: NearToken = NearToken::from_millinear(100);
const MAX_TITLE_LEN: usize = 200;
const X25519_KEY_HEX_LEN: usize = 64;
const USDC: u64 = 1_000_000;
const COMMITMENT_HEX_LEN: usize = 64;
/// Ephemeral key, two u64s and the room's hash, tag.
const MANDATE_HEX_LEN: usize = 2 * (32 + 48 + 16);
/// About an hour for the buyer to pay. Nothing the seller does can use it up.
const PAY_WINDOW_BLOCKS: u64 = 6000;
const MAX_PROFILE_LEN: usize = 64;
/// Pays for the listing's storage, so anyone filling the contract pays to do it.
const LISTING_DEPOSIT: NearToken = NearToken::from_millinear(10);
/// About six minutes. Well past any run, so only a silent relayer ever reaches this.
const STALE_AFTER_BLOCKS: u64 = 600;
/// Mirrors `PRICE_BUCKETS` in `enclave/core`: the enclave quantizes, the contract refuses
/// anything else, so a faulty room cannot widen the covert channel.
const PRICE_BUCKETS: [u64; 8] = [1, 2, 5, 10, 20, 50, 100, 200];

#[near(serializers = [json, borsh])]
#[derive(Clone)]
pub struct Listing {
    pub seller: AccountId,
    pub profile: String,
    pub title: String,
    pub max_rooms: u32,
    pub rooms_opened: u32,
    /// sha256(salt || secret). The room refuses to run on any other secret.
    pub commitment: String,
    /// The only account that may buy. A finding must reach its owner, not whoever pays.
    pub target: Option<AccountId>,
    /// Paid through Gloam, outside this contract, so the chain sees neither price nor payee.
    pub private_settlement: bool,
    /// Private listings: what a buyer risks by learning the price and not paying. Fixed and public.
    pub bond: U128,
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, PartialEq)]
pub enum Status {
    Funded,
    Running,
    NoDeal,
    Cancelled,
    Deal { price: U128, ct_ref: String, ct_hash: String },
}

#[near(serializers = [json, borsh])]
#[derive(Clone)]
pub struct Room {
    pub cap: U128,
    pub buyer_pubkey: String,
    pub protected_value: u64,
    pub status: Status,
    pub opened_at: u64,
    /// `relay` or `chain`. Only that door may run the room, so it negotiates once.
    pub door: String,
    /// Private rooms: the buyer's limit and value at risk, sealed to the room. `cap` holds the bond.
    pub mandate: String,
    /// Private deals: the bond has gone back to the buyer or over to the seller.
    pub bond_done: bool,
}

#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields)]
struct OpenMsg {
    listing_id: u64,
    buyer_pubkey: String,
    /// USDC the buyer has at risk. A number, because free text here reaches both agents.
    protected_value: u64,
    /// Private listings only. Replaces the public limit and `protected_value`.
    #[serde(default)]
    sealed_mandate: Option<String>,
}

/// The fixed schema the room may emit. Unknown fields fail, so no free text gets through.
#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields)]
struct Verdict {
    deal: bool,
    price: u64,
    #[serde(default)]
    ct_ref: String,
    #[serde(default)]
    ct_hash: String,
    /// Relayed runs verify this in `settle_signed`. A yield/resume result is already authentic.
    #[serde(default)]
    #[allow(dead_code)]
    sig: String,
}

/// `None` covers no-deal, malformed output and OutLayer's `null` on a timed-out run.
fn accepted_deal(value: Value, cap: u128, private: bool) -> Option<Verdict> {
    let verdict: Verdict = serde_json::from_value(value).ok()?;
    let priced = if private {
        verdict.price == 0
    } else {
        verdict.price % USDC == 0
            && PRICE_BUCKETS.contains(&(verdict.price / USDC))
            && verdict.price as u128 <= cap
    };
    let valid = verdict.deal
        && priced
        && !verdict.ct_ref.is_empty()
        && !verdict.ct_hash.is_empty();
    valid.then_some(verdict)
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Darkroom {
    outlayer: AccountId,
    project_id: String,
    token: AccountId,
    /// Public half of the room's signing key. The private half exists only inside runs.
    enclave_key: [u8; 32],
    next_listing: u64,
    listings: LookupMap<u64, Listing>,
    // One room per buyer per listing, kept after settlement: this bounds the covert channel.
    rooms: LookupMap<(u64, AccountId), Room>,
    // Payouts whose ft_transfer failed, e.g. an account not registered with the token.
    owed: LookupMap<AccountId, u128>,
}

#[near]
impl Darkroom {
    #[init]
    pub fn new(outlayer: AccountId, project_id: String, token: AccountId, enclave_key: String) -> Self {
        Self {
            outlayer,
            project_id,
            token,
            enclave_key: hex::decode(&enclave_key)
                .ok()
                .and_then(|key| key.try_into().ok())
                .expect("Bad enclave key"),
            next_listing: 0,
            listings: LookupMap::new(b"l"),
            rooms: LookupMap::new(b"r"),
            owed: LookupMap::new(b"o"),
        }
    }

    /// `profile` names the OutLayer secret row the seller stored for this listing. `title` is
    /// public, so it must say nothing an attacker could use: the real claim lives in the row.
    /// `max_rooms` caps sybil buyers: total leak is at most `max_rooms` times the per-room bound.
    #[payable]
    pub fn list(
        &mut self,
        profile: String,
        title: String,
        max_rooms: u32,
        commitment: String,
        target: Option<AccountId>,
        private_settlement: bool,
        bond: U128,
    ) -> u64 {
        require!(max_rooms > 0, "A listing needs at least one room");
        require!(is_hex(&commitment, COMMITMENT_HEX_LEN), "Bad commitment");
        require!(title.len() <= MAX_TITLE_LEN, "Title too long");
        require!(profile.len() <= MAX_PROFILE_LEN, "Profile too long");
        require!(env::attached_deposit() >= LISTING_DEPOSIT, "Attach 0.01 NEAR for storage");
        require!(private_settlement == (bond.0 > 0), "A private listing needs a bond, others none");
        let id = self.next_listing;
        self.next_listing += 1;
        self.listings.insert(id, Listing { seller: env::predecessor_account_id(), profile, title, max_rooms, rooms_opened: 0, commitment, target, private_settlement, bond });
        id
    }

    /// NEP-141 receiver. The transferred amount is the buyer's hard cap.
    pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) -> U128 {
        require!(env::predecessor_account_id() == self.token, "Wrong token");
        let open: OpenMsg = serde_json::from_str(&msg).expect("Bad msg");
        self.add_room(sender_id, open, amount);
        U128(0)
    }

    /// The room signs this only after it sees the swept payment, so the bond comes back.
    pub fn confirm_paid(&mut self, listing_id: u64, buyer: AccountId, sig: String) {
        let room = self.rooms.get(&(listing_id, buyer.clone())).expect("No room");
        require!(matches!(room.status, Status::Deal { .. }) && !room.bond_done, "No bond to return");
        let message = format!("darkroom-paid-v1|{}|{listing_id}|{buyer}", env::current_account_id());
        let sig: [u8; 64] = hex::decode(&sig).ok().and_then(|s| s.try_into().ok()).expect("Bad signature");
        require!(env::ed25519_verify(&sig, message.as_bytes(), &self.enclave_key), "Bad signature");
        let bond = self.close_bond(listing_id, &buyer);
        self.pay(buyer, bond);
    }

    /// A buyer who took a price and never paid loses the bond. Paying needs nothing from the
    /// seller, and the room's receipt returns the bond, so an honest buyer never reaches this.
    pub fn forfeit(&mut self, listing_id: u64, buyer: AccountId) {
        let room = self.rooms.get(&(listing_id, buyer.clone())).expect("No room");
        require!(matches!(room.status, Status::Deal { .. }) && !room.bond_done, "No bond to take");
        require!(env::block_height() > room.opened_at + PAY_WINDOW_BLOCKS, "The buyer can still pay");
        let bond = self.close_bond(listing_id, &buyer);
        let seller = self.listings.get(&listing_id).expect("No such listing").seller.clone();
        self.pay(seller, bond);
    }

    /// Moves a funded room to `Running` for a relayed run. The relayer is untrusted: it can only
    /// deliver a verdict the enclave signed, and if it stays silent `refund_stale` frees the budget.
    pub fn start_room(&mut self, listing_id: u64) {
        let buyer = env::predecessor_account_id();
        self.mark_running(listing_id, &buyer, "relay");
    }

    /// The yield/resume door: the contract asks OutLayer directly and the callback settles.
    /// Separate from funding because `ft_transfer_call` cannot carry the NEAR a run costs.
    #[payable]
    pub fn open_room(&mut self, listing_id: u64) -> Promise {
        require!(env::attached_deposit() >= MIN_RUN_DEPOSIT, "Attach at least 0.1 NEAR");
        let buyer = env::predecessor_account_id();
        // The room's key for sealed limits is the relayer's, so private rooms keep to that door.
        require!(!self.listings.get(&listing_id).expect("No such listing").private_settlement, "Private listings run through the relayer");
        let secrets = self.mark_running(listing_id, &buyer, "chain");
        let input = json!({ "op": "negotiate", "listing_id": listing_id, "buyer": buyer });

        self.request_run(input, Some(secrets), buyer.clone()).then(
            Self::ext(env::current_account_id())
                .with_static_gas(CALLBACK_GAS)
                .on_room_result(listing_id, buyer),
        )
    }

    /// Anyone may relay: the signature, not the sender, is what counts.
    pub fn settle_signed(
        &mut self,
        listing_id: u64,
        buyer: AccountId,
        deal: bool,
        price: u64,
        ct_ref: String,
        ct_hash: String,
        sig: String,
    ) {
        let room = self.rooms.get(&(listing_id, buyer.clone())).expect("No room");
        require!(room.status == Status::Running, "Room is not running");
        let message = format!(
            "darkroom-v1|{}|{listing_id}|{buyer}|{deal}|{price}|{ct_ref}|{ct_hash}",
            env::current_account_id()
        );
        let sig: [u8; 64] = hex::decode(&sig).ok().and_then(|s| s.try_into().ok()).expect("Bad signature");
        require!(env::ed25519_verify(&sig, message.as_bytes(), &self.enclave_key), "Bad signature");
        let verdict = json!({ "deal": deal, "price": price, "ct_ref": ct_ref, "ct_hash": ct_hash });
        self.settle(listing_id, buyer, verdict);
    }

    /// Frees a budget if a relayed run never reports back.
    pub fn refund_stale(&mut self, listing_id: u64, buyer: AccountId) {
        let room = self.rooms.get(&(listing_id, buyer.clone())).expect("No room");
        require!(room.status == Status::Running, "Room is not running");
        require!(env::block_height() > room.opened_at + STALE_AFTER_BLOCKS, "Room is not stale yet");
        self.settle(listing_id, buyer, Value::Null);
    }

    /// Payment first, then reveal: the buyer's key gets the secret only after a recorded deal.
    /// Retryable, so a failed run costs a retry and not the secret. The buyer reads the result
    /// from OutLayer public storage under `reveal:<ct_ref>`.
    #[payable]
    pub fn reveal(&mut self, listing_id: u64) -> Promise {
        require!(env::attached_deposit() >= MIN_RUN_DEPOSIT, "Attach at least 0.1 NEAR");
        let buyer = env::predecessor_account_id();
        let room = self.rooms.get(&(listing_id, buyer.clone())).expect("No room");
        if !matches!(room.status, Status::Deal { .. }) {
            env::panic_str("No deal to reveal");
        }
        let input = json!({ "op": "reveal", "listing_id": listing_id, "buyer": buyer });
        self.request_run(input, None, buyer)
    }

    #[private]
    pub fn on_room_result(
        &mut self,
        listing_id: u64,
        buyer: AccountId,
        #[callback_result] result: Result<Value, PromiseError>,
    ) {
        self.settle(listing_id, buyer, result.unwrap_or(Value::Null));
    }

    /// Refunds a funded room that never ran.
    pub fn cancel(&mut self, listing_id: u64) {
        let buyer = env::predecessor_account_id();
        let room = self.rooms.get_mut(&(listing_id, buyer.clone())).expect("No room");
        require!(room.status == Status::Funded, "Room already used");
        room.status = Status::Cancelled;
        let cap = room.cap.0;
        // A cancelled room frees its slot. The room itself stays, so a buyer gets one try.
        self.listings.get_mut(&listing_id).expect("No such listing").rooms_opened -= 1;
        self.pay(buyer, cap);
    }

    /// Retries a payout that failed.
    pub fn claim(&mut self) {
        let account = env::predecessor_account_id();
        let amount = self.owed.remove(&account).expect("Nothing owed");
        self.pay(account, amount);
    }

    #[private]
    pub fn on_payout(&mut self, account: AccountId, amount: U128) {
        if !is_promise_success() {
            *self.owed.entry(account).or_insert(0) += amount.0;
        }
    }

    pub fn listing_count(&self) -> u64 {
        self.next_listing
    }

    pub fn get_enclave_key(&self) -> String {
        hex::encode(self.enclave_key)
    }

    pub fn get_listing(&self, listing_id: u64) -> Option<Listing> {
        self.listings.get(&listing_id).cloned()
    }

    pub fn get_room(&self, listing_id: u64, buyer: AccountId) -> Option<Room> {
        self.rooms.get(&(listing_id, buyer)).cloned()
    }

    pub fn get_owed(&self, account: AccountId) -> U128 {
        U128(self.owed.get(&account).copied().unwrap_or(0))
    }
}

fn is_hex(text: &str, len: usize) -> bool {
    text.len() == len && text.bytes().all(|b| b.is_ascii_hexdigit())
}

impl Darkroom {
    /// Public rooms have no bond: `bond_done` starts true for them.
    fn close_bond(&mut self, listing_id: u64, buyer: &AccountId) -> u128 {
        let room = self.rooms.get_mut(&(listing_id, buyer.clone())).expect("No room");
        room.bond_done = true;
        room.cap.0
    }

    fn add_room(&mut self, buyer: AccountId, open: OpenMsg, cap: U128) {
        // A dust room would burn a slot and model calls for nothing.
        require!(cap.0 >= USDC as u128, "Budget below the lowest price");
        // The room's schema carries prices as u64.
        require!(cap.0 <= u64::MAX as u128, "Budget too large");
        require!(is_hex(&open.buyer_pubkey, X25519_KEY_HEX_LEN), "Bad buyer key");
        let listing = self.listings.get_mut(&open.listing_id).expect("No such listing");
        let mandate = open.sealed_mandate.unwrap_or_default();
        require!(listing.private_settlement != mandate.is_empty(), "Wrong door for this listing");
        if listing.private_settlement {
            require!(is_hex(&mandate, MANDATE_HEX_LEN), "Bad mandate");
            require!(cap == listing.bond, "Send exactly the bond");
        }
        let private = listing.private_settlement;
        require!(listing.rooms_opened < listing.max_rooms, "Listing has no rooms left");
        if let Some(target) = &listing.target {
            require!(*target == buyer, "This finding is for another buyer");
        }
        listing.rooms_opened += 1;
        let key = (open.listing_id, buyer);
        require!(!self.rooms.contains_key(&key), "One room per buyer per listing");
        self.rooms.insert(
            key,
            Room {
                cap,
                buyer_pubkey: open.buyer_pubkey,
                protected_value: open.protected_value,
                status: Status::Funded,
                opened_at: 0,
                door: String::new(),
                mandate,
                bond_done: !private,
            },
        );
    }

    fn mark_running(&mut self, listing_id: u64, buyer: &AccountId, door: &str) -> Value {
        let listing = self.listings.get(&listing_id).expect("No such listing").clone();
        let room = self.rooms.get_mut(&(listing_id, buyer.clone())).expect("Fund the room first");
        require!(room.status == Status::Funded, "Room already used");
        room.status = Status::Running;
        room.door = door.to_string();
        room.opened_at = env::block_height();
        json!({ "profile": listing.profile, "account_id": listing.seller })
    }

    /// Must not panic: a panic here would strand the escrow in `Running`.
    fn settle(&mut self, listing_id: u64, buyer: AccountId, value: Value) {
        let key = (listing_id, buyer.clone());
        let (Some(listing), Some(room)) =
            (self.listings.get(&listing_id).cloned(), self.rooms.get_mut(&key))
        else {
            return;
        };
        if room.status != Status::Running {
            return;
        }
        let cap = room.cap.0;
        let private = listing.private_settlement;
        match accepted_deal(value, cap, private) {
            Some(verdict) => {
                let price = verdict.price as u128;
                room.status = Status::Deal {
                    price: U128(price),
                    ct_ref: verdict.ct_ref,
                    ct_hash: verdict.ct_hash,
                };
                // The pay window runs from here. A private bond stays until paid or forfeited.
                room.opened_at = env::block_height();
                if !private {
                    self.pay(listing.seller, price);
                    self.pay(buyer, cap - price);
                }
            }
            None => {
                room.status = Status::NoDeal;
                self.pay(buyer, cap);
            }
        }
    }

    fn request_run(&self, input: Value, secrets_ref: Option<Value>, payer: AccountId) -> Promise {
        Promise::new(self.outlayer.clone()).function_call(
            "request_execution".to_string(),
            json!({
                "source": { "Project": { "project_id": self.project_id } },
                // Workers ignore a request that omits any limit, and it times out with no error.
                "resource_limits": { "max_instructions": 10_000_000_000u64, "max_memory_mb": 128, "max_execution_seconds": 90 },
                "input_data": input.to_string(),
                "secrets_ref": secrets_ref,
                "response_format": "Json",
                "payer_account_id": payer,
            })
            .to_string()
            .into_bytes(),
            env::attached_deposit(),
            OUTLAYER_GAS,
        )
    }

    fn pay(&self, account: AccountId, amount: u128) {
        if amount == 0 {
            return;
        }
        Promise::new(self.token.clone())
            .function_call(
                "ft_transfer".to_string(),
                json!({ "receiver_id": account, "amount": U128(amount) }).to_string().into_bytes(),
                NearToken::from_yoctonear(1),
                FT_TRANSFER_GAS,
            )
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(PAYOUT_CALLBACK_GAS)
                    .on_payout(account, U128(amount)),
            )
            .detach();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    const COMMITMENT: &str = "abababababababababababababababababababababababababababababababab";

    fn signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[3; 32])
    }

    fn signed(key: &ed25519_dalek::SigningKey, listing: u64, buyer: &str, deal: bool, price: u64) -> String {
        use ed25519_dalek::Signer;
        let message = format!("darkroom-v1|darkroom|{listing}|{buyer}|{deal}|{price}|r|h");
        hex::encode(key.sign(message.as_bytes()).to_bytes())
    }

    fn started() -> Darkroom {
        let mut c = funded();
        as_caller("buyer");
        c.start_room(0);
        c
    }

    fn open_msg(listing: u64) -> String {
        json!({ "listing_id": listing, "buyer_pubkey": "ab".repeat(32), "protected_value": 50_000 }).to_string()
    }

    fn acct(name: &str) -> AccountId {
        name.parse().unwrap()
    }

    fn as_caller(who: &str) {
        testing_env!(VMContextBuilder::new()
            .predecessor_account_id(acct(who))
            .current_account_id(acct("darkroom"))
            .attached_deposit(NearToken::from_millinear(200))
            .build());
    }

    /// Listing 0 by seller, room funded by buyer with a cap of 10.
    fn funded() -> Darkroom {
        as_caller("seller");
        let mut c = Darkroom::new(acct("outlayer"), "o/room".to_string(), acct("usdc"), hex::encode(signing_key().verifying_key().to_bytes()));
        c.list("listing-0".to_string(), "t".to_string(), 2, COMMITMENT.to_string(), None, false, U128(0));
        as_caller("usdc");
        c.ft_on_transfer(acct("buyer"), U128(20 * USDC as u128), open_msg(0));
        c
    }

    fn running() -> Darkroom {
        let mut c = funded();
        as_caller("buyer");
        let _ = c.open_room(0);
        c
    }

    fn status(c: &Darkroom) -> Status {
        c.get_room(0, acct("buyer")).unwrap().status
    }

    fn settle(value: Value) -> Status {
        let mut c = running();
        c.on_room_result(0, acct("buyer"), Ok(value));
        status(&c)
    }

    #[test]
    fn valid_verdict_settles_as_deal() {
        let got = settle(json!({"deal": true, "price": 5_000_000, "ct_ref": "r", "ct_hash": "h"}));
        assert_eq!(got, Status::Deal { price: U128(5_000_000), ct_ref: "r".into(), ct_hash: "h".into() });
    }

    #[test]
    fn everything_else_is_no_deal() {
        let mut c = funded();
        let cases = [
            Value::Null,
            json!({"deal": false, "price": 0}),
            json!({"deal": true, "price": 50_000_000, "ct_ref": "r", "ct_hash": "h"}),
            json!({"deal": true, "price": 0, "ct_ref": "r", "ct_hash": "h"}),
            json!({"deal": true, "price": 7_000_000, "ct_ref": "r", "ct_hash": "h"}),
            json!({"deal": true, "price": 5_000_001, "ct_ref": "r", "ct_hash": "h"}),
            json!({"deal": true, "price": 7}),
            json!({"deal": true, "price": 5_000_000, "ct_ref": "r", "ct_hash": "h", "note": "smuggled"}),
        ];
        for (i, value) in cases.into_iter().enumerate() {
            let listing = i as u64 + 1;
            c.list("p".to_string(), "t".to_string(), 1, COMMITMENT.to_string(), None, false, U128(0));
            as_caller("usdc");
            c.ft_on_transfer(acct("buyer"), U128(20 * USDC as u128), open_msg(listing));
            as_caller("buyer");
            let _ = c.open_room(listing);
            c.on_room_result(listing, acct("buyer"), Ok(value));
            assert_eq!(c.get_room(listing, acct("buyer")).unwrap().status, Status::NoDeal);
        }
    }

    #[test]
    fn failed_run_is_no_deal() {
        let mut c = running();
        c.on_room_result(0, acct("buyer"), Err(PromiseError::Failed));
        assert_eq!(status(&c), Status::NoDeal);
    }

    #[test]
    fn a_signed_deal_settles_from_any_relayer() {
        let mut c = started();
        let sig = signed(&signing_key(), 0, "buyer", true, 5_000_000);
        as_caller("anyone");
        c.settle_signed(0, acct("buyer"), true, 5_000_000, "r".into(), "h".into(), sig);
        assert_eq!(status(&c), Status::Deal { price: U128(5_000_000), ct_ref: "r".into(), ct_hash: "h".into() });
    }

    #[test]
    fn a_signed_no_deal_refunds() {
        let mut c = started();
        let sig = signed(&signing_key(), 0, "buyer", false, 0);
        c.settle_signed(0, acct("buyer"), false, 0, "r".into(), "h".into(), sig);
        assert_eq!(status(&c), Status::NoDeal);
    }

    #[test]
    #[should_panic(expected = "Bad signature")]
    fn a_forged_signature_is_refused() {
        let mut c = started();
        let forger = ed25519_dalek::SigningKey::from_bytes(&[4; 32]);
        let sig = signed(&forger, 0, "buyer", true, 5_000_000);
        c.settle_signed(0, acct("buyer"), true, 5_000_000, "r".into(), "h".into(), sig);
    }

    #[test]
    #[should_panic(expected = "Bad signature")]
    fn a_relayer_cannot_change_the_price() {
        let mut c = started();
        let sig = signed(&signing_key(), 0, "buyer", true, 5_000_000);
        c.settle_signed(0, acct("buyer"), true, 20_000_000, "r".into(), "h".into(), sig);
    }

    #[test]
    #[should_panic(expected = "Bad signature")]
    fn a_relayer_cannot_flip_a_no_deal_into_a_deal() {
        let mut c = started();
        let sig = signed(&signing_key(), 0, "buyer", false, 0);
        c.settle_signed(0, acct("buyer"), true, 0, "r".into(), "h".into(), sig);
    }

    #[test]
    #[should_panic(expected = "Bad signature")]
    fn a_signature_cannot_move_to_another_buyer() {
        let mut c = started();
        as_caller("usdc");
        c.ft_on_transfer(acct("rival"), U128(20 * USDC as u128), open_msg(0));
        as_caller("rival");
        c.start_room(0);
        let sig = signed(&signing_key(), 0, "buyer", true, 5_000_000);
        c.settle_signed(0, acct("rival"), true, 5_000_000, "r".into(), "h".into(), sig);
    }

    #[test]
    #[should_panic(expected = "Room is not running")]
    fn a_signature_cannot_settle_twice() {
        let mut c = started();
        let sig = signed(&signing_key(), 0, "buyer", true, 5_000_000);
        c.settle_signed(0, acct("buyer"), true, 5_000_000, "r".into(), "h".into(), sig.clone());
        c.settle_signed(0, acct("buyer"), true, 5_000_000, "r".into(), "h".into(), sig);
    }

    #[test]
    #[should_panic(expected = "Room is not running")]
    fn a_funded_room_cannot_settle_before_it_starts() {
        let mut c = funded();
        let sig = signed(&signing_key(), 0, "buyer", true, 5_000_000);
        c.settle_signed(0, acct("buyer"), true, 5_000_000, "r".into(), "h".into(), sig);
    }

    #[test]
    fn a_signed_price_off_bucket_or_over_cap_still_refunds() {
        let mut c = started();
        let sig = signed(&signing_key(), 0, "buyer", true, 7_000_000);
        c.settle_signed(0, acct("buyer"), true, 7_000_000, "r".into(), "h".into(), sig);
        assert_eq!(status(&c), Status::NoDeal);
    }

    #[test]
    #[should_panic(expected = "Room is not stale yet")]
    fn a_running_room_cannot_be_refunded_early() {
        started().refund_stale(0, acct("buyer"));
    }

    #[test]
    fn a_silent_relayer_cannot_trap_the_budget_and_cannot_settle_later() {
        let mut c = started();
        testing_env!(VMContextBuilder::new()
            .predecessor_account_id(acct("anyone"))
            .current_account_id(acct("darkroom"))
            .block_height(STALE_AFTER_BLOCKS + 1)
            .build());
        c.refund_stale(0, acct("buyer"));
        assert_eq!(status(&c), Status::NoDeal);
    }

    #[test]
    #[should_panic(expected = "This finding is for another buyer")]
    fn only_the_target_can_buy_a_targeted_listing() {
        let mut c = funded();
        c.list("p".to_string(), "t".to_string(), 3, COMMITMENT.to_string(), Some(acct("owner")), false, U128(0));
        as_caller("usdc");
        c.ft_on_transfer(acct("attacker"), U128(USDC as u128), open_msg(1));
    }

    #[test]
    fn the_target_can_buy() {
        let mut c = funded();
        c.list("p".to_string(), "t".to_string(), 3, COMMITMENT.to_string(), Some(acct("owner")), false, U128(0));
        as_caller("usdc");
        c.ft_on_transfer(acct("owner"), U128(USDC as u128), open_msg(1));
        assert_eq!(c.get_room(1, acct("owner")).unwrap().status, Status::Funded);
    }

    #[test]
    #[should_panic(expected = "Bad commitment")]
    fn a_listing_needs_a_commitment() {
        let mut c = funded();
        c.list("p".to_string(), "t".to_string(), 1, "nope".to_string(), None, false, U128(0));
    }

    #[test]
    #[should_panic(expected = "Listing has no rooms left")]
    fn sybil_buyers_run_out_of_rooms() {
        let mut c = funded();
        c.ft_on_transfer(acct("sybil1"), U128(USDC as u128), open_msg(0));
        c.ft_on_transfer(acct("sybil2"), U128(USDC as u128), open_msg(0));
    }

    #[test]
    #[should_panic(expected = "Bad buyer key")]
    fn rejects_a_malformed_buyer_key() {
        let mut c = funded();
        let msg = json!({ "listing_id": 0, "buyer_pubkey": "nope", "protected_value": 1 }).to_string();
        c.ft_on_transfer(acct("other"), U128(USDC as u128), msg);
    }

    #[test]
    #[should_panic(expected = "Wrong token")]
    fn rejects_other_tokens() {
        let mut c = funded();
        as_caller("fake-usdc");
        c.ft_on_transfer(acct("other"), U128(USDC as u128), open_msg(0));
    }

    #[test]
    #[should_panic(expected = "One room per buyer per listing")]
    fn one_room_per_buyer() {
        let mut c = funded();
        c.ft_on_transfer(acct("buyer"), U128(USDC as u128), open_msg(0));
    }

    #[test]
    #[should_panic(expected = "Room already used")]
    fn room_runs_once() {
        let mut c = running();
        let _ = c.open_room(0);
    }

    #[test]
    #[should_panic(expected = "Room already used")]
    fn cannot_cancel_a_running_room() {
        running().cancel(0);
    }

    #[test]
    #[should_panic(expected = "No deal to reveal")]
    fn no_reveal_before_a_deal() {
        let mut c = running();
        as_caller("buyer");
        let _ = c.reveal(0);
    }

    #[test]
    #[should_panic(expected = "No deal to reveal")]
    fn no_reveal_after_no_deal() {
        let mut c = running();
        c.on_room_result(0, acct("buyer"), Ok(Value::Null));
        as_caller("buyer");
        let _ = c.reveal(0);
    }

    #[test]
    fn buyer_can_reveal_after_a_deal_and_retry() {
        let mut c = running();
        c.on_room_result(0, acct("buyer"), Ok(json!({"deal": true, "price": 5_000_000, "ct_ref": "r", "ct_hash": "h"})));
        as_caller("buyer");
        let _ = c.reveal(0);
        let _ = c.reveal(0);
    }

    #[test]
    #[should_panic(expected = "No room")]
    fn only_the_buyer_can_reveal() {
        let mut c = running();
        c.on_room_result(0, acct("buyer"), Ok(json!({"deal": true, "price": 5_000_000, "ct_ref": "r", "ct_hash": "h"})));
        as_caller("stranger");
        let _ = c.reveal(0);
    }

    #[test]
    fn funded_room_can_cancel() {
        let mut c = funded();
        as_caller("buyer");
        c.cancel(0);
        assert_eq!(status(&c), Status::Cancelled);
    }

    #[test]
    fn failed_payout_stays_claimable() {
        let mut c = funded();
        testing_env!(
            VMContextBuilder::new().predecessor_account_id(acct("darkroom")).current_account_id(acct("darkroom")).build(),
            near_sdk::test_vm_config(),
            near_sdk::RuntimeFeesConfig::test(),
            Default::default(),
            vec![near_sdk::PromiseResult::Failed]
        );
        c.on_payout(acct("seller"), U128(7));
        assert_eq!(c.get_owed(acct("seller")), U128(7));
        as_caller("seller");
        c.claim();
        assert_eq!(c.get_owed(acct("seller")), U128(0));
    }

    const BOND: u128 = USDC as u128;

    fn sealed_msg(listing: u64) -> String {
        json!({ "listing_id": listing, "buyer_pubkey": "ab".repeat(32), "protected_value": 0, "sealed_mandate": "ef".repeat(MANDATE_HEX_LEN / 2) }).to_string()
    }

    fn private_room() -> Darkroom {
        as_caller("seller");
        let mut c = Darkroom::new(acct("outlayer"), "o/room".to_string(), acct("usdc"), hex::encode(signing_key().verifying_key().to_bytes()));
        c.list("p".to_string(), "t".to_string(), 3, COMMITMENT.to_string(), Some(acct("buyer")), true, U128(BOND));
        as_caller("usdc");
        c.ft_on_transfer(acct("buyer"), U128(BOND), sealed_msg(0));
        as_caller("buyer");
        c.start_room(0);
        c
    }

    fn sign_text(message: String) -> String {
        use ed25519_dalek::Signer;
        hex::encode(signing_key().sign(message.as_bytes()).to_bytes())
    }

    fn private_deal() -> Darkroom {
        let mut c = private_room();
        c.settle_signed(0, acct("buyer"), true, 0, "r".into(), "h".into(), sign_text("darkroom-v1|darkroom|0|buyer|true|0|r|h".to_string()));
        c
    }

    fn at_block(height: u64) {
        testing_env!(VMContextBuilder::new()
            .predecessor_account_id(acct("anyone"))
            .current_account_id(acct("darkroom"))
            .block_height(height)
            .build());
    }

    fn payouts() -> usize {
        near_sdk::test_utils::get_created_receipts().iter().filter(|r| r.receiver_id == acct("usdc")).count()
    }

    #[test]
    fn a_private_deal_records_no_price_and_holds_the_bond() {
        let c = private_deal();
        let room = c.get_room(0, acct("buyer")).unwrap();
        assert!(matches!(room.status, Status::Deal { price: U128(0), .. }));
        assert_eq!(room.mandate.len(), MANDATE_HEX_LEN);
        assert_eq!(room.protected_value, 0);
        assert!(!room.bond_done);
        assert_eq!(payouts(), 0);
    }

    #[test]
    fn a_priced_private_verdict_is_no_deal_and_refunds_the_bond() {
        let mut c = private_room();
        let sig = sign_text("darkroom-v1|darkroom|0|buyer|true|5000000|r|h".to_string());
        c.settle_signed(0, acct("buyer"), true, 5_000_000, "r".into(), "h".into(), sig);
        assert_eq!(c.get_room(0, acct("buyer")).unwrap().status, Status::NoDeal);
        assert_eq!(payouts(), 1);
    }

    #[test]
    #[should_panic(expected = "Private listings run through the relayer")]
    fn a_private_room_has_one_door() {
        as_caller("seller");
        let mut c = Darkroom::new(acct("outlayer"), "o/room".to_string(), acct("usdc"), hex::encode(signing_key().verifying_key().to_bytes()));
        c.list("p".to_string(), "t".to_string(), 3, COMMITMENT.to_string(), None, true, U128(BOND));
        as_caller("usdc");
        c.ft_on_transfer(acct("buyer"), U128(BOND), sealed_msg(0));
        as_caller("buyer");
        c.open_room(0);
    }

    #[test]
    #[should_panic(expected = "Budget below the lowest price")]
    fn a_dust_room_is_refused() {
        let mut c = funded();
        as_caller("usdc");
        c.ft_on_transfer(acct("rival"), U128(1), open_msg(0));
    }

    #[test]
    #[should_panic(expected = "Profile too long")]
    fn a_huge_profile_is_refused() {
        as_caller("seller");
        let mut c = Darkroom::new(acct("outlayer"), "o/room".to_string(), acct("usdc"), hex::encode(signing_key().verifying_key().to_bytes()));
        c.list("p".repeat(290_000), "t".to_string(), 3, COMMITMENT.to_string(), None, false, U128(0));
    }

    #[test]
    fn a_cancelled_room_frees_its_slot() {
        let mut c = funded();
        as_caller("buyer");
        c.cancel(0);
        assert_eq!(c.get_listing(0).unwrap().rooms_opened, 0);
    }

    #[test]
    #[should_panic(expected = "One room per buyer per listing")]
    fn a_cancelled_buyer_gets_no_second_room() {
        let mut c = funded();
        as_caller("buyer");
        c.cancel(0);
        as_caller("usdc");
        c.ft_on_transfer(acct("buyer"), U128(USDC as u128), open_msg(0));
    }

    #[test]
    fn a_paid_signature_returns_the_bond_once() {
        let mut c = private_deal();
        c.confirm_paid(0, acct("buyer"), sign_text("darkroom-paid-v1|darkroom|0|buyer".to_string()));
        assert!(c.get_room(0, acct("buyer")).unwrap().bond_done);
        assert_eq!(payouts(), 1);
    }

    #[test]
    #[should_panic(expected = "No bond to return")]
    fn a_paid_signature_cannot_be_replayed() {
        let mut c = private_deal();
        let sig = sign_text("darkroom-paid-v1|darkroom|0|buyer".to_string());
        c.confirm_paid(0, acct("buyer"), sig.clone());
        c.confirm_paid(0, acct("buyer"), sig);
    }

    #[test]
    #[should_panic(expected = "Bad signature")]
    fn a_forged_paid_signature_is_refused() {
        let mut c = private_deal();
        c.confirm_paid(0, acct("buyer"), sign_text("darkroom-paid-v1|darkroom|1|buyer".to_string()));
    }

    #[test]
    #[should_panic(expected = "The buyer can still pay")]
    fn a_bond_cannot_be_taken_inside_the_pay_window() {
        let mut c = private_deal();
        c.forfeit(0, acct("buyer"));
    }

    #[test]
    fn a_buyer_who_never_pays_loses_the_bond() {
        let mut c = private_deal();
        at_block(PAY_WINDOW_BLOCKS + 1);
        c.forfeit(0, acct("buyer"));
        assert!(c.get_room(0, acct("buyer")).unwrap().bond_done);
    }

    #[test]
    #[should_panic(expected = "No bond to take")]
    fn a_public_deal_has_no_bond_to_take() {
        let mut c = started();
        let sig = signed(&signing_key(), 0, "buyer", true, 5_000_000);
        c.settle_signed(0, acct("buyer"), true, 5_000_000, "r".into(), "h".into(), sig);
        at_block(PAY_WINDOW_BLOCKS + 1);
        c.forfeit(0, acct("buyer"));
    }

    #[test]
    #[should_panic(expected = "Wrong door for this listing")]
    fn a_public_listing_takes_no_mandate() {
        let mut c = funded();
        as_caller("usdc");
        c.ft_on_transfer(acct("rival"), U128(BOND), sealed_msg(0));
    }

    #[test]
    #[should_panic(expected = "Send exactly the bond")]
    fn a_private_room_takes_only_the_bond() {
        as_caller("seller");
        let mut c = Darkroom::new(acct("outlayer"), "o/room".to_string(), acct("usdc"), hex::encode(signing_key().verifying_key().to_bytes()));
        c.list("p".to_string(), "t".to_string(), 3, COMMITMENT.to_string(), None, true, U128(BOND));
        as_caller("usdc");
        c.ft_on_transfer(acct("buyer"), U128(7 * BOND), sealed_msg(0));
    }

    #[test]
    #[should_panic(expected = "This finding is for another buyer")]
    fn a_private_listing_keeps_its_target() {
        let mut c = private_room();
        as_caller("usdc");
        c.ft_on_transfer(acct("rival"), U128(BOND), sealed_msg(0));
    }

}
