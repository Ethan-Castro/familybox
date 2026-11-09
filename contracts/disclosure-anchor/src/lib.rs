//! familybox disclosure anchor.
//!
//! A family box keeps a tamper-evident log per person (each entry carries the hash of the one before).
//! This contract stores the newest chain head for each (box, person), so the box itself cannot later
//! rewrite or shorten a log without the difference showing.
//!
//! Nothing personal goes on-chain: `box_id` is random, `person_hash` is a salted hash made on the box
//! (the salt never leaves it), `head_hash` is a sha256, and `count` is the number of log entries.
//!
//! Who may write: the account that registered a box (`register_box`, paid with a deposit that covers
//! storage). The box itself then calls `anchor` with a function-call access key that can only call
//! `anchor` on this contract, so it never holds a key that can move money.
//!
//! Rules `anchor` enforces:
//! * only the box's writer can anchor for that box;
//! * hashes are 64 lowercase hex characters, box ids 3 to 64 of `a-z 0-9 _ -`;
//! * the count never goes down (a log can only grow);
//! * the same count with a different head is refused (that would be a rewritten log);
//! * new storage is paid from the box's deposit, never from the contract's own balance.
//!
//! Every anchor emits a NEP-297 event: `EVENT_JSON:{"standard":"familybox_anchor","version":"1.0.0",
//! "event":"anchored","data":[{...}]}`, so indexers can keep the full history, not just the latest head.

use near_sdk::serde_json::json;
use near_sdk::store::LookupMap;
use near_sdk::{env, near, require, AccountId, NearToken, PanicOnDefault, Promise};

pub const EVENT_STANDARD: &str = "familybox_anchor";
pub const EVENT_VERSION: &str = "1.0.0";

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
pub struct BoxRecord {
    /// The account allowed to anchor for this box.
    pub writer: AccountId,
    /// What is left of the storage deposit.
    pub storage_balance: NearToken,
    /// How many people have an anchor.
    pub people: u32,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
pub struct Anchor {
    pub head_hash: String,
    pub count: u64,
    pub block_height: u64,
    pub timestamp_ns: u64,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Contract {
    boxes: LookupMap<String, BoxRecord>,
    anchors: LookupMap<String, Anchor>,
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_box_id(s: &str) -> bool {
    (3..=64).contains(&s.len())
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

fn anchor_key(box_id: &str, person_hash: &str) -> String {
    // ':' cannot appear in either part, so keys never collide.
    format!("{box_id}:{person_hash}")
}

fn emit(event: &str, data: near_sdk::serde_json::Value) {
    let ev = json!({"standard": EVENT_STANDARD, "version": EVENT_VERSION, "event": event, "data": [data]});
    env::log_str(&format!("EVENT_JSON:{ev}"));
}

fn storage_cost(bytes: u64) -> NearToken {
    env::storage_byte_cost().saturating_mul(bytes as u128)
}

#[near]
impl Contract {
    #[init]
    pub fn new() -> Self {
        Self { boxes: LookupMap::new(b"b"), anchors: LookupMap::new(b"a") }
    }

    /// Claim a box id for the caller. The attached deposit pays for this record and for later anchors.
    #[payable]
    pub fn register_box(&mut self, box_id: String) -> BoxRecord {
        require!(is_box_id(&box_id), "box_id must be 3 to 64 characters of a-z, 0-9, _ or -");
        require!(!self.boxes.contains_key(&box_id), "this box id is already registered");
        let deposit = env::attached_deposit();
        let writer = env::predecessor_account_id();
        let before = env::storage_usage();
        let mut rec = BoxRecord { writer: writer.clone(), storage_balance: NearToken::from_yoctonear(0), people: 0 };
        self.boxes.insert(box_id.clone(), rec.clone());
        self.boxes.flush();
        let cost = storage_cost(env::storage_usage().saturating_sub(before));
        require!(deposit >= cost, format!("attach at least {} yoctoNEAR to pay for storage", cost.as_yoctonear()));
        rec.storage_balance = deposit.saturating_sub(cost);
        self.boxes.insert(box_id.clone(), rec.clone()); // same size: fixed-width fields only changed
        emit("box_registered", json!({"box_id": box_id, "writer": writer}));
        rec
    }

    /// Add to a box's storage deposit. Anyone may pay.
    #[payable]
    pub fn top_up(&mut self, box_id: String) -> BoxRecord {
        let mut rec = self.boxes.get(&box_id).cloned().unwrap_or_else(|| env::panic_str("unknown box id"));
        rec.storage_balance = rec.storage_balance.saturating_add(env::attached_deposit());
        self.boxes.insert(box_id, rec.clone());
        rec
    }

    /// Hand the box to a new writer account. Needs the current writer's full-access key (1 yoctoNEAR).
    #[payable]
    pub fn set_writer(&mut self, box_id: String, writer: AccountId) -> BoxRecord {
        require!(env::attached_deposit() == NearToken::from_yoctonear(1), "attach exactly 1 yoctoNEAR");
        let mut rec = self.boxes.get(&box_id).cloned().unwrap_or_else(|| env::panic_str("unknown box id"));
        require!(env::predecessor_account_id() == rec.writer, "only the box's writer can do this");
        rec.writer = writer.clone();
        self.boxes.insert(box_id.clone(), rec.clone());
        emit("writer_changed", json!({"box_id": box_id, "writer": writer}));
        rec
    }

    /// Record the newest chain head for one person in one box.
    pub fn anchor(&mut self, box_id: String, person_hash: String, head_hash: String, count: u64) -> Anchor {
        require!(is_box_id(&box_id), "bad box_id");
        require!(is_hex64(&person_hash), "person_hash must be 64 lowercase hex characters");
        require!(is_hex64(&head_hash), "head_hash must be 64 lowercase hex characters");
        require!(count >= 1, "count must be at least 1");
        let mut rec = self.boxes.get(&box_id).cloned().unwrap_or_else(|| env::panic_str("unknown box id"));
        require!(env::predecessor_account_id() == rec.writer, "only the box's writer can anchor");

        let key = anchor_key(&box_id, &person_hash);
        let prev = self.anchors.get(&key).cloned();
        let prev_count = prev.as_ref().map(|p| p.count).unwrap_or(0);
        if let Some(p) = &prev {
            require!(count >= p.count, "count went down: a log can only grow");
            if count == p.count {
                require!(head_hash == p.head_hash, "same count, different head: the log was rewritten");
                return p.clone(); // already anchored; nothing to do
            }
        }

        let a = Anchor {
            head_hash: head_hash.clone(),
            count,
            block_height: env::block_height(),
            timestamp_ns: env::block_timestamp(),
        };
        let before = env::storage_usage();
        self.anchors.insert(key, a.clone());
        self.anchors.flush();
        let grown = env::storage_usage().saturating_sub(before);
        let cost = storage_cost(grown);
        require!(rec.storage_balance >= cost, "the box's storage deposit is used up; call top_up");
        rec.storage_balance = rec.storage_balance.saturating_sub(cost);
        if prev.is_none() {
            rec.people += 1;
        }
        self.boxes.insert(box_id.clone(), rec);

        emit(
            "anchored",
            json!({"box_id": box_id, "person_hash": person_hash, "head_hash": head_hash,
                   "count": count, "prev_count": prev_count}),
        );
        a
    }

    /// The newest anchored head for (box, person), or null.
    pub fn get(&self, box_id: String, person_hash: String) -> Option<Anchor> {
        self.anchors.get(&anchor_key(&box_id, &person_hash)).cloned()
    }

    pub fn get_box(&self, box_id: String) -> Option<BoxRecord> {
        self.boxes.get(&box_id).cloned()
    }

    /// Give back unused storage deposit to the writer. Needs the writer's full-access key (1 yoctoNEAR).
    #[payable]
    pub fn withdraw(&mut self, box_id: String, amount: NearToken) -> Promise {
        require!(env::attached_deposit() == NearToken::from_yoctonear(1), "attach exactly 1 yoctoNEAR");
        let mut rec = self.boxes.get(&box_id).cloned().unwrap_or_else(|| env::panic_str("unknown box id"));
        require!(env::predecessor_account_id() == rec.writer, "only the box's writer can do this");
        require!(amount <= rec.storage_balance, "more than the box has left");
        rec.storage_balance = rec.storage_balance.saturating_sub(amount);
        let to = rec.writer.clone();
        self.boxes.insert(box_id, rec);
        Promise::new(to).transfer(amount.saturating_add(NearToken::from_yoctonear(1)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::{accounts, get_logs, VMContextBuilder};
    use near_sdk::testing_env;

    const BOX: &str = "fb-0123456789abcdef0123";

    fn h(c: char) -> String {
        std::iter::repeat(c).take(64).collect()
    }

    fn ctx(who: usize, deposit: NearToken) {
        let mut b = VMContextBuilder::new();
        b.predecessor_account_id(accounts(who)).attached_deposit(deposit).block_height(7);
        testing_env!(b.build());
    }

    fn setup() -> Contract {
        ctx(0, NearToken::from_yoctonear(0));
        let mut c = Contract::new();
        ctx(1, NearToken::from_millinear(100));
        c.register_box(BOX.to_string());
        ctx(1, NearToken::from_yoctonear(0));
        c
    }

    #[test]
    fn register_charges_storage() {
        let c = setup();
        let rec = c.get_box(BOX.to_string()).unwrap();
        assert_eq!(rec.writer, accounts(1));
        assert!(rec.storage_balance < NearToken::from_millinear(100));
        assert!(rec.storage_balance > NearToken::from_millinear(90));
        assert_eq!(rec.people, 0);
    }

    #[test]
    #[should_panic(expected = "already registered")]
    fn register_twice_fails() {
        let mut c = setup();
        ctx(2, NearToken::from_millinear(100));
        c.register_box(BOX.to_string());
    }

    #[test]
    #[should_panic(expected = "to pay for storage")]
    fn register_without_deposit_fails() {
        ctx(0, NearToken::from_yoctonear(0));
        let mut c = Contract::new();
        ctx(1, NearToken::from_yoctonear(0));
        c.register_box(BOX.to_string());
    }

    #[test]
    #[should_panic(expected = "box_id must be")]
    fn register_bad_id_fails() {
        ctx(0, NearToken::from_yoctonear(0));
        let mut c = Contract::new();
        ctx(1, NearToken::from_millinear(100));
        c.register_box("Has Spaces".to_string());
    }

    #[test]
    fn anchor_get_and_event() {
        let mut c = setup();
        let a = c.anchor(BOX.to_string(), h('a'), h('b'), 3);
        assert_eq!(a.count, 3);
        assert_eq!(a.block_height, 7);
        assert_eq!(c.get(BOX.to_string(), h('a')), Some(a));
        assert_eq!(c.get(BOX.to_string(), h('c')), None);
        let logs = get_logs();
        let last = logs.last().unwrap();
        assert!(last.starts_with("EVENT_JSON:"));
        let ev: near_sdk::serde_json::Value = near_sdk::serde_json::from_str(&last["EVENT_JSON:".len()..]).unwrap();
        assert_eq!(ev["standard"], EVENT_STANDARD);
        assert_eq!(ev["version"], EVENT_VERSION);
        assert_eq!(ev["event"], "anchored");
        assert_eq!(ev["data"][0]["head_hash"], h('b'));
        assert_eq!(ev["data"][0]["count"], 3);
        assert_eq!(ev["data"][0]["prev_count"], 0);
        let rec = c.get_box(BOX.to_string()).unwrap();
        assert_eq!(rec.people, 1);
    }

    #[test]
    fn anchor_grows_and_charges_once_per_person() {
        let mut c = setup();
        c.anchor(BOX.to_string(), h('a'), h('b'), 3);
        let after_first = c.get_box(BOX.to_string()).unwrap().storage_balance;
        c.anchor(BOX.to_string(), h('a'), h('c'), 5);
        let after_second = c.get_box(BOX.to_string()).unwrap();
        assert_eq!(after_second.storage_balance, after_first); // same size record: no new storage
        assert_eq!(after_second.people, 1);
        assert_eq!(c.get(BOX.to_string(), h('a')).unwrap().head_hash, h('c'));
        c.anchor(BOX.to_string(), h('d'), h('e'), 1);
        assert_eq!(c.get_box(BOX.to_string()).unwrap().people, 2);
    }

    #[test]
    fn same_head_again_is_a_no_op() {
        let mut c = setup();
        c.anchor(BOX.to_string(), h('a'), h('b'), 3);
        let again = c.anchor(BOX.to_string(), h('a'), h('b'), 3);
        assert_eq!(again.count, 3);
    }

    #[test]
    #[should_panic(expected = "count went down")]
    fn rollback_refused() {
        let mut c = setup();
        c.anchor(BOX.to_string(), h('a'), h('b'), 5);
        c.anchor(BOX.to_string(), h('a'), h('c'), 4);
    }

    #[test]
    #[should_panic(expected = "the log was rewritten")]
    fn rewrite_refused() {
        let mut c = setup();
        c.anchor(BOX.to_string(), h('a'), h('b'), 5);
        c.anchor(BOX.to_string(), h('a'), h('c'), 5);
    }

    #[test]
    #[should_panic(expected = "only the box's writer can anchor")]
    fn stranger_cannot_anchor() {
        let mut c = setup();
        ctx(2, NearToken::from_yoctonear(0));
        c.anchor(BOX.to_string(), h('a'), h('b'), 1);
    }

    #[test]
    #[should_panic(expected = "unknown box id")]
    fn unknown_box() {
        let mut c = setup();
        c.anchor("fb-unknown".to_string(), h('a'), h('b'), 1);
    }

    #[test]
    #[should_panic(expected = "head_hash must be")]
    fn uppercase_hash_refused() {
        let mut c = setup();
        c.anchor(BOX.to_string(), h('a'), h('B'), 1);
    }

    #[test]
    #[should_panic(expected = "person_hash must be")]
    fn short_person_hash_refused() {
        let mut c = setup();
        c.anchor(BOX.to_string(), "abc".to_string(), h('b'), 1);
    }

    #[test]
    #[should_panic(expected = "count must be at least 1")]
    fn zero_count_refused() {
        let mut c = setup();
        c.anchor(BOX.to_string(), h('a'), h('b'), 0);
    }

    #[test]
    #[should_panic(expected = "storage deposit is used up")]
    fn storage_must_be_paid() {
        ctx(0, NearToken::from_yoctonear(0));
        let mut c = Contract::new();
        ctx(1, NearToken::from_millinear(100));
        c.register_box(BOX.to_string());
        let left = c.get_box(BOX.to_string()).unwrap().storage_balance;
        ctx(1, NearToken::from_yoctonear(1));
        c.withdraw(BOX.to_string(), left);
        ctx(1, NearToken::from_yoctonear(0));
        c.anchor(BOX.to_string(), h('a'), h('b'), 1);
    }

    #[test]
    fn top_up_adds() {
        let mut c = setup();
        let before = c.get_box(BOX.to_string()).unwrap().storage_balance;
        ctx(3, NearToken::from_millinear(10));
        let rec = c.top_up(BOX.to_string());
        assert_eq!(rec.storage_balance, before.saturating_add(NearToken::from_millinear(10)));
    }

    #[test]
    fn writer_can_hand_over() {
        let mut c = setup();
        ctx(1, NearToken::from_yoctonear(1));
        c.set_writer(BOX.to_string(), accounts(2));
        ctx(2, NearToken::from_yoctonear(0));
        c.anchor(BOX.to_string(), h('a'), h('b'), 1);
    }

    #[test]
    #[should_panic(expected = "only the box's writer can do this")]
    fn stranger_cannot_take_box() {
        let mut c = setup();
        ctx(2, NearToken::from_yoctonear(1));
        c.set_writer(BOX.to_string(), accounts(2));
    }

    #[test]
    #[should_panic(expected = "attach exactly 1 yoctoNEAR")]
    fn hand_over_needs_full_access_key() {
        let mut c = setup();
        ctx(1, NearToken::from_yoctonear(0));
        c.set_writer(BOX.to_string(), accounts(2));
    }
}
