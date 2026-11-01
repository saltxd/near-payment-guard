//! The agent payment guard contract.
//!
//! The guard holds the funds. An AI agent is given a NEAR **function-call access
//! key** restricted to this contract and to `request_payment`; such a key cannot
//! attach a deposit, so the agent can never move value, only *ask* the guard to. The
//! guard releases money only when an ed25519-signed ChainWard verdict says the payee
//! is safe **and** the owner's policy allows the amount.
//!
//! Stage A (this module today): storage, owner-only configuration, and the funds the
//! guard holds (`deposit` / `withdraw`). `request_payment` and the verdict gate arrive
//! in Stage B. The signature verification itself reuses the canonical encoding in the
//! dependency-free `guard-auth` crate, which the TypeScript signer agrees with byte for
//! byte (see `docs/canonical-bytes.md`).

use near_sdk::json_types::{Base64VecU8, U128};
use near_sdk::store::LookupSet;
use near_sdk::{
    env, near, require, AccountId, BorshStorageKey, NearToken, PanicOnDefault, Promise,
};

/// Length of a raw ed25519 public key, in bytes.
const PUBKEY_LEN: usize = 32;

/// The owner-set rules the guard enforces on every payment.
///
/// Stored with borsh and exchanged with the owner over JSON. Caps are in the
/// contract's native token unit (yoctoNEAR in the demo); `allowlist`/`denylist` hold
/// lowercase EVM destinations, matching `guard-auth`'s canonical form.
#[near(serializers = [json, borsh])]
#[derive(Clone)]
pub struct Policy {
    /// Largest single payment allowed.
    pub per_tx_cap: U128,
    /// Largest total across a rolling 24h window (enforced in a later stage).
    pub daily_cap: U128,
    /// Largest total to one destination across a rolling 24h window (later stage).
    pub per_counterparty_cap: U128,
    /// If non-empty, only these destinations may be paid (later stage).
    pub allowlist: Vec<String>,
    /// Destinations that are always refused (later stage).
    pub denylist: Vec<String>,
    /// Maximum age of a verdict, in seconds, before it is stale (later stage).
    pub max_verdict_age_sec: u64,
}

/// Storage prefixes for the collections the contract owns.
#[derive(BorshStorageKey)]
#[near]
enum StorageKey {
    /// Nonces already honoured, so a signed authorization cannot be replayed.
    UsedNonces,
}

/// Guard contract state.
#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct GuardContract {
    /// The human owner. Holds a full-access key; the only account that may configure
    /// the guard or withdraw from it.
    owner_id: AccountId,
    /// ChainWard's ed25519 verdict public key, raw 32 bytes. Rotatable by the owner.
    chainward_pubkey: [u8; PUBKEY_LEN],
    /// The active policy.
    policy: Policy,
    /// Replay protection. A nonce is recorded the first time it is honoured and
    /// refused ever after. Populated by `request_payment` in a later stage.
    used_nonces: LookupSet<u128>,
}

#[near]
impl GuardContract {
    /// Deploys the guard: sets the owner, the ChainWard verdict key and the policy.
    ///
    /// `chainward_pubkey` is the raw 32-byte ed25519 public key, base64-encoded.
    #[init]
    pub fn new(owner_id: AccountId, chainward_pubkey: Base64VecU8, policy: Policy) -> Self {
        Self {
            owner_id,
            chainward_pubkey: to_pubkey(chainward_pubkey),
            policy,
            used_nonces: LookupSet::new(StorageKey::UsedNonces),
        }
    }

    /// Replaces the policy. Owner only.
    pub fn set_policy(&mut self, policy: Policy) {
        self.assert_owner();
        self.policy = policy;
    }

    /// Rotates the ChainWard verdict key. Owner only.
    pub fn set_chainward_pubkey(&mut self, chainward_pubkey: Base64VecU8) {
        self.assert_owner();
        self.chainward_pubkey = to_pubkey(chainward_pubkey);
    }

    /// Funds the guard. Owner only, and a deposit must be attached.
    ///
    /// The runtime adds the attached deposit to the contract balance before this runs;
    /// the method exists to make funding an explicit, owner-gated action rather than a
    /// side effect of any payable call.
    #[payable]
    pub fn deposit(&mut self) {
        self.assert_owner();
        require!(
            env::attached_deposit().as_yoctonear() > 0,
            "attach a deposit"
        );
    }

    /// Sends `amount` back to the owner. Owner only, always allowed up to the
    /// balance that is not locked for storage staking.
    pub fn withdraw(&mut self, amount: U128) -> Promise {
        self.assert_owner();
        let amount = NearToken::from_yoctonear(amount.0);
        require!(
            amount <= self.available_balance(),
            "insufficient available balance"
        );
        Promise::new(self.owner_id.clone()).transfer(amount)
    }

    /// The owner account id.
    pub fn get_owner(&self) -> AccountId {
        self.owner_id.clone()
    }

    /// The active policy.
    pub fn get_policy(&self) -> Policy {
        self.policy.clone()
    }

    /// ChainWard's verdict public key, raw 32 bytes, base64-encoded.
    pub fn get_chainward_pubkey(&self) -> Base64VecU8 {
        self.chainward_pubkey.to_vec().into()
    }

    /// Balance not locked for storage staking: what `withdraw` can pay out.
    pub fn get_available_balance(&self) -> U128 {
        U128(self.available_balance().as_yoctonear())
    }

    /// Whether a nonce has already been honoured.
    pub fn is_nonce_used(&self, nonce: U128) -> bool {
        self.used_nonces.contains(&nonce.0)
    }
}

impl GuardContract {
    /// Panics unless the caller is the owner.
    fn assert_owner(&self) {
        require!(env::predecessor_account_id() == self.owner_id, "owner only");
    }

    /// Account balance minus the amount locked for storage staking.
    fn available_balance(&self) -> NearToken {
        let locked = env::storage_byte_cost().saturating_mul(u128::from(env::storage_usage()));
        env::account_balance().saturating_sub(locked)
    }
}

/// Converts a base64-encoded public key to a fixed 32-byte array, or panics.
fn to_pubkey(bytes: Base64VecU8) -> [u8; PUBKEY_LEN] {
    let v = bytes.0;
    require!(v.len() == PUBKEY_LEN, "chainward_pubkey must be 32 bytes");
    let mut out = [0u8; PUBKEY_LEN];
    out.copy_from_slice(&v);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::testing_env;

    fn pubkey32() -> Base64VecU8 {
        vec![7u8; PUBKEY_LEN].into()
    }

    fn sample_policy() -> Policy {
        Policy {
            per_tx_cap: U128(10),
            daily_cap: U128(100),
            per_counterparty_cap: U128(50),
            allowlist: vec![],
            denylist: vec![],
            max_verdict_age_sec: 300,
        }
    }

    /// Context with `guard` as the contract and `caller` as the predecessor.
    fn context(caller: AccountId) -> VMContextBuilder {
        let mut builder = VMContextBuilder::new();
        builder
            .current_account_id(accounts(0))
            .predecessor_account_id(caller);
        builder
    }

    /// Owner is `accounts(1)`; a fresh guard constructed as the owner.
    fn owned_guard() -> GuardContract {
        testing_env!(context(accounts(1)).build());
        GuardContract::new(accounts(1), pubkey32(), sample_policy())
    }

    #[test]
    fn new_sets_owner_policy_and_key() {
        let guard = owned_guard();
        assert_eq!(guard.get_owner(), accounts(1));
        assert_eq!(guard.get_policy().per_tx_cap, U128(10));
        assert_eq!(guard.get_chainward_pubkey(), pubkey32());
    }

    #[test]
    #[should_panic(expected = "chainward_pubkey must be 32 bytes")]
    fn new_rejects_a_wrong_length_key() {
        testing_env!(context(accounts(1)).build());
        GuardContract::new(accounts(1), vec![1u8; 31].into(), sample_policy());
    }

    #[test]
    fn owner_can_set_policy() {
        let mut guard = owned_guard();
        testing_env!(context(accounts(1)).build());
        let mut next = sample_policy();
        next.per_tx_cap = U128(999);
        guard.set_policy(next);
        assert_eq!(guard.get_policy().per_tx_cap, U128(999));
    }

    #[test]
    #[should_panic(expected = "owner only")]
    fn non_owner_cannot_set_policy() {
        let mut guard = owned_guard();
        testing_env!(context(accounts(2)).build());
        guard.set_policy(sample_policy());
    }

    #[test]
    fn owner_can_rotate_the_key() {
        let mut guard = owned_guard();
        testing_env!(context(accounts(1)).build());
        let rotated: Base64VecU8 = vec![9u8; PUBKEY_LEN].into();
        guard.set_chainward_pubkey(rotated.clone());
        assert_eq!(guard.get_chainward_pubkey(), rotated);
    }

    #[test]
    #[should_panic(expected = "owner only")]
    fn non_owner_cannot_rotate_the_key() {
        let mut guard = owned_guard();
        testing_env!(context(accounts(2)).build());
        guard.set_chainward_pubkey(vec![9u8; PUBKEY_LEN].into());
    }

    #[test]
    fn owner_can_deposit_with_an_attached_amount() {
        let mut guard = owned_guard();
        testing_env!(context(accounts(1))
            .attached_deposit(NearToken::from_yoctonear(5))
            .build());
        guard.deposit();
    }

    #[test]
    #[should_panic(expected = "attach a deposit")]
    fn deposit_requires_an_attached_amount() {
        let mut guard = owned_guard();
        testing_env!(context(accounts(1)).build());
        guard.deposit();
    }

    #[test]
    #[should_panic(expected = "owner only")]
    fn non_owner_cannot_deposit() {
        let mut guard = owned_guard();
        testing_env!(context(accounts(2))
            .attached_deposit(NearToken::from_yoctonear(5))
            .build());
        guard.deposit();
    }

    #[test]
    #[should_panic(expected = "owner only")]
    fn non_owner_cannot_withdraw() {
        let mut guard = owned_guard();
        testing_env!(context(accounts(2))
            .account_balance(NearToken::from_near(10))
            .build());
        let _ = guard.withdraw(U128(1));
    }

    #[test]
    fn owner_withdraw_creates_a_transfer_to_the_owner() {
        let mut guard = owned_guard();
        testing_env!(context(accounts(1))
            .account_balance(NearToken::from_near(10))
            .build());
        let _ = guard.withdraw(U128(NearToken::from_near(3).as_yoctonear()));

        let receipts = near_sdk::test_utils::get_created_receipts();
        assert_eq!(receipts.len(), 1, "exactly one transfer receipt");
        assert_eq!(receipts[0].receiver_id, accounts(1), "paid the owner");
    }

    #[test]
    #[should_panic(expected = "insufficient available balance")]
    fn withdraw_cannot_exceed_the_available_balance() {
        let mut guard = owned_guard();
        testing_env!(context(accounts(1))
            .account_balance(NearToken::from_near(1))
            .build());
        let _ = guard.withdraw(U128(NearToken::from_near(5).as_yoctonear()));
    }
}
