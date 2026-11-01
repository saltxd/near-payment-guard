//! The agent payment guard contract.
//!
//! The guard holds the funds. An AI agent is given a NEAR **function-call access
//! key** restricted to this contract and to `request_payment`; such a key cannot
//! attach a deposit, so the agent can never move value, only *ask* the guard to. The
//! guard releases money only when an ed25519-signed ChainWard verdict says the payee
//! is safe **and** the owner's policy allows the amount.
//!
//! Covered so far:
//! - Stage A: storage, owner-only configuration, the funds the guard holds
//!   (`deposit` / `withdraw`).
//! - Stage B: `request_payment` — the one method the agent's restricted key may call.
//!   It binds the verdict to this guard, verifies ChainWard's ed25519 signature over
//!   the canonical bytes, gates on the verdict, refuses a replayed nonce and the
//!   per-transaction cap, then pays the signed deposit address.
//!
//! The signature verification reuses the canonical encoding in the dependency-free
//! `guard-auth` crate, which the TypeScript signer agrees with byte for byte (see
//! `docs/canonical-bytes.md`). Freshness, the rolling caps and the allow/deny lists
//! are Stage C.

pub mod oneclick;

use near_sdk::json_types::{Base64VecU8, U128, U64};
use near_sdk::store::{LookupSet, Vector};
use near_sdk::{
    env, near, require, AccountId, BorshStorageKey, NearToken, PanicOnDefault, Promise,
};

/// Length of a raw ed25519 public key, in bytes.
const PUBKEY_LEN: usize = 32;

/// Length of an ed25519 signature, in bytes.
const SIGNATURE_LEN: usize = 64;

/// The rolling window the daily and per-counterparty caps are measured over.
const SECONDS_PER_DAY: u64 = 86_400;

/// Current block time, in unix seconds. Block time is nanoseconds on NEAR.
fn now_seconds() -> u64 {
    env::block_timestamp() / 1_000_000_000
}

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

/// A payment authorization as it arrives over JSON from the agent.
///
/// This mirrors `guard_auth::PaymentAuth` field for field, but the big integers are
/// `U128`/`U64` so they survive JSON as decimal strings. It is converted into the
/// dependency-free core type before anything is validated or encoded, so there is
/// exactly one definition of the canonical bytes (`guard-auth`), shared with the
/// TypeScript signer.
#[near(serializers = [json])]
#[derive(Clone)]
pub struct PaymentAuthArgs {
    /// NEAR account id of the guard this authorization is for. Must equal the running
    /// contract, so a verdict signed for one guard cannot be replayed against another.
    pub guard_id: String,
    /// The only address the guard will pay.
    pub deposit_address: String,
    /// Lowercase `0x`-prefixed EVM address the money must surface at.
    pub destination: String,
    /// `"base"` or `"bsc"`.
    pub chain: String,
    /// Exact amount this authorization covers, in the contract's token unit.
    pub amount: U128,
    /// `"pay"`, `"hold"` or `"unknown"`.
    pub verdict: String,
    /// The one fact the verdict rests on.
    pub reason: String,
    /// Unix seconds when ChainWard signed.
    pub issued_at: U64,
    /// Unix seconds, the 1Click quote deadline.
    pub quote_expiry: U64,
    /// Replay protection.
    pub nonce: U128,
}

impl PaymentAuthArgs {
    /// Projects the JSON args onto the dependency-free core type used for encoding
    /// and shape validation.
    fn to_core(&self) -> guard_auth::PaymentAuth {
        guard_auth::PaymentAuth {
            guard_id: self.guard_id.clone(),
            deposit_address: self.deposit_address.clone(),
            destination: self.destination.clone(),
            chain: self.chain.clone(),
            amount: self.amount.0,
            verdict: self.verdict.clone(),
            reason: self.reason.clone(),
            issued_at: self.issued_at.0,
            quote_expiry: self.quote_expiry.0,
            nonce: self.nonce.0,
        }
    }
}

/// What `request_payment` returns when a payment is released.
///
/// A refusal is a panic with a specific message, not a `paid: false` result, so a
/// caller cannot mistake a refusal for a success by ignoring a field.
#[near(serializers = [json])]
pub struct PaymentResult {
    /// Always `true`: a refusal never returns.
    pub paid: bool,
    /// The amount paid.
    pub amount: U128,
    /// The address paid, read back out of the signed authorization.
    pub deposit_address: String,
    /// The EVM destination the money is bound to surface at.
    pub destination: String,
    /// ChainWard's one fact behind the verdict.
    pub reason: String,
    /// The nonce now recorded as used.
    pub nonce: U128,
}

/// One honoured payment, kept so the rolling 24h caps can be measured.
#[near(serializers = [borsh])]
#[derive(Clone)]
struct Spend {
    /// Unix seconds the payment was made.
    at_sec: u64,
    /// Amount paid.
    amount: u128,
    /// The EVM destination it counts against (not the NEAR deposit address).
    destination: String,
}

/// Storage prefixes for the collections the contract owns.
#[derive(BorshStorageKey)]
#[near]
enum StorageKey {
    /// Nonces already honoured, so a signed authorization cannot be replayed.
    UsedNonces,
    /// The recent payments the rolling caps are measured over.
    Spends,
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
    /// refused ever after.
    used_nonces: LookupSet<u128>,
    /// Recent honoured payments, pruned to the last 24h, for the rolling caps.
    spends: Vector<Spend>,
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
            spends: Vector::new(StorageKey::Spends),
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

    /// The one method the agent's restricted key may call.
    ///
    /// The agent holds a NEAR function-call access key on the owner's account,
    /// restricted to this method; it cannot attach a deposit and cannot call anything
    /// else. So the agent can only *ask*. Every call therefore arrives with the owner
    /// as predecessor, and the method is not `#[payable]`, so the runtime rejects any
    /// attached deposit before this body runs.
    ///
    /// Checks, in order (a refusal is a panic with a specific message):
    /// 1. caller is the owner (the key restriction does the rest);
    /// 2. the authorization is shape-valid (`guard-auth`);
    /// 3. `guard_id` names *this* contract, so a verdict for another guard is refused
    ///    before the signature is even checked;
    /// 4. ChainWard's ed25519 signature verifies over the canonical bytes — only now is
    ///    any field trusted, so the verdict and reason echoed below are signed, not
    ///    attacker-chosen (this orders the signature before the verdict gate, unlike
    ///    `design.md` section 4, which checks the verdict first to save a trivial amount
    ///    of gas; see the stage notes);
    /// 5. freshness: the quote has not expired, the verdict is within
    ///    `max_verdict_age_sec`, and it was not issued after its own quote expired;
    /// 6. the verdict is `"pay"`; a `hold`/`unknown` is refused with its signed reason;
    /// 7. the nonce has not been used, then it is recorded;
    /// 8. policy: the destination is not denylisted and (if an allowlist is set) is on
    ///    it; the amount is within the per-transaction cap, the rolling 24h daily cap,
    ///    and the rolling 24h per-counterparty cap.
    ///
    /// Then it records the spend, pays the signed `deposit_address` and returns
    /// [`PaymentResult`]. The demo pays with a native NEAR transfer; the production flow
    /// releases a NEP-245 balance held inside `intents.near` via `mt_transfer` (see the
    /// design). The allow/deny lists and the per-counterparty cap key on the EVM
    /// `destination`, not the NEAR `deposit_address`.
    pub fn request_payment(
        &mut self,
        auth: PaymentAuthArgs,
        signature: Base64VecU8,
    ) -> PaymentResult {
        // 1. Only the owner (or the agent's restricted key on the owner's account).
        self.assert_owner();

        let core = auth.to_core();

        // 2. Shape: refuse with the stable code, identical to the signer's view.
        if let Some(failure) = guard_auth::validate(&core) {
            env::panic_str(&format!("invalid authorization: {}", failure.code()));
        }

        // 3. Audience: this verdict must be for this guard.
        require!(
            auth.guard_id == env::current_account_id().as_str(),
            "wrong guard"
        );

        // 4. Signature over the canonical bytes. Nothing above this line trusted a
        //    signed field; nothing below it distrusts one.
        let signature = to_signature(signature);
        let message = guard_auth::canonical_bytes(&core);
        require!(
            env::ed25519_verify(&signature, &message, &self.chainward_pubkey),
            "bad signature"
        );

        // 5. Freshness: the quote must not have expired, the verdict must be recent,
        //    and a verdict cannot be issued after its own quote expired.
        let now_sec = now_seconds();
        require!(now_sec < auth.quote_expiry.0, "quote expired");
        require!(
            auth.issued_at.0 <= auth.quote_expiry.0,
            "issued after expiry"
        );
        require!(
            now_sec.saturating_sub(auth.issued_at.0) <= self.policy.max_verdict_age_sec,
            "verdict too old"
        );

        // 6. Verdict gate. The reason is now ChainWard-signed, so it is safe to echo.
        require!(
            auth.verdict == "pay",
            format!("verdict: {}, {}", auth.verdict, auth.reason)
        );

        // 7. Replay: a nonce is honoured at most once.
        require!(
            !self.used_nonces.contains(&auth.nonce.0),
            "nonce already used"
        );
        self.used_nonces.insert(auth.nonce.0);

        // 8. Policy. Membership gates first (a banned payee is refused outright),
        //    then the amount caps. Lists and per-counterparty caps key on the EVM
        //    destination, not the NEAR deposit address.
        let amount = auth.amount.0;
        require!(
            !self.policy.denylist.contains(&auth.destination),
            "destination on denylist"
        );
        require!(
            self.policy.allowlist.is_empty() || self.policy.allowlist.contains(&auth.destination),
            "destination not on allowlist"
        );
        require!(
            amount <= self.policy.per_tx_cap.0,
            "amount exceeds per-transaction cap"
        );

        self.prune(now_sec);
        let spent_total = self.sum_window(now_sec, None);
        let spent_counterparty = self.sum_window(now_sec, Some(&auth.destination));
        require!(
            spent_total.saturating_add(amount) <= self.policy.daily_cap.0,
            "daily cap exceeded"
        );
        require!(
            spent_counterparty.saturating_add(amount) <= self.policy.per_counterparty_cap.0,
            "counterparty cap exceeded"
        );

        // 9. Record the spend against the rolling window.
        self.spends.push(Spend {
            at_sec: now_sec,
            amount,
            destination: auth.destination.clone(),
        });

        // 10. Pay the one address the signature bound us to. The transfer is scheduled
        //     as a receipt when this Promise is dropped; the method still returns
        //     PaymentResult. Bound to `_` to consume the #[must_use].
        let payee: AccountId = auth
            .deposit_address
            .parse()
            .unwrap_or_else(|_| env::panic_str("deposit_address is not a NEAR account"));
        let _ = Promise::new(payee).transfer(NearToken::from_yoctonear(amount));

        PaymentResult {
            paid: true,
            amount: auth.amount,
            deposit_address: auth.deposit_address,
            destination: auth.destination,
            reason: auth.reason,
            nonce: auth.nonce,
        }
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

    /// Total paid across all destinations in the last 24h.
    pub fn get_spent_24h(&self) -> U128 {
        U128(self.sum_window(now_seconds(), None))
    }

    /// Total paid to one EVM destination in the last 24h.
    pub fn get_counterparty_spent(&self, destination: String) -> U128 {
        U128(self.sum_window(now_seconds(), Some(&destination)))
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

    /// Sum of in-window spends, optionally filtered to one destination.
    ///
    /// Read-only: it never prunes, so the views are safe to call on `&self`. The
    /// window filter here is what makes a view correct even between prunes.
    fn sum_window(&self, now_sec: u64, destination: Option<&str>) -> u128 {
        let window_start = now_sec.saturating_sub(SECONDS_PER_DAY);
        let mut total = 0u128;
        for spend in self.spends.iter() {
            let in_window = spend.at_sec >= window_start;
            let matches = destination.is_none_or(|d| spend.destination == d);
            if in_window && matches {
                total = total.saturating_add(spend.amount);
            }
        }
        total
    }

    /// Drops spends older than the rolling window, so storage does not grow without
    /// bound. Rebuilds only when something is actually stale (`store::Vector` has no
    /// `retain`).
    fn prune(&mut self, now_sec: u64) {
        let window_start = now_sec.saturating_sub(SECONDS_PER_DAY);
        let any_stale = self.spends.iter().any(|s| s.at_sec < window_start);
        if !any_stale {
            return;
        }
        let kept: Vec<Spend> = self
            .spends
            .iter()
            .filter(|s| s.at_sec >= window_start)
            .cloned()
            .collect();
        self.spends.clear();
        for spend in kept {
            self.spends.push(spend);
        }
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

/// Converts a base64-encoded signature to a fixed 64-byte array, or panics.
fn to_signature(bytes: Base64VecU8) -> [u8; SIGNATURE_LEN] {
    let v = bytes.0;
    require!(v.len() == SIGNATURE_LEN, "signature must be 64 bytes");
    let mut out = [0u8; SIGNATURE_LEN];
    out.copy_from_slice(&v);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use near_sdk::test_utils::{accounts, get_created_receipts, VMContextBuilder};
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

    // --- Stage B: request_payment and the signed-verdict gate ---

    /// The throwaway verdict key the tests sign with. Deterministic; protects nothing.
    fn verdict_key() -> SigningKey {
        SigningKey::from_bytes(&[13u8; 32])
    }

    /// A guard whose registered verdict key is `verdict_key()`, owned by `accounts(1)`.
    fn guard_with(key: &SigningKey) -> GuardContract {
        testing_env!(context(accounts(1)).build());
        let pubkey: Base64VecU8 = key.verifying_key().to_bytes().to_vec().into();
        GuardContract::new(accounts(1), pubkey, sample_policy())
    }

    /// A shape-valid, in-policy "pay" authorization for this guard (`accounts(0)`),
    /// paying `accounts(3)`.
    fn valid_auth() -> PaymentAuthArgs {
        PaymentAuthArgs {
            guard_id: accounts(0).to_string(),
            deposit_address: accounts(3).to_string(),
            destination: format!("0x{}", "a".repeat(40)),
            chain: "base".to_string(),
            amount: U128(5),
            verdict: "pay".to_string(),
            reason: "no adverse history".to_string(),
            issued_at: U64(1_762_000_000),
            quote_expiry: U64(1_762_000_900),
            nonce: U128(1),
        }
    }

    /// Signs the canonical bytes of `auth` with `key`, exactly as the TypeScript signer
    /// does: over `guard_auth::canonical_bytes`, the one shared definition.
    fn sign(auth: &PaymentAuthArgs, key: &SigningKey) -> Base64VecU8 {
        let bytes = guard_auth::canonical_bytes(&auth.to_core());
        key.sign(&bytes).to_bytes().to_vec().into()
    }

    /// `valid_auth`'s `issued_at`, in nanoseconds, so block time can be set relative
    /// to the verdict in freshness tests.
    const ISSUED_AT_SEC: u64 = 1_762_000_000;

    /// Context for a payment request: owner predecessor, a funded guard, block time
    /// 60s after the verdict was issued (inside the freshness window).
    fn pay_env() {
        pay_env_at(ISSUED_AT_SEC + 60);
    }

    /// `pay_env` with the block time set to `now_sec`.
    fn pay_env_at(now_sec: u64) {
        testing_env!(context(accounts(1))
            .account_balance(NearToken::from_near(10))
            .block_timestamp(now_sec * 1_000_000_000)
            .build());
    }

    #[test]
    fn a_valid_signed_request_pays_the_bound_address() {
        let key = verdict_key();
        let mut guard = guard_with(&key);
        pay_env();
        let auth = valid_auth();
        let signature = sign(&auth, &key);

        let result = guard.request_payment(auth, signature);

        assert!(result.paid);
        assert_eq!(result.amount, U128(5));
        assert_eq!(result.deposit_address, accounts(3).to_string());
        assert!(guard.is_nonce_used(U128(1)), "the nonce is now recorded");

        let receipts = get_created_receipts();
        assert_eq!(receipts.len(), 1, "exactly one transfer");
        assert_eq!(
            receipts[0].receiver_id,
            accounts(3),
            "paid the deposit address"
        );
    }

    #[test]
    #[should_panic(expected = "bad signature")]
    fn a_tampered_destination_fails_the_signature() {
        let key = verdict_key();
        let mut guard = guard_with(&key);
        pay_env();
        let auth = valid_auth();
        let signature = sign(&auth, &key);
        let mut tampered = auth;
        tampered.destination = format!("0x{}", "b".repeat(40));
        let _ = guard.request_payment(tampered, signature);
    }

    #[test]
    #[should_panic(expected = "bad signature")]
    fn swapping_in_a_different_deposit_address_fails() {
        // Scenario 5: the agent keeps a clean verdict's signature but redirects the
        // money to an address of its own. The deposit address is inside the signed
        // bytes, so the signature no longer verifies.
        let key = verdict_key();
        let mut guard = guard_with(&key);
        pay_env();
        let auth = valid_auth();
        let signature = sign(&auth, &key);
        let mut redirected = auth;
        redirected.deposit_address = accounts(4).to_string();
        let _ = guard.request_payment(redirected, signature);
    }

    #[test]
    #[should_panic(expected = "bad signature")]
    fn a_signature_from_the_wrong_key_fails() {
        let registered = verdict_key();
        let mut guard = guard_with(&registered);
        pay_env();
        let auth = valid_auth();
        let impostor = SigningKey::from_bytes(&[99u8; 32]);
        let signature = sign(&auth, &impostor);
        let _ = guard.request_payment(auth, signature);
    }

    #[test]
    #[should_panic(expected = "signature must be 64 bytes")]
    fn a_wrong_length_signature_is_refused() {
        let key = verdict_key();
        let mut guard = guard_with(&key);
        pay_env();
        let auth = valid_auth();
        let _ = guard.request_payment(auth, vec![0u8; 63].into());
    }

    #[test]
    #[should_panic(expected = "nonce already used")]
    fn replaying_a_nonce_fails() {
        // Scenario 3: the first request succeeds (no panic); the replay is refused.
        let key = verdict_key();
        let mut guard = guard_with(&key);
        pay_env();
        let auth = valid_auth();
        let signature = sign(&auth, &key);
        let first = guard.request_payment(auth.clone(), signature.clone());
        assert!(first.paid, "the first request is honoured");
        pay_env();
        let _ = guard.request_payment(auth, signature);
    }

    #[test]
    #[should_panic(expected = "wrong guard")]
    fn a_verdict_for_another_guard_is_refused() {
        // The classic missing-audience bug: a genuine signature, but for a different
        // contract. Refused before the signature is even checked.
        let key = verdict_key();
        let mut guard = guard_with(&key);
        pay_env();
        let mut auth = valid_auth();
        auth.guard_id = "other-guard.near".to_string();
        let signature = sign(&auth, &key);
        let _ = guard.request_payment(auth, signature);
    }

    #[test]
    #[should_panic(expected = "invalid authorization: destination_invalid")]
    fn a_shape_invalid_authorization_is_refused_with_its_code() {
        // An uppercase EVM address: shape-invalid, so it never reaches the signature.
        let key = verdict_key();
        let mut guard = guard_with(&key);
        pay_env();
        let mut auth = valid_auth();
        auth.destination = format!("0x{}", "A".repeat(40));
        let signature = sign(&auth, &key);
        let _ = guard.request_payment(auth, signature);
    }

    #[test]
    #[should_panic(expected = "verdict: hold, sanctions list match")]
    fn a_hold_verdict_is_refused_with_its_signed_reason() {
        // Scenario 2: the payee is sanctioned, so ChainWard signs a hold. The signature
        // is genuine, so the guard echoes the signed reason rather than paying.
        let key = verdict_key();
        let mut guard = guard_with(&key);
        pay_env();
        let mut auth = valid_auth();
        auth.verdict = "hold".to_string();
        auth.reason = "sanctions list match".to_string();
        let signature = sign(&auth, &key);
        let _ = guard.request_payment(auth, signature);
    }

    #[test]
    #[should_panic(expected = "amount exceeds per-transaction cap")]
    fn an_amount_over_the_per_tx_cap_is_refused() {
        // sample_policy caps a single payment at 10.
        let key = verdict_key();
        let mut guard = guard_with(&key);
        pay_env();
        let mut auth = valid_auth();
        auth.amount = U128(11);
        let signature = sign(&auth, &key);
        let _ = guard.request_payment(auth, signature);
    }

    #[test]
    #[should_panic(expected = "owner only")]
    fn a_non_owner_cannot_request_payment() {
        // A key that is not on the owner's account (predecessor != owner) is rejected
        // by the contract, over and above the protocol's method restriction.
        let key = verdict_key();
        let mut guard = guard_with(&key);
        let auth = valid_auth();
        let signature = sign(&auth, &key);
        testing_env!(context(accounts(2))
            .account_balance(NearToken::from_near(10))
            .build());
        let _ = guard.request_payment(auth, signature);
    }

    #[test]
    fn a_pay_verdict_at_exactly_the_cap_is_honoured() {
        // Boundary: amount == per_tx_cap passes (the cap is inclusive).
        let key = verdict_key();
        let mut guard = guard_with(&key);
        pay_env();
        let mut auth = valid_auth();
        auth.amount = U128(10);
        let signature = sign(&auth, &key);
        let result = guard.request_payment(auth, signature);
        assert!(result.paid);
        assert_eq!(result.amount, U128(10));
    }

    // --- Stage C: freshness and the rolling policy engine ---

    /// A lowercase EVM address made of one repeated hex digit.
    fn evm(digit: &str) -> String {
        format!("0x{}", digit.repeat(40))
    }

    /// A guard with a custom policy, the verdict key registered, owned by accounts(1).
    fn guard_with_policy(key: &SigningKey, policy: Policy) -> GuardContract {
        testing_env!(context(accounts(1)).build());
        let pubkey: Base64VecU8 = key.verifying_key().to_bytes().to_vec().into();
        GuardContract::new(accounts(1), pubkey, policy)
    }

    /// A "pay" authorization issued at `now_sec` (always fresh), for `amount` to
    /// `destination`, with `nonce`.
    fn fresh_auth(now_sec: u64, amount: u128, destination: &str, nonce: u128) -> PaymentAuthArgs {
        PaymentAuthArgs {
            guard_id: accounts(0).to_string(),
            deposit_address: accounts(3).to_string(),
            destination: destination.to_string(),
            chain: "base".to_string(),
            amount: U128(amount),
            verdict: "pay".to_string(),
            reason: "ok".to_string(),
            issued_at: U64(now_sec),
            quote_expiry: U64(now_sec + 900),
            nonce: U128(nonce),
        }
    }

    /// Sets the env to `now_sec`, signs a fresh auth and submits it.
    fn request(
        guard: &mut GuardContract,
        key: &SigningKey,
        now_sec: u64,
        amount: u128,
        destination: &str,
        nonce: u128,
    ) -> PaymentResult {
        pay_env_at(now_sec);
        let auth = fresh_auth(now_sec, amount, destination, nonce);
        let signature = sign(&auth, key);
        guard.request_payment(auth, signature)
    }

    #[test]
    #[should_panic(expected = "verdict too old")]
    fn a_stale_verdict_is_refused() {
        // Scenario 6: a verdict issued more than max_verdict_age_sec (300s) ago.
        let key = verdict_key();
        let mut guard = guard_with(&key);
        let auth = valid_auth(); // issued at ISSUED_AT_SEC, quote_expiry +900
        pay_env_at(ISSUED_AT_SEC + 400); // age 400 > 300, but quote not yet expired
        let signature = sign(&auth, &key);
        let _ = guard.request_payment(auth, signature);
    }

    #[test]
    #[should_panic(expected = "quote expired")]
    fn an_expired_quote_is_refused() {
        let key = verdict_key();
        let mut guard = guard_with(&key);
        let auth = valid_auth();
        pay_env_at(ISSUED_AT_SEC + 1000); // past quote_expiry (+900)
        let signature = sign(&auth, &key);
        let _ = guard.request_payment(auth, signature);
    }

    #[test]
    #[should_panic(expected = "destination on denylist")]
    fn a_denylisted_destination_is_refused() {
        let key = verdict_key();
        let policy = Policy {
            denylist: vec![evm("a")],
            ..sample_policy()
        };
        let mut guard = guard_with_policy(&key, policy);
        // valid_auth pays evm("a").
        let _ = request(&mut guard, &key, ISSUED_AT_SEC, 5, &evm("a"), 1);
    }

    #[test]
    #[should_panic(expected = "destination not on allowlist")]
    fn a_destination_off_the_allowlist_is_refused() {
        let key = verdict_key();
        let policy = Policy {
            allowlist: vec![evm("b")], // allows only evm("b")
            ..sample_policy()
        };
        let mut guard = guard_with_policy(&key, policy);
        let _ = request(&mut guard, &key, ISSUED_AT_SEC, 5, &evm("a"), 1);
    }

    #[test]
    fn a_destination_on_the_allowlist_is_paid() {
        let key = verdict_key();
        let policy = Policy {
            allowlist: vec![evm("a")],
            ..sample_policy()
        };
        let mut guard = guard_with_policy(&key, policy);
        let result = request(&mut guard, &key, ISSUED_AT_SEC, 5, &evm("a"), 1);
        assert!(result.paid);
    }

    #[test]
    fn small_payments_pay_until_the_daily_cap() {
        // Scenario 7, the drain: daily cap 100, so 60 + 40 is honoured in full.
        let key = verdict_key();
        let policy = Policy {
            per_tx_cap: U128(60),
            daily_cap: U128(100),
            per_counterparty_cap: U128(1000),
            ..sample_policy()
        };
        let mut guard = guard_with_policy(&key, policy);
        let a = evm("a");
        assert!(request(&mut guard, &key, ISSUED_AT_SEC, 60, &a, 1).paid);
        assert!(request(&mut guard, &key, ISSUED_AT_SEC, 40, &a, 2).paid);
        assert_eq!(guard.get_spent_24h().0, 100, "the window total is the cap");
    }

    #[test]
    #[should_panic(expected = "daily cap exceeded")]
    fn a_payment_over_the_daily_cap_is_refused() {
        // Scenario 7, the wall: the third payment would push the window past 100.
        let key = verdict_key();
        let policy = Policy {
            per_tx_cap: U128(60),
            daily_cap: U128(100),
            per_counterparty_cap: U128(1000),
            ..sample_policy()
        };
        let mut guard = guard_with_policy(&key, policy);
        let a = evm("a");
        assert!(request(&mut guard, &key, ISSUED_AT_SEC, 60, &a, 1).paid);
        assert!(request(&mut guard, &key, ISSUED_AT_SEC, 40, &a, 2).paid);
        let _ = request(&mut guard, &key, ISSUED_AT_SEC, 1, &a, 3);
    }

    #[test]
    fn the_daily_cap_rolls_over_after_24h() {
        // Scenario 7, clean rollover: a full window a day ago does not block today.
        let key = verdict_key();
        let policy = Policy {
            per_tx_cap: U128(60),
            daily_cap: U128(100),
            per_counterparty_cap: U128(1000),
            ..sample_policy()
        };
        let mut guard = guard_with_policy(&key, policy);
        let a = evm("a");
        assert!(request(&mut guard, &key, ISSUED_AT_SEC, 60, &a, 1).paid);
        assert!(request(&mut guard, &key, ISSUED_AT_SEC, 40, &a, 2).paid);

        // One day and a second later, yesterday's spend is out of the window.
        let tomorrow = ISSUED_AT_SEC + SECONDS_PER_DAY + 1;
        assert!(request(&mut guard, &key, tomorrow, 60, &a, 3).paid);
        assert_eq!(
            guard.get_spent_24h().0,
            60,
            "only today's payment is in the window"
        );
    }

    #[test]
    #[should_panic(expected = "counterparty cap exceeded")]
    fn a_payment_over_the_per_counterparty_cap_is_refused() {
        let key = verdict_key();
        let policy = Policy {
            per_tx_cap: U128(60),
            daily_cap: U128(1000),
            per_counterparty_cap: U128(50),
            ..sample_policy()
        };
        let mut guard = guard_with_policy(&key, policy);
        let a = evm("a");
        assert!(request(&mut guard, &key, ISSUED_AT_SEC, 40, &a, 1).paid);
        let _ = request(&mut guard, &key, ISSUED_AT_SEC, 40, &a, 2); // 80 > 50
    }

    #[test]
    fn the_per_counterparty_cap_is_isolated_per_destination() {
        // One maxed destination does not block a different one.
        let key = verdict_key();
        let policy = Policy {
            per_tx_cap: U128(60),
            daily_cap: U128(1000),
            per_counterparty_cap: U128(50),
            ..sample_policy()
        };
        let mut guard = guard_with_policy(&key, policy);
        let (a, b) = (evm("a"), evm("b"));
        assert!(request(&mut guard, &key, ISSUED_AT_SEC, 40, &a, 1).paid);
        assert!(request(&mut guard, &key, ISSUED_AT_SEC, 40, &b, 2).paid);

        assert_eq!(guard.get_counterparty_spent(a).0, 40);
        assert_eq!(guard.get_counterparty_spent(b).0, 40);
        assert_eq!(guard.get_spent_24h().0, 80);
    }
}
