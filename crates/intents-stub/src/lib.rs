//! A test-only stand-in for NEAR Intents (`intents.near`).
//!
//! NEAR Intents has no testnet ("use small amounts for test swaps", design.md section 6), so a
//! sandbox cannot call the real `intents.near`. The guard releases funds by calling
//! `mt_transfer` on its configured intents account ([`guard_contract`'s `set_intents_account`]);
//! in the sandbox the owner points the guard at this stub, which receives that call so the nine
//! demo scenarios can assert the release actually happened.
//!
//! It is deliberately minimal: it records and logs each `mt_transfer` but does **not** track
//! NEP-245 balances. It is never deployed to any real network.

use near_sdk::json_types::U128;
use near_sdk::{env, near, PanicOnDefault};

/// Stub state: the number of `mt_transfer` calls received.
#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct IntentsStub {
    transfers: u64,
}

#[near]
impl IntentsStub {
    /// Deploys the stub with a zero transfer count.
    #[init]
    #[allow(clippy::new_without_default)] // a NEAR #[init] method is not a Default impl
    pub fn new() -> Self {
        Self { transfers: 0 }
    }

    /// Stand-in for NEP-245 `mt_transfer`. Records and logs the release so a sandbox test can
    /// assert the guard settled; it does not track balances (this is a stub). Payable because the
    /// guard attaches the one required yoctoNEAR.
    #[payable]
    pub fn mt_transfer(
        &mut self,
        receiver_id: String,
        amount: U128,
        token_id: String,
        memo: Option<String>,
    ) {
        self.transfers += 1;
        env::log_str(&format!(
            "intents-stub mt_transfer receiver_id={} token_id={} amount={} memo={}",
            receiver_id,
            token_id,
            amount.0,
            memo.unwrap_or_default(),
        ));
    }

    /// Number of `mt_transfer` calls received so far.
    pub fn transfers(&self) -> u64 {
        self.transfers
    }
}
