//! Nonce management for multi-key signing (`trading` feature).
//!
//! Mirrors `lighter.nonce_manager`. Each (account, api-key) pair has its own
//! monotonically increasing nonce. With several API keys the manager cycles
//! through them round-robin so independent transactions can be submitted
//! concurrently without nonce collisions.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use crate::error::{Error, Result};
use crate::rest::RestClient;

/// How the next nonce for an API key is determined.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NonceStrategy {
    /// Track nonces locally, incrementing optimistically without a network
    /// round-trip. Fastest; the default. Failed sends roll the counter back.
    Optimistic,
    /// Fetch the next nonce from the API on every call. Safer across processes
    /// but adds a round-trip and requires pacing (~350ms) between reuses.
    Api,
    /// Don't manage nonces at all; the caller supplies them explicitly.
    NoOp,
}

/// Thread-safe nonce manager shared across concurrent senders.
pub struct NonceManager {
    rest: RestClient,
    account_index: i64,
    keys: Vec<u8>,
    strategy: NonceStrategy,
    /// Round-robin cursor over `keys`.
    cursor: AtomicUsize,
    /// Last issued nonce per api-key index.
    nonces: Mutex<HashMap<u8, i64>>,
}

impl NonceManager {
    /// Builds a manager and primes the per-key nonce cache from the API
    /// (except for [`NonceStrategy::NoOp`], which performs no I/O).
    pub async fn new(
        rest: RestClient,
        account_index: i64,
        keys: Vec<u8>,
        strategy: NonceStrategy,
    ) -> Result<Self> {
        if keys.is_empty() {
            return Err(Error::MissingField("api keys"));
        }
        let mut nonces = HashMap::with_capacity(keys.len());
        if strategy != NonceStrategy::NoOp {
            for &k in &keys {
                // Store next_nonce - 1 so the first `next()` returns next_nonce.
                let n = rest.next_nonce(account_index, k).await?;
                nonces.insert(k, n - 1);
            }
        }
        Ok(NonceManager {
            rest,
            account_index,
            keys,
            strategy,
            cursor: AtomicUsize::new(0),
            nonces: Mutex::new(nonces),
        })
    }

    /// The strategy this manager was built with.
    pub fn strategy(&self) -> NonceStrategy {
        self.strategy
    }

    /// Returns the next `(api_key_index, nonce)` to use.
    ///
    /// When `api_key` is `None`, the next key is chosen round-robin.
    pub async fn next(&self, api_key: Option<u8>) -> Result<(u8, i64)> {
        if self.strategy == NonceStrategy::NoOp {
            return Err(Error::NonceManagerDisabled);
        }
        let key = api_key.unwrap_or_else(|| self.round_robin_key());
        match self.strategy {
            NonceStrategy::Optimistic => {
                let mut guard = self.nonces.lock().unwrap();
                let entry = guard.entry(key).or_insert(-1);
                *entry += 1;
                Ok((key, *entry))
            }
            NonceStrategy::Api => {
                // Network call performed outside the lock.
                let nonce = self.rest.next_nonce(self.account_index, key).await?;
                self.nonces.lock().unwrap().insert(key, nonce);
                Ok((key, nonce))
            }
            NonceStrategy::NoOp => unreachable!(),
        }
    }

    /// Rolls back the optimistic counter after a failed send so the nonce is
    /// reused. No-op for other strategies.
    pub fn acknowledge_failure(&self, api_key: u8) {
        if self.strategy == NonceStrategy::Optimistic {
            if let Some(n) = self.nonces.lock().unwrap().get_mut(&api_key) {
                *n -= 1;
            }
        }
    }

    /// Re-syncs a key's nonce from the API (used after an "invalid nonce"
    /// rejection). Stored as `fetched - 1` so the next `next()` returns it.
    pub async fn hard_refresh(&self, api_key: u8) -> Result<()> {
        if self.strategy == NonceStrategy::NoOp {
            return Ok(());
        }
        let n = self.rest.next_nonce(self.account_index, api_key).await?;
        self.nonces.lock().unwrap().insert(api_key, n - 1);
        Ok(())
    }

    fn round_robin_key(&self) -> u8 {
        let len = self.keys.len();
        let idx = (self.cursor.fetch_add(1, Ordering::Relaxed) + 1) % len;
        self.keys[idx]
    }
}
