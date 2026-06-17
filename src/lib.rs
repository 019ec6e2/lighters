//! Native Rust signer & client for the [Lighter](https://lighter.xyz) exchange.
//!
//! This is a from-scratch Rust port of the official Go SDK (`lighter-go`). It
//! produces byte-identical transaction hashes and Schnorr signatures, so signed
//! payloads are accepted by the same sequencer.
//!
//! # Cryptography provenance
//!
//! No cryptographic primitives are implemented here. All field arithmetic,
//! Poseidon2 hashing, the ECgFp5 curve, and Schnorr signatures come from the
//! [`poseidon-hash`](https://crates.io/crates/poseidon-hash) and
//! [`goldilocks-crypto`](https://crates.io/crates/goldilocks-crypto) crates,
//! which mirror the `elliottech/poseidon_crypto` Go reference.
//!
//! # Quick start
//!
//! ```no_run
//! use lighter::{TxClient, TransactOpts, transactions::TxInfo};
//!
//! # fn main() -> lighter::Result<()> {
//! let client = TxClient::new("0x...", /*account*/ 3, /*api key*/ 0, /*chain*/ 304)?;
//! let opts = TransactOpts { nonce: Some(0), ..Default::default() };
//! let order = client.create_order(
//!     lighter::OrderReq {
//!         market_index: 0,
//!         client_order_index: 1,
//!         base_amount: 100,
//!         price: 1000,
//!         is_ask: 0,
//!         order_type: 0,
//!         time_in_force: 1,
//!         reduce_only: 0,
//!         trigger_price: 0,
//!         order_expiry: 1,
//!     },
//!     &opts,
//! )?;
//! println!("tx hash: {}", order.tx_hash());
//! println!("json: {}", order.to_json()?);
//! # Ok(())
//! # }
//! ```

// Several range checks are ported verbatim from the Go reference, where the
// operands are wider integer types. In Rust some of those comparisons are
// against a type's own min/max (always true/false) or look like manual range
// checks, but keeping them 1:1 with Go avoids subtle divergence.
#![allow(clippy::absurd_extreme_comparisons)]
#![allow(clippy::manual_range_contains)]

pub mod attributes;
pub mod client;
pub mod constants;
pub mod error;
pub mod hash;
pub mod http;
pub mod models;
pub mod signer;
pub mod transactions;

#[cfg(feature = "trading")]
pub mod nonce;
#[cfg(feature = "trading")]
pub mod rest;
#[cfg(feature = "trading")]
pub mod trading;

pub use attributes::TxAttributes;
pub use client::{
    generate_api_key, ApproveIntegratorReq, OrderReq, TransferReq, TransactOpts, TxClient,
    DEFAULT_EXPIRE_MS,
};
pub use error::{Error, Result};
pub use signer::KeyManager;
pub use transactions::{SignedTransaction, TxInfo};

#[cfg(feature = "trading")]
pub use nonce::{NonceManager, NonceStrategy};
#[cfg(feature = "trading")]
pub use rest::RestClient;
#[cfg(feature = "trading")]
pub use trading::{OrderParams, TradeOpts, TradingClient};
