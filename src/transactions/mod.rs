//! Transaction types: validation, hashing, and JSON serialization.
//!
//! Each type mirrors a `*TxInfo` struct in `lighter-go/types/txtypes`. The
//! `hash` methods reproduce the exact Goldilocks field-element layout used by
//! the Go reference, so the resulting message hash (and therefore the signature
//! verified server-side) is byte-identical.

mod account;
mod funds;
mod orders;
mod pool;

pub use account::*;
pub use funds::*;
pub use orders::*;
pub use pool::*;

use poseidon_hash::Goldilocks;
use serde::Serialize;

use crate::constants::*;
use crate::error::{Error, Result};
use crate::hash::gf;
use crate::signer::KeyManager;

/// Behaviour shared by every signable transaction.
pub trait TxInfo: Serialize {
    /// The protocol transaction-type byte.
    fn tx_type(&self) -> u8;

    /// Validates all fields. Returns the first violation, matching Go order.
    fn validate(&self) -> Result<()>;

    /// Computes the 40-byte little-endian message hash to be signed.
    fn hash(&self, chain_id: u32) -> Result<[u8; HASH_LENGTH]>;

    /// Stores the signature and the hex-encoded signed hash after signing.
    fn set_signature(&mut self, sig: Vec<u8>, signed_hash: String);

    /// The hex-encoded signed hash (empty until signed).
    fn tx_hash(&self) -> &str;

    /// Optional L1 message body (only for ChangePubKey / Transfer / ApproveIntegrator).
    fn message_to_sign(&self, _chain_id: u32) -> Option<String> {
        None
    }

    /// Serializes the transaction to the JSON expected by the Lighter API.
    fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }
}

/// A fully signed transaction bundle, equivalent to the Go `SignedTxResponse`.
#[derive(Debug, Clone)]
pub struct SignedTransaction {
    pub tx_type: u8,
    pub tx_info: String,
    pub tx_hash: String,
    pub message_to_sign: Option<String>,
}

/// Validates, hashes, and signs `tx` in place with a freshly sampled nonce.
pub fn sign_tx<T: TxInfo>(tx: &mut T, key: &KeyManager, chain_id: u32) -> Result<()> {
    tx.validate()?;
    let hash = tx.hash(chain_id)?;
    let sig = key.sign(&hash)?;
    tx.set_signature(sig.to_vec(), hex::encode(hash));
    Ok(())
}

/// Like [`sign_tx`] but with an explicit nonce (deterministic; for testing).
pub fn sign_tx_with_nonce<T: TxInfo>(
    tx: &mut T,
    key: &KeyManager,
    chain_id: u32,
    nonce: &[u8],
) -> Result<()> {
    tx.validate()?;
    let hash = tx.hash(chain_id)?;
    let sig = key.sign_with_nonce(&hash, nonce)?;
    tx.set_signature(sig.to_vec(), hex::encode(hash));
    Ok(())
}

/// Builds the [`SignedTransaction`] bundle from a signed transaction.
pub fn to_signed<T: TxInfo>(tx: &T, chain_id: u32) -> Result<SignedTransaction> {
    Ok(SignedTransaction {
        tx_type: tx.tx_type(),
        tx_info: tx.to_json()?,
        tx_hash: tx.tx_hash().to_string(),
        message_to_sign: tx.message_to_sign(chain_id),
    })
}

/// Order parameters shared by create / grouped-order transactions
/// (`txtypes.OrderInfo`).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct OrderInfo {
    pub market_index: i16,
    pub client_order_index: i64,
    pub base_amount: i64,
    pub price: u32,
    pub is_ask: u8,
    #[serde(rename = "Type")]
    pub order_type: u8,
    pub time_in_force: u8,
    pub reduce_only: u8,
    pub trigger_price: u32,
    pub order_expiry: i64,
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Pushes the common transaction header used by every `Hash` implementation:
/// `chainId, txType, nonce, expiredAt, accountIndex, apiKeyIndex`.
pub(crate) fn push_header(
    elems: &mut Vec<Goldilocks>,
    chain_id: u32,
    tx_type: u8,
    nonce: i64,
    expired_at: i64,
    account_index: i64,
    api_key_index: u8,
) {
    elems.push(gf(chain_id));
    elems.push(gf(tx_type));
    elems.push(gf(nonce));
    elems.push(gf(expired_at));
    elems.push(gf(account_index));
    elems.push(gf(api_key_index));
}

pub(crate) fn check_account_index(idx: i64, max: i64) -> Result<()> {
    if idx < MIN_ACCOUNT_INDEX {
        Err(Error::AccountIndexTooLow {
            min: MIN_ACCOUNT_INDEX,
        })
    } else if idx > max {
        Err(Error::AccountIndexTooHigh { max })
    } else {
        Ok(())
    }
}

pub(crate) fn check_api_key_index(idx: u8) -> Result<()> {
    if idx > MAX_API_KEY_INDEX {
        Err(Error::ApiKeyIndexTooHigh {
            max: MAX_API_KEY_INDEX,
        })
    } else {
        Ok(())
    }
}

pub(crate) fn check_nonce(nonce: i64) -> Result<()> {
    if nonce < MIN_NONCE {
        Err(Error::NonceTooLow { min: MIN_NONCE })
    } else {
        Ok(())
    }
}

pub(crate) fn check_expired_at(expired_at: i64) -> Result<()> {
    if expired_at < 0 || expired_at > MAX_TIMESTAMP {
        Err(Error::ExpiredAtInvalid)
    } else {
        Ok(())
    }
}

pub(crate) fn is_spot_market(m: i16) -> bool {
    m >= MIN_SPOT_MARKET_INDEX && m <= MAX_SPOT_MARKET_INDEX
}

pub(crate) fn is_perps_market(m: i16) -> bool {
    m >= MIN_PERPS_MARKET_INDEX && m <= MAX_PERPS_MARKET_INDEX
}

/// Serde helper: serialize any byte sequence as Go does for `[]byte` (base64
/// std). Works for both `Vec<u8>` signatures and fixed-size key arrays.
pub(crate) mod b64 {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::Serializer;

    pub fn serialize<T, S>(bytes: &T, s: S) -> Result<S::Ok, S::Error>
    where
        T: AsRef<[u8]> + ?Sized,
        S: Serializer,
    {
        s.serialize_str(&STANDARD.encode(bytes.as_ref()))
    }
}

/// Formats a `uint64` as Go's `getHex10FromUint64`: `0x` + 16 lowercase hex
/// digits (left zero-padded), used for L1 signature bodies.
pub(crate) fn hex10_from_u64(value: u64) -> String {
    format!("0x{:016x}", value)
}
