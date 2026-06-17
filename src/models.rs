//! Typed REST response models.
//!
//! A hand-written subset of the Lighter API schema covering what the trading
//! runtime needs (transaction submission and order-book reads). Pure `serde`,
//! so these compile regardless of feature flags.

use serde::Deserialize;

/// API status code returned in every response body (HTTP-style).
pub const CODE_OK: i32 = 200;

/// Response to `POST /api/v1/sendTx`.
#[derive(Debug, Clone, Deserialize)]
pub struct RespSendTx {
    pub code: i32,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub tx_hash: String,
    #[serde(default)]
    pub predicted_execution_time_ms: i64,
    #[serde(default)]
    pub volume_quota_remaining: i64,
}

/// Response to `POST /api/v1/sendTxBatch`.
#[derive(Debug, Clone, Deserialize)]
pub struct RespSendTxBatch {
    pub code: i32,
    #[serde(default)]
    pub message: Option<String>,
    /// One hash per submitted transaction, in order.
    #[serde(default)]
    pub tx_hash: Vec<String>,
    #[serde(default)]
    pub predicted_execution_time_ms: i64,
    #[serde(default)]
    pub volume_quota_remaining: i64,
}

/// A single resting order in the order book (`SimpleOrder`).
///
/// Amounts and prices are decimal strings exactly as returned by the API; use
/// [`SimpleOrder::price_ticks`] / [`SimpleOrder::remaining_ticks`] to get the
/// integer tick values used for order math.
#[derive(Debug, Clone, Deserialize)]
pub struct SimpleOrder {
    pub order_index: i64,
    #[serde(default)]
    pub order_id: String,
    #[serde(default)]
    pub owner_account_index: i64,
    #[serde(default)]
    pub initial_base_amount: String,
    #[serde(default)]
    pub remaining_base_amount: String,
    pub price: String,
    #[serde(default)]
    pub order_expiry: i64,
}

impl SimpleOrder {
    /// The price as an integer number of ticks (decimal point removed), e.g.
    /// `"1234.56"` → `123456`. Mirrors the Python client's
    /// `int(price.replace(".", ""))`.
    pub fn price_ticks(&self) -> Result<u64, std::num::ParseIntError> {
        ticks(&self.price)
    }

    /// The remaining base amount as integer ticks.
    pub fn remaining_ticks(&self) -> Result<u64, std::num::ParseIntError> {
        ticks(&self.remaining_base_amount)
    }
}

fn ticks(s: &str) -> Result<u64, std::num::ParseIntError> {
    let mut digits = String::with_capacity(s.len());
    for c in s.chars() {
        if c != '.' {
            digits.push(c);
        }
    }
    if digits.is_empty() {
        // Force a clean ParseIntError for empty input.
        return "".parse::<u64>();
    }
    digits.parse::<u64>()
}

/// Response to `GET /api/v1/orderBookOrders`.
#[derive(Debug, Clone, Deserialize)]
pub struct OrderBookOrders {
    pub code: i32,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub total_asks: i64,
    #[serde(default)]
    pub asks: Vec<SimpleOrder>,
    #[serde(default)]
    pub total_bids: i64,
    #[serde(default)]
    pub bids: Vec<SimpleOrder>,
}

/// Response to `GET /api/v1/nextNonce`.
#[derive(Debug, Clone, Deserialize)]
pub struct NextNonce {
    #[serde(default)]
    pub code: i32,
    #[serde(default)]
    pub message: Option<String>,
    pub nonce: i64,
}

/// A registered API key entry from `GET /api/v1/apikeys`.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiKeyEntry {
    pub api_key_index: u8,
    #[serde(default)]
    pub public_key: String,
}

/// Response to `GET /api/v1/apikeys`.
#[derive(Debug, Clone, Deserialize)]
pub struct AccountApiKeys {
    #[serde(default)]
    pub code: i32,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub api_keys: Vec<ApiKeyEntry>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticks_strips_decimal_point() {
        assert_eq!(ticks("1234.56").unwrap(), 123456);
        assert_eq!(ticks("100").unwrap(), 100);
        assert_eq!(ticks("0.00010000").unwrap(), 10000);
        assert!(ticks("").is_err());
    }
}
