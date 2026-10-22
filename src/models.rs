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

// ---------------------------------------------------------------------------
// Read-surface models (account, orders, books, trades, candles, funding, …)
// ---------------------------------------------------------------------------

/// A resting/historical order (`Order`). Decimal fields are API strings.
#[derive(Debug, Clone, Deserialize)]
pub struct Order {
    #[serde(default)]
    pub order_index: i64,
    #[serde(default)]
    pub client_order_index: i64,
    #[serde(default)]
    pub order_id: String,
    #[serde(default)]
    pub client_order_id: String,
    #[serde(default)]
    pub market_index: i64,
    #[serde(default)]
    pub owner_account_index: i64,
    #[serde(default)]
    pub initial_base_amount: String,
    #[serde(default)]
    pub price: String,
    #[serde(default)]
    pub remaining_base_amount: String,
    #[serde(default)]
    pub filled_base_amount: String,
    #[serde(default)]
    pub filled_quote_amount: String,
    #[serde(default)]
    pub is_ask: bool,
    #[serde(default)]
    pub side: String,
    #[serde(rename = "type", default)]
    pub order_type: String,
    #[serde(default)]
    pub time_in_force: String,
    #[serde(default)]
    pub reduce_only: bool,
    #[serde(default)]
    pub trigger_price: String,
    #[serde(default)]
    pub order_expiry: i64,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub nonce: i64,
    #[serde(default)]
    pub timestamp: i64,
}

/// Response to the order-list endpoints (`accountActiveOrders` /
/// `accountInactiveOrders`).
#[derive(Debug, Clone, Deserialize)]
pub struct Orders {
    #[serde(default)]
    pub code: i32,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub orders: Vec<Order>,
}

/// A single open position on an account (`AccountPosition`).
#[derive(Debug, Clone, Deserialize)]
pub struct AccountPosition {
    #[serde(default)]
    pub market_id: i64,
    #[serde(default)]
    pub symbol: String,
    #[serde(default)]
    pub initial_margin_fraction: String,
    #[serde(default)]
    pub sign: i64,
    #[serde(default)]
    pub position: String,
    #[serde(default)]
    pub avg_entry_price: String,
    #[serde(default)]
    pub position_value: String,
    #[serde(default)]
    pub unrealized_pnl: String,
    #[serde(default)]
    pub realized_pnl: String,
    #[serde(default)]
    pub liquidation_price: String,
    #[serde(default)]
    pub margin_mode: i64,
    #[serde(default)]
    pub allocated_margin: String,
}

/// A detailed account record (`DetailedAccount`).
#[derive(Debug, Clone, Deserialize)]
pub struct DetailedAccount {
    #[serde(default)]
    pub account_index: i64,
    #[serde(default)]
    pub index: i64,
    #[serde(default)]
    pub l1_address: String,
    #[serde(default)]
    pub account_type: i64,
    #[serde(default)]
    pub account_trading_mode: i64,
    #[serde(default)]
    pub collateral: String,
    #[serde(default)]
    pub available_balance: String,
    #[serde(default)]
    pub total_asset_value: String,
    #[serde(default)]
    pub status: i64,
    #[serde(default)]
    pub positions: Vec<AccountPosition>,
    #[serde(default)]
    pub bo_positions: Vec<BoPosition>,
}

/// A binary-options position (`bo_positions` entry).
#[derive(Debug, Clone, Deserialize)]
pub struct BoPosition {
    #[serde(default)]
    pub market_id: i64,
    /// `1` holds Up, `-1` holds Down.
    #[serde(default)]
    pub sign: i64,
    /// Shares held, positive magnitude.
    #[serde(default)]
    pub size: String,
    #[serde(default)]
    pub entry_quote: String,
    /// Average price paid for the held side (Down price when `sign = -1`).
    #[serde(default)]
    pub avg_entry_price: String,
}

// ---------------------------------------------------------------------------
// Binary options (events)
// ---------------------------------------------------------------------------

/// Binary-options outcome codes (`outcome` on a market).
pub const BO_OUTCOME_PENDING: i64 = 0;
pub const BO_OUTCOME_DOWN: i64 = 1;
pub const BO_OUTCOME_UP: i64 = 2;

/// Live stats attached to a binary-options order book.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct BoMarketStats {
    #[serde(default)]
    pub mid_price: String,
    #[serde(default)]
    pub best_ask_price: String,
    #[serde(default)]
    pub best_bid_price: String,
    #[serde(default)]
    pub last_trade_price: String,
    #[serde(default)]
    pub open_interest: String,
    #[serde(default)]
    pub lifetime_quote_token_volume: f64,
}

/// A binary-options order book as returned inside `events`.
///
/// Fee fields are the market maxima (e.g. `"1.0000"` = 1%); the effective fee
/// is `taker_fee × bo_fee_rate × size × P × (1 − P)`.
#[derive(Debug, Clone, Deserialize)]
pub struct BoOrderBook {
    pub symbol: String,
    pub market_id: i64,
    #[serde(default)]
    pub market_type: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub taker_fee: String,
    #[serde(default)]
    pub maker_fee: String,
    #[serde(default)]
    pub min_base_amount: String,
    #[serde(default)]
    pub min_quote_amount: String,
    #[serde(default)]
    pub size_decimals: i64,
    #[serde(default)]
    pub price_decimals: i64,
    /// Trading window, unix ms. `0` start means tradable from listing.
    #[serde(default)]
    pub start_timestamp: i64,
    #[serde(default)]
    pub end_timestamp: i64,
    #[serde(default)]
    pub outcome: i64,
    #[serde(default)]
    pub settlement_cap: i64,
    #[serde(default)]
    pub settlement_price: i64,
    #[serde(default)]
    pub default_price: i64,
    #[serde(default)]
    pub is_frozen: bool,
    #[serde(default)]
    pub open_interest: String,
    #[serde(default)]
    pub stats: BoMarketStats,
}

/// Series metadata on an event (`metadata`).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct EventMetadata {
    #[serde(default)]
    pub duration: String,
    #[serde(default)]
    pub feed_id: String,
    #[serde(default)]
    pub market_id: i64,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub symbol: String,
    #[serde(rename = "type", default)]
    pub kind: String,
}

/// One binary-options event (`GET /api/v1/events`). Up/Down series have one
/// order book per event.
#[derive(Debug, Clone, Deserialize)]
pub struct Event {
    pub event_id: i64,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub tag: String,
    /// Observation window, unix ms.
    #[serde(default)]
    pub start_at: i64,
    #[serde(default)]
    pub end_at: i64,
    #[serde(default)]
    pub metadata: EventMetadata,
    #[serde(default)]
    pub order_books: Vec<BoOrderBook>,
}

/// Response to `GET /api/v1/events`.
#[derive(Debug, Clone, Deserialize)]
pub struct Events {
    #[serde(default)]
    pub code: i32,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub next_cursor: Option<i64>,
    #[serde(default)]
    pub events: Vec<Event>,
}

/// Query for `GET /api/v1/events`.
#[derive(Debug, Clone, Default)]
pub struct EventsQuery {
    pub tag: Option<String>,
    pub active: Option<bool>,
    /// e.g. `"start_at"`.
    pub sort: Option<String>,
    /// `"asc"` / `"desc"`.
    pub order: Option<String>,
    pub limit: Option<u32>,
    pub cursor: Option<i64>,
}

/// Response to `GET /api/v1/account`.
#[derive(Debug, Clone, Deserialize)]
pub struct DetailedAccounts {
    #[serde(default)]
    pub code: i32,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub total: i64,
    #[serde(default)]
    pub accounts: Vec<DetailedAccount>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

/// A market/order-book listing (`OrderBook`).
#[derive(Debug, Clone, Deserialize)]
pub struct OrderBook {
    #[serde(default)]
    pub symbol: String,
    #[serde(default)]
    pub market_id: i64,
    #[serde(default)]
    pub market_type: String,
    #[serde(default)]
    pub base_asset_id: i64,
    #[serde(default)]
    pub quote_asset_id: i64,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub taker_fee: String,
    #[serde(default)]
    pub maker_fee: String,
    #[serde(default)]
    pub min_base_amount: String,
    #[serde(default)]
    pub min_quote_amount: String,
    #[serde(default)]
    pub supported_size_decimals: i64,
    #[serde(default)]
    pub supported_price_decimals: i64,
    #[serde(default)]
    pub supported_quote_decimals: i64,
}

/// Response to `GET /api/v1/orderBooks`.
#[derive(Debug, Clone, Deserialize)]
pub struct OrderBooks {
    #[serde(default)]
    pub code: i32,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub order_books: Vec<OrderBook>,
}

/// A detailed market listing with live stats (`PerpsOrderBookDetail` /
/// `SpotOrderBookDetail`). Fields absent for a side are left at their defaults.
#[derive(Debug, Clone, Deserialize)]
pub struct OrderBookDetail {
    #[serde(default)]
    pub symbol: String,
    #[serde(default)]
    pub market_id: i64,
    #[serde(default)]
    pub market_type: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub taker_fee: String,
    #[serde(default)]
    pub maker_fee: String,
    #[serde(default)]
    pub min_base_amount: String,
    #[serde(default)]
    pub min_quote_amount: String,
    #[serde(default)]
    pub supported_size_decimals: i64,
    #[serde(default)]
    pub supported_price_decimals: i64,
    #[serde(default)]
    pub supported_quote_decimals: i64,
    #[serde(default)]
    pub size_decimals: i64,
    #[serde(default)]
    pub price_decimals: i64,
    #[serde(default, deserialize_with = "de_f64_lenient")]
    pub last_trade_price: f64,
    #[serde(default, deserialize_with = "de_f64_lenient")]
    pub daily_quote_token_volume: f64,
    #[serde(default, deserialize_with = "de_f64_lenient")]
    pub daily_price_change: f64,
    #[serde(default, deserialize_with = "de_f64_lenient")]
    pub open_interest: f64,
}

/// Accepts a JSON number or a numeric string (spot markets send some stats as
/// strings, e.g. `"open_interest": "0.000000"`). Unparseable values become 0.
fn de_f64_lenient<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<f64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum NumOrStr {
        Num(f64),
        Str(String),
        Null(()),
    }
    Ok(match NumOrStr::deserialize(d)? {
        NumOrStr::Num(n) => n,
        NumOrStr::Str(s) => s.parse().unwrap_or(0.0),
        NumOrStr::Null(()) => 0.0,
    })
}

/// Response to `GET /api/v1/orderBookDetails`.
#[derive(Debug, Clone, Deserialize)]
pub struct OrderBookDetails {
    #[serde(default)]
    pub code: i32,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub order_book_details: Vec<OrderBookDetail>,
    #[serde(default)]
    pub spot_order_book_details: Vec<OrderBookDetail>,
}

/// A public trade (`Trade`). Decimal fields are API strings.
#[derive(Debug, Clone, Deserialize)]
pub struct Trade {
    #[serde(default)]
    pub trade_id: i64,
    #[serde(default)]
    pub tx_hash: String,
    #[serde(rename = "type", default)]
    pub trade_type: String,
    #[serde(default)]
    pub market_id: i64,
    #[serde(default)]
    pub size: String,
    #[serde(default)]
    pub price: String,
    #[serde(default)]
    pub usd_amount: String,
    #[serde(default)]
    pub ask_id: i64,
    #[serde(default)]
    pub bid_id: i64,
    #[serde(default)]
    pub ask_account_id: i64,
    #[serde(default)]
    pub bid_account_id: i64,
    #[serde(default)]
    pub is_maker_ask: bool,
    #[serde(default)]
    pub block_height: i64,
    #[serde(default)]
    pub timestamp: i64,
}

/// Response to `GET /api/v1/recentTrades` and `GET /api/v1/trades`.
#[derive(Debug, Clone, Deserialize)]
pub struct Trades {
    #[serde(default)]
    pub code: i32,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub trades: Vec<Trade>,
}

/// A single OHLCV candle (`Candle`). The API uses terse single-letter keys.
#[derive(Debug, Clone, Deserialize)]
pub struct Candle {
    /// Start timestamp.
    #[serde(rename = "t", default)]
    pub timestamp: i64,
    #[serde(rename = "o", default)]
    pub open: String,
    #[serde(rename = "h", default)]
    pub high: String,
    #[serde(rename = "l", default)]
    pub low: String,
    #[serde(rename = "c", default)]
    pub close: String,
    /// Base-asset volume.
    #[serde(rename = "v", default)]
    pub base_volume: String,
    /// Quote-asset volume.
    #[serde(rename = "V", default)]
    pub quote_volume: String,
}

/// Response to `GET /api/v1/candles`.
#[derive(Debug, Clone, Deserialize)]
pub struct Candles {
    #[serde(default)]
    pub code: i32,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(rename = "r", default)]
    pub resolution: String,
    #[serde(rename = "c", default)]
    pub candles: Vec<Candle>,
}

/// A funding data point (`Funding`).
#[derive(Debug, Clone, Deserialize)]
pub struct Funding {
    #[serde(default)]
    pub timestamp: i64,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub rate: String,
    #[serde(default)]
    pub direction: String,
}

/// Response to `GET /api/v1/fundings`.
#[derive(Debug, Clone, Deserialize)]
pub struct Fundings {
    #[serde(default)]
    pub code: i32,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub resolution: String,
    #[serde(default)]
    pub fundings: Vec<Funding>,
}

/// A current funding rate for a market (`FundingRate`).
#[derive(Debug, Clone, Deserialize)]
pub struct FundingRate {
    #[serde(default)]
    pub market_id: i64,
    #[serde(default)]
    pub exchange: String,
    #[serde(default)]
    pub symbol: String,
    #[serde(default)]
    pub rate: String,
}

/// Response to `GET /api/v1/funding-rates`.
#[derive(Debug, Clone, Deserialize)]
pub struct FundingRates {
    #[serde(default)]
    pub code: i32,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub funding_rates: Vec<FundingRate>,
}

/// Response to `GET /api/v1/systemConfig`.
#[derive(Debug, Clone, Deserialize)]
pub struct SystemConfig {
    #[serde(default)]
    pub code: i32,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub liquidity_pool_index: i64,
    #[serde(default)]
    pub staking_pool_index: i64,
    #[serde(default)]
    pub funding_fee_rebate_account_index: i64,
    #[serde(default)]
    pub liquidity_pool_cooldown_period: i64,
    #[serde(default)]
    pub staking_pool_lockup_period: i64,
    #[serde(default)]
    pub max_integrator_perps_maker_fee: i64,
    #[serde(default)]
    pub max_integrator_perps_taker_fee: i64,
    #[serde(default)]
    pub max_integrator_spot_maker_fee: i64,
    #[serde(default)]
    pub max_integrator_spot_taker_fee: i64,
    #[serde(default)]
    pub market_maker_incentive_account_index: i64,
}

/// A transaction record (`Tx` / `EnrichedTx`).
#[derive(Debug, Clone, Deserialize)]
pub struct EnrichedTx {
    #[serde(default)]
    pub code: i32,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub hash: String,
    #[serde(rename = "type", default)]
    pub tx_type: i64,
    #[serde(default)]
    pub info: String,
    #[serde(default)]
    pub event_info: String,
    #[serde(default)]
    pub status: i64,
    #[serde(default)]
    pub transaction_index: i64,
    #[serde(default)]
    pub l1_address: String,
    #[serde(default)]
    pub account_index: i64,
    #[serde(default)]
    pub nonce: i64,
    #[serde(default)]
    pub expire_at: i64,
    #[serde(default)]
    pub block_height: i64,
    #[serde(default)]
    pub api_key_index: i64,
    #[serde(default)]
    pub transaction_time: i64,
}

/// Response to `GET /api/v1/txs` and `GET /api/v1/accountTxs`.
#[derive(Debug, Clone, Deserialize)]
pub struct Txs {
    #[serde(default)]
    pub code: i32,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub txs: Vec<EnrichedTx>,
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

    #[test]
    fn events_deserialize_binary_options() {
        let json = r#"{
            "code": 200,
            "next_cursor": 491,
            "events": [{
                "event_id": 487,
                "title": "BTC Up or Down",
                "tag": "btc-updown-15m",
                "event_kind": "recurrent",
                "start_at": 1792637100000,
                "end_at": 1792638000000,
                "metadata": {
                    "duration": "15m",
                    "feed_id": "0x0002ee6757e8822c00d273bc340fc24c9cafe123a4ff2ea1dbdb31944bc7d95f",
                    "market_id": 4587,
                    "provider": "chainlink",
                    "symbol": "btc",
                    "type": "updown",
                    "underlying_market_id": 1
                },
                "order_books": [{
                    "symbol": "BTC-UPDOWN-15M-1792637100",
                    "market_id": 4587,
                    "market_type": "binary_options",
                    "status": "active",
                    "taker_fee": "1.0000",
                    "maker_fee": "0.0000",
                    "min_base_amount": "5.0000",
                    "min_quote_amount": "0.000001",
                    "size_decimals": 4,
                    "price_decimals": 2,
                    "start_timestamp": 1792629900000,
                    "end_timestamp": 1792638000000,
                    "outcome": 0,
                    "settlement_cap": 100,
                    "settlement_price": 0,
                    "default_price": 50,
                    "is_frozen": false,
                    "open_interest": "6.0000",
                    "stats": {
                        "mid_price": "0.63",
                        "best_ask_price": "0.64",
                        "best_bid_price": "0.61",
                        "last_trade_price": "0.65",
                        "lifetime_quote_token_volume": 6.55
                    }
                }]
            }]
        }"#;
        let r: Events = serde_json::from_str(json).unwrap();
        assert_eq!(r.next_cursor, Some(491));
        let e = &r.events[0];
        assert_eq!(e.metadata.kind, "updown");
        assert_eq!(e.metadata.market_id, 4587);
        let ob = &e.order_books[0];
        assert_eq!(ob.market_id, 4587);
        assert_eq!(ob.settlement_cap, 100);
        assert_eq!(ob.outcome, BO_OUTCOME_PENDING);
        assert_eq!(ob.stats.best_ask_price, "0.64");
    }

    #[test]
    fn account_deserializes_bo_positions() {
        let json = r#"{"code":200,"accounts":[{"index":3,"bo_positions":[
            {"market_id":4206,"sign":-1,"size":"100.0000","entry_quote":"49.000000","avg_entry_price":"0.49"}
        ]}]}"#;
        let r: DetailedAccounts = serde_json::from_str(json).unwrap();
        let p = &r.accounts[0].bo_positions[0];
        assert_eq!((p.market_id, p.sign, p.size.as_str()), (4206, -1, "100.0000"));
    }

    #[test]
    fn orders_deserialize_subset_and_ignore_extras() {
        let json = r#"{
            "code": 200,
            "orders": [{
                "order_index": 7,
                "market_index": 1,
                "price": "100.5",
                "is_ask": true,
                "type": "limit",
                "status": "open",
                "unknown_field": 42
            }]
        }"#;
        let parsed: Orders = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.code, 200);
        assert_eq!(parsed.orders.len(), 1);
        assert_eq!(parsed.orders[0].order_index, 7);
        assert_eq!(parsed.orders[0].order_type, "limit");
        assert!(parsed.orders[0].is_ask);
    }

    #[test]
    fn candles_use_terse_keys() {
        let json = r#"{"code":200,"r":"1m","c":[{"t":1000,"o":"1","h":"2","l":"0.5","c":"1.5","v":"10","V":"15"}]}"#;
        let parsed: Candles = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.resolution, "1m");
        assert_eq!(parsed.candles[0].timestamp, 1000);
        assert_eq!(parsed.candles[0].close, "1.5");
        assert_eq!(parsed.candles[0].quote_volume, "15");
    }

    #[test]
    fn order_book_details_accept_numeric_strings() {
        // Spot markets send `open_interest` as a string; perps send numbers.
        let json = r#"{
            "code": 200,
            "order_book_details": [
                {"symbol": "ETH", "market_id": 0, "last_trade_price": 2680.5,
                 "daily_quote_token_volume": 100, "daily_price_change": -1.5,
                 "open_interest": 12.5}
            ],
            "spot_order_book_details": [
                {"symbol": "ETH/USDC", "market_id": 2048, "last_trade_price": 2680.5,
                 "open_interest": "0.000000", "daily_price_change": null}
            ]
        }"#;
        let parsed: OrderBookDetails = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.order_book_details[0].open_interest, 12.5);
        assert_eq!(parsed.order_book_details[0].daily_quote_token_volume, 100.0);
        assert_eq!(parsed.spot_order_book_details[0].open_interest, 0.0);
        assert_eq!(parsed.spot_order_book_details[0].daily_price_change, 0.0);
    }
}
