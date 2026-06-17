//! High-level async trading client (`trading` feature).
//!
//! Combines the native signer, a [`NonceManager`], and the [`RestClient`] into
//! the ergonomic surface the Python `SignerClient` exposes: build → sign →
//! resolve nonce → submit, plus order-book reads and market-order helpers.
//!
//! Signing stays byte-for-byte identical to the Go reference; this layer only
//! orchestrates I/O and fills in the documented defaults (28-day order expiry,
//! 10-minute transaction lifetime, leverage→IMF conversion, …).

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::attributes::TxAttributes;
use crate::constants::{GOOD_TILL_TIME, IMMEDIATE_OR_CANCEL, LIMIT_ORDER, MARKET_ORDER};
use crate::error::{Error, Result};
use crate::hash::{bytes_to_field_elems, fp5_to_le_bytes, hash_to_fp5};
use crate::models::{OrderBookOrders, RespSendTx, RespSendTxBatch};
use crate::nonce::{NonceManager, NonceStrategy};
use crate::rest::RestClient;
use crate::signer::KeyManager;
use crate::transactions::{
    sign_tx, to_signed, CancelAllOrders, CancelOrder, CreateOrder, ModifyOrder, OrderInfo, TxInfo,
    UpdateLeverage, Withdraw,
};

/// Default transaction lifetime (ms): 10 minutes minus 1s of slack.
pub const DEFAULT_EXPIRE_MS: i64 = 10 * 60 * 1000 - 1000;
/// Sentinel for [`OrderParams::order_expiry`] meaning "28 days from now".
pub const DEFAULT_28_DAY_ORDER_EXPIRY: i64 = -1;
const TWENTY_EIGHT_DAYS_MS: i64 = 28 * 24 * 60 * 60 * 1000;

/// Per-call overrides. Defaults route through the nonce manager and use the
/// default transaction lifetime.
#[derive(Debug, Clone, Default)]
pub struct TradeOpts {
    /// Explicit api-key index. `None` lets the nonce manager pick (round-robin).
    pub api_key_index: Option<u8>,
    /// Explicit nonce. `None` lets the nonce manager assign one.
    pub nonce: Option<i64>,
    /// Explicit `expiredAt` (unix-ms). `None` uses [`DEFAULT_EXPIRE_MS`].
    pub expired_at: Option<i64>,
    /// Server-side price-protection flag for `sendTx`.
    pub price_protection: Option<bool>,
}

/// Parameters for [`TradingClient::create_order`].
#[derive(Debug, Clone)]
pub struct OrderParams {
    pub market_index: i16,
    pub client_order_index: i64,
    /// Base size in market ticks.
    pub base_amount: i64,
    /// Limit price in market ticks.
    pub price: u32,
    pub is_ask: bool,
    pub order_type: u8,
    pub time_in_force: u8,
    pub reduce_only: bool,
    pub trigger_price: u32,
    /// `-1` → 28-day expiry, `0` → IOC, otherwise an explicit unix-ms expiry.
    pub order_expiry: i64,
    /// Optional integrator / self-trade attributes.
    pub attributes: TxAttributes,
}

impl Default for OrderParams {
    fn default() -> Self {
        OrderParams {
            market_index: 0,
            client_order_index: 0,
            base_amount: 0,
            price: 0,
            is_ask: false,
            order_type: LIMIT_ORDER,
            time_in_force: GOOD_TILL_TIME,
            reduce_only: false,
            trigger_price: 0,
            order_expiry: DEFAULT_28_DAY_ORDER_EXPIRY,
            attributes: TxAttributes::default(),
        }
    }
}

/// A high-level, cloneable-by-`Arc` trading client.
pub struct TradingClient {
    rest: RestClient,
    account_index: i64,
    chain_id: u32,
    signers: HashMap<u8, KeyManager>,
    nonce_manager: NonceManager,
}

impl TradingClient {
    /// Connects to `url`, derives a signer per provided private key, and primes
    /// the nonce manager.
    ///
    /// `api_private_keys` maps api-key index → 40-byte hex private key.
    pub async fn new(
        url: &str,
        account_index: i64,
        api_private_keys: HashMap<u8, String>,
        strategy: NonceStrategy,
    ) -> Result<Self> {
        if api_private_keys.is_empty() {
            return Err(Error::MissingField("api keys"));
        }
        let chain_id = if url.contains("mainnet") || url.contains("api") {
            304
        } else {
            300
        };
        let rest = RestClient::new(url)?;

        let mut signers = HashMap::with_capacity(api_private_keys.len());
        for (idx, pk) in &api_private_keys {
            signers.insert(*idx, KeyManager::from_hex(pk)?);
        }
        let mut keys: Vec<u8> = api_private_keys.keys().copied().collect();
        keys.sort_unstable();

        let nonce_manager =
            NonceManager::new(rest.clone(), account_index, keys, strategy).await?;

        Ok(TradingClient {
            rest,
            account_index,
            chain_id,
            signers,
            nonce_manager,
        })
    }

    /// The REST client (for read endpoints not yet wrapped here).
    pub fn rest(&self) -> &RestClient {
        &self.rest
    }

    /// The nonce manager.
    pub fn nonce_manager(&self) -> &NonceManager {
        &self.nonce_manager
    }

    pub fn account_index(&self) -> i64 {
        self.account_index
    }

    pub fn chain_id(&self) -> u32 {
        self.chain_id
    }

    // --- order lifecycle -----------------------------------------------------

    /// Signs and submits a create-order transaction.
    pub async fn create_order(
        &self,
        params: OrderParams,
        opts: &TradeOpts,
    ) -> Result<(CreateOrder, RespSendTx)> {
        let (api_key_index, nonce) = self.resolve(opts).await?;
        let tx = CreateOrder {
            account_index: self.account_index,
            api_key_index,
            order: OrderInfo {
                market_index: params.market_index,
                client_order_index: params.client_order_index,
                base_amount: params.base_amount,
                price: params.price,
                is_ask: params.is_ask as u8,
                order_type: params.order_type,
                time_in_force: params.time_in_force,
                reduce_only: params.reduce_only as u8,
                trigger_price: params.trigger_price,
                order_expiry: resolve_order_expiry(params.order_expiry),
            },
            expired_at: self.expired_at(opts),
            nonce,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: params.attributes.to_map(),
        };
        self.sign_and_send(tx, api_key_index, opts.price_protection).await
    }

    /// Convenience: an IOC market order at `avg_execution_price`.
    ///
    /// A thin positional wrapper over [`create_order`](Self::create_order); the
    /// structured `OrderParams` API is the primary entry point.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_market_order(
        &self,
        market_index: i16,
        client_order_index: i64,
        base_amount: i64,
        avg_execution_price: u32,
        is_ask: bool,
        reduce_only: bool,
        opts: &TradeOpts,
    ) -> Result<(CreateOrder, RespSendTx)> {
        self.create_order(
            OrderParams {
                market_index,
                client_order_index,
                base_amount,
                price: avg_execution_price,
                is_ask,
                order_type: MARKET_ORDER,
                time_in_force: IMMEDIATE_OR_CANCEL,
                reduce_only,
                order_expiry: 0,
                ..Default::default()
            },
            opts,
        )
        .await
    }

    /// Market order whose limit price is derived from the live book and the
    /// caller's slippage tolerance, refusing to send if the book is too thin.
    ///
    /// `max_slippage` is a fraction (e.g. `0.01` = 1%). If `ideal_price` is
    /// `None` it is fetched from the order book.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_market_order_limited_slippage(
        &self,
        market_index: i16,
        client_order_index: i64,
        base_amount: i64,
        max_slippage: f64,
        is_ask: bool,
        reduce_only: bool,
        ideal_price: Option<u64>,
        opts: &TradeOpts,
    ) -> Result<(CreateOrder, RespSendTx)> {
        let book = self.order_book_orders(market_index, 100).await?;
        let ideal = match ideal_price {
            Some(p) => p,
            None => best_price_from(&book, is_ask)?,
        };
        let (potential, matched) = potential_execution_price(&book, base_amount as u64, is_ask)?;
        let acceptable = acceptable_price(ideal, max_slippage, is_ask);

        // Reject if the realistic fill price is worse than tolerance.
        if (is_ask && potential < acceptable as f64) || (!is_ask && potential > acceptable as f64) {
            return Err(Error::ExcessiveSlippage);
        }
        if matched < base_amount as u64 {
            return Err(Error::InsufficientDepth);
        }

        self.create_order(
            OrderParams {
                market_index,
                client_order_index,
                base_amount,
                price: acceptable,
                is_ask,
                order_type: MARKET_ORDER,
                time_in_force: IMMEDIATE_OR_CANCEL,
                reduce_only,
                order_expiry: 0,
                ..Default::default()
            },
            opts,
        )
        .await
    }

    /// Signs and submits a cancel-order transaction.
    pub async fn cancel_order(
        &self,
        market_index: i16,
        order_index: i64,
        opts: &TradeOpts,
    ) -> Result<(CancelOrder, RespSendTx)> {
        let (api_key_index, nonce) = self.resolve(opts).await?;
        let tx = CancelOrder {
            account_index: self.account_index,
            api_key_index,
            market_index,
            index: order_index,
            expired_at: self.expired_at(opts),
            nonce,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: None,
        };
        self.sign_and_send(tx, api_key_index, opts.price_protection).await
    }

    /// Signs and submits a cancel-all-orders transaction. `market_index` of
    /// `None` cancels across all markets.
    pub async fn cancel_all_orders(
        &self,
        time_in_force: u8,
        time_ms: i64,
        market_index: Option<i16>,
        opts: &TradeOpts,
    ) -> Result<(CancelAllOrders, RespSendTx)> {
        let (api_key_index, nonce) = self.resolve(opts).await?;
        let attributes = market_index.map(|m| TxAttributes {
            cancel_all_market_index: Some(m),
            ..Default::default()
        });
        let tx = CancelAllOrders {
            account_index: self.account_index,
            api_key_index,
            time_in_force,
            time: time_ms,
            expired_at: self.expired_at(opts),
            nonce,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: attributes.and_then(|a| a.to_map()),
        };
        self.sign_and_send(tx, api_key_index, opts.price_protection).await
    }

    /// Signs and submits a modify-order transaction.
    pub async fn modify_order(
        &self,
        market_index: i16,
        order_index: i64,
        base_amount: i64,
        price: u32,
        trigger_price: u32,
        opts: &TradeOpts,
    ) -> Result<(ModifyOrder, RespSendTx)> {
        let (api_key_index, nonce) = self.resolve(opts).await?;
        let tx = ModifyOrder {
            account_index: self.account_index,
            api_key_index,
            market_index,
            index: order_index,
            base_amount,
            price,
            trigger_price,
            expired_at: self.expired_at(opts),
            nonce,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: None,
        };
        self.sign_and_send(tx, api_key_index, opts.price_protection).await
    }

    /// Signs and submits a withdraw transaction. `amount` is in asset ticks.
    pub async fn withdraw(
        &self,
        asset_index: i16,
        route_type: u8,
        amount: u64,
        opts: &TradeOpts,
    ) -> Result<(Withdraw, RespSendTx)> {
        let (api_key_index, nonce) = self.resolve(opts).await?;
        let tx = Withdraw {
            from_account_index: self.account_index,
            api_key_index,
            asset_index,
            route_type,
            amount,
            expired_at: self.expired_at(opts),
            nonce,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: None,
        };
        self.sign_and_send(tx, api_key_index, opts.price_protection).await
    }

    /// Signs and submits an update-leverage transaction.
    ///
    /// `leverage` is the human leverage (e.g. `20`); it is converted to the
    /// initial-margin fraction `10_000 / leverage`, matching the Python client.
    pub async fn update_leverage(
        &self,
        market_index: i16,
        margin_mode: u8,
        leverage: u16,
        opts: &TradeOpts,
    ) -> Result<(UpdateLeverage, RespSendTx)> {
        let (api_key_index, nonce) = self.resolve(opts).await?;
        let imf = if leverage == 0 {
            0
        } else {
            (10_000 / leverage as u32) as u16
        };
        let tx = UpdateLeverage {
            account_index: self.account_index,
            api_key_index,
            market_index,
            initial_margin_fraction: imf,
            margin_mode,
            expired_at: self.expired_at(opts),
            nonce,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: None,
        };
        self.sign_and_send(tx, api_key_index, opts.price_protection).await
    }

    // --- reads & helpers -----------------------------------------------------

    /// Fetches resting bids/asks for a market (`limit` in 1..=100).
    pub async fn order_book_orders(&self, market_index: i16, limit: u32) -> Result<OrderBookOrders> {
        self.rest.order_book_orders(market_index, limit).await
    }

    /// Best price (in ticks) for the given side: top bid when selling
    /// (`is_ask`), top ask when buying.
    pub async fn best_price(&self, market_index: i16, is_ask: bool) -> Result<u64> {
        let book = self.rest.order_book_orders(market_index, 1).await?;
        best_price_from(&book, is_ask)
    }

    /// Builds an auth-token string `deadline:account:apiKey:signature`.
    pub fn auth_token(&self, deadline_unix_secs: i64, api_key_index: u8) -> Result<String> {
        let key = self
            .signers
            .get(&api_key_index)
            .ok_or(Error::UnknownApiKey(api_key_index))?;
        let message = format!("{deadline_unix_secs}:{}:{}", self.account_index, api_key_index);
        let elems = bytes_to_field_elems(message.as_bytes())?;
        let msg_hash = fp5_to_le_bytes(&hash_to_fp5(&elems));
        let sig = key.sign(&msg_hash)?;
        Ok(format!("{message}:{}", hex::encode(sig)))
    }

    /// Submits a pre-signed transaction directly.
    pub async fn send_tx(
        &self,
        tx_type: u8,
        tx_info: &str,
        price_protection: Option<bool>,
    ) -> Result<RespSendTx> {
        self.rest.send_tx(tx_type, tx_info, price_protection).await
    }

    /// Submits a batch of pre-signed transactions.
    pub async fn send_tx_batch(
        &self,
        tx_types: &[u8],
        tx_infos: &[String],
    ) -> Result<RespSendTxBatch> {
        self.rest.send_tx_batch(tx_types, tx_infos).await
    }

    /// Verifies each configured signer's public key matches the one registered
    /// on Lighter for this account. Returns the first mismatch, if any.
    pub async fn check_client(&self) -> Result<()> {
        let registered = self.rest.apikeys(self.account_index).await?;
        for (idx, signer) in &self.signers {
            let expected = registered
                .api_keys
                .iter()
                .find(|e| e.api_key_index == *idx)
                .ok_or(Error::UnknownApiKey(*idx))?;
            let local = signer.public_key_hex();
            if !keys_equal(&local, &expected.public_key) {
                return Err(Error::Api {
                    code: -1,
                    message: format!("public key mismatch on api key {idx}"),
                });
            }
        }
        Ok(())
    }

    // --- internals -----------------------------------------------------------

    async fn resolve(&self, opts: &TradeOpts) -> Result<(u8, i64)> {
        match (opts.api_key_index, opts.nonce) {
            (Some(k), Some(n)) => Ok((k, n)),
            (k, _) => self.nonce_manager.next(k).await,
        }
    }

    fn expired_at(&self, opts: &TradeOpts) -> i64 {
        opts.expired_at.unwrap_or_else(|| now_ms() + DEFAULT_EXPIRE_MS)
    }

    async fn sign_and_send<T: TxInfo>(
        &self,
        mut tx: T,
        api_key_index: u8,
        price_protection: Option<bool>,
    ) -> Result<(T, RespSendTx)> {
        let key = self
            .signers
            .get(&api_key_index)
            .ok_or(Error::UnknownApiKey(api_key_index))?;
        sign_tx(&mut tx, key, self.chain_id)?;
        let signed = to_signed(&tx, self.chain_id)?;
        match self
            .rest
            .send_tx(signed.tx_type, &signed.tx_info, price_protection)
            .await
        {
            Ok(resp) => Ok((tx, resp)),
            Err(e) => {
                if is_invalid_nonce(&e) {
                    let _ = self.nonce_manager.hard_refresh(api_key_index).await;
                } else {
                    self.nonce_manager.acknowledge_failure(api_key_index);
                }
                Err(e)
            }
        }
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn resolve_order_expiry(order_expiry: i64) -> i64 {
    if order_expiry == DEFAULT_28_DAY_ORDER_EXPIRY {
        now_ms() + TWENTY_EIGHT_DAYS_MS
    } else {
        order_expiry
    }
}

fn is_invalid_nonce(e: &Error) -> bool {
    match e {
        Error::Api { message, .. } => message.contains("invalid nonce"),
        Error::Http(body) => body.contains("invalid nonce"),
        _ => false,
    }
}

fn keys_equal(a: &str, b: &str) -> bool {
    a.trim_start_matches("0x") == b.trim_start_matches("0x")
}

/// Best price (ticks) for a side: top bid when selling, top ask when buying.
fn best_price_from(book: &OrderBookOrders, is_ask: bool) -> Result<u64> {
    let side = if is_ask { &book.bids } else { &book.asks };
    let top = side.first().ok_or(Error::EmptyOrderBook)?;
    top.price_ticks().map_err(|e| Error::Http(e.to_string()))
}

/// Walks the book to estimate the average fill price for a base-size order.
/// Returns `(avg_price_ticks, matched_base_ticks)`.
fn potential_execution_price(
    book: &OrderBookOrders,
    base_amount: u64,
    is_ask: bool,
) -> Result<(f64, u64)> {
    let side = if is_ask { &book.bids } else { &book.asks };
    let mut matched_quote: u128 = 0;
    let mut matched_size: u64 = 0;
    for order in side {
        if matched_size >= base_amount {
            break;
        }
        let price = order.price_ticks().map_err(|e| Error::Http(e.to_string()))?;
        let size = order
            .remaining_ticks()
            .map_err(|e| Error::Http(e.to_string()))?;
        let take = size.min(base_amount - matched_size);
        matched_quote += price as u128 * take as u128;
        matched_size += take;
    }
    if matched_size == 0 {
        return Err(Error::EmptyOrderBook);
    }
    let avg = matched_quote as f64 / matched_size as f64;
    Ok((avg, matched_size))
}

fn acceptable_price(ideal: u64, max_slippage: f64, is_ask: bool) -> u32 {
    let dir = if is_ask { -1.0 } else { 1.0 };
    (ideal as f64 * (1.0 + max_slippage * dir)).round() as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{SimpleOrder, CODE_OK};

    fn order(price: &str, remaining: &str) -> SimpleOrder {
        SimpleOrder {
            order_index: 0,
            order_id: String::new(),
            owner_account_index: 0,
            initial_base_amount: remaining.to_string(),
            remaining_base_amount: remaining.to_string(),
            price: price.to_string(),
            order_expiry: 0,
        }
    }

    fn book() -> OrderBookOrders {
        OrderBookOrders {
            code: CODE_OK,
            message: None,
            total_asks: 2,
            asks: vec![order("100", "10"), order("101", "10")],
            total_bids: 2,
            bids: vec![order("99", "10"), order("98", "10")],
        }
    }

    #[test]
    fn best_price_uses_correct_side() {
        // Selling -> top bid; buying -> top ask.
        assert_eq!(best_price_from(&book(), true).unwrap(), 99);
        assert_eq!(best_price_from(&book(), false).unwrap(), 100);
    }

    #[test]
    fn potential_price_walks_levels() {
        // Buy 15 units: 10 @ 100 + 5 @ 101 = 1505 / 15.
        let (avg, matched) = potential_execution_price(&book(), 15, false).unwrap();
        assert_eq!(matched, 15);
        assert!((avg - (1505.0 / 15.0)).abs() < 1e-9);
    }

    #[test]
    fn acceptable_price_applies_slippage_direction() {
        // Buyer tolerates a higher price, seller a lower one.
        assert_eq!(acceptable_price(100, 0.01, false), 101);
        assert_eq!(acceptable_price(100, 0.01, true), 99);
    }

    #[test]
    fn empty_side_is_an_error() {
        let mut b = book();
        b.asks.clear();
        assert!(matches!(
            best_price_from(&b, false),
            Err(Error::EmptyOrderBook)
        ));
    }
}
