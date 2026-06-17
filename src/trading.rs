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
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::attributes::TxAttributes;
use crate::constants::{
    ticker_scale, GOOD_TILL_TIME, IMMEDIATE_OR_CANCEL, LIMIT_ORDER, MARKET_ORDER,
    STOP_LOSS_LIMIT_ORDER, STOP_LOSS_ORDER, TAKE_PROFIT_LIMIT_ORDER, TAKE_PROFIT_ORDER,
    USDC_TICKER_SCALE,
};
use crate::error::{Error, Result};
use crate::hash::{bytes_to_field_elems, fp5_to_le_bytes, hash_to_fp5};
use crate::models::{OrderBookDetail, OrderBookOrders, RespSendTx, RespSendTxBatch};
use crate::nonce::{NonceManager, NonceStrategy};
use crate::rest::RestClient;
use crate::signer::KeyManager;
use crate::transactions::{
    sign_tx, to_signed, ApproveIntegrator, BurnShares, CancelAllOrders, CancelOrder,
    CreateGroupedOrders, CreateOrder, CreatePublicPool, CreateSubAccount, MintShares, ModifyOrder,
    OrderInfo, StakeAssets, Transfer, TxInfo, UnstakeAssets, UpdateAccountAssetConfig,
    UpdateAccountConfig, UpdateLeverage, UpdateMargin, UpdatePublicPool, Withdraw,
};

#[cfg(feature = "eth")]
use crate::eth::EthSigner;
#[cfg(feature = "eth")]
use crate::transactions::ChangePubKey;

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

/// Per-market scaling metadata, derived from `orderBookDetails`.
///
/// Lets callers work in human prices/sizes: the protocol's integer tick values
/// are `round(human × 10^decimals)`.
#[derive(Debug, Clone)]
pub struct MarketConfig {
    pub market_id: i16,
    pub symbol: String,
    pub market_type: String,
    pub price_decimals: i64,
    pub size_decimals: i64,
    pub min_base_amount: String,
    pub min_quote_amount: String,
}

impl MarketConfig {
    fn from_detail(d: &OrderBookDetail) -> Self {
        MarketConfig {
            market_id: d.market_id as i16,
            symbol: d.symbol.clone(),
            market_type: d.market_type.clone(),
            price_decimals: d.price_decimals,
            size_decimals: d.size_decimals,
            min_base_amount: d.min_base_amount.clone(),
            min_quote_amount: d.min_quote_amount.clone(),
        }
    }

    /// Converts a human price to integer price ticks.
    pub fn price_to_ticks(&self, price: f64) -> u32 {
        (price * 10f64.powi(self.price_decimals as i32)).round() as u32
    }

    /// Converts a human base size to integer base-amount ticks.
    pub fn size_to_ticks(&self, size: f64) -> i64 {
        (size * 10f64.powi(self.size_decimals as i32)).round() as i64
    }

    /// Converts integer price ticks back to a human price.
    pub fn ticks_to_price(&self, ticks: u64) -> f64 {
        ticks as f64 / 10f64.powi(self.price_decimals as i32)
    }

    /// Converts integer base ticks back to a human size.
    pub fn ticks_to_size(&self, ticks: u64) -> f64 {
        ticks as f64 / 10f64.powi(self.size_decimals as i32)
    }
}

/// A high-level, cloneable-by-`Arc` trading client.
pub struct TradingClient {
    rest: RestClient,
    account_index: i64,
    chain_id: u32,
    signers: HashMap<u8, KeyManager>,
    nonce_manager: NonceManager,
    markets: RwLock<HashMap<i16, MarketConfig>>,
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
            markets: RwLock::new(HashMap::new()),
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

    // --- market metadata & human-unit helpers --------------------------------

    /// Returns the cached [`MarketConfig`] for `market_index`, fetching it from
    /// `orderBookDetails` on first use.
    pub async fn market_config(&self, market_index: i16) -> Result<MarketConfig> {
        if let Some(cfg) = self.markets.read().unwrap().get(&market_index).cloned() {
            return Ok(cfg);
        }
        let details = self.rest.order_book_details(Some(market_index)).await?;
        let mut found = None;
        {
            let mut cache = self.markets.write().unwrap();
            for d in details
                .order_book_details
                .iter()
                .chain(details.spot_order_book_details.iter())
            {
                let cfg = MarketConfig::from_detail(d);
                if cfg.market_id == market_index {
                    found = Some(cfg.clone());
                }
                cache.insert(cfg.market_id, cfg);
            }
        }
        found.ok_or(Error::InvalidMarketIndex)
    }

    /// Fetches and caches metadata for every market (one `orderBookDetails`
    /// call). Call once up front to avoid per-market lookups.
    pub async fn refresh_markets(&self) -> Result<()> {
        let details = self.rest.order_book_details(None).await?;
        let mut cache = self.markets.write().unwrap();
        cache.clear();
        for d in details
            .order_book_details
            .iter()
            .chain(details.spot_order_book_details.iter())
        {
            let cfg = MarketConfig::from_detail(d);
            cache.insert(cfg.market_id, cfg);
        }
        Ok(())
    }

    /// Converts a human price to integer price ticks for `market_index`.
    pub async fn price_to_ticks(&self, market_index: i16, price: f64) -> Result<u32> {
        Ok(self.market_config(market_index).await?.price_to_ticks(price))
    }

    /// Converts a human base size to integer base-amount ticks.
    pub async fn size_to_ticks(&self, market_index: i16, size: f64) -> Result<i64> {
        Ok(self.market_config(market_index).await?.size_to_ticks(size))
    }

    /// Limit order specified in human price/size units (auto-scaled to ticks via
    /// the market's decimals).
    #[allow(clippy::too_many_arguments)]
    pub async fn create_limit_order(
        &self,
        market_index: i16,
        client_order_index: i64,
        size: f64,
        price: f64,
        is_ask: bool,
        time_in_force: u8,
        reduce_only: bool,
        opts: &TradeOpts,
    ) -> Result<(CreateOrder, RespSendTx)> {
        let cfg = self.market_config(market_index).await?;
        self.create_order(
            OrderParams {
                market_index,
                client_order_index,
                base_amount: cfg.size_to_ticks(size),
                price: cfg.price_to_ticks(price),
                is_ask,
                order_type: LIMIT_ORDER,
                time_in_force,
                reduce_only,
                order_expiry: DEFAULT_28_DAY_ORDER_EXPIRY,
                ..Default::default()
            },
            opts,
        )
        .await
    }

    /// IOC market order specified in human price/size units. `avg_price` caps
    /// the worst acceptable fill (auto-scaled to ticks via the market's
    /// decimals).
    #[allow(clippy::too_many_arguments)]
    pub async fn create_market_order_value(
        &self,
        market_index: i16,
        client_order_index: i64,
        size: f64,
        avg_price: f64,
        is_ask: bool,
        reduce_only: bool,
        opts: &TradeOpts,
    ) -> Result<(CreateOrder, RespSendTx)> {
        let cfg = self.market_config(market_index).await?;
        self.create_order(
            market_order_params(
                market_index,
                client_order_index,
                cfg.size_to_ticks(size),
                cfg.price_to_ticks(avg_price),
                is_ask,
                reduce_only,
            ),
            opts,
        )
        .await
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

    /// Market order whose IOC limit price is set from the live best price and a
    /// slippage tolerance, capping the worst fill without inspecting depth.
    ///
    /// `max_slippage` is a fraction (e.g. `0.01` = 1%). If `ideal_price` is
    /// `None` the top-of-book price is fetched. Mirrors the Python client's
    /// `create_market_order_limited_slippage`.
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
        let ideal = match ideal_price {
            Some(p) => p,
            None => self.best_price(market_index, is_ask).await?,
        };
        let acceptable = acceptable_price(ideal, max_slippage, is_ask);
        self.create_order(
            market_order_params(market_index, client_order_index, base_amount, acceptable, is_ask, reduce_only),
            opts,
        )
        .await
    }

    /// Market order that walks the live book and only submits if the realistic
    /// fill price stays within `max_slippage` and the book is deep enough.
    ///
    /// Mirrors the Python client's `create_market_order_if_slippage`.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_market_order_if_slippage(
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
        let (potential, matched) =
            potential_execution_price(&book, base_amount as u64, is_ask, true)?;
        let acceptable = acceptable_price(ideal, max_slippage, is_ask);

        if (is_ask && potential < acceptable as f64) || (!is_ask && potential > acceptable as f64) {
            return Err(Error::ExcessiveSlippage);
        }
        if matched < base_amount as u64 {
            return Err(Error::InsufficientDepth);
        }

        self.create_order(
            market_order_params(market_index, client_order_index, base_amount, acceptable, is_ask, reduce_only),
            opts,
        )
        .await
    }

    /// Market order sized by quote (USDC) amount rather than base size. Walks
    /// the book to translate `quote_amount` into a base size at the realistic
    /// fill price, rejecting on excessive slippage or insufficient depth.
    ///
    /// `quote_amount` is a human USDC value (scaled by 1e6 internally). Mirrors
    /// the Python client's `create_market_order_quote_amount`.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_market_order_quote_amount(
        &self,
        market_index: i16,
        client_order_index: i64,
        quote_amount: f64,
        max_slippage: f64,
        is_ask: bool,
        reduce_only: bool,
        ideal_price: Option<u64>,
        opts: &TradeOpts,
    ) -> Result<(CreateOrder, RespSendTx)> {
        let quote = (quote_amount * USDC_TICKER_SCALE as f64) as u64;
        let book = self.order_book_orders(market_index, 100).await?;
        let ideal = match ideal_price {
            Some(p) => p,
            None => best_price_from(&book, is_ask)?,
        };
        let acceptable = acceptable_price(ideal, max_slippage, is_ask);
        let (potential, matched_quote) = potential_execution_price(&book, quote, is_ask, false)?;

        if (is_ask && potential < acceptable as f64) || (!is_ask && potential > acceptable as f64) {
            return Err(Error::ExcessiveSlippage);
        }
        if matched_quote < quote {
            return Err(Error::InsufficientDepth);
        }

        let base_amount = (quote as f64 / potential) as i64;
        self.create_order(
            market_order_params(market_index, client_order_index, base_amount, acceptable, is_ask, reduce_only),
            opts,
        )
        .await
    }

    // --- TP / SL helpers -----------------------------------------------------

    /// Take-profit (market) order: IOC, triggered at `trigger_price`.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_tp_order(
        &self,
        market_index: i16,
        client_order_index: i64,
        base_amount: i64,
        trigger_price: u32,
        price: u32,
        is_ask: bool,
        reduce_only: bool,
        opts: &TradeOpts,
    ) -> Result<(CreateOrder, RespSendTx)> {
        self.create_trigger_order(
            TAKE_PROFIT_ORDER,
            IMMEDIATE_OR_CANCEL,
            market_index,
            client_order_index,
            base_amount,
            trigger_price,
            price,
            is_ask,
            reduce_only,
            opts,
        )
        .await
    }

    /// Take-profit limit order: GTT, triggered at `trigger_price`.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_tp_limit_order(
        &self,
        market_index: i16,
        client_order_index: i64,
        base_amount: i64,
        trigger_price: u32,
        price: u32,
        is_ask: bool,
        reduce_only: bool,
        opts: &TradeOpts,
    ) -> Result<(CreateOrder, RespSendTx)> {
        self.create_trigger_order(
            TAKE_PROFIT_LIMIT_ORDER,
            GOOD_TILL_TIME,
            market_index,
            client_order_index,
            base_amount,
            trigger_price,
            price,
            is_ask,
            reduce_only,
            opts,
        )
        .await
    }

    /// Stop-loss (market) order: IOC, triggered at `trigger_price`.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_sl_order(
        &self,
        market_index: i16,
        client_order_index: i64,
        base_amount: i64,
        trigger_price: u32,
        price: u32,
        is_ask: bool,
        reduce_only: bool,
        opts: &TradeOpts,
    ) -> Result<(CreateOrder, RespSendTx)> {
        self.create_trigger_order(
            STOP_LOSS_ORDER,
            IMMEDIATE_OR_CANCEL,
            market_index,
            client_order_index,
            base_amount,
            trigger_price,
            price,
            is_ask,
            reduce_only,
            opts,
        )
        .await
    }

    /// Stop-loss limit order: GTT, triggered at `trigger_price`.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_sl_limit_order(
        &self,
        market_index: i16,
        client_order_index: i64,
        base_amount: i64,
        trigger_price: u32,
        price: u32,
        is_ask: bool,
        reduce_only: bool,
        opts: &TradeOpts,
    ) -> Result<(CreateOrder, RespSendTx)> {
        self.create_trigger_order(
            STOP_LOSS_LIMIT_ORDER,
            GOOD_TILL_TIME,
            market_index,
            client_order_index,
            base_amount,
            trigger_price,
            price,
            is_ask,
            reduce_only,
            opts,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_trigger_order(
        &self,
        order_type: u8,
        time_in_force: u8,
        market_index: i16,
        client_order_index: i64,
        base_amount: i64,
        trigger_price: u32,
        price: u32,
        is_ask: bool,
        reduce_only: bool,
        opts: &TradeOpts,
    ) -> Result<(CreateOrder, RespSendTx)> {
        self.create_order(
            OrderParams {
                market_index,
                client_order_index,
                base_amount,
                price,
                is_ask,
                order_type,
                time_in_force,
                reduce_only,
                trigger_price,
                order_expiry: DEFAULT_28_DAY_ORDER_EXPIRY,
                ..Default::default()
            },
            opts,
        )
        .await
    }

    /// Signs and submits a grouped-orders transaction (OTO / OCO / OTOCO).
    pub async fn create_grouped_orders(
        &self,
        grouping_type: u8,
        orders: Vec<OrderParams>,
        attributes: TxAttributes,
        opts: &TradeOpts,
    ) -> Result<(CreateGroupedOrders, RespSendTx)> {
        let (api_key_index, nonce) = self.resolve(opts).await?;
        let orders = orders
            .into_iter()
            .map(|p| OrderInfo {
                market_index: p.market_index,
                client_order_index: p.client_order_index,
                base_amount: p.base_amount,
                price: p.price,
                is_ask: p.is_ask as u8,
                order_type: p.order_type,
                time_in_force: p.time_in_force,
                reduce_only: p.reduce_only as u8,
                trigger_price: p.trigger_price,
                order_expiry: resolve_order_expiry(p.order_expiry),
            })
            .collect();
        let tx = CreateGroupedOrders {
            account_index: self.account_index,
            api_key_index,
            grouping_type,
            orders,
            expired_at: self.expired_at(opts),
            nonce,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: attributes.to_map(),
        };
        self.sign_and_send(tx, api_key_index, opts.price_protection).await
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

    /// Float-amount variant of [`withdraw`](Self::withdraw): `amount` is scaled
    /// to ticks by the asset's ticker scale.
    pub async fn withdraw_amount(
        &self,
        asset_id: i16,
        route_type: u8,
        amount: f64,
        opts: &TradeOpts,
    ) -> Result<(Withdraw, RespSendTx)> {
        let ticks = scale_amount(asset_id, amount)?;
        self.withdraw(asset_id, route_type, ticks, opts).await
    }

    /// Signs and submits a create-sub-account transaction.
    pub async fn create_sub_account(
        &self,
        opts: &TradeOpts,
    ) -> Result<(CreateSubAccount, RespSendTx)> {
        let (api_key_index, nonce) = self.resolve(opts).await?;
        let tx = CreateSubAccount {
            account_index: self.account_index,
            api_key_index,
            expired_at: self.expired_at(opts),
            nonce,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: None,
        };
        self.sign_and_send(tx, api_key_index, opts.price_protection).await
    }

    /// Signs and submits an update-margin transaction. `usdc_amount` is a human
    /// USDC value (scaled by 1e6 internally).
    pub async fn update_margin(
        &self,
        market_index: i16,
        usdc_amount: f64,
        direction: u8,
        opts: &TradeOpts,
    ) -> Result<(UpdateMargin, RespSendTx)> {
        let (api_key_index, nonce) = self.resolve(opts).await?;
        let tx = UpdateMargin {
            account_index: self.account_index,
            api_key_index,
            market_index,
            usdc_amount: (usdc_amount * USDC_TICKER_SCALE as f64) as i64,
            direction,
            expired_at: self.expired_at(opts),
            nonce,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: None,
        };
        self.sign_and_send(tx, api_key_index, opts.price_protection).await
    }

    /// Signs and submits an update-account-config transaction.
    pub async fn update_account_config(
        &self,
        account_trading_mode: u8,
        opts: &TradeOpts,
    ) -> Result<(UpdateAccountConfig, RespSendTx)> {
        let (api_key_index, nonce) = self.resolve(opts).await?;
        let tx = UpdateAccountConfig {
            account_index: self.account_index,
            api_key_index,
            account_trading_mode,
            expired_at: self.expired_at(opts),
            nonce,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: None,
        };
        self.sign_and_send(tx, api_key_index, opts.price_protection).await
    }

    /// Signs and submits an update-account-asset-config transaction.
    pub async fn update_account_asset_config(
        &self,
        asset_index: i16,
        asset_margin_mode: u8,
        opts: &TradeOpts,
    ) -> Result<(UpdateAccountAssetConfig, RespSendTx)> {
        let (api_key_index, nonce) = self.resolve(opts).await?;
        let tx = UpdateAccountAssetConfig {
            account_index: self.account_index,
            api_key_index,
            asset_index,
            asset_margin_mode,
            expired_at: self.expired_at(opts),
            nonce,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: None,
        };
        self.sign_and_send(tx, api_key_index, opts.price_protection).await
    }

    /// Signs and submits a create-public-pool transaction.
    pub async fn create_public_pool(
        &self,
        operator_fee: i64,
        initial_total_shares: i64,
        min_operator_share_rate: u16,
        opts: &TradeOpts,
    ) -> Result<(CreatePublicPool, RespSendTx)> {
        let (api_key_index, nonce) = self.resolve(opts).await?;
        let tx = CreatePublicPool {
            account_index: self.account_index,
            api_key_index,
            operator_fee,
            initial_total_shares,
            min_operator_share_rate,
            expired_at: self.expired_at(opts),
            nonce,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: None,
        };
        self.sign_and_send(tx, api_key_index, opts.price_protection).await
    }

    /// Signs and submits an update-public-pool transaction.
    pub async fn update_public_pool(
        &self,
        public_pool_index: i64,
        status: u8,
        operator_fee: i64,
        min_operator_share_rate: u16,
        opts: &TradeOpts,
    ) -> Result<(UpdatePublicPool, RespSendTx)> {
        let (api_key_index, nonce) = self.resolve(opts).await?;
        let tx = UpdatePublicPool {
            account_index: self.account_index,
            api_key_index,
            public_pool_index,
            status,
            operator_fee,
            min_operator_share_rate,
            expired_at: self.expired_at(opts),
            nonce,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: None,
        };
        self.sign_and_send(tx, api_key_index, opts.price_protection).await
    }

    /// Signs and submits a mint-shares transaction.
    pub async fn mint_shares(
        &self,
        public_pool_index: i64,
        share_amount: i64,
        opts: &TradeOpts,
    ) -> Result<(MintShares, RespSendTx)> {
        let (api_key_index, nonce) = self.resolve(opts).await?;
        let tx = MintShares {
            account_index: self.account_index,
            api_key_index,
            public_pool_index,
            share_amount,
            expired_at: self.expired_at(opts),
            nonce,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: None,
        };
        self.sign_and_send(tx, api_key_index, opts.price_protection).await
    }

    /// Signs and submits a burn-shares transaction.
    pub async fn burn_shares(
        &self,
        public_pool_index: i64,
        share_amount: i64,
        opts: &TradeOpts,
    ) -> Result<(BurnShares, RespSendTx)> {
        let (api_key_index, nonce) = self.resolve(opts).await?;
        let tx = BurnShares {
            account_index: self.account_index,
            api_key_index,
            public_pool_index,
            share_amount,
            expired_at: self.expired_at(opts),
            nonce,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: None,
        };
        self.sign_and_send(tx, api_key_index, opts.price_protection).await
    }

    /// Signs and submits a stake-assets transaction.
    pub async fn stake_assets(
        &self,
        staking_pool_index: i64,
        share_amount: i64,
        opts: &TradeOpts,
    ) -> Result<(StakeAssets, RespSendTx)> {
        let (api_key_index, nonce) = self.resolve(opts).await?;
        let tx = StakeAssets {
            account_index: self.account_index,
            api_key_index,
            staking_pool_index,
            share_amount,
            expired_at: self.expired_at(opts),
            nonce,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: None,
        };
        self.sign_and_send(tx, api_key_index, opts.price_protection).await
    }

    /// Signs and submits an unstake-assets transaction.
    pub async fn unstake_assets(
        &self,
        staking_pool_index: i64,
        share_amount: i64,
        opts: &TradeOpts,
    ) -> Result<(UnstakeAssets, RespSendTx)> {
        let (api_key_index, nonce) = self.resolve(opts).await?;
        let tx = UnstakeAssets {
            account_index: self.account_index,
            api_key_index,
            staking_pool_index,
            share_amount,
            expired_at: self.expired_at(opts),
            nonce,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: None,
        };
        self.sign_and_send(tx, api_key_index, opts.price_protection).await
    }

    /// Transfer between accounts under the same L1 master (no L1 signature).
    /// `amount` is a human asset value scaled by the asset's ticker scale.
    #[allow(clippy::too_many_arguments)]
    pub async fn transfer_same_master_account(
        &self,
        to_account_index: i64,
        asset_id: i16,
        route_from: u8,
        route_to: u8,
        amount: f64,
        fee: i64,
        memo: &str,
        opts: &TradeOpts,
    ) -> Result<(Transfer, RespSendTx)> {
        let tx = self.build_transfer(
            to_account_index,
            asset_id,
            route_from,
            route_to,
            amount,
            fee,
            memo,
            String::new(),
            opts,
        )
        .await?;
        let api_key_index = tx.api_key_index;
        self.sign_and_send(tx, api_key_index, opts.price_protection).await
    }

    /// Approve an integrator from an account under the same L1 master (no L1
    /// signature).
    #[allow(clippy::too_many_arguments)]
    pub async fn approve_integrator_same_master_account(
        &self,
        integrator_account_index: i64,
        max_perps_taker_fee: u32,
        max_perps_maker_fee: u32,
        max_spot_taker_fee: u32,
        max_spot_maker_fee: u32,
        approval_expiry: i64,
        opts: &TradeOpts,
    ) -> Result<(ApproveIntegrator, RespSendTx)> {
        let tx = self.build_approve_integrator(
            integrator_account_index,
            max_perps_taker_fee,
            max_perps_maker_fee,
            max_spot_taker_fee,
            max_spot_maker_fee,
            approval_expiry,
            String::new(),
            opts,
        )
        .await?;
        let api_key_index = tx.api_key_index;
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

    /// This account's detailed record (positions, balances, …).
    pub async fn account(&self) -> Result<crate::models::DetailedAccounts> {
        self.rest.account("index", &self.account_index.to_string()).await
    }

    /// Active orders for this account. `market_index` of `None` returns all
    /// markets. Signs a short-lived auth token internally.
    pub async fn active_orders(
        &self,
        market_index: Option<i16>,
    ) -> Result<crate::models::Orders> {
        let api_key_index = self.default_api_key_index();
        let deadline = now_ms() / 1000 + 10 * 60;
        let auth = self.auth_token(deadline, api_key_index)?;
        self.rest
            .account_active_orders(&auth, self.account_index, market_index)
            .await
    }

    /// Inactive (historical) orders for this account.
    pub async fn inactive_orders(
        &self,
        market_index: Option<i16>,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<crate::models::Orders> {
        self.rest
            .account_inactive_orders(self.account_index, market_index, limit, cursor)
            .await
    }

    /// Market details with live stats. `None` returns all markets.
    pub async fn order_book_details(
        &self,
        market_index: Option<i16>,
    ) -> Result<crate::models::OrderBookDetails> {
        self.rest.order_book_details(market_index).await
    }

    /// List of markets / order books. `None` returns all markets.
    pub async fn order_books(
        &self,
        market_index: Option<i16>,
    ) -> Result<crate::models::OrderBooks> {
        self.rest.order_books(market_index).await
    }

    /// Recent public trades for a market.
    pub async fn recent_trades(
        &self,
        market_index: i16,
        limit: u32,
    ) -> Result<crate::models::Trades> {
        self.rest.recent_trades(market_index, limit).await
    }

    /// Trades for a market, optionally filtered to an account.
    pub async fn trades(
        &self,
        market_index: i16,
        limit: u32,
        account_index: Option<i64>,
    ) -> Result<crate::models::Trades> {
        self.rest.trades(market_index, limit, account_index).await
    }

    /// OHLCV candles for a market.
    pub async fn candles(
        &self,
        market_index: i16,
        resolution: &str,
        start_timestamp: i64,
        end_timestamp: i64,
        count_back: u32,
    ) -> Result<crate::models::Candles> {
        self.rest
            .candles(market_index, resolution, start_timestamp, end_timestamp, count_back)
            .await
    }

    /// Historical funding for a market.
    pub async fn fundings(
        &self,
        market_index: i16,
        resolution: &str,
        start_timestamp: i64,
        end_timestamp: i64,
        count_back: u32,
    ) -> Result<crate::models::Fundings> {
        self.rest
            .fundings(market_index, resolution, start_timestamp, end_timestamp, count_back)
            .await
    }

    /// Current funding rates across markets.
    pub async fn funding_rates(&self) -> Result<crate::models::FundingRates> {
        self.rest.funding_rates().await
    }

    /// Exchange-wide configuration.
    pub async fn system_config(&self) -> Result<crate::models::SystemConfig> {
        self.rest.system_config().await
    }

    /// A single transaction by hash.
    pub async fn tx_by_hash(&self, hash: &str) -> Result<crate::models::EnrichedTx> {
        self.rest.tx("hash", hash).await
    }

    /// A page of transactions starting at sequence `index`.
    pub async fn txs(&self, index: i64, limit: u32) -> Result<crate::models::Txs> {
        self.rest.txs(index, limit).await
    }

    /// The lowest configured api-key index (used for read auth tokens).
    fn default_api_key_index(&self) -> u8 {
        self.signers.keys().copied().min().unwrap_or(0)
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

    // --- L1-signed wrappers (`eth` feature) ----------------------------------

    /// Transfer to another account, authorized by an Ethereum L1 signature.
    ///
    /// `eth_private_key` is the L1 wallet key controlling the account; `amount`
    /// is a human asset value scaled by the asset's ticker scale. Requires the
    /// `eth` feature.
    #[cfg(feature = "eth")]
    #[allow(clippy::too_many_arguments)]
    pub async fn transfer(
        &self,
        eth_private_key: &str,
        to_account_index: i64,
        asset_id: i16,
        route_from: u8,
        route_to: u8,
        amount: f64,
        fee: i64,
        memo: &str,
        opts: &TradeOpts,
    ) -> Result<(Transfer, RespSendTx)> {
        let mut tx = self
            .build_transfer(
                to_account_index,
                asset_id,
                route_from,
                route_to,
                amount,
                fee,
                memo,
                String::new(),
                opts,
            )
            .await?;
        tx.l1_sig = self.sign_l1(eth_private_key, &tx)?;
        let api_key_index = tx.api_key_index;
        self.sign_and_send(tx, api_key_index, opts.price_protection).await
    }

    /// Register a new L2 public key, authorized by an Ethereum L1 signature.
    /// Requires the `eth` feature.
    #[cfg(feature = "eth")]
    pub async fn change_pub_key(
        &self,
        eth_private_key: &str,
        pub_key: [u8; crate::constants::PUB_KEY_LENGTH],
        opts: &TradeOpts,
    ) -> Result<(ChangePubKey, RespSendTx)> {
        let (api_key_index, nonce) = self.resolve(opts).await?;
        let mut tx = ChangePubKey {
            account_index: self.account_index,
            api_key_index,
            pub_key,
            l1_sig: String::new(),
            expired_at: self.expired_at(opts),
            nonce,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: None,
        };
        tx.l1_sig = self.sign_l1(eth_private_key, &tx)?;
        self.sign_and_send(tx, api_key_index, opts.price_protection).await
    }

    /// Approve an integrator, authorized by an Ethereum L1 signature. Requires
    /// the `eth` feature.
    #[cfg(feature = "eth")]
    #[allow(clippy::too_many_arguments)]
    pub async fn approve_integrator(
        &self,
        eth_private_key: &str,
        integrator_account_index: i64,
        max_perps_taker_fee: u32,
        max_perps_maker_fee: u32,
        max_spot_taker_fee: u32,
        max_spot_maker_fee: u32,
        approval_expiry: i64,
        opts: &TradeOpts,
    ) -> Result<(ApproveIntegrator, RespSendTx)> {
        let mut tx = self
            .build_approve_integrator(
                integrator_account_index,
                max_perps_taker_fee,
                max_perps_maker_fee,
                max_spot_taker_fee,
                max_spot_maker_fee,
                approval_expiry,
                String::new(),
                opts,
            )
            .await?;
        tx.l1_sig = self.sign_l1(eth_private_key, &tx)?;
        let api_key_index = tx.api_key_index;
        self.sign_and_send(tx, api_key_index, opts.price_protection).await
    }

    #[cfg(feature = "eth")]
    fn sign_l1<T: TxInfo>(&self, eth_private_key: &str, tx: &T) -> Result<String> {
        let message = tx.message_to_sign(self.chain_id).ok_or(Error::L1SignerRequired)?;
        let signer = EthSigner::from_hex(eth_private_key)?;
        signer.sign_eip191(&message)
    }

    #[allow(clippy::too_many_arguments)]
    async fn build_transfer(
        &self,
        to_account_index: i64,
        asset_id: i16,
        route_from: u8,
        route_to: u8,
        amount: f64,
        fee: i64,
        memo: &str,
        l1_sig: String,
        opts: &TradeOpts,
    ) -> Result<Transfer> {
        let (api_key_index, nonce) = self.resolve(opts).await?;
        Ok(Transfer {
            from_account_index: self.account_index,
            api_key_index,
            to_account_index,
            asset_index: asset_id,
            from_route_type: route_from,
            to_route_type: route_to,
            amount: scale_amount(asset_id, amount)? as i64,
            usdc_fee: fee,
            memo: parse_memo(memo)?,
            expired_at: self.expired_at(opts),
            nonce,
            sig: Vec::new(),
            l1_sig,
            signed_hash: String::new(),
            attributes: None,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn build_approve_integrator(
        &self,
        integrator_account_index: i64,
        max_perps_taker_fee: u32,
        max_perps_maker_fee: u32,
        max_spot_taker_fee: u32,
        max_spot_maker_fee: u32,
        approval_expiry: i64,
        l1_sig: String,
        opts: &TradeOpts,
    ) -> Result<ApproveIntegrator> {
        let (api_key_index, nonce) = self.resolve(opts).await?;
        Ok(ApproveIntegrator {
            account_index: self.account_index,
            api_key_index,
            integrator_account_index,
            max_perps_taker_fee,
            max_perps_maker_fee,
            max_spot_taker_fee,
            max_spot_maker_fee,
            approval_expiry,
            expired_at: self.expired_at(opts),
            nonce,
            sig: Vec::new(),
            l1_sig,
            signed_hash: String::new(),
            attributes: None,
        })
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

/// Walks the book to estimate the average fill price for an order.
///
/// When `is_amount_base` is true, `amount` is a base size and the second
/// return value is the matched base size; otherwise `amount` is a quote (USDC)
/// size and the second return value is the matched quote size. Mirrors the
/// Python client's `get_potential_execution_price`.
fn potential_execution_price(
    book: &OrderBookOrders,
    amount: u64,
    is_ask: bool,
    is_amount_base: bool,
) -> Result<(f64, u64)> {
    let side = if is_ask { &book.bids } else { &book.asks };
    let mut matched_quote: u128 = 0;
    let mut matched_size: u64 = 0;
    for order in side {
        let matched = if is_amount_base {
            matched_size
        } else {
            matched_quote as u64
        };
        if matched >= amount {
            break;
        }
        let price = order.price_ticks().map_err(|e| Error::Http(e.to_string()))?;
        let size = order
            .remaining_ticks()
            .map_err(|e| Error::Http(e.to_string()))?;
        let max_possible = if is_amount_base {
            amount - matched_size
        } else if price == 0 {
            0
        } else {
            (amount - matched_quote as u64) / price
        };
        let take = size.min(max_possible);
        matched_quote += price as u128 * take as u128;
        matched_size += take;
    }
    if matched_size == 0 {
        return Err(Error::EmptyOrderBook);
    }
    let avg = matched_quote as f64 / matched_size as f64;
    let matched = if is_amount_base {
        matched_size
    } else {
        matched_quote as u64
    };
    Ok((avg, matched))
}

fn acceptable_price(ideal: u64, max_slippage: f64, is_ask: bool) -> u32 {
    let dir = if is_ask { -1.0 } else { 1.0 };
    (ideal as f64 * (1.0 + max_slippage * dir)).round() as u32
}

/// Builds the [`OrderParams`] for an IOC market order at `price`.
fn market_order_params(
    market_index: i16,
    client_order_index: i64,
    base_amount: i64,
    price: u32,
    is_ask: bool,
    reduce_only: bool,
) -> OrderParams {
    OrderParams {
        market_index,
        client_order_index,
        base_amount,
        price,
        is_ask,
        order_type: MARKET_ORDER,
        time_in_force: IMMEDIATE_OR_CANCEL,
        reduce_only,
        order_expiry: 0,
        ..Default::default()
    }
}

/// Scales a human float `amount` to integer ticks for `asset_id`.
fn scale_amount(asset_id: i16, amount: f64) -> Result<u64> {
    let scale = ticker_scale(asset_id).ok_or(Error::UnsupportedAsset(asset_id))?;
    Ok((amount * scale as f64) as u64)
}

/// Parses a memo as the Go/Python signer does: 32 raw bytes, 64 hex chars, or
/// `0x` + 64 hex chars.
fn parse_memo(memo: &str) -> Result<[u8; 32]> {
    let mut s = memo;
    if s.len() == 66 && s.starts_with("0x") {
        s = &s[2..];
    }
    let mut out = [0u8; 32];
    if s.len() == 64 {
        hex::decode_to_slice(s, &mut out).map_err(|_| Error::InvalidMemo)?;
    } else if s.len() == 32 {
        out.copy_from_slice(s.as_bytes());
    } else {
        return Err(Error::InvalidMemo);
    }
    Ok(out)
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
        let (avg, matched) = potential_execution_price(&book(), 15, false, true).unwrap();
        assert_eq!(matched, 15);
        assert!((avg - (1505.0 / 15.0)).abs() < 1e-9);
    }

    #[test]
    fn potential_price_quote_amount() {
        // Spend 1500 quote buying: 10 @ 100 (=1000) then 4 @ 101 (=404) -> 1404
        // matched quote, 14 base. floor((1500-1000)/101)=4.
        let (avg, matched_quote) = potential_execution_price(&book(), 1500, false, false).unwrap();
        assert_eq!(matched_quote, 1404);
        assert!((avg - (1404.0 / 14.0)).abs() < 1e-9);
    }

    #[test]
    fn parse_memo_accepts_known_forms() {
        assert_eq!(parse_memo(&"a".repeat(32)).unwrap(), [b'a'; 32]);
        let hex = "00".repeat(32);
        assert_eq!(parse_memo(&hex).unwrap(), [0u8; 32]);
        let prefixed = format!("0x{}", "01".repeat(32));
        assert_eq!(parse_memo(&prefixed).unwrap(), [1u8; 32]);
        assert!(matches!(parse_memo("short"), Err(Error::InvalidMemo)));
    }

    #[test]
    fn scale_amount_uses_asset_scale() {
        use crate::constants::{ASSET_ID_ETH, ASSET_ID_USDC};
        assert_eq!(scale_amount(ASSET_ID_USDC, 1.5).unwrap(), 1_500_000);
        assert_eq!(scale_amount(ASSET_ID_ETH, 1.0).unwrap(), 100_000_000);
        assert!(matches!(scale_amount(99, 1.0), Err(Error::UnsupportedAsset(99))));
    }

    #[test]
    fn market_config_scales_human_units() {
        let cfg = MarketConfig {
            market_id: 0,
            symbol: "ETH".to_string(),
            market_type: "perps".to_string(),
            price_decimals: 2,
            size_decimals: 4,
            min_base_amount: "0".to_string(),
            min_quote_amount: "0".to_string(),
        };
        assert_eq!(cfg.price_to_ticks(1234.56), 123_456);
        assert_eq!(cfg.size_to_ticks(1.5), 15_000);
        assert!((cfg.ticks_to_price(123_456) - 1234.56).abs() < 1e-9);
        assert!((cfg.ticks_to_size(15_000) - 1.5).abs() < 1e-9);
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
