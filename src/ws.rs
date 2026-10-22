//! Async WebSocket live-data client (`ws` feature).
//!
//! Connects to the Lighter `/stream` endpoint, subscribes to order-book and
//! account channels, transparently answers pings, and maintains incremental
//! order-book state (a port of the Python client's `update_orders`).
//!
//! Unlike the Python client's print callbacks, this exposes a typed
//! [`WsEvent`] pull-stream via [`WsClient::next_event`], which composes
//! naturally with `tokio::select!` and the rest of an async program.
//!
//! For long-running bots it auto-reconnects with exponential backoff, sends a
//! periodic keepalive ping, and forces a reconnect when the stream goes idle —
//! all tunable via [`WsConfig`]. After a reconnect it clears cached state and
//! emits [`WsEvent::Reconnected`] before fresh snapshots replay.
//!
//! ```no_run
//! # async fn run() -> lighters::Result<()> {
//! use lighters::ws::{WsClient, WsEvent};
//!
//! let mut ws = WsClient::connect("mainnet.zklighter.elliot.ai", &[0], &[]).await?;
//! while let Some(event) = ws.next_event().await? {
//!     if let WsEvent::OrderBook { market_id, book } = event {
//!         println!("market {market_id}: {} bids / {} asks", book.bids.len(), book.asks.len());
//!     }
//! }
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use tokio::time::{Instant, Interval, MissedTickBehavior};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

use crate::error::{Error, Result};

type Stream = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// Effectively-never duration for disabled keepalive / idle timers.
const NEVER: Duration = Duration::from_secs(86_400);

/// A single price level in a streamed order book.
#[derive(Debug, Clone, Deserialize)]
pub struct WsOrder {
    pub price: String,
    #[serde(default)]
    pub size: String,
}

/// The (incrementally maintained) state of one side-pair of an order book.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct OrderBookState {
    #[serde(default, deserialize_with = "de_lenient_vec")]
    pub asks: Vec<WsOrder>,
    #[serde(default, deserialize_with = "de_lenient_vec")]
    pub bids: Vec<WsOrder>,
}

/// A typed event yielded by [`WsClient::next_event`].
#[derive(Debug, Clone)]
pub enum WsEvent {
    /// A snapshot (on subscribe) or post-merge order book for a market.
    OrderBook {
        market_id: String,
        book: OrderBookState,
    },
    /// A typed account snapshot or incremental update from the `account_all`
    /// channel (positions, trades/fills, balances, funding, pool shares).
    ///
    /// Boxed because the account payload is much larger than the order-book
    /// variant.
    Account {
        account_id: String,
        update: Box<AccountUpdate>,
    },
    /// Emitted after the client transparently reconnected and resubscribed
    /// following a dropped connection or idle timeout. All locally cached
    /// order-book / account state was cleared; treat the next snapshots as
    /// authoritative.
    Reconnected,
}

/// Tunables for [`WsClient`] reconnection and keepalive behavior.
///
/// [`Default`] enables auto-reconnect with exponential backoff, a 15s
/// client-initiated keepalive ping, and a 60s idle watchdog.
#[derive(Debug, Clone)]
pub struct WsConfig {
    /// Reconnect transparently when the connection drops or goes idle.
    pub auto_reconnect: bool,
    /// Maximum consecutive reconnect attempts before giving up. `None` retries
    /// forever.
    pub max_reconnect_attempts: Option<u32>,
    /// First reconnect backoff; doubles up to `max_backoff`.
    pub initial_backoff: Duration,
    /// Backoff ceiling.
    pub max_backoff: Duration,
    /// Interval between client-initiated `ping` frames. `None` disables them
    /// (the client still answers server pings).
    pub ping_interval: Option<Duration>,
    /// Force a reconnect if no frame arrives within this window. `None`
    /// disables the watchdog.
    pub idle_timeout: Option<Duration>,
}

impl Default for WsConfig {
    fn default() -> Self {
        WsConfig {
            auto_reconnect: true,
            max_reconnect_attempts: None,
            initial_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(30),
            ping_interval: Some(Duration::from_secs(15)),
            idle_timeout: Some(Duration::from_secs(60)),
        }
    }
}

/// A balance entry from an account update.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct WsAsset {
    #[serde(default)]
    pub symbol: String,
    #[serde(default)]
    pub asset_id: i64,
    #[serde(default)]
    pub balance: String,
    #[serde(default)]
    pub locked_balance: String,
}

/// A perp/spot position from an account update.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct WsPosition {
    #[serde(default)]
    pub market_id: i64,
    #[serde(default)]
    pub symbol: String,
    #[serde(default)]
    pub initial_margin_fraction: String,
    #[serde(default)]
    pub open_order_count: i64,
    #[serde(default)]
    pub pending_order_count: i64,
    #[serde(default)]
    pub position_tied_order_count: i64,
    /// `1` for long, `-1` for short.
    #[serde(default)]
    pub sign: i64,
    /// Absolute position size (base units, as a decimal string).
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
    pub total_funding_paid_out: String,
    #[serde(default)]
    pub margin_mode: i64,
    #[serde(default)]
    pub allocated_margin: String,
}

impl WsPosition {
    /// Signed position size (negative for shorts), parsed from the string.
    pub fn signed_size(&self) -> f64 {
        let mag = self.position.parse::<f64>().unwrap_or(0.0).abs();
        if self.sign < 0 {
            -mag
        } else {
            mag
        }
    }
}

/// A trade (fill) as delivered over the `account_all` channel.
///
/// The account is the `ask` side (seller) when its index equals
/// [`ask_account_id`](Self::ask_account_id) and the `bid` side (buyer) when it
/// equals [`bid_account_id`](Self::bid_account_id). Use [`fill_for`](Self::fill_for)
/// to resolve side / maker-taker / fee from your account's perspective.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct WsTrade {
    #[serde(default)]
    pub trade_id: i64,
    #[serde(default)]
    pub tx_hash: String,
    #[serde(rename = "type", default)]
    pub kind: String,
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
    #[serde(default)]
    pub taker_fee: Option<i64>,
    #[serde(default)]
    pub maker_fee: Option<i64>,
    #[serde(default)]
    pub transaction_time: i64,
}

impl WsTrade {
    /// Resolves this trade into a fill from `account_index`'s perspective, or
    /// `None` if the account is not a counterparty.
    pub fn fill_for(&self, account_index: i64) -> Option<AccountFill> {
        let is_ask = self.ask_account_id == account_index;
        let is_bid = self.bid_account_id == account_index;
        // Not our trade, or a self-trade (nets to zero position change).
        if is_ask == is_bid {
            return None;
        }
        let is_maker = if is_ask {
            self.is_maker_ask
        } else {
            !self.is_maker_ask
        };
        let fee = if is_maker { self.maker_fee } else { self.taker_fee }.unwrap_or(0);
        Some(AccountFill {
            market_id: self.market_id,
            trade_id: self.trade_id,
            tx_hash: self.tx_hash.clone(),
            size: self.size.parse().unwrap_or(0.0),
            price: self.price.parse().unwrap_or(0.0),
            is_buy: is_bid,
            is_maker,
            fee,
            timestamp: self.timestamp,
        })
    }
}

/// A realized fill from one account's perspective, derived from [`WsTrade`].
#[derive(Debug, Clone)]
pub struct AccountFill {
    pub market_id: i64,
    pub trade_id: i64,
    pub tx_hash: String,
    /// Filled base size (always positive).
    pub size: f64,
    pub price: f64,
    /// `true` if the account bought (was the bid), `false` if it sold.
    pub is_buy: bool,
    pub is_maker: bool,
    /// Fee charged to the account, in micro-USDC (1e-6 USDC).
    pub fee: i64,
    pub timestamp: i64,
}

/// A funding payment entry from an account update.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct WsPositionFunding {
    #[serde(default)]
    pub timestamp: i64,
    #[serde(default)]
    pub market_id: i64,
    #[serde(default)]
    pub funding_id: i64,
    #[serde(default)]
    pub change: String,
    #[serde(default)]
    pub rate: String,
    #[serde(default)]
    pub position_size: String,
    #[serde(default)]
    pub position_side: String,
}

/// A public-pool share entry from an account update.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct WsPoolShares {
    #[serde(default)]
    pub public_pool_index: i64,
    #[serde(default)]
    pub shares_amount: i64,
    #[serde(default)]
    pub entry_usdc: String,
}

/// A typed `account_all` snapshot or incremental update.
///
/// `trades` and `funding_histories` are keyed by market index (as a string).
/// On a snapshot ([`is_snapshot`](Self::is_snapshot) is `true`) `trades` carries
/// recent history; on an update it carries only newly matched fills.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AccountUpdate {
    /// `true` for the initial `subscribed/account_all` snapshot, `false` for
    /// subsequent `update/account_all` deltas.
    #[serde(skip)]
    pub is_snapshot: bool,
    #[serde(default)]
    pub account: i64,
    #[serde(default)]
    pub channel: String,
    #[serde(default, deserialize_with = "de_lenient_map")]
    pub assets: HashMap<String, WsAsset>,
    #[serde(default, deserialize_with = "de_lenient_map")]
    pub positions: HashMap<String, WsPosition>,
    #[serde(default, deserialize_with = "de_lenient_map_vec")]
    pub trades: HashMap<String, Vec<WsTrade>>,
    #[serde(default, deserialize_with = "de_lenient_map_vec")]
    pub funding_histories: HashMap<String, Vec<WsPositionFunding>>,
    #[serde(default, deserialize_with = "de_lenient_vec")]
    pub shares: Vec<WsPoolShares>,
    #[serde(default)]
    pub daily_trades_count: i64,
    #[serde(default)]
    pub daily_volume: f64,
    #[serde(default)]
    pub weekly_trades_count: i64,
    #[serde(default)]
    pub weekly_volume: f64,
    #[serde(default)]
    pub monthly_trades_count: i64,
    #[serde(default)]
    pub monthly_volume: f64,
    #[serde(default)]
    pub total_trades_count: i64,
    #[serde(default)]
    pub total_volume: f64,
}

impl AccountUpdate {
    /// All fills in this update from `account_index`'s perspective, across every
    /// market, ordered by `trade_id`.
    pub fn fills_for(&self, account_index: i64) -> Vec<AccountFill> {
        let mut fills: Vec<AccountFill> = self
            .trades
            .values()
            .flatten()
            .filter_map(|t| t.fill_for(account_index))
            .collect();
        fills.sort_by_key(|f| f.trade_id);
        fills
    }

    /// The position in `market_index`, if present.
    pub fn position(&self, market_index: i64) -> Option<&WsPosition> {
        self.positions.get(&market_index.to_string())
    }
}

/// An async WebSocket client for Lighter's `/stream` endpoint.
pub struct WsClient {
    ws: Stream,
    host: String,
    config: WsConfig,
    order_book_ids: Vec<String>,
    account_ids: Vec<String>,
    order_book_states: HashMap<String, OrderBookState>,
    account_states: HashMap<String, AccountUpdate>,
    ping_interval: Interval,
    idle_timeout: Duration,
    last_activity: Instant,
}

/// The outcome of one `select!` race inside [`WsClient::next_event`].
enum Race {
    Frame(Option<std::result::Result<Message, tokio_tungstenite::tungstenite::Error>>),
    PingDue,
    Idle,
}

impl WsClient {
    /// Connects with default [`WsConfig`] (auto-reconnect + keepalive on).
    ///
    /// `host` may include or omit the scheme (`https://` / `wss://`); the
    /// `/stream` path is appended automatically. At least one subscription is
    /// required. Subscriptions are sent once the server's `connected` frame
    /// arrives (driven by [`next_event`](Self::next_event)).
    pub async fn connect(host: &str, order_book_ids: &[i64], account_ids: &[i64]) -> Result<Self> {
        Self::connect_with_config(host, order_book_ids, account_ids, WsConfig::default()).await
    }

    /// Connects with an explicit [`WsConfig`].
    pub async fn connect_with_config(
        host: &str,
        order_book_ids: &[i64],
        account_ids: &[i64],
        config: WsConfig,
    ) -> Result<Self> {
        if order_book_ids.is_empty() && account_ids.is_empty() {
            return Err(Error::MissingField("ws subscriptions"));
        }
        let host = host
            .trim_start_matches("https://")
            .trim_start_matches("wss://")
            .trim_end_matches('/')
            .to_string();
        let ws = dial(&host).await?;
        let ping_interval = make_interval(config.ping_interval.unwrap_or(NEVER));
        let idle_timeout = config.idle_timeout.unwrap_or(NEVER);
        Ok(WsClient {
            ws,
            host,
            config,
            order_book_ids: order_book_ids.iter().map(|i| i.to_string()).collect(),
            account_ids: account_ids.iter().map(|i| i.to_string()).collect(),
            order_book_states: HashMap::new(),
            account_states: HashMap::new(),
            ping_interval,
            idle_timeout,
            last_activity: Instant::now(),
        })
    }

    /// Returns the latest known state of a subscribed order book, if any.
    pub fn order_book(&self, market_id: &str) -> Option<&OrderBookState> {
        self.order_book_states.get(market_id)
    }

    /// Returns the latest known account snapshot for a subscribed account, if any.
    pub fn account(&self, account_id: &str) -> Option<&AccountUpdate> {
        self.account_states.get(account_id)
    }

    /// Reads frames until the next [`WsEvent`], or `Ok(None)` when the stream
    /// closes and auto-reconnect is disabled. Server/client pings, the
    /// `connected` handshake, subscriptions, the idle watchdog, and transparent
    /// reconnection are all handled internally.
    pub async fn next_event(&mut self) -> Result<Option<WsEvent>> {
        loop {
            let deadline = self.last_activity + self.idle_timeout;
            let race = tokio::select! {
                frame = self.ws.next() => Race::Frame(frame),
                _ = self.ping_interval.tick() => Race::PingDue,
                _ = tokio::time::sleep_until(deadline) => Race::Idle,
            };

            match race {
                Race::PingDue => {
                    if self.config.ping_interval.is_some()
                        && self.send_json(r#"{"type":"ping"}"#).await.is_err()
                    {
                        if let Some(ev) = self.on_disconnect().await? {
                            return Ok(Some(ev));
                        }
                        return Ok(None);
                    }
                }
                Race::Idle => {
                    if let Some(ev) = self.on_disconnect().await? {
                        return Ok(Some(ev));
                    }
                    return Ok(None);
                }
                Race::Frame(None) => {
                    if let Some(ev) = self.on_disconnect().await? {
                        return Ok(Some(ev));
                    }
                    return Ok(None);
                }
                Race::Frame(Some(Err(_))) => {
                    if let Some(ev) = self.on_disconnect().await? {
                        return Ok(Some(ev));
                    }
                    return Ok(None);
                }
                Race::Frame(Some(Ok(frame))) => {
                    self.last_activity = Instant::now();
                    let text = match frame {
                        Message::Text(t) => t.to_string(),
                        Message::Binary(b) => String::from_utf8_lossy(&b).into_owned(),
                        Message::Ping(p) => {
                            self.ws
                                .send(Message::Pong(p))
                                .await
                                .map_err(|e| Error::Http(e.to_string()))?;
                            continue;
                        }
                        Message::Close(_) => {
                            if let Some(ev) = self.on_disconnect().await? {
                                return Ok(Some(ev));
                            }
                            return Ok(None);
                        }
                        _ => continue,
                    };
                    if let Some(event) = self.handle_text(&text).await? {
                        return Ok(Some(event));
                    }
                }
            }
        }
    }

    /// Dispatches one decoded text frame, returning an event to surface (or
    /// `None` for internally-handled control frames). Unparseable frames are
    /// skipped rather than killing the stream.
    async fn handle_text(&mut self, text: &str) -> Result<Option<WsEvent>> {
        let value: Value = match serde_json::from_str(text) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        match value.get("type").and_then(Value::as_str).unwrap_or("") {
            "connected" => {
                self.send_subscriptions().await?;
                Ok(None)
            }
            "ping" => {
                self.send_pong().await?;
                Ok(None)
            }
            // A single malformed/edge data frame must not tear down the stream:
            // skip it (return None) rather than letting the parse error bubble
            // out of `next_event` and terminate the connection.
            "subscribed/order_book" => Ok(skip_on_err(self.handle_order_book(&value, true))),
            "update/order_book" => Ok(skip_on_err(self.handle_order_book(&value, false))),
            "subscribed/account_all" => Ok(skip_on_err(self.handle_account(value, true))),
            "update/account_all" => Ok(skip_on_err(self.handle_account(value, false))),
            _ => Ok(None),
        }
    }

    /// Handles a dropped/idle connection: reconnects (clearing stale state) when
    /// `auto_reconnect` is set, returning a [`WsEvent::Reconnected`]; otherwise
    /// signals end-of-stream via `Ok(None)`.
    async fn on_disconnect(&mut self) -> Result<Option<WsEvent>> {
        if !self.config.auto_reconnect {
            return Ok(None);
        }
        self.reconnect().await?;
        Ok(Some(WsEvent::Reconnected))
    }

    /// Reconnects with exponential backoff and clears cached state so the next
    /// snapshots are authoritative. Subscriptions are re-sent on the server's
    /// `connected` frame.
    async fn reconnect(&mut self) -> Result<()> {
        let mut backoff = self.config.initial_backoff;
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            match dial(&self.host).await {
                Ok(ws) => {
                    self.ws = ws;
                    self.order_book_states.clear();
                    self.account_states.clear();
                    self.ping_interval =
                        make_interval(self.config.ping_interval.unwrap_or(NEVER));
                    self.last_activity = Instant::now();
                    return Ok(());
                }
                Err(e) => {
                    if matches!(self.config.max_reconnect_attempts, Some(max) if attempt >= max) {
                        return Err(e);
                    }
                    tokio::time::sleep(backoff).await;
                    backoff = next_backoff(backoff, self.config.max_backoff);
                }
            }
        }
    }

    async fn send_subscriptions(&mut self) -> Result<()> {
        for market_id in self.order_book_ids.clone() {
            self.send_json(&format!(
                r#"{{"type":"subscribe","channel":"order_book/{market_id}"}}"#
            ))
            .await?;
        }
        for account_id in self.account_ids.clone() {
            self.send_json(&format!(
                r#"{{"type":"subscribe","channel":"account_all/{account_id}"}}"#
            ))
            .await?;
        }
        Ok(())
    }

    async fn send_pong(&mut self) -> Result<()> {
        self.send_json(r#"{"type":"pong"}"#).await
    }

    async fn send_json(&mut self, payload: &str) -> Result<()> {
        self.ws
            .send(Message::text(payload.to_string()))
            .await
            .map_err(|e| Error::Http(e.to_string()))
    }

    fn handle_order_book(&mut self, value: &Value, snapshot: bool) -> Result<WsEvent> {
        let market_id = channel_id(value);
        // Treat a present-but-null `order_book` the same as an absent one: the
        // server occasionally sends `"order_book": null`, and `serde(default)`
        // only covers the absent (key-missing) case, not an explicit null.
        let incoming: OrderBookState = value
            .get("order_book")
            .filter(|v| !v.is_null())
            .cloned()
            .map(serde_json::from_value)
            .transpose()?
            .unwrap_or_default();

        let state = self.order_book_states.entry(market_id.clone()).or_default();
        if snapshot {
            *state = incoming;
        } else {
            merge_orders(&incoming.asks, &mut state.asks);
            merge_orders(&incoming.bids, &mut state.bids);
        }
        Ok(WsEvent::OrderBook {
            market_id,
            book: state.clone(),
        })
    }

    fn handle_account(&mut self, value: Value, snapshot: bool) -> Result<WsEvent> {
        let account_id = channel_id(&value);
        let mut update: AccountUpdate = serde_json::from_value(value)?;
        update.is_snapshot = snapshot;
        // The snapshot is full state; deltas only carry changed sub-objects, so
        // we expose them as-is rather than merging (positions are authoritative
        // per message and trades are incremental fills).
        self.account_states
            .insert(account_id.clone(), update.clone());
        Ok(WsEvent::Account {
            account_id,
            update: Box::new(update),
        })
    }
}

/// Downgrades a per-frame handler error into a skipped frame: one malformed or
/// edge-case data frame shouldn't drop the whole connection. Returns `None` so
/// `next_event` keeps reading, mirroring how `handle_text` already silently
/// skips frames whose outer JSON fails to parse.
fn skip_on_err(result: Result<WsEvent>) -> Option<WsEvent> {
    result.ok()
}

/// Doubles `current` backoff, capped at `max`.
fn next_backoff(current: Duration, max: Duration) -> Duration {
    current.saturating_mul(2).min(max)
}

/// Opens a fresh WebSocket connection to `host`'s `/stream` endpoint.
async fn dial(host: &str) -> Result<Stream> {
    let url = format!("wss://{host}/stream");
    let (ws, _) = connect_async(url)
        .await
        .map_err(|e| Error::Http(e.to_string()))?;
    Ok(ws)
}

/// A self-pacing interval whose first tick is skipped (so we don't ping
/// immediately on connect) and that never bursts after a stall.
fn make_interval(period: Duration) -> Interval {
    let mut interval = tokio::time::interval_at(Instant::now() + period, period);
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    interval
}

/// Extracts the id portion of a channel field like `"order_book:1"` → `"1"`.
fn channel_id(value: &Value) -> String {
    value
        .get("channel")
        .and_then(Value::as_str)
        .and_then(|c| c.split(':').nth(1))
        .unwrap_or("")
        .to_string()
}

/// Merges an incremental order update into existing levels (port of the Python
/// client's `update_orders`): matching prices overwrite size, new prices are
/// appended, and zero-size levels are dropped.
fn merge_orders(new_orders: &[WsOrder], existing: &mut Vec<WsOrder>) {
    for new_order in new_orders {
        let mut is_new = true;
        for level in existing.iter_mut() {
            if level.price == new_order.price {
                is_new = false;
                level.size = new_order.size.clone();
            }
        }
        if is_new {
            existing.push(new_order.clone());
        }
    }
    existing.retain(|o| o.size.parse::<f64>().unwrap_or(0.0) > 0.0);
}

/// Coerces a JSON value that may be a single object, an array, or null into a
/// `Vec<T>`, skipping entries that fail to parse. The Lighter docs are
/// inconsistent about whether per-market collections arrive as a single object
/// or an array, so we accept both rather than hard-failing the whole update.
fn lenient_vec<T: DeserializeOwned>(v: Value) -> Vec<T> {
    match v {
        Value::Array(items) => items
            .into_iter()
            .filter_map(|x| serde_json::from_value(x).ok())
            .collect(),
        Value::Null => Vec::new(),
        other => serde_json::from_value::<T>(other).ok().into_iter().collect(),
    }
}

fn de_lenient_vec<'de, D, T>(d: D) -> std::result::Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned,
{
    Ok(lenient_vec(Value::deserialize(d)?))
}

fn de_lenient_map<'de, D, T>(d: D) -> std::result::Result<HashMap<String, T>, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned,
{
    let mut out = HashMap::new();
    if let Value::Object(map) = Value::deserialize(d)? {
        for (k, v) in map {
            if let Ok(t) = serde_json::from_value(v) {
                out.insert(k, t);
            }
        }
    }
    Ok(out)
}

fn de_lenient_map_vec<'de, D, T>(d: D) -> std::result::Result<HashMap<String, Vec<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned,
{
    let mut out = HashMap::new();
    if let Value::Object(map) = Value::deserialize(d)? {
        for (k, v) in map {
            out.insert(k, lenient_vec(v));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn order(price: &str, size: &str) -> WsOrder {
        WsOrder {
            price: price.to_string(),
            size: size.to_string(),
        }
    }

    #[test]
    fn backoff_doubles_and_saturates_at_cap() {
        let max = Duration::from_secs(30);
        assert_eq!(next_backoff(Duration::from_millis(500), max), Duration::from_secs(1));
        assert_eq!(next_backoff(Duration::from_secs(20), max), max);
        // Never exceeds the cap, even from a huge starting point.
        assert_eq!(next_backoff(Duration::from_secs(10_000), max), max);
    }

    #[test]
    fn default_config_enables_reconnect_and_keepalive() {
        let c = WsConfig::default();
        assert!(c.auto_reconnect);
        assert!(c.max_reconnect_attempts.is_none());
        assert!(c.ping_interval.is_some());
        assert!(c.idle_timeout.is_some());
    }

    #[test]
    fn channel_id_extracts_second_segment() {
        let v: Value = serde_json::from_str(r#"{"channel":"order_book:42"}"#).unwrap();
        assert_eq!(channel_id(&v), "42");
    }

    fn parse_account(json: &str) -> AccountUpdate {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn account_update_resolves_fills_from_our_perspective() {
        // Account 10 is the ask (seller) and the maker on this trade.
        let json = r#"{
            "account": 10,
            "channel": "account_all:10",
            "positions": {
                "0": {"market_id": 0, "sign": -1, "position": "4.318"}
            },
            "trades": {
                "0": [{
                    "trade_id": 401,
                    "tx_hash": "0xabc",
                    "type": "trade",
                    "market_id": 0,
                    "size": "0.5",
                    "price": "20000.00",
                    "ask_account_id": 10,
                    "bid_account_id": 99,
                    "is_maker_ask": true,
                    "maker_fee": 28,
                    "taker_fee": 196,
                    "timestamp": 1700000000
                }]
            },
            "type": "update/account_all"
        }"#;
        let update = parse_account(json);
        let fills = update.fills_for(10);
        assert_eq!(fills.len(), 1);
        let f = &fills[0];
        assert_eq!(f.market_id, 0);
        assert!(!f.is_buy, "account was the ask side (seller)");
        assert!(f.is_maker, "is_maker_ask=true and we are the ask");
        assert_eq!(f.fee, 28, "maker fee applies");
        assert!((f.size - 0.5).abs() < 1e-9);
        assert!((f.price - 20000.0).abs() < 1e-9);

        // The counterparty sees the mirror image: a taker buy.
        let other = update.fills_for(99);
        assert_eq!(other.len(), 1);
        assert!(other[0].is_buy);
        assert!(!other[0].is_maker);
        assert_eq!(other[0].fee, 196);

        // An uninvolved account has no fills.
        assert!(update.fills_for(123).is_empty());

        let pos = update.position(0).unwrap();
        assert!((pos.signed_size() - (-4.318)).abs() < 1e-9);
    }

    #[test]
    fn account_update_accepts_single_object_collections() {
        // Docs sometimes deliver per-market collections as a single object
        // rather than an array; we must accept both.
        let json = r#"{
            "account": 7,
            "channel": "account_all:7",
            "trades": {
                "1": {
                    "trade_id": 1, "market_id": 1, "size": "1", "price": "10",
                    "ask_account_id": 7, "bid_account_id": 8, "is_maker_ask": false
                }
            },
            "shares": {"public_pool_index": 1, "shares_amount": 100, "entry_usdc": "1000"},
            "type": "subscribed/account_all"
        }"#;
        let update = parse_account(json);
        let fills = update.fills_for(7);
        assert_eq!(fills.len(), 1);
        // is_maker_ask=false and we are the ask → we are the taker, selling.
        assert!(!fills[0].is_maker && !fills[0].is_buy);
        assert_eq!(update.shares.len(), 1);
    }

    #[test]
    fn account_update_survives_explicit_null_collections() {
        // The server may send a key present-but-null for an empty collection.
        // `serde(default)` only covers the absent case, so every map/vec field
        // must tolerate an explicit null without failing the whole parse.
        let json = r#"{
            "account": 5,
            "channel": "account_all:5",
            "assets": null,
            "positions": null,
            "trades": null,
            "funding_histories": null,
            "shares": null,
            "type": "update/account_all"
        }"#;
        let update = parse_account(json);
        assert_eq!(update.account, 5);
        assert!(update.assets.is_empty());
        assert!(update.positions.is_empty());
        assert!(update.trades.is_empty());
        assert!(update.funding_histories.is_empty());
        assert!(update.shares.is_empty());
    }

    #[test]
    fn order_book_state_survives_explicit_null_sides() {
        // `"asks": null` / `"bids": null` must deserialize to empty, not error
        // with "invalid type: null, expected a sequence".
        let book: OrderBookState =
            serde_json::from_str(r#"{"asks": null, "bids": null}"#).unwrap();
        assert!(book.asks.is_empty());
        assert!(book.bids.is_empty());
    }

    #[test]
    fn skip_on_err_drops_errors_but_passes_events() {
        assert!(skip_on_err(Err(Error::MissingField("x"))).is_none());
        let ev = WsEvent::OrderBook {
            market_id: "1".to_string(),
            book: OrderBookState::default(),
        };
        assert!(skip_on_err(Ok(ev)).is_some());
    }

    #[test]
    fn merge_overwrites_appends_and_prunes() {
        let mut book = vec![order("100", "5"), order("101", "3")];
        // Overwrite 100, remove 101 (size 0), add 102.
        merge_orders(
            &[order("100", "8"), order("101", "0"), order("102", "2")],
            &mut book,
        );
        assert_eq!(book.len(), 2);
        let p100 = book.iter().find(|o| o.price == "100").unwrap();
        assert_eq!(p100.size, "8");
        assert!(book.iter().any(|o| o.price == "102"));
        assert!(!book.iter().any(|o| o.price == "101"));
    }
}
