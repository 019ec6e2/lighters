//! Async REST client for the Lighter API (`trading` feature).
//!
//! A thin, hand-written wrapper over `reqwest`'s async client covering the
//! endpoints the trading runtime needs. Bring your own async runtime (e.g.
//! tokio) — this type never spawns tasks or blocks.

use serde::de::DeserializeOwned;

use crate::error::{Error, Result};
use crate::models::{
    AccountApiKeys, Candles, DetailedAccounts, EnrichedTx, Fundings, FundingRates, NextNonce,
    OrderBookDetails, OrderBookOrders, OrderBooks, Orders, RespSendTx, RespSendTxBatch,
    SystemConfig, Trades, Txs, CODE_OK,
};

/// A cheaply-cloneable async client bound to one API host.
///
/// `reqwest::Client` holds an internal connection pool behind an `Arc`, so
/// cloning a [`RestClient`] shares that pool.
#[derive(Clone)]
pub struct RestClient {
    base: String,
    http: reqwest::Client,
}

impl RestClient {
    /// Builds a client pointed at `base` (e.g. `https://mainnet.zklighter.elliot.ai`).
    pub fn new(base: impl Into<String>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .build()
            .map_err(|e| Error::Http(e.to_string()))?;
        Ok(Self::with_client(base, http))
    }

    /// Builds a client around a pre-configured `reqwest::Client` (custom
    /// timeouts, proxies, headers, …).
    pub fn with_client(base: impl Into<String>, http: reqwest::Client) -> Self {
        RestClient {
            base: base.into().trim_end_matches('/').to_string(),
            http,
        }
    }

    /// The base URL this client targets.
    pub fn base_url(&self) -> &str {
        &self.base
    }

    async fn get_json<T: DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<T> {
        let url = format!("{}/{path}", self.base);
        let resp = self
            .http
            .get(&url)
            .query(query)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;
        let status = resp.status();
        let body = resp.text().await.map_err(|e| Error::Http(e.to_string()))?;
        if !status.is_success() {
            return Err(Error::Http(body));
        }
        serde_json::from_str(&body).map_err(Error::Json)
    }

    async fn get_json_auth<T: DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, String)],
        auth: &str,
    ) -> Result<T> {
        let url = format!("{}/{path}", self.base);
        let resp = self
            .http
            .get(&url)
            .query(query)
            .header("authorization", auth)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;
        let status = resp.status();
        let body = resp.text().await.map_err(|e| Error::Http(e.to_string()))?;
        if !status.is_success() {
            return Err(Error::Http(body));
        }
        serde_json::from_str(&body).map_err(Error::Json)
    }

    /// `GET /api/v1/nextNonce` — next nonce for an (account, api-key) pair.
    pub async fn next_nonce(&self, account_index: i64, api_key_index: u8) -> Result<i64> {
        let resp: NextNonce = self
            .get_json(
                "api/v1/nextNonce",
                &[
                    ("account_index", account_index.to_string()),
                    ("api_key_index", api_key_index.to_string()),
                ],
            )
            .await?;
        Ok(resp.nonce)
    }

    /// `GET /api/v1/apikeys` — registered API keys for an account.
    pub async fn apikeys(&self, account_index: i64) -> Result<AccountApiKeys> {
        let resp: AccountApiKeys = self
            .get_json(
                "api/v1/apikeys",
                &[("account_index", account_index.to_string())],
            )
            .await?;
        check_code(resp.code, &resp.message)?;
        Ok(resp)
    }

    /// `GET /api/v1/orderBookOrders` — resting bids/asks for a market.
    ///
    /// `limit` must be 1..=100.
    pub async fn order_book_orders(&self, market_index: i16, limit: u32) -> Result<OrderBookOrders> {
        let resp: OrderBookOrders = self
            .get_json(
                "api/v1/orderBookOrders",
                &[
                    ("market_id", market_index.to_string()),
                    ("limit", limit.to_string()),
                ],
            )
            .await?;
        check_code(resp.code, &resp.message)?;
        Ok(resp)
    }

    // --- prioritized read endpoints ------------------------------------------

    /// `GET /api/v1/account` — detailed account(s) looked up by `by`/`value`
    /// (e.g. `("index", "3")` or `("l1_address", "0x…")`).
    pub async fn account(&self, by: &str, value: &str) -> Result<DetailedAccounts> {
        let resp: DetailedAccounts = self
            .get_json(
                "api/v1/account",
                &[("by", by.to_string()), ("value", value.to_string())],
            )
            .await?;
        check_code(resp.code, &resp.message)?;
        Ok(resp)
    }

    /// `GET /api/v1/accountActiveOrders` — active orders for an account.
    ///
    /// `auth` is an auth token (see `TradingClient::auth_token`). `market_id`
    /// of `None` returns all markets.
    pub async fn account_active_orders(
        &self,
        auth: &str,
        account_index: i64,
        market_id: Option<i16>,
    ) -> Result<Orders> {
        let mut query = vec![("account_index", account_index.to_string())];
        if let Some(m) = market_id {
            query.push(("market_id", m.to_string()));
        }
        let resp: Orders = self
            .get_json_auth("api/v1/accountActiveOrders", &query, auth)
            .await?;
        check_code(resp.code, &resp.message)?;
        Ok(resp)
    }

    /// `GET /api/v1/accountInactiveOrders` — inactive orders for an account.
    pub async fn account_inactive_orders(
        &self,
        account_index: i64,
        market_id: Option<i16>,
        limit: Option<u32>,
        cursor: Option<&str>,
    ) -> Result<Orders> {
        let mut query = vec![("account_index", account_index.to_string())];
        if let Some(m) = market_id {
            query.push(("market_id", m.to_string()));
        }
        if let Some(l) = limit {
            query.push(("limit", l.to_string()));
        }
        if let Some(c) = cursor {
            query.push(("cursor", c.to_string()));
        }
        let resp: Orders = self
            .get_json("api/v1/accountInactiveOrders", &query)
            .await?;
        check_code(resp.code, &resp.message)?;
        Ok(resp)
    }

    /// `GET /api/v1/orderBookDetails` — market details with live stats.
    /// `market_id` of `None` returns all markets.
    pub async fn order_book_details(&self, market_id: Option<i16>) -> Result<OrderBookDetails> {
        let query = market_id
            .map(|m| vec![("market_id", m.to_string())])
            .unwrap_or_default();
        let resp: OrderBookDetails = self.get_json("api/v1/orderBookDetails", &query).await?;
        check_code(resp.code, &resp.message)?;
        Ok(resp)
    }

    /// `GET /api/v1/orderBooks` — list of markets / order books.
    pub async fn order_books(&self, market_id: Option<i16>) -> Result<OrderBooks> {
        let query = market_id
            .map(|m| vec![("market_id", m.to_string())])
            .unwrap_or_default();
        let resp: OrderBooks = self.get_json("api/v1/orderBooks", &query).await?;
        check_code(resp.code, &resp.message)?;
        Ok(resp)
    }

    /// `GET /api/v1/recentTrades` — recent public trades for a market.
    pub async fn recent_trades(&self, market_id: i16, limit: u32) -> Result<Trades> {
        let resp: Trades = self
            .get_json(
                "api/v1/recentTrades",
                &[
                    ("market_id", market_id.to_string()),
                    ("limit", limit.to_string()),
                ],
            )
            .await?;
        check_code(resp.code, &resp.message)?;
        Ok(resp)
    }

    /// `GET /api/v1/trades` — trades for a market with optional account filter.
    pub async fn trades(
        &self,
        market_id: i16,
        limit: u32,
        account_index: Option<i64>,
    ) -> Result<Trades> {
        let mut query = vec![
            ("market_id", market_id.to_string()),
            ("limit", limit.to_string()),
        ];
        if let Some(a) = account_index {
            query.push(("account_index", a.to_string()));
        }
        let resp: Trades = self.get_json("api/v1/trades", &query).await?;
        check_code(resp.code, &resp.message)?;
        Ok(resp)
    }

    /// `GET /api/v1/candles` — OHLCV candles for a market.
    pub async fn candles(
        &self,
        market_id: i16,
        resolution: &str,
        start_timestamp: i64,
        end_timestamp: i64,
        count_back: u32,
    ) -> Result<Candles> {
        let resp: Candles = self
            .get_json(
                "api/v1/candles",
                &[
                    ("market_id", market_id.to_string()),
                    ("resolution", resolution.to_string()),
                    ("start_timestamp", start_timestamp.to_string()),
                    ("end_timestamp", end_timestamp.to_string()),
                    ("count_back", count_back.to_string()),
                ],
            )
            .await?;
        check_code(resp.code, &resp.message)?;
        Ok(resp)
    }

    /// `GET /api/v1/fundings` — historical funding for a market.
    pub async fn fundings(
        &self,
        market_id: i16,
        resolution: &str,
        start_timestamp: i64,
        end_timestamp: i64,
        count_back: u32,
    ) -> Result<Fundings> {
        let resp: Fundings = self
            .get_json(
                "api/v1/fundings",
                &[
                    ("market_id", market_id.to_string()),
                    ("resolution", resolution.to_string()),
                    ("start_timestamp", start_timestamp.to_string()),
                    ("end_timestamp", end_timestamp.to_string()),
                    ("count_back", count_back.to_string()),
                ],
            )
            .await?;
        check_code(resp.code, &resp.message)?;
        Ok(resp)
    }

    /// `GET /api/v1/funding-rates` — current funding rates across markets.
    pub async fn funding_rates(&self) -> Result<FundingRates> {
        let resp: FundingRates = self.get_json("api/v1/funding-rates", &[]).await?;
        check_code(resp.code, &resp.message)?;
        Ok(resp)
    }

    /// `GET /api/v1/systemConfig` — exchange-wide configuration.
    pub async fn system_config(&self) -> Result<SystemConfig> {
        let resp: SystemConfig = self.get_json("api/v1/systemConfig", &[]).await?;
        check_code(resp.code, &resp.message)?;
        Ok(resp)
    }

    /// `GET /api/v1/tx` — a single transaction looked up by `by`/`value`
    /// (e.g. `("hash", "0x…")` or `("sequence_index", "42")`).
    pub async fn tx(&self, by: &str, value: &str) -> Result<EnrichedTx> {
        let resp: EnrichedTx = self
            .get_json(
                "api/v1/tx",
                &[("by", by.to_string()), ("value", value.to_string())],
            )
            .await?;
        check_code(resp.code, &resp.message)?;
        Ok(resp)
    }

    /// `GET /api/v1/txs` — a page of transactions starting at `index`.
    pub async fn txs(&self, index: i64, limit: u32) -> Result<Txs> {
        let resp: Txs = self
            .get_json(
                "api/v1/txs",
                &[
                    ("index", index.to_string()),
                    ("limit", limit.to_string()),
                ],
            )
            .await?;
        check_code(resp.code, &resp.message)?;
        Ok(resp)
    }

    /// `POST /api/v1/sendTx` — submit one signed transaction.
    pub async fn send_tx(
        &self,
        tx_type: u8,
        tx_info: &str,
        price_protection: Option<bool>,
    ) -> Result<RespSendTx> {
        let mut form: Vec<(&str, String)> =
            vec![("tx_type", tx_type.to_string()), ("tx_info", tx_info.to_string())];
        if let Some(pp) = price_protection {
            form.push(("price_protection", pp.to_string()));
        }
        let resp: RespSendTx = self.post_form("api/v1/sendTx", &form).await?;
        check_code(resp.code, &resp.message)?;
        Ok(resp)
    }

    /// `POST /api/v1/sendTxBatch` — submit a batch of signed transactions.
    ///
    /// `tx_types[i]` corresponds to `tx_infos[i]`; both must be the same length.
    pub async fn send_tx_batch(
        &self,
        tx_types: &[u8],
        tx_infos: &[String],
    ) -> Result<RespSendTxBatch> {
        if tx_types.len() != tx_infos.len() {
            return Err(Error::Http(
                "tx_types and tx_infos must have the same length".to_string(),
            ));
        }
        if tx_types.is_empty() {
            return Err(Error::Http("empty batch".to_string()));
        }
        let types_json = serde_json::to_string(tx_types).map_err(Error::Json)?;
        let infos_json = serde_json::to_string(tx_infos).map_err(Error::Json)?;
        let resp: RespSendTxBatch = self
            .post_form(
                "api/v1/sendTxBatch",
                &[("tx_types", types_json), ("tx_infos", infos_json)],
            )
            .await?;
        check_code(resp.code, &resp.message)?;
        Ok(resp)
    }

    async fn post_form<T: DeserializeOwned>(
        &self,
        path: &str,
        form: &[(&str, String)],
    ) -> Result<T> {
        let url = format!("{}/{path}", self.base);
        let resp = self
            .http
            .post(&url)
            .form(form)
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;
        let status = resp.status();
        let body = resp.text().await.map_err(|e| Error::Http(e.to_string()))?;
        if !status.is_success() {
            return Err(Error::Http(body));
        }
        serde_json::from_str(&body).map_err(Error::Json)
    }
}

fn check_code(code: i32, message: &Option<String>) -> Result<()> {
    if code != CODE_OK {
        return Err(Error::Api {
            code,
            message: message.clone().unwrap_or_default(),
        });
    }
    Ok(())
}
