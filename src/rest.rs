//! Async REST client for the Lighter API (`trading` feature).
//!
//! A thin, hand-written wrapper over `reqwest`'s async client covering the
//! endpoints the trading runtime needs. Bring your own async runtime (e.g.
//! tokio) — this type never spawns tasks or blocks.

use serde::de::DeserializeOwned;

use crate::error::{Error, Result};
use crate::models::{
    AccountApiKeys, NextNonce, OrderBookOrders, RespSendTx, RespSendTxBatch, CODE_OK,
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
