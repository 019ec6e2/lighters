//! Minimal HTTP client for fetching nonces and API keys.
//!
//! Mirrors `lighter-go/client/http`. The [`HttpClient`] trait lets callers plug
//! in their own transport; [`ReqwestClient`] is a blocking default available
//! behind the `http` feature.

use crate::error::{Error, Result};

/// The subset of Lighter's REST API needed to build & submit transactions.
pub trait HttpClient: Send + Sync {
    /// `GET /api/v1/nextNonce` — next nonce for an (account, api-key) pair.
    fn get_next_nonce(&self, account_index: i64, api_key_index: u8) -> Result<i64>;

    /// `GET /api/v1/apikeys` — registered public key for an (account, api-key).
    fn get_api_key(&self, account_index: i64, api_key_index: u8) -> Result<String>;
}

#[cfg(feature = "http")]
mod reqwest_impl {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct ResultCode {
        #[serde(default)]
        code: i32,
        #[serde(default)]
        message: String,
    }

    #[derive(Debug, Deserialize)]
    struct NextNonce {
        #[serde(flatten)]
        status: ResultCode,
        nonce: i64,
    }

    #[derive(Debug, Deserialize)]
    struct ApiKeyEntry {
        api_key_index: u8,
        public_key: String,
    }

    #[derive(Debug, Deserialize)]
    struct AccountApiKeys {
        #[serde(flatten)]
        status: ResultCode,
        #[serde(default)]
        api_keys: Vec<ApiKeyEntry>,
    }

    const CODE_OK: i32 = 200;

    /// A blocking [`HttpClient`] backed by `reqwest`.
    pub struct ReqwestClient {
        endpoint: String,
        client: reqwest::blocking::Client,
    }

    impl ReqwestClient {
        /// Builds a client pointed at `endpoint` (e.g. `https://mainnet.zklighter.elliot.ai`).
        pub fn new(endpoint: impl Into<String>) -> Result<Self> {
            let client = reqwest::blocking::Client::builder()
                .build()
                .map_err(|e| Error::Http(e.to_string()))?;
            Ok(ReqwestClient {
                endpoint: endpoint.into().trim_end_matches('/').to_string(),
                client,
            })
        }

        fn get_text(&self, path: &str, query: &[(&str, String)]) -> Result<String> {
            let url = format!("{}/{}", self.endpoint, path);
            let resp = self
                .client
                .get(&url)
                .query(query)
                .send()
                .map_err(|e| Error::Http(e.to_string()))?;
            let status = resp.status();
            let body = resp.text().map_err(|e| Error::Http(e.to_string()))?;
            if !status.is_success() {
                return Err(Error::Http(body));
            }
            Ok(body)
        }
    }

    impl HttpClient for ReqwestClient {
        fn get_next_nonce(&self, account_index: i64, api_key_index: u8) -> Result<i64> {
            let body = self.get_text(
                "api/v1/nextNonce",
                &[
                    ("account_index", account_index.to_string()),
                    ("api_key_index", api_key_index.to_string()),
                ],
            )?;
            let parsed: NextNonce = serde_json::from_str(&body)?;
            if parsed.status.code != CODE_OK {
                return Err(Error::Http(parsed.status.message));
            }
            Ok(parsed.nonce)
        }

        fn get_api_key(&self, account_index: i64, api_key_index: u8) -> Result<String> {
            let body = self.get_text(
                "api/v1/apikeys",
                &[("account_index", account_index.to_string())],
            )?;
            let parsed: AccountApiKeys = serde_json::from_str(&body)?;
            if parsed.status.code != CODE_OK {
                return Err(Error::Http(parsed.status.message));
            }
            parsed
                .api_keys
                .into_iter()
                .find(|k| k.api_key_index == api_key_index)
                .map(|k| k.public_key)
                .ok_or_else(|| Error::Http(format!("no api key returned for index {api_key_index}")))
        }
    }
}

#[cfg(feature = "http")]
pub use reqwest_impl::ReqwestClient;
