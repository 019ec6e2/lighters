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
//! ```no_run
//! # async fn run() -> lighter::Result<()> {
//! use lighter::ws::{WsClient, WsEvent};
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

use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::Value;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

use crate::error::{Error, Result};

type Stream = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

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
    #[serde(default)]
    pub asks: Vec<WsOrder>,
    #[serde(default)]
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
    /// An account snapshot or update. The raw JSON is preserved since the
    /// account payload is large and use-case specific.
    Account { account_id: String, data: Value },
}

/// An async WebSocket client for Lighter's `/stream` endpoint.
pub struct WsClient {
    ws: Stream,
    order_book_ids: Vec<String>,
    account_ids: Vec<String>,
    order_book_states: HashMap<String, OrderBookState>,
}

impl WsClient {
    /// Connects and prepares subscriptions for the given market and account ids.
    ///
    /// `host` may include or omit the scheme (`https://` / `wss://`); the
    /// `/stream` path is appended automatically. At least one subscription is
    /// required. Subscriptions are sent once the server's `connected` frame
    /// arrives (driven by [`next_event`](Self::next_event)).
    pub async fn connect(host: &str, order_book_ids: &[i16], account_ids: &[i64]) -> Result<Self> {
        if order_book_ids.is_empty() && account_ids.is_empty() {
            return Err(Error::MissingField("ws subscriptions"));
        }
        let host = host
            .trim_start_matches("https://")
            .trim_start_matches("wss://")
            .trim_end_matches('/');
        let url = format!("wss://{host}/stream");
        let (ws, _) = connect_async(url)
            .await
            .map_err(|e| Error::Http(e.to_string()))?;
        Ok(WsClient {
            ws,
            order_book_ids: order_book_ids.iter().map(|i| i.to_string()).collect(),
            account_ids: account_ids.iter().map(|i| i.to_string()).collect(),
            order_book_states: HashMap::new(),
        })
    }

    /// Returns the latest known state of a subscribed order book, if any.
    pub fn order_book(&self, market_id: &str) -> Option<&OrderBookState> {
        self.order_book_states.get(market_id)
    }

    /// Reads frames until the next [`WsEvent`], or `Ok(None)` when the stream
    /// closes. Pings, the `connected` handshake, and subscriptions are handled
    /// internally.
    pub async fn next_event(&mut self) -> Result<Option<WsEvent>> {
        while let Some(frame) = self.ws.next().await {
            let frame = frame.map_err(|e| Error::Http(e.to_string()))?;
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
                Message::Close(_) => return Ok(None),
                _ => continue,
            };

            let value: Value = serde_json::from_str(&text)?;
            match value.get("type").and_then(Value::as_str).unwrap_or("") {
                "connected" => self.send_subscriptions().await?,
                "ping" => self.send_pong().await?,
                "subscribed/order_book" => {
                    return Ok(Some(self.handle_order_book(&value, true)?));
                }
                "update/order_book" => {
                    return Ok(Some(self.handle_order_book(&value, false)?));
                }
                "subscribed/account_all" | "update/account_all" => {
                    return Ok(Some(WsEvent::Account {
                        account_id: channel_id(&value),
                        data: value,
                    }));
                }
                _ => continue,
            }
        }
        Ok(None)
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
        let incoming: OrderBookState = value
            .get("order_book")
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
    fn channel_id_extracts_second_segment() {
        let v: Value = serde_json::from_str(r#"{"channel":"order_book:42"}"#).unwrap();
        assert_eq!(channel_id(&v), "42");
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
