# lighter-rust

A native Rust signer and transaction client for the [Lighter](https://lighter.xyz)
exchange. It is a from-scratch port of the official Go SDK
([`lighter-go`](../lighter-go)) and produces **byte-identical** transaction
hashes and Schnorr signatures, so payloads it signs are accepted by the same
sequencer.

## Why a native port (not FFI)

This crate contains no `cgo`/FFI shims and no hand-rolled cryptography. It is
idiomatic Rust that depends on two audited-in-spirit community crates which
mirror the `elliottech/poseidon_crypto` Go reference:

| Concern | Crate | Mirrors (Go) |
| --- | --- | --- |
| Goldilocks field + Poseidon2 hash + `Fp5` quintic extension | [`poseidon-hash`](https://crates.io/crates/poseidon-hash) | `field/goldilocks`, `hash/poseidon2_goldilocks*` |
| ECgFp5 curve + Schnorr signatures + scalar field | [`goldilocks-crypto`](https://crates.io/crates/goldilocks-crypto) | `curve/ecgfp5`, `signature/schnorr` |

We verified that:

- `poseidon-hash::hash_to_quintic_extension` reproduces Go's
  `p2.HashToQuinticExtension` (both Poseidon2 variants in Go use identical round
  constants and the same permutation; only their internal field representation
  differs, so the output values are equal).
- `goldilocks-crypto` uses the same 5-limb (320-bit) scalar field as Go, and its
  Schnorr challenge `e = H(r ‖ H(m))`, response `s = k − e·sk`, and `s ‖ e`
  80-byte encoding match `schnorr.SchnorrSignHashedMessage`.

> ⚠️ Like the upstream crates, this library is **not security audited**. Use at
> your own risk.

## Installation

```toml
[dependencies]
lighter = { path = "../lighter-rust" }
```

Feature flags:

| Feature | Enables |
| --- | --- |
| `http` *(default)* | Blocking `reqwest` client for nonce / api-key lookups. |
| `trading` | Async runtime: REST submission, nonce manager, order/cancel/market helpers, prioritized read endpoints. |
| `eth` | Ethereum L1 (EIP-191 `personal_sign`) signing for `transfer` / `change_pub_key` / `approve_integrator`. |
| `ws` | Async WebSocket live-data client (implies `trading`). |

For a pure offline signer:

```toml
lighter = { path = "../lighter-rust", default-features = false }
```

## Quick start

```rust
use lighter::{TxClient, TransactOpts, OrderReq, TxInfo};

let client = TxClient::new(
    "0x<40-byte-hex-private-key>",
    /* account_index */ 3,
    /* api_key_index */ 0,
    /* chain_id      */ 304,
)?;

// Provide the nonce yourself for a fully offline signer...
let opts = TransactOpts { nonce: Some(0), ..Default::default() };

// ...or attach an HTTP client and leave `nonce: None` to fetch it:
// let client = client.with_http(Box::new(
//     lighter::http::ReqwestClient::new("https://mainnet.zklighter.elliot.ai")?,
// ));

let order = client.create_order(
    OrderReq {
        market_index: 0,
        client_order_index: 1,
        base_amount: 1000,
        price: 50_000,
        is_ask: 0,
        order_type: 0,      // limit
        time_in_force: 1,   // good-till-time
        reduce_only: 0,
        trigger_price: 0,
        order_expiry: 99_999_999,
    },
    &opts,
)?;

println!("tx type:  {}", order.tx_type());
println!("tx hash:  {}", order.tx_hash());
println!("payload:  {}", order.to_json()?);
```

## Trading (online client)

The `trading` feature adds a full async runtime on top of the signer: REST
submission (`sendTx` / `sendTxBatch`), a nonce manager, order-book reads, and
high-level order helpers. Bring your own async runtime (e.g. tokio).

```toml
[dependencies]
lighter = { path = "../lighter-rust", features = ["trading"] }
tokio = { version = "1", features = ["full"] }
```

```rust
use std::collections::HashMap;
use lighter::{TradingClient, NonceStrategy, OrderParams, TradeOpts};
use lighter::constants::{LIMIT_ORDER, GOOD_TILL_TIME};

let mut keys = HashMap::new();
keys.insert(0u8, "0x<40-byte-hex-private-key>".to_string());

let client = TradingClient::new(
    "https://mainnet.zklighter.elliot.ai",
    /* account_index */ 3,
    keys,
    NonceStrategy::Optimistic,
)
.await?;

// Limit order — nonce + api key resolved automatically.
let (order, resp) = client
    .create_order(
        OrderParams {
            market_index: 0,
            client_order_index: 1,
            base_amount: 1000,
            price: 50_000,
            is_ask: false,
            order_type: LIMIT_ORDER,
            time_in_force: GOOD_TILL_TIME,
            ..Default::default()
        },
        &TradeOpts::default(),
    )
    .await?;
println!("submitted {} -> {}", order.tx_hash(), resp.tx_hash);

// IOC market order bounded by 1% slippage off the live book.
let (_mkt, _resp) = client
    .create_market_order_limited_slippage(0, 2, 500, 0.01, false, false, None, &TradeOpts::default())
    .await?;
```

`NonceStrategy::{Optimistic, Api, NoOp}` mirror the Python nonce managers.
Failed submissions automatically roll back the optimistic counter (or hard-
refresh on an "invalid nonce" rejection). Lower-level building blocks are also
public: `RestClient`, `NonceManager`, and the per-transaction structs.

`TradingClient` covers the full trading surface: create / grouped / cancel /
cancel-all / modify orders, TP & SL (market + limit) helpers, market orders by
base size, quote amount, or slippage budget (`create_market_order`,
`create_market_order_limited_slippage`, `create_market_order_if_slippage`,
`create_market_order_quote_amount`), withdraw, transfer, update leverage /
margin / account & asset config, create / update public pools, mint / burn
shares, stake / unstake, sub-accounts, and approve-integrator. Float `amount`
arguments are scaled by the asset's ticker scale (see
`lighter::constants::ticker_scale`).

### Ethereum L1 signing (`eth` feature)

`transfer`, `change_pub_key`, and `approve_integrator` require an L1
`personal_sign` (EIP-191) signature by the account's Ethereum wallet. Pass the
L1 key and the client signs both layers:

```rust
let (tx, resp) = client
    .transfer(
        "0x<eth-private-key>",
        /* to_account_index */ 2,
        /* asset_id (ETH)    */ 1,
        /* route_from        */ 0,
        /* route_to          */ 0,
        /* amount (float)    */ 1.5,
        /* fee (usdc ticks)  */ 1_000,
        /* memo (32B / hex)  */ &"00".repeat(32),
        &TradeOpts::default(),
    )
    .await?;
```

For transfers between accounts under the same L1 master, use the
`*_same_master_account` variants, which skip the L1 signature. `EthSigner` is
also usable standalone for offline EIP-191 signing.

### Prioritized REST reads (`trading` feature)

`TradingClient` and `RestClient` expose the trading-relevant read endpoints:
`account`, `active_orders` / `inactive_orders`, `order_books` /
`order_book_details`, `recent_trades` / `trades`, `candles`, `fundings` /
`funding_rates`, `system_config`, and `tx_by_hash` / `txs`.

### WebSocket live data (`ws` feature)

```rust
use lighter::ws::{WsClient, WsEvent};

let mut ws = WsClient::connect("mainnet.zklighter.elliot.ai", &[0], &[]).await?;
while let Some(event) = ws.next_event().await? {
    match event {
        WsEvent::OrderBook { market_id, book } =>
            println!("market {market_id}: {} bids / {} asks", book.bids.len(), book.asks.len()),
        WsEvent::Account { account_id, .. } =>
            println!("account {account_id} update"),
    }
}
```

The client answers pings, sends subscriptions on connect, and maintains
incremental order-book state, surfacing a typed `WsEvent` pull-stream that
composes with `tokio::select!`.

> Out of scope: `paper_client` and the full ~60-endpoint REST read surface.

## API key generation & auth tokens

```rust
let (private_key_hex, public_key_hex) = lighter::generate_api_key();

let token = client.auth_token(/* deadline unix secs */ 1_900_000_000, &Default::default())?;
```

## Supported transactions

`TxClient` exposes a signing method for every L2 transaction in the Go SDK:

create / grouped / cancel / cancel-all / modify orders, change pubkey,
create sub-account, transfer, withdraw, update leverage / margin /
account-config / account-asset-config, approve integrator, create / update
public pool, mint / burn shares, stake / unstake assets.

Each returns a strongly-typed struct implementing [`TxInfo`], which exposes
`tx_type()`, `validate()`, `hash()`, `tx_hash()`, `to_json()`, and (for
ChangePubKey / Transfer / ApproveIntegrator) `message_to_sign()` for the L1
wallet signature.

## Optional transaction attributes

```rust
use lighter::TxAttributes;

let opts = TransactOpts {
    nonce: Some(0),
    tx_attributes: Some(TxAttributes {
        integrator_account_index: Some(7),
        integrator_taker_fee: Some(100),
        integrator_maker_fee: Some(50),
        ..Default::default()
    }),
    ..Default::default()
};
```

## Compatibility testing

Parity is enforced by tests that diff against vectors generated by the Go
reference:

- `tests/vectors.json` — produced by `go run ./cmd/vectors` in `lighter-go`;
  `tests/parity.rs` rebuilds each transaction and asserts the **message hash**,
  **JSON payload**, and **L1 message** match byte-for-byte.
- `tests/sigvector.json` — produced by `go run ./cmd/sigvector`;
  `tests/signing.rs` asserts public-key derivation and a fixed-nonce signature
  match Go exactly, and that fresh signatures verify.

```bash
cargo test
```

To regenerate the vectors after changing the protocol:

```bash
cd ../lighter-go
go run ./cmd/vectors   > ../lighter-rust/tests/vectors.json
go run ./cmd/sigvector > ../lighter-rust/tests/sigvector.json
```

## License

MIT OR Apache-2.0.
