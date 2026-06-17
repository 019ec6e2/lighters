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

The optional `http` feature (on by default) pulls in a blocking `reqwest`
client for nonce / api-key lookups. For a pure offline signer:

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

> Scope: this first pass covers the trading-critical path (orders, cancels,
> modify, market orders + slippage, withdraw, leverage, auth tokens, batch
> submission). The full REST read surface and the live WebSocket feed are not
> yet ported.

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
