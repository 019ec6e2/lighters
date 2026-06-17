//! Byte-for-byte parity tests against vectors emitted by the Go reference
//! (`lighter-go/cmd/vectors`). For each transaction we rebuild the exact same
//! inputs, then assert the message hash and JSON match Go's output.

use std::collections::HashMap;

use lighter::attributes::{AttributeMap, TxAttributes};
use lighter::transactions::*;
use serde::Deserialize;

const CHAIN_ID: u32 = 304;
const EXPIRED_AT: i64 = 1_700_000_000_000;
const NONCE: i64 = 42;
const ACCOUNT: i64 = 1;
const API_KEY: u8 = 0;

#[derive(Debug, Deserialize)]
struct Vector {
    name: String,
    tx_type: u8,
    hash: String,
    json: String,
    #[serde(default)]
    msg: String,
}

fn load() -> HashMap<String, Vector> {
    let raw = include_str!("vectors.json");
    let vecs: Vec<Vector> = serde_json::from_str(raw).expect("parse vectors.json");
    vecs.into_iter().map(|v| (v.name.clone(), v)).collect()
}

fn dummy_sig() -> Vec<u8> {
    (0u16..80).map(|i| i as u8).collect()
}

#[allow(clippy::too_many_arguments)]
fn order(market: i16, coi: i64, base: i64, price: u32, is_ask: u8, ty: u8, tif: u8, ro: u8, trig: u32, exp: i64) -> OrderInfo {
    OrderInfo {
        market_index: market,
        client_order_index: coi,
        base_amount: base,
        price,
        is_ask,
        order_type: ty,
        time_in_force: tif,
        reduce_only: ro,
        trigger_price: trig,
        order_expiry: exp,
    }
}

/// Validates, hashes, sets the dummy signature, and checks against the vector.
fn check<T: TxInfo>(vectors: &HashMap<String, Vector>, name: &str, mut tx: T) {
    let v = vectors.get(name).unwrap_or_else(|| panic!("missing vector {name}"));
    assert_eq!(tx.tx_type(), v.tx_type, "{name}: tx_type");
    tx.validate().unwrap_or_else(|e| panic!("{name}: validate: {e}"));
    let hash = tx.hash(CHAIN_ID).unwrap_or_else(|e| panic!("{name}: hash: {e}"));
    assert_eq!(hex::encode(hash), v.hash, "{name}: hash mismatch");
    tx.set_signature(dummy_sig(), String::new());
    assert_eq!(tx.to_json().unwrap(), v.json, "{name}: json mismatch");
}

fn attrs(pairs: &[(u8, i64)]) -> Option<AttributeMap> {
    let mut m = std::collections::BTreeMap::new();
    for (k, val) in pairs {
        m.insert(*k, *val);
    }
    Some(AttributeMap(m))
}

#[test]
fn create_order() {
    let v = load();
    check(
        &v,
        "create_order",
        CreateOrder {
            account_index: ACCOUNT,
            api_key_index: API_KEY,
            order: order(0, 1, 1000, 50000, 0, 0, 1, 0, 0, 99999999),
            expired_at: EXPIRED_AT,
            nonce: NONCE,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: None,
        },
    );
}

#[test]
fn create_order_attrs() {
    let v = load();
    check(
        &v,
        "create_order_attrs",
        CreateOrder {
            account_index: ACCOUNT,
            api_key_index: API_KEY,
            order: order(0, 1, 1000, 50000, 0, 0, 1, 0, 0, 99999999),
            expired_at: EXPIRED_AT,
            nonce: NONCE,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: attrs(&[(1, 7), (2, 100), (3, 50)]),
        },
    );
}

#[test]
fn create_grouped_orders() {
    let v = load();
    let expiry = 7 * 24 * 60 * 60 * 1000;
    check(
        &v,
        "create_grouped_orders",
        CreateGroupedOrders {
            account_index: ACCOUNT,
            api_key_index: API_KEY,
            grouping_type: 1,
            orders: vec![
                order(0, 0, 1000, 50000, 0, 0, 1, 0, 0, expiry),
                order(0, 0, 0, 51000, 1, 4, 0, 1, 49000, expiry),
            ],
            expired_at: EXPIRED_AT,
            nonce: NONCE,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: None,
        },
    );
}

#[test]
fn cancel_order() {
    let v = load();
    check(
        &v,
        "cancel_order",
        CancelOrder {
            account_index: ACCOUNT,
            api_key_index: API_KEY,
            market_index: 0,
            index: 12345,
            expired_at: EXPIRED_AT,
            nonce: NONCE,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: None,
        },
    );
}

#[test]
fn cancel_all_orders_skip() {
    let v = load();
    check(
        &v,
        "cancel_all_orders_skip",
        CancelAllOrders {
            account_index: ACCOUNT,
            api_key_index: API_KEY,
            time_in_force: 0,
            time: 0,
            expired_at: EXPIRED_AT,
            nonce: NONCE,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: attrs(&[(4, 1)]),
        },
    );
}

#[test]
fn modify_order() {
    let v = load();
    check(
        &v,
        "modify_order",
        ModifyOrder {
            account_index: ACCOUNT,
            api_key_index: API_KEY,
            market_index: 0,
            index: 12345,
            base_amount: 2000,
            price: 50000,
            trigger_price: 0,
            expired_at: EXPIRED_AT,
            nonce: NONCE,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: None,
        },
    );
}

#[test]
fn change_pub_key() {
    let v = load();
    let tx = ChangePubKey {
        account_index: ACCOUNT,
        api_key_index: API_KEY,
        pub_key: [0u8; 40],
        l1_sig: String::new(),
        expired_at: EXPIRED_AT,
        nonce: NONCE,
        sig: Vec::new(),
        signed_hash: String::new(),
        attributes: None,
    };
    assert_eq!(
        tx.message_to_sign(CHAIN_ID).unwrap(),
        v["change_pub_key"].msg,
        "change_pub_key: L1 message"
    );
    check(&v, "change_pub_key", tx);
}

#[test]
fn create_sub_account() {
    let v = load();
    check(
        &v,
        "create_sub_account",
        CreateSubAccount {
            account_index: ACCOUNT,
            api_key_index: API_KEY,
            expired_at: EXPIRED_AT,
            nonce: NONCE,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: None,
        },
    );
}

#[test]
fn transfer() {
    let v = load();
    let mut memo = [0u8; 32];
    for (i, b) in memo.iter_mut().enumerate() {
        *b = (i + 1) as u8;
    }
    let tx = Transfer {
        from_account_index: ACCOUNT,
        api_key_index: API_KEY,
        to_account_index: 2,
        asset_index: 1,
        from_route_type: 0,
        to_route_type: 0,
        amount: 1234567890123,
        usdc_fee: 1000,
        memo,
        expired_at: EXPIRED_AT,
        nonce: NONCE,
        sig: Vec::new(),
        l1_sig: String::new(),
        signed_hash: String::new(),
        attributes: None,
    };
    assert_eq!(
        tx.message_to_sign(CHAIN_ID).unwrap(),
        v["transfer"].msg,
        "transfer: L1 message"
    );
    check(&v, "transfer", tx);
}

#[test]
fn withdraw() {
    let v = load();
    check(
        &v,
        "withdraw",
        Withdraw {
            from_account_index: ACCOUNT,
            api_key_index: API_KEY,
            asset_index: 1,
            route_type: 0,
            amount: 9876543210,
            expired_at: EXPIRED_AT,
            nonce: NONCE,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: None,
        },
    );
}

#[test]
fn update_leverage() {
    let v = load();
    check(
        &v,
        "update_leverage",
        UpdateLeverage {
            account_index: ACCOUNT,
            api_key_index: API_KEY,
            market_index: 0,
            initial_margin_fraction: 100,
            margin_mode: 0,
            expired_at: EXPIRED_AT,
            nonce: NONCE,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: None,
        },
    );
}

#[test]
fn update_margin() {
    let v = load();
    check(
        &v,
        "update_margin",
        UpdateMargin {
            account_index: ACCOUNT,
            api_key_index: API_KEY,
            market_index: 0,
            usdc_amount: 5000000,
            direction: 1,
            expired_at: EXPIRED_AT,
            nonce: NONCE,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: None,
        },
    );
}

#[test]
fn update_account_config() {
    let v = load();
    check(
        &v,
        "update_account_config",
        UpdateAccountConfig {
            account_index: ACCOUNT,
            api_key_index: API_KEY,
            account_trading_mode: 1,
            expired_at: EXPIRED_AT,
            nonce: NONCE,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: None,
        },
    );
}

#[test]
fn update_account_asset_config() {
    let v = load();
    check(
        &v,
        "update_account_asset_config",
        UpdateAccountAssetConfig {
            account_index: ACCOUNT,
            api_key_index: API_KEY,
            asset_index: 1,
            asset_margin_mode: 1,
            expired_at: EXPIRED_AT,
            nonce: NONCE,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: None,
        },
    );
}

#[test]
fn approve_integrator() {
    let v = load();
    let tx = ApproveIntegrator {
        account_index: ACCOUNT,
        api_key_index: API_KEY,
        integrator_account_index: 5,
        max_perps_taker_fee: 1000,
        max_perps_maker_fee: 500,
        max_spot_taker_fee: 800,
        max_spot_maker_fee: 400,
        approval_expiry: 1800000000000,
        expired_at: EXPIRED_AT,
        nonce: NONCE,
        sig: Vec::new(),
        l1_sig: String::new(),
        signed_hash: String::new(),
        attributes: None,
    };
    assert_eq!(
        tx.message_to_sign(CHAIN_ID).unwrap(),
        v["approve_integrator"].msg,
        "approve_integrator: L1 message"
    );
    check(&v, "approve_integrator", tx);
}

#[test]
fn create_public_pool() {
    let v = load();
    check(
        &v,
        "create_public_pool",
        CreatePublicPool {
            account_index: ACCOUNT,
            api_key_index: API_KEY,
            operator_fee: 1000,
            initial_total_shares: 1000000,
            min_operator_share_rate: 5000,
            expired_at: EXPIRED_AT,
            nonce: NONCE,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: None,
        },
    );
}

#[test]
fn update_public_pool() {
    let v = load();
    check(
        &v,
        "update_public_pool",
        UpdatePublicPool {
            account_index: ACCOUNT,
            api_key_index: API_KEY,
            public_pool_index: 100,
            status: 1,
            operator_fee: 1000,
            min_operator_share_rate: 5000,
            expired_at: EXPIRED_AT,
            nonce: NONCE,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: None,
        },
    );
}

#[test]
fn mint_shares() {
    let v = load();
    check(
        &v,
        "mint_shares",
        MintShares {
            account_index: ACCOUNT,
            api_key_index: API_KEY,
            public_pool_index: 140737488355328,
            share_amount: 1000,
            expired_at: EXPIRED_AT,
            nonce: NONCE,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: None,
        },
    );
}

#[test]
fn burn_shares() {
    let v = load();
    check(
        &v,
        "burn_shares",
        BurnShares {
            account_index: ACCOUNT,
            api_key_index: API_KEY,
            public_pool_index: 140737488355328,
            share_amount: 1000,
            expired_at: EXPIRED_AT,
            nonce: NONCE,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: None,
        },
    );
}

#[test]
fn stake_assets() {
    let v = load();
    check(
        &v,
        "stake_assets",
        StakeAssets {
            account_index: ACCOUNT,
            api_key_index: API_KEY,
            staking_pool_index: 140737488355328,
            share_amount: 1000,
            expired_at: EXPIRED_AT,
            nonce: NONCE,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: None,
        },
    );
}

#[test]
fn unstake_assets() {
    let v = load();
    check(
        &v,
        "unstake_assets",
        UnstakeAssets {
            account_index: ACCOUNT,
            api_key_index: API_KEY,
            staking_pool_index: 140737488355328,
            share_amount: 1000,
            expired_at: EXPIRED_AT,
            nonce: NONCE,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: None,
        },
    );
}

/// `TxAttributes::to_map` should reproduce the same maps used above.
#[test]
fn tx_attributes_to_map() {
    let a = TxAttributes {
        integrator_account_index: Some(7),
        integrator_taker_fee: Some(100),
        integrator_maker_fee: Some(50),
        ..Default::default()
    };
    assert_eq!(a.to_map(), attrs(&[(1, 7), (2, 100), (3, 50)]));
    assert_eq!(TxAttributes::skip_nonce(true).to_map(), attrs(&[(4, 1)]));
    assert!(TxAttributes::default().to_map().is_none());
}
