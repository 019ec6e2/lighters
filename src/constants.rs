//! Protocol constants, ported verbatim from `lighter-go/types/txtypes/constants.go`.
//!
//! The numeric values here are part of the wire protocol; do not change them
//! without keeping them in sync with the Go reference and the sequencer.

// -- Transaction types --
pub const TX_TYPE_L2_CHANGE_PUB_KEY: u8 = 8;
pub const TX_TYPE_L2_CREATE_SUB_ACCOUNT: u8 = 9;
pub const TX_TYPE_L2_CREATE_PUBLIC_POOL: u8 = 10;
pub const TX_TYPE_L2_UPDATE_PUBLIC_POOL: u8 = 11;
pub const TX_TYPE_L2_TRANSFER: u8 = 12;
pub const TX_TYPE_L2_WITHDRAW: u8 = 13;
pub const TX_TYPE_L2_CREATE_ORDER: u8 = 14;
pub const TX_TYPE_L2_CANCEL_ORDER: u8 = 15;
pub const TX_TYPE_L2_CANCEL_ALL_ORDERS: u8 = 16;
pub const TX_TYPE_L2_MODIFY_ORDER: u8 = 17;
pub const TX_TYPE_L2_MINT_SHARES: u8 = 18;
pub const TX_TYPE_L2_BURN_SHARES: u8 = 19;
pub const TX_TYPE_L2_UPDATE_LEVERAGE: u8 = 20;
pub const TX_TYPE_L2_APPROVE_INTEGRATOR: u8 = 45;
pub const TX_TYPE_L2_CREATE_GROUPED_ORDERS: u8 = 28;
pub const TX_TYPE_L2_UPDATE_MARGIN: u8 = 29;
pub const TX_TYPE_L2_UPDATE_ACCOUNT_CONFIG: u8 = 41;
pub const TX_TYPE_L2_UPDATE_ACCOUNT_ASSET_CONFIG: u8 = 42;
pub const TX_TYPE_L2_STAKE_ASSETS: u8 = 35;
pub const TX_TYPE_L2_UNSTAKE_ASSETS: u8 = 36;

// -- Order types --
pub const LIMIT_ORDER: u8 = 0;
pub const MARKET_ORDER: u8 = 1;
pub const STOP_LOSS_ORDER: u8 = 2;
pub const STOP_LOSS_LIMIT_ORDER: u8 = 3;
pub const TAKE_PROFIT_ORDER: u8 = 4;
pub const TAKE_PROFIT_LIMIT_ORDER: u8 = 5;
pub const TWAP_ORDER: u8 = 6;

// -- Time-in-force --
pub const IMMEDIATE_OR_CANCEL: u8 = 0;
pub const GOOD_TILL_TIME: u8 = 1;
pub const POST_ONLY: u8 = 2;

// -- Grouping types --
pub const GROUPING_TYPE_ONE_TRIGGERS_THE_OTHER: u8 = 1;
pub const GROUPING_TYPE_ONE_CANCELS_THE_OTHER: u8 = 2;
pub const GROUPING_TYPE_ONE_TRIGGERS_A_ONE_CANCELS_THE_OTHER: u8 = 3;

// -- Cancel-all time-in-force --
pub const IMMEDIATE_CANCEL_ALL: u8 = 0;
pub const SCHEDULED_CANCEL_ALL: u8 = 1;
pub const ABORT_SCHEDULED_CANCEL_ALL: u8 = 2;

// -- Account asset margin mode --
pub const ACCOUNT_ASSET_MARGIN_MODE_DISABLED: u8 = 0;
pub const ACCOUNT_ASSET_MARGIN_MODE_ENABLED: u8 = 1;

// -- Asset route type --
pub const ASSET_ROUTE_TYPE_PERPS: u8 = 0;
pub const ASSET_ROUTE_TYPE_SPOT: u8 = 1;

// -- Position margin mode --
pub const CROSS_MARGIN: u8 = 0;
pub const ISOLATED_MARGIN: u8 = 1;

// -- Margin update direction --
pub const REMOVE_FROM_ISOLATED_MARGIN: u8 = 0;
pub const ADD_TO_ISOLATED_MARGIN: u8 = 1;

// -- Self trade behavior/equality --
pub const SELF_TRADE_BEHAVIOR_EXPIRE_MAKER: i64 = 0;
pub const SELF_TRADE_BEHAVIOR_REDUCE: i64 = 3;
pub const SELF_TRADE_EQUALITY_ACCOUNT_INDEX: i64 = 0;
pub const SELF_TRADE_EQUALITY_MASTER_ACCOUNT_INDEX: i64 = 1;

// -- Numeric limits --
pub const ONE_USDC: i64 = 1_000_000;
pub const ONE_LIT: i64 = 100_000_000;
pub const FEE_TICK: i64 = 1_000_000;
pub const MARGIN_FRACTION_TICK: i64 = 10_000;
pub const SHARE_TICK: u16 = 10_000;

pub const MIN_ACCOUNT_INDEX: i64 = -1;
pub const MAX_ACCOUNT_INDEX: i64 = 281_474_976_710_654; // (1 << 48) - 2
pub const MAX_MASTER_ACCOUNT_INDEX: i64 = 140_737_488_355_327; // (1 << 47) - 1
pub const MIN_SUB_ACCOUNT_INDEX: i64 = 140_737_488_355_328; // (1 << 47)
pub const MIN_API_KEY_INDEX: u8 = 0;
pub const MAX_API_KEY_INDEX: u8 = 254; // (1 << 8) - 2
pub const NIL_API_KEY_INDEX: u8 = 255; // MaxApiKeyIndex + 1

pub const MIN_PERPS_MARKET_INDEX: i16 = 0;
pub const MAX_PERPS_MARKET_INDEX: i16 = 254; // (1 << 8) - 2
pub const NIL_MARKET_INDEX: i16 = 255;
pub const MIN_SPOT_MARKET_INDEX: i16 = 2048; // (1 << 11)
pub const MAX_SPOT_MARKET_INDEX: i16 = 4094; // (1 << 12) - 2

pub const NIL_INTEGRATOR_INDEX: i64 = 0;
pub const NIL_INTEGRATOR_TAKER_FEE: u32 = 0;
pub const NIL_INTEGRATOR_MAKER_FEE: u32 = 0;

pub const MIN_ASSET_INDEX: i16 = 1;
pub const MAX_ASSET_INDEX: i16 = (1 << 6) - 2;

pub const INITIAL_POOL_SHARE_VALUE: i64 = 1_000;
pub const MIN_INITIAL_TOTAL_SHARES: i64 = 1_000 * (ONE_USDC / INITIAL_POOL_SHARE_VALUE);
pub const MAX_INITIAL_TOTAL_SHARES: i64 = 1_000_000_000 * (ONE_USDC / INITIAL_POOL_SHARE_VALUE);
pub const MIN_POOL_SHARES_TO_MINT_OR_BURN: i64 = 1;
pub const MAX_POOL_SHARES_TO_MINT_OR_BURN: i64 = (1 << 60) - 1;
pub const MIN_STAKING_SHARES_TO_MINT_OR_BURN: i64 = 1;
pub const MAX_STAKING_SHARES_TO_MINT_OR_BURN: i64 = (1 << 60) - 1;

pub const NB_ATTRIBUTES_PER_TX: usize = 4;

pub const MIN_NONCE: i64 = 0;

pub const NIL_CLIENT_ORDER_INDEX: i64 = 0;
pub const MIN_CLIENT_ORDER_INDEX: i64 = 1;
pub const MAX_CLIENT_ORDER_INDEX: i64 = (1 << 48) - 1;
pub const MIN_ORDER_INDEX: i64 = MAX_CLIENT_ORDER_INDEX + 1;
pub const MAX_ORDER_INDEX: i64 = (1 << 60) - 1;

pub const MIN_ORDER_BASE_AMOUNT: i64 = 1;
pub const MAX_ORDER_BASE_AMOUNT: i64 = (1 << 48) - 1;
pub const NIL_ORDER_BASE_AMOUNT: i64 = 0;

pub const MIN_ORDER_PRICE: u32 = 1;
pub const MAX_ORDER_PRICE: u32 = u32::MAX;

pub const NIL_ORDER_EXPIRY: i64 = 0;
pub const MIN_ORDER_EXPIRY: i64 = 1;
pub const MAX_ORDER_EXPIRY: i64 = i64::MAX;

pub const NIL_ORDER_TRIGGER_PRICE: u32 = 0;
pub const MIN_ORDER_TRIGGER_PRICE: u32 = 1;
pub const MAX_ORDER_TRIGGER_PRICE: u32 = u32::MAX;

pub const MAX_GROUPED_ORDER_COUNT: usize = 3;

pub const MAX_TIMESTAMP: i64 = (1 << 48) - 1;

pub const MAX_EXCHANGE_USDC: i64 = (1 << 60) - 1;
pub const MIN_TRANSFER_AMOUNT: i64 = 1;
pub const MAX_TRANSFER_AMOUNT: i64 = MAX_EXCHANGE_USDC;
pub const MIN_WITHDRAWAL_AMOUNT: u64 = 1;
pub const MAX_WITHDRAWAL_AMOUNT: u64 = MAX_EXCHANGE_USDC as u64;

// -- Attribute types --
pub const ATTRIBUTE_TYPE_INTEGRATOR_ACCOUNT_INDEX: u8 = 1;
pub const ATTRIBUTE_TYPE_INTEGRATOR_TAKER_FEE: u8 = 2;
pub const ATTRIBUTE_TYPE_INTEGRATOR_MAKER_FEE: u8 = 3;
pub const ATTRIBUTE_TYPE_SKIP_TX_NONCE: u8 = 4;
pub const ATTRIBUTE_TYPE_CANCEL_ALL_MARKET_INDEX: u8 = 5;
pub const ATTRIBUTE_TYPE_SELF_TRADE_BEHAVIOR_MODE: u8 = 6;
pub const ATTRIBUTE_TYPE_SELF_TRADE_EQUALITY_MODE: u8 = 7;
pub const MAX_ATTRIBUTE_TYPE: u8 = ATTRIBUTE_TYPE_SELF_TRADE_EQUALITY_MODE;

// -- Asset ids & ticker scales --
//
// Off-chain amounts (floats) are scaled to integer ticks by an asset-specific
// factor before signing, matching the Python client's `ASSET_TO_TICKER_SCALE`.
pub const ASSET_ID_ETH: i16 = 1;
pub const ASSET_ID_LIT: i16 = 2;
pub const ASSET_ID_USDC: i16 = 3;
pub const ASSET_ID_LINK: i16 = 5;
pub const ASSET_ID_UNI: i16 = 6;
pub const ASSET_ID_AAVE: i16 = 7;
pub const ASSET_ID_SKY: i16 = 8;
pub const ASSET_ID_LDO: i16 = 9;

/// USDC ticker scale (1e6); also used for `update_margin` amounts.
pub const USDC_TICKER_SCALE: u64 = 1_000_000;
/// Default ticker scale for the 1e8 assets (ETH, LIT, LINK, …).
pub const DEFAULT_TICKER_SCALE: u64 = 100_000_000;

/// Returns the integer ticker scale for `asset_id`, or `None` if unsupported.
pub fn ticker_scale(asset_id: i16) -> Option<u64> {
    match asset_id {
        ASSET_ID_USDC => Some(USDC_TICKER_SCALE),
        ASSET_ID_ETH | ASSET_ID_LIT | ASSET_ID_LINK | ASSET_ID_UNI | ASSET_ID_AAVE
        | ASSET_ID_SKY | ASSET_ID_LDO => Some(DEFAULT_TICKER_SCALE),
        _ => None,
    }
}

// -- Crypto sizes --
pub const SIGNATURE_LENGTH: usize = 80;
pub const PUB_KEY_LENGTH: usize = 40;
pub const PRIVATE_KEY_LENGTH: usize = 40;
pub const HASH_LENGTH: usize = 40;
