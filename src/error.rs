//! Error types for the Lighter client.

use thiserror::Error;

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur while building, validating, or signing transactions.
#[derive(Debug, Error)]
pub enum Error {
    // -- validation errors (mirror the Go `txtypes` error set) --
    #[error("AccountIndex should not be less than {min}")]
    AccountIndexTooLow { min: i64 },
    #[error("AccountIndex should not be larger than {max}")]
    AccountIndexTooHigh { max: i64 },
    #[error("ApiKeyIndex should not be less than {min}")]
    ApiKeyIndexTooLow { min: u8 },
    #[error("ApiKeyIndex should not be larger than {max}")]
    ApiKeyIndexTooHigh { max: u8 },
    #[error("ToAccountIndex is out of range")]
    ToAccountIndexOutOfRange,
    #[error("AssetIndex is out of range")]
    AssetIndexOutOfRange,
    #[error("RouteType is invalid")]
    RouteTypeInvalid,
    #[error("Nonce should not be less than {min}")]
    NonceTooLow { min: i64 },
    #[error("ExpiredAt is invalid")]
    ExpiredAtInvalid,
    #[error("MarketIndex is not valid")]
    InvalidMarketIndex,
    #[error("ClientOrderIndex is out of range")]
    ClientOrderIndexOutOfRange,
    #[error("ClientOrderIndex should be unique within the group")]
    ClientOrderIndexDuplicate,
    #[error("OrderIndex is out of range")]
    OrderIndexOutOfRange,
    #[error("BaseAmount is out of range")]
    BaseAmountOutOfRange,
    #[error("BaseAmounts should be equal")]
    BaseAmountsNotEqual,
    #[error("BaseAmount should be nil")]
    BaseAmountNotNil,
    #[error("OrderPrice is out of range")]
    PriceOutOfRange,
    #[error("IsAsk should be 0 or 1")]
    IsAskInvalid,
    #[error("OrderType is not valid")]
    OrderTypeInvalid,
    #[error("OrderTimeInForce is not valid")]
    OrderTimeInForceInvalid,
    #[error("ReduceOnly is invalid")]
    OrderReduceOnlyInvalid,
    #[error("TriggerPrice is invalid")]
    OrderTriggerPriceInvalid,
    #[error("OrderExpiry is invalid")]
    OrderExpiryInvalid,
    #[error("GroupingType is not valid")]
    GroupingTypeInvalid,
    #[error("OrderGroupSize is not valid")]
    OrderGroupSizeInvalid,
    #[error("MarketIndex should match the market index of the order")]
    MarketIndexMismatch,
    #[error("WithdrawalAmount is out of range")]
    WithdrawalAmountOutOfRange,
    #[error("TransferAmount is out of range")]
    TransferAmountOutOfRange,
    #[error("TransferFee is invalid")]
    TransferFeeInvalid,
    #[error("PubKey is invalid")]
    PubKeyInvalid,
    #[error("MarginMode is not valid")]
    InvalidMarginMode,
    #[error("Margin movement direction is not valid")]
    InvalidUpdateMarginDirection,
    #[error("InitialMarginFraction is out of range")]
    InitialMarginFractionOutOfRange,
    #[error("PublicPoolIndex is out of range")]
    PublicPoolIndexOutOfRange,
    #[error("PoolStatus should be either 0 or 1")]
    InvalidPoolStatus,
    #[error("PoolOperatorFee is invalid")]
    InvalidPoolOperatorFee,
    #[error("PoolInitialTotalShares is out of range")]
    PoolInitialTotalSharesOutOfRange,
    #[error("PoolMinOperatorShareRate should not be larger than {max}")]
    PoolMinOperatorShareRateTooHigh { max: u16 },
    #[error("Pool share amount is out of range")]
    PoolShareAmountOutOfRange,
    #[error("StakingPoolIndex is out of range")]
    StakingPoolIndexOutOfRange,
    #[error("Staking share amount is out of range")]
    StakingShareAmountOutOfRange,
    #[error("AccountTradingMode is invalid")]
    InvalidAccountTradingMode,
    #[error("CancelAll time-in-force is invalid")]
    InvalidCancelAllTimeInForce,
    #[error("CancelAll time is invalid")]
    CancelAllTimeInvalid,
    #[error("Cancel all for market index can't be scheduled")]
    CancelAllMarketIndexCantBeScheduled,
    #[error("ApprovalExpiry is invalid")]
    ApprovalExpiryInvalid,
    #[error("ApprovalExpiry should be zero when revoking integrator approval")]
    ApprovalExpiryZeroOnRevocation,
    #[error("IntegratorAccountIndex is out of range")]
    IntegratorAccountIndexOutOfRange,
    #[error("MarketFee should not be larger than {max}")]
    FeeTooHigh { max: i64 },

    // -- attribute errors --
    #[error("Too many attributes, should not be larger than {max}")]
    TooManyAttributes { max: usize },
    #[error("Attribute value is out of range")]
    AttributeValueOutOfRange,
    #[error("IntegratorAccountIndex should be non-zero when integrator fees are non-zero")]
    IntegratorAccountIndexRequiredForNonZeroFees,
    #[error("Self-trade specification isn't allowed with integrator fees")]
    SelfTradeSpecificationNotAllowedWithNonZeroFees,
    #[error("Reduce self-trade behavior mode isn't allowed with master account index equality mode")]
    ReduceModeNotAllowedWithMasterAccountIndexEqualityMode,

    // -- crypto / encoding errors --
    #[error("invalid private key length: expected 40 bytes, got {0}")]
    InvalidPrivateKeyLength(usize),
    #[error("invalid public key: not a canonical curve point")]
    InvalidPublicKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("crypto error: {0}")]
    Crypto(String),

    // -- client / transport errors --
    #[error("nonce was not provided and no HTTP client is configured")]
    NonceUnavailable,
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    #[error("http error: {0}")]
    Http(String),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    // -- trading runtime errors --
    #[error("api error (code {code}): {message}")]
    Api { code: i32, message: String },
    #[error("no signer configured for api key index {0}")]
    UnknownApiKey(u8),
    #[error("nonce manager is disabled; provide nonce and api_key_index explicitly")]
    NonceManagerDisabled,
    #[error("excessive slippage")]
    ExcessiveSlippage,
    #[error("insufficient order-book depth to guarantee the requested size")]
    InsufficientDepth,
    #[error("order book is empty for this side")]
    EmptyOrderBook,
}
