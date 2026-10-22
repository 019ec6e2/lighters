//! Account-management transactions: change pubkey, sub-accounts, leverage,
//! margin, account/asset config, integrator approval.

use serde::Serialize;

use super::*;
use crate::attributes::{aggregate, AttributeMap};
use crate::constants::*;
use crate::error::{Error, Result};
use crate::hash::{fp5_from_canonical_le_bytes, gf, hash_to_fp5};

// ---------------------------------------------------------------------------
// ChangePubKey
// ---------------------------------------------------------------------------

/// `L2ChangePubKeyTxInfo`
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ChangePubKey {
    pub account_index: i64,
    pub api_key_index: u8,
    /// The new 40-byte public key (little-endian limbs).
    #[serde(rename = "PubKey", serialize_with = "b64::serialize")]
    pub pub_key: [u8; PUB_KEY_LENGTH],
    #[serde(rename = "L1Sig")]
    pub l1_sig: String,
    pub expired_at: i64,
    pub nonce: i64,
    #[serde(serialize_with = "b64::serialize")]
    pub sig: Vec<u8>,
    #[serde(skip)]
    pub signed_hash: String,
    #[serde(rename = "L2TxAttributes")]
    pub attributes: Option<AttributeMap>,
}

impl TxInfo for ChangePubKey {
    fn tx_type(&self) -> u8 {
        TX_TYPE_L2_CHANGE_PUB_KEY
    }

    fn validate(&self) -> Result<()> {
        if let Some(a) = &self.attributes {
            a.validate()?;
        }
        check_account_index(self.account_index, MAX_ACCOUNT_INDEX)?;
        check_api_key_index(self.api_key_index)?;
        check_nonce(self.nonce)?;
        check_expired_at(self.expired_at)?;
        Ok(())
    }

    fn hash(&self, chain_id: u32) -> Result<[u8; HASH_LENGTH]> {
        let mut e = Vec::with_capacity(11);
        push_header(
            &mut e,
            chain_id,
            TX_TYPE_L2_CHANGE_PUB_KEY,
            self.nonce,
            self.expired_at,
            self.account_index,
            self.api_key_index,
        );
        let pk = fp5_from_canonical_le_bytes(&self.pub_key)?;
        e.extend_from_slice(&pk.0);
        Ok(aggregate(&self.attributes, hash_to_fp5(&e)))
    }

    fn set_signature(&mut self, sig: Vec<u8>, signed_hash: String) {
        self.sig = sig;
        self.signed_hash = signed_hash;
    }

    fn tx_hash(&self) -> &str {
        &self.signed_hash
    }

    fn message_to_sign(&self, _chain_id: u32) -> Option<String> {
        Some(format!(
            "Register Lighter Account\n\npubkey: 0x{}\nnonce: {}\naccount index: {}\napi key index: {}\nOnly sign this message for a trusted client!",
            hex::encode(self.pub_key),
            hex10_from_u64(self.nonce as u64),
            hex10_from_u64(self.account_index as u64),
            hex10_from_u64(self.api_key_index as u64),
        ))
    }
}

// ---------------------------------------------------------------------------
// CreateSubAccount
// ---------------------------------------------------------------------------

/// `L2CreateSubAccountTxInfo`
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreateSubAccount {
    pub account_index: i64,
    pub api_key_index: u8,
    pub expired_at: i64,
    pub nonce: i64,
    #[serde(serialize_with = "b64::serialize")]
    pub sig: Vec<u8>,
    #[serde(skip)]
    pub signed_hash: String,
    #[serde(rename = "L2TxAttributes")]
    pub attributes: Option<AttributeMap>,
}

impl TxInfo for CreateSubAccount {
    fn tx_type(&self) -> u8 {
        TX_TYPE_L2_CREATE_SUB_ACCOUNT
    }

    fn validate(&self) -> Result<()> {
        if let Some(a) = &self.attributes {
            a.validate()?;
        }
        check_account_index(self.account_index, MAX_MASTER_ACCOUNT_INDEX)?;
        check_api_key_index(self.api_key_index)?;
        check_nonce(self.nonce)?;
        check_expired_at(self.expired_at)?;
        Ok(())
    }

    fn hash(&self, chain_id: u32) -> Result<[u8; HASH_LENGTH]> {
        let mut e = Vec::with_capacity(6);
        push_header(
            &mut e,
            chain_id,
            TX_TYPE_L2_CREATE_SUB_ACCOUNT,
            self.nonce,
            self.expired_at,
            self.account_index,
            self.api_key_index,
        );
        Ok(aggregate(&self.attributes, hash_to_fp5(&e)))
    }

    fn set_signature(&mut self, sig: Vec<u8>, signed_hash: String) {
        self.sig = sig;
        self.signed_hash = signed_hash;
    }

    fn tx_hash(&self) -> &str {
        &self.signed_hash
    }
}

// ---------------------------------------------------------------------------
// UpdateLeverage
// ---------------------------------------------------------------------------

/// `L2UpdateLeverageTxInfo`
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct UpdateLeverage {
    pub account_index: i64,
    pub api_key_index: u8,
    pub market_index: i64,
    pub initial_margin_fraction: u16,
    pub margin_mode: u8,
    pub expired_at: i64,
    pub nonce: i64,
    #[serde(serialize_with = "b64::serialize")]
    pub sig: Vec<u8>,
    #[serde(skip)]
    pub signed_hash: String,
    #[serde(rename = "L2TxAttributes")]
    pub attributes: Option<AttributeMap>,
}

impl TxInfo for UpdateLeverage {
    fn tx_type(&self) -> u8 {
        TX_TYPE_L2_UPDATE_LEVERAGE
    }

    fn validate(&self) -> Result<()> {
        if let Some(a) = &self.attributes {
            a.validate()?;
        }
        check_account_index(self.account_index, MAX_ACCOUNT_INDEX)?;
        check_api_key_index(self.api_key_index)?;
        if self.market_index < MIN_PERPS_MARKET_INDEX
            || self.market_index == NIL_MARKET_INDEX
            || self.market_index > MAX_MARKET_INDEX
        {
            return Err(Error::InvalidMarketIndex);
        }
        if self.margin_mode != CROSS_MARGIN && self.margin_mode != ISOLATED_MARGIN {
            return Err(Error::InvalidMarginMode);
        }
        if self.initial_margin_fraction == 0 {
            return Err(Error::InitialMarginFractionOutOfRange);
        }
        if self.initial_margin_fraction as i64 > MARGIN_FRACTION_TICK {
            return Err(Error::InitialMarginFractionOutOfRange);
        }
        check_nonce(self.nonce)?;
        check_expired_at(self.expired_at)?;
        Ok(())
    }

    fn hash(&self, chain_id: u32) -> Result<[u8; HASH_LENGTH]> {
        let mut e = Vec::with_capacity(9);
        push_header(
            &mut e,
            chain_id,
            TX_TYPE_L2_UPDATE_LEVERAGE,
            self.nonce,
            self.expired_at,
            self.account_index,
            self.api_key_index,
        );
        e.push(gf(self.market_index));
        e.push(gf(self.initial_margin_fraction));
        e.push(gf(self.margin_mode));
        Ok(aggregate(&self.attributes, hash_to_fp5(&e)))
    }

    fn set_signature(&mut self, sig: Vec<u8>, signed_hash: String) {
        self.sig = sig;
        self.signed_hash = signed_hash;
    }

    fn tx_hash(&self) -> &str {
        &self.signed_hash
    }
}

// ---------------------------------------------------------------------------
// UpdateMargin
// ---------------------------------------------------------------------------

/// `L2UpdateMarginTxInfo`
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct UpdateMargin {
    pub account_index: i64,
    pub api_key_index: u8,
    pub market_index: i64,
    #[serde(rename = "USDCAmount")]
    pub usdc_amount: i64,
    pub direction: u8,
    pub expired_at: i64,
    pub nonce: i64,
    #[serde(serialize_with = "b64::serialize")]
    pub sig: Vec<u8>,
    #[serde(skip)]
    pub signed_hash: String,
    #[serde(rename = "L2TxAttributes")]
    pub attributes: Option<AttributeMap>,
}

impl TxInfo for UpdateMargin {
    fn tx_type(&self) -> u8 {
        TX_TYPE_L2_UPDATE_MARGIN
    }

    fn validate(&self) -> Result<()> {
        if let Some(a) = &self.attributes {
            a.validate()?;
        }
        check_account_index(self.account_index, MAX_ACCOUNT_INDEX)?;
        check_api_key_index(self.api_key_index)?;
        if self.market_index < MIN_PERPS_MARKET_INDEX
            || self.market_index == NIL_MARKET_INDEX
            || self.market_index > MAX_MARKET_INDEX
        {
            return Err(Error::InvalidMarketIndex);
        }
        if self.usdc_amount == 0 || self.usdc_amount > MAX_TRANSFER_AMOUNT {
            return Err(Error::TransferAmountOutOfRange);
        }
        if self.direction != REMOVE_FROM_ISOLATED_MARGIN && self.direction != ADD_TO_ISOLATED_MARGIN
        {
            return Err(Error::InvalidUpdateMarginDirection);
        }
        check_nonce(self.nonce)?;
        check_expired_at(self.expired_at)?;
        Ok(())
    }

    fn hash(&self, chain_id: u32) -> Result<[u8; HASH_LENGTH]> {
        let mut e = Vec::with_capacity(10);
        push_header(
            &mut e,
            chain_id,
            TX_TYPE_L2_UPDATE_MARGIN,
            self.nonce,
            self.expired_at,
            self.account_index,
            self.api_key_index,
        );
        e.push(gf(self.market_index));
        e.push(gf(self.usdc_amount & 0xFFFF_FFFF));
        e.push(gf(self.usdc_amount >> 32));
        e.push(gf(self.direction));
        Ok(aggregate(&self.attributes, hash_to_fp5(&e)))
    }

    fn set_signature(&mut self, sig: Vec<u8>, signed_hash: String) {
        self.sig = sig;
        self.signed_hash = signed_hash;
    }

    fn tx_hash(&self) -> &str {
        &self.signed_hash
    }
}

// ---------------------------------------------------------------------------
// UpdateAccountConfig
// ---------------------------------------------------------------------------

/// `L2UpdateAccountConfigTxInfo`
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct UpdateAccountConfig {
    pub account_index: i64,
    pub api_key_index: u8,
    pub account_trading_mode: u8,
    pub expired_at: i64,
    pub nonce: i64,
    #[serde(serialize_with = "b64::serialize")]
    pub sig: Vec<u8>,
    #[serde(skip)]
    pub signed_hash: String,
    #[serde(rename = "L2TxAttributes")]
    pub attributes: Option<AttributeMap>,
}

impl TxInfo for UpdateAccountConfig {
    fn tx_type(&self) -> u8 {
        TX_TYPE_L2_UPDATE_ACCOUNT_CONFIG
    }

    fn validate(&self) -> Result<()> {
        if let Some(a) = &self.attributes {
            a.validate()?;
        }
        check_account_index(self.account_index, MAX_ACCOUNT_INDEX)?;
        check_api_key_index(self.api_key_index)?;
        if self.account_trading_mode != 0 && self.account_trading_mode != 1 {
            return Err(Error::InvalidAccountTradingMode);
        }
        check_nonce(self.nonce)?;
        check_expired_at(self.expired_at)?;
        Ok(())
    }

    fn hash(&self, chain_id: u32) -> Result<[u8; HASH_LENGTH]> {
        let mut e = Vec::with_capacity(7);
        push_header(
            &mut e,
            chain_id,
            TX_TYPE_L2_UPDATE_ACCOUNT_CONFIG,
            self.nonce,
            self.expired_at,
            self.account_index,
            self.api_key_index,
        );
        e.push(gf(self.account_trading_mode));
        Ok(aggregate(&self.attributes, hash_to_fp5(&e)))
    }

    fn set_signature(&mut self, sig: Vec<u8>, signed_hash: String) {
        self.sig = sig;
        self.signed_hash = signed_hash;
    }

    fn tx_hash(&self) -> &str {
        &self.signed_hash
    }
}

// ---------------------------------------------------------------------------
// UpdateAccountAssetConfig
// ---------------------------------------------------------------------------

/// `L2UpdateAccountAssetConfigTxInfo`
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct UpdateAccountAssetConfig {
    pub account_index: i64,
    pub api_key_index: u8,
    pub asset_index: i16,
    pub asset_margin_mode: u8,
    pub expired_at: i64,
    pub nonce: i64,
    #[serde(serialize_with = "b64::serialize")]
    pub sig: Vec<u8>,
    #[serde(skip)]
    pub signed_hash: String,
    #[serde(rename = "L2TxAttributes")]
    pub attributes: Option<AttributeMap>,
}

impl TxInfo for UpdateAccountAssetConfig {
    fn tx_type(&self) -> u8 {
        TX_TYPE_L2_UPDATE_ACCOUNT_ASSET_CONFIG
    }

    fn validate(&self) -> Result<()> {
        if let Some(a) = &self.attributes {
            a.validate()?;
        }
        check_account_index(self.account_index, MAX_ACCOUNT_INDEX)?;
        check_api_key_index(self.api_key_index)?;
        if self.asset_index < MIN_ASSET_INDEX || self.asset_index > MAX_ASSET_INDEX {
            return Err(Error::AssetIndexOutOfRange);
        }
        if self.asset_margin_mode != ACCOUNT_ASSET_MARGIN_MODE_DISABLED
            && self.asset_margin_mode != ACCOUNT_ASSET_MARGIN_MODE_ENABLED
        {
            return Err(Error::InvalidMarginMode);
        }
        check_nonce(self.nonce)?;
        check_expired_at(self.expired_at)?;
        Ok(())
    }

    fn hash(&self, chain_id: u32) -> Result<[u8; HASH_LENGTH]> {
        let mut e = Vec::with_capacity(8);
        push_header(
            &mut e,
            chain_id,
            TX_TYPE_L2_UPDATE_ACCOUNT_ASSET_CONFIG,
            self.nonce,
            self.expired_at,
            self.account_index,
            self.api_key_index,
        );
        e.push(gf(self.asset_index));
        e.push(gf(self.asset_margin_mode));
        Ok(aggregate(&self.attributes, hash_to_fp5(&e)))
    }

    fn set_signature(&mut self, sig: Vec<u8>, signed_hash: String) {
        self.sig = sig;
        self.signed_hash = signed_hash;
    }

    fn tx_hash(&self) -> &str {
        &self.signed_hash
    }
}

// ---------------------------------------------------------------------------
// ApproveIntegrator
// ---------------------------------------------------------------------------

/// `L2ApproveIntegratorTxInfo`
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ApproveIntegrator {
    pub account_index: i64,
    pub api_key_index: u8,
    pub integrator_account_index: i64,
    pub max_perps_taker_fee: u32,
    pub max_perps_maker_fee: u32,
    pub max_spot_taker_fee: u32,
    pub max_spot_maker_fee: u32,
    pub approval_expiry: i64,
    pub expired_at: i64,
    pub nonce: i64,
    #[serde(serialize_with = "b64::serialize")]
    pub sig: Vec<u8>,
    #[serde(rename = "L1Sig")]
    pub l1_sig: String,
    #[serde(skip)]
    pub signed_hash: String,
    #[serde(rename = "L2TxAttributes")]
    pub attributes: Option<AttributeMap>,
}

impl TxInfo for ApproveIntegrator {
    fn tx_type(&self) -> u8 {
        TX_TYPE_L2_APPROVE_INTEGRATOR
    }

    fn validate(&self) -> Result<()> {
        if let Some(a) = &self.attributes {
            a.validate()?;
        }
        check_account_index(self.account_index, MAX_ACCOUNT_INDEX)?;
        check_api_key_index(self.api_key_index)?;
        check_account_index(self.integrator_account_index, MAX_ACCOUNT_INDEX)
            .map_err(|_| Error::IntegratorAccountIndexOutOfRange)?;

        if self.max_perps_taker_fee as i64 > FEE_TICK
            || self.max_perps_maker_fee as i64 > FEE_TICK
            || self.max_spot_taker_fee as i64 > FEE_TICK
            || self.max_spot_maker_fee as i64 > FEE_TICK
        {
            return Err(Error::FeeTooHigh { max: FEE_TICK });
        }

        if self.approval_expiry == 0 {
            let all_zero = self.max_perps_taker_fee == 0
                && self.max_perps_maker_fee == 0
                && self.max_spot_taker_fee == 0
                && self.max_spot_maker_fee == 0;
            if !all_zero {
                return Err(Error::ApprovalExpiryZeroOnRevocation);
            }
        }
        if self.approval_expiry < 0 || self.approval_expiry > MAX_TIMESTAMP {
            return Err(Error::ApprovalExpiryInvalid);
        }
        check_nonce(self.nonce)?;
        check_expired_at(self.expired_at)?;
        Ok(())
    }

    fn hash(&self, chain_id: u32) -> Result<[u8; HASH_LENGTH]> {
        let mut e = Vec::with_capacity(12);
        push_header(
            &mut e,
            chain_id,
            TX_TYPE_L2_APPROVE_INTEGRATOR,
            self.nonce,
            self.expired_at,
            self.account_index,
            self.api_key_index,
        );
        e.push(gf(self.integrator_account_index));
        e.push(gf(self.max_perps_taker_fee));
        e.push(gf(self.max_perps_maker_fee));
        e.push(gf(self.max_spot_taker_fee));
        e.push(gf(self.max_spot_maker_fee));
        e.push(gf(self.approval_expiry));
        Ok(aggregate(&self.attributes, hash_to_fp5(&e)))
    }

    fn set_signature(&mut self, sig: Vec<u8>, signed_hash: String) {
        self.sig = sig;
        self.signed_hash = signed_hash;
    }

    fn tx_hash(&self) -> &str {
        &self.signed_hash
    }

    fn message_to_sign(&self, chain_id: u32) -> Option<String> {
        Some(format!(
            "Approve Integrator\n\nnonce: {}\naccount index: {}\napi key index: {}\nintegrator account index: {}\nmax perps taker fee: {}\nmax perps maker fee: {}\nmax spot taker fee: {}\nmax spot maker fee: {}\napproval expiry: {}\nchainId: {}\nOnly sign this message for a trusted client!",
            hex10_from_u64(self.nonce as u64),
            hex10_from_u64(self.account_index as u64),
            hex10_from_u64(self.api_key_index as u64),
            hex10_from_u64(self.integrator_account_index as u64),
            hex10_from_u64(self.max_perps_taker_fee as u64),
            hex10_from_u64(self.max_perps_maker_fee as u64),
            hex10_from_u64(self.max_spot_taker_fee as u64),
            hex10_from_u64(self.max_spot_maker_fee as u64),
            hex10_from_u64(self.approval_expiry as u64),
            hex10_from_u64(chain_id as u64),
        ))
    }
}
