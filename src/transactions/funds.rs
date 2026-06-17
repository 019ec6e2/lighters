//! Fund-movement transactions: transfer and withdraw.

use serde::Serialize;

use super::*;
use crate::attributes::{aggregate, AttributeMap};
use crate::constants::*;
use crate::error::{Error, Result};
use crate::hash::{gf, hash_to_fp5};

// ---------------------------------------------------------------------------
// Transfer
// ---------------------------------------------------------------------------

/// `L2TransferTxInfo`
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Transfer {
    pub from_account_index: i64,
    pub api_key_index: u8,
    pub to_account_index: i64,
    pub asset_index: i16,
    pub from_route_type: u8,
    pub to_route_type: u8,
    pub amount: i64,
    #[serde(rename = "USDCFee")]
    pub usdc_fee: i64,
    pub memo: [u8; 32],
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

impl TxInfo for Transfer {
    fn tx_type(&self) -> u8 {
        TX_TYPE_L2_TRANSFER
    }

    fn validate(&self) -> Result<()> {
        if let Some(a) = &self.attributes {
            a.validate()?;
        }
        check_account_index(self.from_account_index, MAX_ACCOUNT_INDEX)?;
        check_api_key_index(self.api_key_index)?;
        check_account_index(self.to_account_index, MAX_ACCOUNT_INDEX)
            .map_err(|_| Error::ToAccountIndexOutOfRange)?;
        if self.asset_index < MIN_ASSET_INDEX || self.asset_index > MAX_ASSET_INDEX {
            return Err(Error::AssetIndexOutOfRange);
        }
        if self.from_route_type != ASSET_ROUTE_TYPE_PERPS
            && self.from_route_type != ASSET_ROUTE_TYPE_SPOT
        {
            return Err(Error::RouteTypeInvalid);
        }
        if self.to_route_type != ASSET_ROUTE_TYPE_PERPS && self.to_route_type != ASSET_ROUTE_TYPE_SPOT
        {
            return Err(Error::RouteTypeInvalid);
        }
        if self.amount <= 0 || self.amount > MAX_TRANSFER_AMOUNT {
            return Err(Error::TransferAmountOutOfRange);
        }
        if self.usdc_fee < 0 || self.usdc_fee > MAX_TRANSFER_AMOUNT {
            return Err(Error::TransferFeeInvalid);
        }
        check_nonce(self.nonce)?;
        check_expired_at(self.expired_at)?;
        Ok(())
    }

    fn hash(&self, chain_id: u32) -> Result<[u8; HASH_LENGTH]> {
        let mut e = Vec::with_capacity(14);
        push_header(
            &mut e,
            chain_id,
            TX_TYPE_L2_TRANSFER,
            self.nonce,
            self.expired_at,
            self.from_account_index,
            self.api_key_index,
        );
        e.push(gf(self.to_account_index));
        e.push(gf(self.asset_index));
        e.push(gf(self.from_route_type));
        e.push(gf(self.to_route_type));
        let amount = self.amount as u64;
        e.push(gf(amount & 0xFFFF_FFFF));
        e.push(gf(amount >> 32));
        let fee = self.usdc_fee as u64;
        e.push(gf(fee & 0xFFFF_FFFF));
        e.push(gf(fee >> 32));
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
            "Transfer\n\nnonce: {}\nfrom: {} (route {})\napi key: {}\nto: {} (route {})\nasset: {}\namount: {}\nfee: {}\nchainId: {}\nmemo: {}\nOnly sign this message for a trusted client!",
            hex10_from_u64(self.nonce as u64),
            hex10_from_u64(self.from_account_index as u64),
            hex10_from_u64(self.from_route_type as u64),
            hex10_from_u64(self.api_key_index as u64),
            hex10_from_u64(self.to_account_index as u64),
            hex10_from_u64(self.to_route_type as u64),
            hex10_from_u64(self.asset_index as u64),
            hex10_from_u64(self.amount as u64),
            hex10_from_u64(self.usdc_fee as u64),
            hex10_from_u64(chain_id as u64),
            hex::encode(self.memo),
        ))
    }
}

// ---------------------------------------------------------------------------
// Withdraw
// ---------------------------------------------------------------------------

/// `L2WithdrawTxInfo`
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Withdraw {
    pub from_account_index: i64,
    pub api_key_index: u8,
    pub asset_index: i16,
    pub route_type: u8,
    pub amount: u64,
    pub expired_at: i64,
    pub nonce: i64,
    #[serde(serialize_with = "b64::serialize")]
    pub sig: Vec<u8>,
    #[serde(skip)]
    pub signed_hash: String,
    #[serde(rename = "L2TxAttributes")]
    pub attributes: Option<AttributeMap>,
}

impl TxInfo for Withdraw {
    fn tx_type(&self) -> u8 {
        TX_TYPE_L2_WITHDRAW
    }

    fn validate(&self) -> Result<()> {
        if let Some(a) = &self.attributes {
            a.validate()?;
        }
        check_account_index(self.from_account_index, MAX_ACCOUNT_INDEX)?;
        check_api_key_index(self.api_key_index)?;
        if self.asset_index < MIN_ASSET_INDEX || self.asset_index > MAX_ASSET_INDEX {
            return Err(Error::AssetIndexOutOfRange);
        }
        if self.route_type != ASSET_ROUTE_TYPE_PERPS && self.route_type != ASSET_ROUTE_TYPE_SPOT {
            return Err(Error::RouteTypeInvalid);
        }
        if self.amount < MIN_WITHDRAWAL_AMOUNT || self.amount > MAX_WITHDRAWAL_AMOUNT {
            return Err(Error::WithdrawalAmountOutOfRange);
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
            TX_TYPE_L2_WITHDRAW,
            self.nonce,
            self.expired_at,
            self.from_account_index,
            self.api_key_index,
        );
        e.push(gf(self.asset_index));
        e.push(gf(self.route_type));
        e.push(gf(self.amount & 0xFFFF_FFFF));
        e.push(gf(self.amount >> 32));
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
