//! Public-pool and staking transactions: create/update pool, mint/burn shares,
//! stake/unstake assets.

use serde::Serialize;

use super::*;
use crate::attributes::{aggregate, AttributeMap};
use crate::constants::*;
use crate::error::{Error, Result};
use crate::hash::{gf, hash_to_fp5};

// ---------------------------------------------------------------------------
// CreatePublicPool
// ---------------------------------------------------------------------------

/// `L2CreatePublicPoolTxInfo`
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreatePublicPool {
    pub account_index: i64,
    pub api_key_index: u8,
    pub operator_fee: i64,
    pub initial_total_shares: i64,
    pub min_operator_share_rate: u16,
    pub expired_at: i64,
    pub nonce: i64,
    #[serde(serialize_with = "b64::serialize")]
    pub sig: Vec<u8>,
    #[serde(skip)]
    pub signed_hash: String,
    #[serde(rename = "L2TxAttributes")]
    pub attributes: Option<AttributeMap>,
}

impl TxInfo for CreatePublicPool {
    fn tx_type(&self) -> u8 {
        TX_TYPE_L2_CREATE_PUBLIC_POOL
    }

    fn validate(&self) -> Result<()> {
        if let Some(a) = &self.attributes {
            a.validate()?;
        }
        check_account_index(self.account_index, MAX_MASTER_ACCOUNT_INDEX)?;
        check_api_key_index(self.api_key_index)?;
        if self.operator_fee < 0 || self.operator_fee > FEE_TICK {
            return Err(Error::InvalidPoolOperatorFee);
        }
        if self.initial_total_shares <= 0 || self.initial_total_shares > MAX_INITIAL_TOTAL_SHARES {
            return Err(Error::PoolInitialTotalSharesOutOfRange);
        }
        if self.min_operator_share_rate > SHARE_TICK {
            return Err(Error::PoolMinOperatorShareRateTooHigh { max: SHARE_TICK });
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
            TX_TYPE_L2_CREATE_PUBLIC_POOL,
            self.nonce,
            self.expired_at,
            self.account_index,
            self.api_key_index,
        );
        e.push(gf(self.operator_fee));
        e.push(gf(self.initial_total_shares));
        e.push(gf(self.min_operator_share_rate));
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
// UpdatePublicPool
// ---------------------------------------------------------------------------

/// `L2UpdatePublicPoolTxInfo`
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct UpdatePublicPool {
    pub account_index: i64,
    pub api_key_index: u8,
    pub public_pool_index: i64,
    pub status: u8,
    pub operator_fee: i64,
    pub min_operator_share_rate: u16,
    pub expired_at: i64,
    pub nonce: i64,
    #[serde(serialize_with = "b64::serialize")]
    pub sig: Vec<u8>,
    #[serde(skip)]
    pub signed_hash: String,
    #[serde(rename = "L2TxAttributes")]
    pub attributes: Option<AttributeMap>,
}

impl TxInfo for UpdatePublicPool {
    fn tx_type(&self) -> u8 {
        TX_TYPE_L2_UPDATE_PUBLIC_POOL
    }

    fn validate(&self) -> Result<()> {
        if let Some(a) = &self.attributes {
            a.validate()?;
        }
        check_account_index(self.account_index, MAX_ACCOUNT_INDEX)?;
        check_api_key_index(self.api_key_index)?;
        if self.public_pool_index < MIN_ACCOUNT_INDEX || self.public_pool_index > MAX_ACCOUNT_INDEX {
            return Err(Error::PublicPoolIndexOutOfRange);
        }
        if self.status != 0 && self.status != 1 {
            return Err(Error::InvalidPoolStatus);
        }
        if self.operator_fee < 0 || self.operator_fee > FEE_TICK {
            return Err(Error::InvalidPoolOperatorFee);
        }
        if self.min_operator_share_rate > SHARE_TICK {
            return Err(Error::PoolMinOperatorShareRateTooHigh { max: SHARE_TICK });
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
            TX_TYPE_L2_UPDATE_PUBLIC_POOL,
            self.nonce,
            self.expired_at,
            self.account_index,
            self.api_key_index,
        );
        e.push(gf(self.public_pool_index));
        e.push(gf(self.status));
        e.push(gf(self.operator_fee));
        e.push(gf(self.min_operator_share_rate));
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
// MintShares / BurnShares
// ---------------------------------------------------------------------------

macro_rules! share_tx {
    ($name:ident, $tx_type:expr) => {
        #[derive(Debug, Clone, Serialize)]
        #[serde(rename_all = "PascalCase")]
        pub struct $name {
            pub account_index: i64,
            pub api_key_index: u8,
            pub public_pool_index: i64,
            pub share_amount: i64,
            pub expired_at: i64,
            pub nonce: i64,
            #[serde(serialize_with = "b64::serialize")]
            pub sig: Vec<u8>,
            #[serde(skip)]
            pub signed_hash: String,
            #[serde(rename = "L2TxAttributes")]
            pub attributes: Option<AttributeMap>,
        }

        impl TxInfo for $name {
            fn tx_type(&self) -> u8 {
                $tx_type
            }

            fn validate(&self) -> Result<()> {
                if let Some(a) = &self.attributes {
                    a.validate()?;
                }
                check_account_index(self.account_index, MAX_ACCOUNT_INDEX)?;
                check_api_key_index(self.api_key_index)?;
                if self.public_pool_index < MIN_SUB_ACCOUNT_INDEX
                    || self.public_pool_index > MAX_ACCOUNT_INDEX
                {
                    return Err(Error::PublicPoolIndexOutOfRange);
                }
                if self.share_amount < MIN_POOL_SHARES_TO_MINT_OR_BURN
                    || self.share_amount > MAX_POOL_SHARES_TO_MINT_OR_BURN
                {
                    return Err(Error::PoolShareAmountOutOfRange);
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
                    $tx_type,
                    self.nonce,
                    self.expired_at,
                    self.account_index,
                    self.api_key_index,
                );
                e.push(gf(self.public_pool_index));
                e.push(gf(self.share_amount));
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
    };
}

share_tx!(MintShares, TX_TYPE_L2_MINT_SHARES);
share_tx!(BurnShares, TX_TYPE_L2_BURN_SHARES);

// ---------------------------------------------------------------------------
// StakeAssets / UnstakeAssets
// ---------------------------------------------------------------------------

macro_rules! staking_tx {
    ($name:ident, $tx_type:expr) => {
        #[derive(Debug, Clone, Serialize)]
        #[serde(rename_all = "PascalCase")]
        pub struct $name {
            pub account_index: i64,
            pub api_key_index: u8,
            pub staking_pool_index: i64,
            pub share_amount: i64,
            pub expired_at: i64,
            pub nonce: i64,
            #[serde(serialize_with = "b64::serialize")]
            pub sig: Vec<u8>,
            #[serde(skip)]
            pub signed_hash: String,
            #[serde(rename = "L2TxAttributes")]
            pub attributes: Option<AttributeMap>,
        }

        impl TxInfo for $name {
            fn tx_type(&self) -> u8 {
                $tx_type
            }

            fn validate(&self) -> Result<()> {
                if let Some(a) = &self.attributes {
                    a.validate()?;
                }
                check_account_index(self.account_index, MAX_ACCOUNT_INDEX)?;
                check_api_key_index(self.api_key_index)?;
                if self.staking_pool_index < MIN_SUB_ACCOUNT_INDEX
                    || self.staking_pool_index > MAX_ACCOUNT_INDEX
                {
                    return Err(Error::StakingPoolIndexOutOfRange);
                }
                if self.share_amount < MIN_STAKING_SHARES_TO_MINT_OR_BURN
                    || self.share_amount > MAX_STAKING_SHARES_TO_MINT_OR_BURN
                {
                    return Err(Error::StakingShareAmountOutOfRange);
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
                    $tx_type,
                    self.nonce,
                    self.expired_at,
                    self.account_index,
                    self.api_key_index,
                );
                e.push(gf(self.staking_pool_index));
                e.push(gf(self.share_amount));
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
    };
}

staking_tx!(StakeAssets, TX_TYPE_L2_STAKE_ASSETS);
staking_tx!(UnstakeAssets, TX_TYPE_L2_UNSTAKE_ASSETS);
