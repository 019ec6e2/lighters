//! Order-related transactions: create, grouped, cancel, cancel-all, modify.

use poseidon_hash::Goldilocks;
use serde::Serialize;

use super::*;
use crate::attributes::{aggregate, AttributeMap};
use crate::constants::*;
use crate::error::{Error, Result};
use crate::hash::{gf, hash_digest, hash_n_to_one, hash_to_fp5};

// ---------------------------------------------------------------------------
// CreateOrder
// ---------------------------------------------------------------------------

/// `L2CreateOrderTxInfo`
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreateOrder {
    pub account_index: i64,
    pub api_key_index: u8,
    #[serde(flatten)]
    pub order: OrderInfo,
    pub expired_at: i64,
    pub nonce: i64,
    #[serde(serialize_with = "b64::serialize")]
    pub sig: Vec<u8>,
    #[serde(skip)]
    pub signed_hash: String,
    #[serde(rename = "L2TxAttributes")]
    pub attributes: Option<AttributeMap>,
}

impl TxInfo for CreateOrder {
    fn tx_type(&self) -> u8 {
        TX_TYPE_L2_CREATE_ORDER
    }

    fn validate(&self) -> Result<()> {
        if let Some(a) = &self.attributes {
            a.validate()?;
        }
        check_account_index(self.account_index, MAX_ACCOUNT_INDEX)?;
        check_api_key_index(self.api_key_index)?;

        let o = &self.order;
        check_market_index(o.market_index)?;

        if o.client_order_index != NIL_CLIENT_ORDER_INDEX
            && (o.client_order_index < MIN_CLIENT_ORDER_INDEX
                || o.client_order_index > MAX_CLIENT_ORDER_INDEX)
        {
            return Err(Error::ClientOrderIndexOutOfRange);
        }

        if o.reduce_only != 1 && o.base_amount == NIL_ORDER_BASE_AMOUNT {
            return Err(Error::BaseAmountOutOfRange);
        }
        if (o.base_amount != NIL_ORDER_BASE_AMOUNT && o.base_amount < MIN_ORDER_BASE_AMOUNT)
            || o.base_amount > MAX_ORDER_BASE_AMOUNT
        {
            return Err(Error::BaseAmountOutOfRange);
        }

        if o.price < MIN_ORDER_PRICE || o.price > MAX_ORDER_PRICE {
            return Err(Error::PriceOutOfRange);
        }

        if o.is_ask != 0 && o.is_ask != 1 {
            return Err(Error::IsAskInvalid);
        }

        if o.time_in_force != IMMEDIATE_OR_CANCEL
            && o.time_in_force != GOOD_TILL_TIME
            && o.time_in_force != POST_ONLY
        {
            return Err(Error::OrderTimeInForceInvalid);
        }

        if o.reduce_only != 0 && o.reduce_only != 1 {
            return Err(Error::OrderReduceOnlyInvalid);
        }

        if (o.order_expiry < MIN_ORDER_EXPIRY || o.order_expiry > MAX_ORDER_EXPIRY)
            && o.order_expiry != NIL_ORDER_EXPIRY
        {
            return Err(Error::OrderExpiryInvalid);
        }

        match o.order_type {
            MARKET_ORDER => {
                if o.time_in_force != IMMEDIATE_OR_CANCEL {
                    return Err(Error::OrderTimeInForceInvalid);
                } else if o.order_expiry != NIL_ORDER_EXPIRY {
                    return Err(Error::OrderExpiryInvalid);
                } else if o.trigger_price != NIL_ORDER_TRIGGER_PRICE {
                    return Err(Error::OrderTriggerPriceInvalid);
                }
            }
            LIMIT_ORDER => {
                if o.trigger_price != NIL_ORDER_TRIGGER_PRICE {
                    return Err(Error::OrderTriggerPriceInvalid);
                } else if (o.time_in_force == IMMEDIATE_OR_CANCEL
                    && o.order_expiry != NIL_ORDER_EXPIRY)
                    || (o.time_in_force != IMMEDIATE_OR_CANCEL
                        && o.order_expiry == NIL_ORDER_EXPIRY)
                {
                    return Err(Error::OrderExpiryInvalid);
                }
            }
            STOP_LOSS_ORDER | TAKE_PROFIT_ORDER => {
                if o.time_in_force != IMMEDIATE_OR_CANCEL {
                    return Err(Error::OrderTimeInForceInvalid);
                } else if o.trigger_price == NIL_ORDER_TRIGGER_PRICE {
                    return Err(Error::OrderTriggerPriceInvalid);
                } else if o.order_expiry == NIL_ORDER_EXPIRY {
                    return Err(Error::OrderExpiryInvalid);
                }
            }
            STOP_LOSS_LIMIT_ORDER | TAKE_PROFIT_LIMIT_ORDER => {
                if o.trigger_price == NIL_ORDER_TRIGGER_PRICE {
                    return Err(Error::OrderTriggerPriceInvalid);
                } else if o.order_expiry == NIL_ORDER_EXPIRY {
                    return Err(Error::OrderExpiryInvalid);
                }
            }
            TWAP_ORDER => {
                if o.time_in_force != GOOD_TILL_TIME {
                    return Err(Error::OrderTimeInForceInvalid);
                } else if o.trigger_price != NIL_ORDER_TRIGGER_PRICE {
                    return Err(Error::OrderTriggerPriceInvalid);
                } else if o.order_expiry == NIL_ORDER_EXPIRY {
                    return Err(Error::OrderExpiryInvalid);
                }
            }
            _ => return Err(Error::OrderTypeInvalid),
        }

        if (o.trigger_price < MIN_ORDER_TRIGGER_PRICE || o.trigger_price > MAX_ORDER_TRIGGER_PRICE)
            && o.trigger_price != NIL_ORDER_TRIGGER_PRICE
        {
            return Err(Error::OrderTriggerPriceInvalid);
        }

        check_nonce(self.nonce)?;
        check_expired_at(self.expired_at)?;
        Ok(())
    }

    fn hash(&self, chain_id: u32) -> Result<[u8; HASH_LENGTH]> {
        let mut e = Vec::with_capacity(16);
        push_header(
            &mut e,
            chain_id,
            TX_TYPE_L2_CREATE_ORDER,
            self.nonce,
            self.expired_at,
            self.account_index,
            self.api_key_index,
        );
        let o = &self.order;
        e.push(gf(o.market_index));
        e.push(gf(o.client_order_index));
        e.push(gf(o.base_amount));
        e.push(gf(o.price));
        e.push(gf(o.is_ask));
        e.push(gf(o.order_type));
        e.push(gf(o.time_in_force));
        e.push(gf(o.reduce_only));
        e.push(gf(o.trigger_price));
        e.push(gf(o.order_expiry));
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
// CreateGroupedOrders
// ---------------------------------------------------------------------------

/// `L2CreateGroupedOrdersTxInfo`
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreateGroupedOrders {
    pub account_index: i64,
    pub api_key_index: u8,
    pub grouping_type: u8,
    pub orders: Vec<OrderInfo>,
    pub expired_at: i64,
    pub nonce: i64,
    #[serde(serialize_with = "b64::serialize")]
    pub sig: Vec<u8>,
    #[serde(skip)]
    pub signed_hash: String,
    #[serde(rename = "L2TxAttributes")]
    pub attributes: Option<AttributeMap>,
}

impl CreateGroupedOrders {
    fn validate_order_common(o: &OrderInfo, seen: &mut Vec<i64>) -> Result<()> {
        if o.client_order_index != NIL_CLIENT_ORDER_INDEX {
            if o.client_order_index < MIN_CLIENT_ORDER_INDEX {
                return Err(Error::ClientOrderIndexOutOfRange);
            }
            if o.client_order_index > MAX_CLIENT_ORDER_INDEX {
                return Err(Error::ClientOrderIndexOutOfRange);
            }
            if seen.contains(&o.client_order_index) {
                return Err(Error::ClientOrderIndexDuplicate);
            }
            seen.push(o.client_order_index);
        }
        if o.reduce_only != 1 && o.base_amount == NIL_ORDER_BASE_AMOUNT {
            return Err(Error::BaseAmountOutOfRange);
        }
        if (o.base_amount != NIL_ORDER_BASE_AMOUNT && o.base_amount < MIN_ORDER_BASE_AMOUNT)
            || o.base_amount > MAX_ORDER_BASE_AMOUNT
        {
            return Err(Error::BaseAmountOutOfRange);
        }
        if o.price < MIN_ORDER_PRICE || o.price > MAX_ORDER_PRICE {
            return Err(Error::PriceOutOfRange);
        }
        if o.is_ask != 0 && o.is_ask != 1 {
            return Err(Error::IsAskInvalid);
        }
        if o.time_in_force != IMMEDIATE_OR_CANCEL
            && o.time_in_force != GOOD_TILL_TIME
            && o.time_in_force != POST_ONLY
        {
            return Err(Error::OrderTimeInForceInvalid);
        }
        if o.reduce_only != 0 && o.reduce_only != 1 {
            return Err(Error::OrderReduceOnlyInvalid);
        }
        if (o.order_expiry < MIN_ORDER_EXPIRY || o.order_expiry > MAX_ORDER_EXPIRY)
            && o.order_expiry != NIL_ORDER_EXPIRY
        {
            return Err(Error::OrderExpiryInvalid);
        }
        if (o.trigger_price < MIN_ORDER_TRIGGER_PRICE || o.trigger_price > MAX_ORDER_TRIGGER_PRICE)
            && o.trigger_price != NIL_ORDER_TRIGGER_PRICE
        {
            return Err(Error::OrderTriggerPriceInvalid);
        }
        Ok(())
    }

    fn validate_parent(o: &OrderInfo) -> Result<()> {
        match o.order_type {
            MARKET_ORDER => {
                if o.time_in_force != IMMEDIATE_OR_CANCEL {
                    return Err(Error::OrderTimeInForceInvalid);
                } else if o.order_expiry != NIL_ORDER_EXPIRY {
                    return Err(Error::OrderExpiryInvalid);
                } else if o.trigger_price != NIL_ORDER_TRIGGER_PRICE {
                    return Err(Error::OrderTriggerPriceInvalid);
                }
            }
            LIMIT_ORDER => {
                if o.trigger_price != NIL_ORDER_TRIGGER_PRICE {
                    return Err(Error::OrderTriggerPriceInvalid);
                } else if (o.time_in_force == IMMEDIATE_OR_CANCEL
                    && o.order_expiry != NIL_ORDER_EXPIRY)
                    || (o.time_in_force != IMMEDIATE_OR_CANCEL
                        && o.order_expiry == NIL_ORDER_EXPIRY)
                {
                    return Err(Error::OrderExpiryInvalid);
                }
            }
            _ => return Err(Error::OrderTypeInvalid),
        }
        Ok(())
    }

    fn validate_child(o: &OrderInfo) -> Result<()> {
        match o.order_type {
            STOP_LOSS_ORDER | TAKE_PROFIT_ORDER => {
                if o.time_in_force != IMMEDIATE_OR_CANCEL {
                    return Err(Error::OrderTimeInForceInvalid);
                } else if o.trigger_price == NIL_ORDER_TRIGGER_PRICE {
                    return Err(Error::OrderTriggerPriceInvalid);
                } else if o.order_expiry == NIL_ORDER_EXPIRY {
                    return Err(Error::OrderExpiryInvalid);
                }
            }
            STOP_LOSS_LIMIT_ORDER | TAKE_PROFIT_LIMIT_ORDER => {
                if o.trigger_price == NIL_ORDER_TRIGGER_PRICE {
                    return Err(Error::OrderTriggerPriceInvalid);
                } else if o.order_expiry == NIL_ORDER_EXPIRY {
                    return Err(Error::OrderExpiryInvalid);
                }
            }
            _ => return Err(Error::OrderTypeInvalid),
        }
        Ok(())
    }

    fn validate_siblings(orders: &[OrderInfo]) -> Result<()> {
        if orders.len() != 2 {
            return Err(Error::OrderGroupSizeInvalid);
        }
        let mut sl = false;
        let mut tp = false;
        for o in orders {
            Self::validate_child(o)?;
            match o.order_type {
                STOP_LOSS_ORDER | STOP_LOSS_LIMIT_ORDER => sl = true,
                TAKE_PROFIT_ORDER | TAKE_PROFIT_LIMIT_ORDER => tp = true,
                _ => {}
            }
        }
        if !sl || !tp {
            return Err(Error::OrderTypeInvalid);
        }
        Ok(())
    }

    fn validate_oco(&self) -> Result<()> {
        let o = &self.orders;
        if o.len() != 2 {
            return Err(Error::OrderGroupSizeInvalid);
        }
        if o[0].base_amount != o[1].base_amount {
            return Err(Error::BaseAmountsNotEqual);
        }
        if o[0].is_ask != o[1].is_ask {
            return Err(Error::IsAskInvalid);
        }
        if o[0].reduce_only != 1 || o[1].reduce_only != 1 {
            return Err(Error::OrderReduceOnlyInvalid);
        }
        if o[0].order_expiry != o[1].order_expiry {
            return Err(Error::OrderExpiryInvalid);
        }
        Self::validate_siblings(o)
    }

    fn validate_oto(&self) -> Result<()> {
        let o = &self.orders;
        if o.len() != 2 {
            return Err(Error::OrderGroupSizeInvalid);
        }
        if o[1].base_amount != NIL_ORDER_BASE_AMOUNT {
            return Err(Error::BaseAmountNotNil);
        }
        if o[0].is_ask == o[1].is_ask {
            return Err(Error::IsAskInvalid);
        }
        if o[0].order_expiry != NIL_ORDER_EXPIRY && o[0].order_expiry != o[1].order_expiry {
            return Err(Error::OrderExpiryInvalid);
        }
        Self::validate_parent(&o[0])?;
        Self::validate_child(&o[1])
    }

    fn validate_otoco(&self) -> Result<()> {
        let o = &self.orders;
        if o.len() != 3 {
            return Err(Error::OrderGroupSizeInvalid);
        }
        if o[1].base_amount != NIL_ORDER_BASE_AMOUNT || o[2].base_amount != NIL_ORDER_BASE_AMOUNT {
            return Err(Error::BaseAmountNotNil);
        }
        if o[0].is_ask == o[1].is_ask || o[0].is_ask == o[2].is_ask {
            return Err(Error::IsAskInvalid);
        }
        if o[1].order_expiry != o[2].order_expiry {
            return Err(Error::OrderExpiryInvalid);
        }
        if o[0].order_expiry != NIL_ORDER_EXPIRY && o[0].order_expiry != o[1].order_expiry {
            return Err(Error::OrderExpiryInvalid);
        }
        Self::validate_parent(&o[0])?;
        Self::validate_siblings(&o[1..])
    }
}

impl TxInfo for CreateGroupedOrders {
    fn tx_type(&self) -> u8 {
        TX_TYPE_L2_CREATE_GROUPED_ORDERS
    }

    fn validate(&self) -> Result<()> {
        if let Some(a) = &self.attributes {
            a.validate()?;
        }
        check_account_index(self.account_index, MAX_ACCOUNT_INDEX)?;
        check_api_key_index(self.api_key_index)?;

        if self.orders.is_empty() || self.orders.len() > MAX_GROUPED_ORDER_COUNT {
            return Err(Error::OrderGroupSizeInvalid);
        }
        let m0 = self.orders[0].market_index;
        if m0 < MIN_PERPS_MARKET_INDEX || m0 == NIL_MARKET_INDEX || m0 > MAX_MARKET_INDEX {
            return Err(Error::InvalidMarketIndex);
        }
        let mut seen = Vec::new();
        for o in &self.orders {
            if o.market_index != m0 {
                return Err(Error::MarketIndexMismatch);
            }
            Self::validate_order_common(o, &mut seen)?;
        }

        check_nonce(self.nonce)?;
        check_expired_at(self.expired_at)?;

        match self.grouping_type {
            GROUPING_TYPE_ONE_CANCELS_THE_OTHER => self.validate_oco(),
            GROUPING_TYPE_ONE_TRIGGERS_THE_OTHER => self.validate_oto(),
            GROUPING_TYPE_ONE_TRIGGERS_A_ONE_CANCELS_THE_OTHER => self.validate_otoco(),
            _ => Err(Error::GroupingTypeInvalid),
        }
    }

    fn hash(&self, chain_id: u32) -> Result<[u8; HASH_LENGTH]> {
        let mut e: Vec<Goldilocks> = Vec::with_capacity(11);
        e.push(gf(chain_id));
        e.push(gf(TX_TYPE_L2_CREATE_GROUPED_ORDERS));
        e.push(gf(self.nonce));
        e.push(gf(self.expired_at));
        e.push(gf(self.account_index));
        e.push(gf(self.api_key_index));
        e.push(gf(self.grouping_type));

        let mut aggregated = hash_digest(&[]); // overwritten on first iter
        for (index, o) in self.orders.iter().enumerate() {
            let order_hash = hash_digest(&[
                gf(o.market_index),
                gf(o.client_order_index),
                gf(o.base_amount),
                gf(o.price),
                gf(o.is_ask),
                gf(o.order_type),
                gf(o.time_in_force),
                gf(o.reduce_only),
                gf(o.trigger_price),
                gf(o.order_expiry),
            ]);
            if index == 0 {
                aggregated = order_hash;
            } else {
                aggregated = hash_n_to_one(&[aggregated, order_hash]);
            }
        }
        e.extend_from_slice(&aggregated);

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
// CancelOrder
// ---------------------------------------------------------------------------

/// `L2CancelOrderTxInfo`
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CancelOrder {
    pub account_index: i64,
    pub api_key_index: u8,
    pub market_index: i64,
    pub index: i64,
    pub expired_at: i64,
    pub nonce: i64,
    #[serde(serialize_with = "b64::serialize")]
    pub sig: Vec<u8>,
    #[serde(skip)]
    pub signed_hash: String,
    #[serde(rename = "L2TxAttributes")]
    pub attributes: Option<AttributeMap>,
}

impl TxInfo for CancelOrder {
    fn tx_type(&self) -> u8 {
        TX_TYPE_L2_CANCEL_ORDER
    }

    fn validate(&self) -> Result<()> {
        if let Some(a) = &self.attributes {
            a.validate()?;
        }
        check_account_index(self.account_index, MAX_ACCOUNT_INDEX)?;
        check_api_key_index(self.api_key_index)?;

        check_market_index(self.market_index)?;
        // Go checks `< MinClientOrderIndex && < MinOrderIndex` and
        // `> MaxClientOrderIndex && > MaxOrderIndex`; since the client-order
        // range is nested inside the order range these reduce to the bounds below.
        if self.index < MIN_CLIENT_ORDER_INDEX {
            return Err(Error::OrderIndexOutOfRange);
        }
        if self.index > MAX_ORDER_INDEX {
            return Err(Error::OrderIndexOutOfRange);
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
            TX_TYPE_L2_CANCEL_ORDER,
            self.nonce,
            self.expired_at,
            self.account_index,
            self.api_key_index,
        );
        e.push(gf(self.market_index));
        e.push(gf(self.index));
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
// CancelAllOrders
// ---------------------------------------------------------------------------

/// `L2CancelAllOrdersTxInfo`
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CancelAllOrders {
    pub account_index: i64,
    pub api_key_index: u8,
    pub time_in_force: u8,
    pub time: i64,
    pub expired_at: i64,
    pub nonce: i64,
    #[serde(serialize_with = "b64::serialize")]
    pub sig: Vec<u8>,
    #[serde(skip)]
    pub signed_hash: String,
    #[serde(rename = "L2TxAttributes")]
    pub attributes: Option<AttributeMap>,
}

impl TxInfo for CancelAllOrders {
    fn tx_type(&self) -> u8 {
        TX_TYPE_L2_CANCEL_ALL_ORDERS
    }

    fn validate(&self) -> Result<()> {
        if let Some(a) = &self.attributes {
            a.validate()?;
        }
        check_account_index(self.account_index, MAX_ACCOUNT_INDEX)?;
        // ApiKeyIndex: allow Nil (255) in addition to the normal range.
        if self.api_key_index > MAX_API_KEY_INDEX && self.api_key_index != NIL_API_KEY_INDEX {
            return Err(Error::ApiKeyIndexTooHigh {
                max: MAX_API_KEY_INDEX,
            });
        }

        check_nonce(self.nonce)?;
        check_expired_at(self.expired_at)?;

        if let Some(m) = self
            .attributes
            .as_ref()
            .and_then(|a| a.0.get(&ATTRIBUTE_TYPE_CANCEL_ALL_MARKET_INDEX).copied())
        {
            if self.time_in_force != IMMEDIATE_CANCEL_ALL && m != NIL_MARKET_INDEX {
                return Err(Error::CancelAllMarketIndexCantBeScheduled);
            }
        }

        match self.time_in_force {
            IMMEDIATE_CANCEL_ALL => {
                if self.time != NIL_ORDER_EXPIRY {
                    return Err(Error::CancelAllTimeInvalid);
                }
            }
            SCHEDULED_CANCEL_ALL => {
                if self.time < MIN_ORDER_EXPIRY || self.time > MAX_ORDER_EXPIRY {
                    return Err(Error::CancelAllTimeInvalid);
                }
            }
            ABORT_SCHEDULED_CANCEL_ALL => {
                if self.time != 0 {
                    return Err(Error::CancelAllTimeInvalid);
                }
            }
            _ => return Err(Error::InvalidCancelAllTimeInForce),
        }
        Ok(())
    }

    fn hash(&self, chain_id: u32) -> Result<[u8; HASH_LENGTH]> {
        let mut e = Vec::with_capacity(8);
        push_header(
            &mut e,
            chain_id,
            TX_TYPE_L2_CANCEL_ALL_ORDERS,
            self.nonce,
            self.expired_at,
            self.account_index,
            self.api_key_index,
        );
        e.push(gf(self.time_in_force));
        e.push(gf(self.time));
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
// ModifyOrder
// ---------------------------------------------------------------------------

/// `L2ModifyOrderTxInfo`
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ModifyOrder {
    pub account_index: i64,
    pub api_key_index: u8,
    pub market_index: i64,
    pub index: i64,
    pub base_amount: i64,
    pub price: u32,
    pub trigger_price: u32,
    pub expired_at: i64,
    pub nonce: i64,
    #[serde(serialize_with = "b64::serialize")]
    pub sig: Vec<u8>,
    #[serde(skip)]
    pub signed_hash: String,
    #[serde(rename = "L2TxAttributes")]
    pub attributes: Option<AttributeMap>,
}

impl TxInfo for ModifyOrder {
    fn tx_type(&self) -> u8 {
        TX_TYPE_L2_MODIFY_ORDER
    }

    fn validate(&self) -> Result<()> {
        if let Some(a) = &self.attributes {
            a.validate()?;
        }
        check_account_index(self.account_index, MAX_ACCOUNT_INDEX)?;
        check_api_key_index(self.api_key_index)?;

        check_market_index(self.market_index)?;
        // See CancelOrder: the nested ranges reduce to these bounds.
        if self.index < MIN_CLIENT_ORDER_INDEX {
            return Err(Error::ClientOrderIndexOutOfRange);
        }
        if self.index > MAX_ORDER_INDEX {
            return Err(Error::ClientOrderIndexOutOfRange);
        }
        if self.base_amount != NIL_ORDER_BASE_AMOUNT && self.base_amount < MIN_ORDER_BASE_AMOUNT {
            return Err(Error::BaseAmountOutOfRange);
        }
        if self.base_amount > MAX_ORDER_BASE_AMOUNT {
            return Err(Error::BaseAmountOutOfRange);
        }
        if self.price < MIN_ORDER_PRICE || self.price > MAX_ORDER_PRICE {
            return Err(Error::PriceOutOfRange);
        }
        if (self.trigger_price < MIN_ORDER_TRIGGER_PRICE
            || self.trigger_price > MAX_ORDER_TRIGGER_PRICE)
            && self.trigger_price != NIL_ORDER_TRIGGER_PRICE
        {
            return Err(Error::OrderTriggerPriceInvalid);
        }

        check_nonce(self.nonce)?;
        check_expired_at(self.expired_at)?;
        Ok(())
    }

    fn hash(&self, chain_id: u32) -> Result<[u8; HASH_LENGTH]> {
        let mut e = Vec::with_capacity(11);
        push_header(
            &mut e,
            chain_id,
            TX_TYPE_L2_MODIFY_ORDER,
            self.nonce,
            self.expired_at,
            self.account_index,
            self.api_key_index,
        );
        e.push(gf(self.market_index));
        e.push(gf(self.index));
        e.push(gf(self.base_amount));
        e.push(gf(self.price));
        e.push(gf(self.trigger_price));
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
