//! Optional L2 transaction attributes.
//!
//! Mirrors `types.L2TxAttributes` (the user-facing options) and
//! `txtypes.L2TxAttributes` (the `map[uint8]int` used for hashing and JSON).

use std::collections::BTreeMap;

use poseidon_hash::Fp5Element;
use serde::ser::{Serialize, SerializeMap, Serializer};

use crate::constants::*;
use crate::error::{Error, Result};
use crate::hash::{fp5_to_le_bytes, gf, hash_to_fp5};

/// Per-attribute range configuration (`AttributeTypeToConfig` in Go).
struct AttrConfig {
    min: i64,
    max: i64,
    nil: i64,
    err: Error,
}

fn attr_config(typ: u8) -> Option<AttrConfig> {
    let cfg = match typ {
        ATTRIBUTE_TYPE_INTEGRATOR_ACCOUNT_INDEX => AttrConfig {
            min: 0,
            max: MAX_ACCOUNT_INDEX,
            nil: NIL_INTEGRATOR_INDEX,
            err: Error::IntegratorAccountIndexOutOfRange,
        },
        ATTRIBUTE_TYPE_INTEGRATOR_TAKER_FEE => AttrConfig {
            min: 0,
            max: FEE_TICK,
            nil: NIL_INTEGRATOR_TAKER_FEE as i64,
            err: Error::AttributeValueOutOfRange,
        },
        ATTRIBUTE_TYPE_INTEGRATOR_MAKER_FEE => AttrConfig {
            min: 0,
            max: FEE_TICK,
            nil: NIL_INTEGRATOR_MAKER_FEE as i64,
            err: Error::AttributeValueOutOfRange,
        },
        ATTRIBUTE_TYPE_SKIP_TX_NONCE => AttrConfig {
            min: 1,
            max: 1,
            nil: 0,
            err: Error::AttributeValueOutOfRange,
        },
        ATTRIBUTE_TYPE_CANCEL_ALL_MARKET_INDEX => AttrConfig {
            min: MIN_PERPS_MARKET_INDEX as i64,
            max: NIL_MARKET_INDEX as i64,
            nil: NIL_MARKET_INDEX as i64,
            err: Error::AttributeValueOutOfRange,
        },
        ATTRIBUTE_TYPE_SELF_TRADE_BEHAVIOR_MODE => AttrConfig {
            min: SELF_TRADE_BEHAVIOR_EXPIRE_MAKER,
            max: SELF_TRADE_BEHAVIOR_REDUCE,
            nil: SELF_TRADE_BEHAVIOR_EXPIRE_MAKER,
            err: Error::AttributeValueOutOfRange,
        },
        ATTRIBUTE_TYPE_SELF_TRADE_EQUALITY_MODE => AttrConfig {
            min: SELF_TRADE_EQUALITY_ACCOUNT_INDEX,
            max: SELF_TRADE_EQUALITY_MASTER_ACCOUNT_INDEX,
            nil: SELF_TRADE_EQUALITY_ACCOUNT_INDEX,
            err: Error::AttributeValueOutOfRange,
        },
        _ => return None,
    };
    Some(cfg)
}

/// User-facing optional transaction attributes (`types.L2TxAttributes`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TxAttributes {
    pub integrator_account_index: Option<i64>,
    pub integrator_taker_fee: Option<u32>,
    pub integrator_maker_fee: Option<u32>,
    pub skip_nonce: Option<u8>,
    pub cancel_all_market_index: Option<i16>,
    pub self_trade_behavior_mode: Option<u8>,
    pub self_trade_equality_mode: Option<u8>,
}

impl TxAttributes {
    /// Convenience constructor used by simple flows (`skipNonce` only).
    pub fn skip_nonce(skip: bool) -> Self {
        TxAttributes {
            skip_nonce: if skip { Some(1) } else { None },
            ..Default::default()
        }
    }

    /// Returns `true` if no attribute is set.
    pub fn is_none(&self) -> bool {
        self.integrator_account_index.is_none()
            && self.integrator_taker_fee.is_none()
            && self.integrator_maker_fee.is_none()
            && self.skip_nonce.is_none()
            && self.cancel_all_market_index.is_none()
            && self.self_trade_behavior_mode.is_none()
            && self.self_trade_equality_mode.is_none()
    }

    /// Builds the internal `map[uint8]int` representation.
    ///
    /// Returns `None` when no attribute is set, matching Go's
    /// `ConstructL2TxAttributes` (which returns a nil map → JSON `null`).
    pub fn to_map(&self) -> Option<AttributeMap> {
        if self.is_none() {
            return None;
        }
        let mut m = BTreeMap::new();
        if let Some(v) = self.integrator_account_index {
            m.insert(ATTRIBUTE_TYPE_INTEGRATOR_ACCOUNT_INDEX, v);
        }
        if let Some(v) = self.integrator_taker_fee {
            m.insert(ATTRIBUTE_TYPE_INTEGRATOR_TAKER_FEE, v as i64);
        }
        if let Some(v) = self.integrator_maker_fee {
            m.insert(ATTRIBUTE_TYPE_INTEGRATOR_MAKER_FEE, v as i64);
        }
        if let Some(v) = self.skip_nonce {
            m.insert(ATTRIBUTE_TYPE_SKIP_TX_NONCE, v as i64);
        }
        if let Some(v) = self.cancel_all_market_index {
            m.insert(ATTRIBUTE_TYPE_CANCEL_ALL_MARKET_INDEX, v as i64);
        }
        if let Some(v) = self.self_trade_behavior_mode {
            m.insert(ATTRIBUTE_TYPE_SELF_TRADE_BEHAVIOR_MODE, v as i64);
        }
        if let Some(v) = self.self_trade_equality_mode {
            m.insert(ATTRIBUTE_TYPE_SELF_TRADE_EQUALITY_MODE, v as i64);
        }
        Some(AttributeMap(m))
    }
}

/// The `txtypes.L2TxAttributes` map (attribute type → value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeMap(pub BTreeMap<u8, i64>);

impl AttributeMap {
    fn get_or_default(&self, typ: u8) -> i64 {
        match self.0.get(&typ) {
            Some(v) => *v,
            None => attr_config(typ).map(|c| c.nil).unwrap_or(0),
        }
    }

    /// Validates the attribute map (ranges + cross-field rules).
    pub fn validate(&self) -> Result<()> {
        if self.0.is_empty() {
            return Ok(());
        }
        if self.0.len() > NB_ATTRIBUTES_PER_TX {
            return Err(Error::TooManyAttributes {
                max: NB_ATTRIBUTES_PER_TX,
            });
        }
        for (&typ, &val) in &self.0 {
            let cfg = attr_config(typ).ok_or(Error::AttributeValueOutOfRange)?;
            if val < cfg.min || val > cfg.max {
                return Err(clone_err(&cfg.err));
            }
        }

        let is_nil = |typ: u8| self.get_or_default(typ) == attr_config(typ).unwrap().nil;

        let has_fees = !is_nil(ATTRIBUTE_TYPE_INTEGRATOR_TAKER_FEE)
            || !is_nil(ATTRIBUTE_TYPE_INTEGRATOR_MAKER_FEE);
        let has_integrator_index = !is_nil(ATTRIBUTE_TYPE_INTEGRATOR_ACCOUNT_INDEX);
        if has_fees && !has_integrator_index {
            return Err(Error::IntegratorAccountIndexRequiredForNonZeroFees);
        }

        let has_self_trade_spec = !is_nil(ATTRIBUTE_TYPE_SELF_TRADE_BEHAVIOR_MODE)
            || !is_nil(ATTRIBUTE_TYPE_SELF_TRADE_EQUALITY_MODE);
        if has_self_trade_spec && has_fees {
            return Err(Error::SelfTradeSpecificationNotAllowedWithNonZeroFees);
        }

        let is_mai_equality = self.0.get(&ATTRIBUTE_TYPE_SELF_TRADE_EQUALITY_MODE).copied()
            == Some(SELF_TRADE_EQUALITY_MASTER_ACCOUNT_INDEX);
        let is_reduce_behavior = self.0.get(&ATTRIBUTE_TYPE_SELF_TRADE_BEHAVIOR_MODE).copied()
            == Some(SELF_TRADE_BEHAVIOR_REDUCE);
        if is_reduce_behavior && is_mai_equality {
            return Err(Error::ReduceModeNotAllowedWithMasterAccountIndexEqualityMode);
        }

        Ok(())
    }

    /// Mirrors Go's `IsEmpty`: all present values equal their nil value.
    fn is_empty(&self) -> bool {
        self.0
            .iter()
            .all(|(&k, &v)| v == attr_config(k).map(|c| c.nil).unwrap_or(0))
    }

    /// Non-nil types in ascending order, padded with zeros to `NB_ATTRIBUTES_PER_TX`.
    fn normalized_types(&self) -> [u8; NB_ATTRIBUTES_PER_TX] {
        let mut types = [0u8; NB_ATTRIBUTES_PER_TX];
        let mut i = 0;
        for (&k, &v) in &self.0 {
            if attr_config(k).map(|c| c.nil).unwrap_or(0) == v {
                continue;
            }
            types[i] = k;
            i += 1;
        }
        types[..i].sort_unstable();
        types
    }

    /// `attr.Hash()` — Poseidon2 over the (type, value) pairs.
    fn hash(&self) -> Fp5Element {
        let mut elems = Vec::with_capacity(NB_ATTRIBUTES_PER_TX * 2);
        for typ in self.normalized_types() {
            let value = if typ != 0 { self.get_or_default(typ) } else { 0 };
            elems.push(gf(typ));
            elems.push(gf(value));
        }
        hash_to_fp5(&elems)
    }

    /// `attr.AggregateTxHash` — folds the attributes hash into the tx hash.
    pub fn aggregate_tx_hash(&self, tx_hash: Fp5Element) -> [u8; 40] {
        if self.is_empty() {
            return fp5_to_le_bytes(&tx_hash);
        }
        let attr_hash = self.hash();
        let mut combined = Vec::with_capacity(10);
        combined.extend_from_slice(&tx_hash.0);
        combined.extend_from_slice(&attr_hash.0);
        fp5_to_le_bytes(&hash_to_fp5(&combined))
    }
}

/// `Error` is not `Clone` (it carries `serde_json::Error`), but the attribute
/// variants we surface here are unit/struct variants, so reconstruct them.
fn clone_err(e: &Error) -> Error {
    match e {
        Error::IntegratorAccountIndexOutOfRange => Error::IntegratorAccountIndexOutOfRange,
        Error::AttributeValueOutOfRange => Error::AttributeValueOutOfRange,
        _ => Error::AttributeValueOutOfRange,
    }
}

/// Helper: aggregate a tx hash with optional attributes.
///
/// `None` (no attributes) returns the bare tx hash bytes, matching Go where a
/// nil attribute map short-circuits in `AggregateTxHash`.
pub fn aggregate(attrs: &Option<AttributeMap>, tx_hash: Fp5Element) -> [u8; 40] {
    match attrs {
        Some(m) => m.aggregate_tx_hash(tx_hash),
        None => fp5_to_le_bytes(&tx_hash),
    }
}

/// Serializes the optional attribute map exactly like Go's embedded
/// `L2TxAttributes` field: `null` when absent, otherwise an object keyed by the
/// decimal attribute type.
impl Serialize for AttributeMap {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (k, v) in &self.0 {
            map.serialize_entry(&k.to_string(), v)?;
        }
        map.end()
    }
}
