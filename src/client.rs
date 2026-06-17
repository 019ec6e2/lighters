//! High-level transaction client.
//!
//! Mirrors `lighter-go/client` + `types`: a [`TxClient`] is bound to an
//! (account, api-key) pair and builds, validates, and signs transactions,
//! optionally fetching the nonce over HTTP.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::attributes::{AttributeMap, TxAttributes};
use crate::error::{Error, Result};
use crate::hash::{bytes_to_field_elems, fp5_to_le_bytes, hash_to_fp5};
use crate::http::HttpClient;
use crate::signer::KeyManager;
use crate::transactions::*;

/// Default transaction lifetime: 10 minutes minus 1s of slack (millis),
/// matching Go's `DefaultExpireTime`.
pub const DEFAULT_EXPIRE_MS: i64 = 10 * 60 * 1000 - 1000;

/// Per-transaction options. Unset fields fall back to the client's defaults
/// (and the nonce is fetched over HTTP when left unset).
#[derive(Debug, Clone, Default)]
pub struct TransactOpts {
    pub from_account_index: Option<i64>,
    pub api_key_index: Option<u8>,
    /// UnixMilli expiry; `0` means "use the default lifetime".
    pub expired_at: i64,
    /// `None` or `Some(-1)` triggers an HTTP nonce lookup.
    pub nonce: Option<i64>,
    pub tx_attributes: Option<TxAttributes>,
}

struct Resolved {
    account_index: i64,
    api_key_index: u8,
    expired_at: i64,
    nonce: i64,
    attributes: Option<AttributeMap>,
}

/// Generates a fresh API key, returning `(private_key_hex, public_key_hex)`,
/// both `0x`-prefixed. Equivalent to Go's `GenerateAPIKey`.
pub fn generate_api_key() -> (String, String) {
    let km = KeyManager::generate();
    (km.private_key_hex(), km.public_key_hex())
}

/// A signing client bound to one (account, api-key) pair.
pub struct TxClient {
    http: Option<Box<dyn HttpClient>>,
    chain_id: u32,
    key: KeyManager,
    account_index: i64,
    api_key_index: u8,
}

impl TxClient {
    /// Builds a client from a hex-encoded (optionally `0x`-prefixed) private key.
    pub fn new(
        private_key: &str,
        account_index: i64,
        api_key_index: u8,
        chain_id: u32,
    ) -> Result<Self> {
        let key = KeyManager::from_hex(private_key)?;
        Ok(TxClient {
            http: None,
            chain_id,
            key,
            account_index,
            api_key_index,
        })
    }

    /// Attaches an HTTP client so nonces can be fetched automatically.
    pub fn with_http(mut self, http: Box<dyn HttpClient>) -> Self {
        self.http = Some(http);
        self
    }

    pub fn chain_id(&self) -> u32 {
        self.chain_id
    }

    pub fn account_index(&self) -> i64 {
        self.account_index
    }

    pub fn api_key_index(&self) -> u8 {
        self.api_key_index
    }

    pub fn key_manager(&self) -> &KeyManager {
        &self.key
    }

    fn fulfill(&self, opts: &TransactOpts) -> Result<Resolved> {
        let expired_at = if opts.expired_at == 0 {
            now_unix_millis() + DEFAULT_EXPIRE_MS
        } else {
            opts.expired_at
        };
        let account_index = opts.from_account_index.unwrap_or(self.account_index);
        let api_key_index = opts.api_key_index.unwrap_or(self.api_key_index);
        let nonce = match opts.nonce {
            Some(n) if n != -1 => n,
            _ => {
                let http = self.http.as_ref().ok_or(Error::NonceUnavailable)?;
                http.get_next_nonce(account_index, api_key_index)?
            }
        };
        let attributes = opts.tx_attributes.as_ref().and_then(|a| a.to_map());
        Ok(Resolved {
            account_index,
            api_key_index,
            expired_at,
            nonce,
            attributes,
        })
    }

    /// Builds the auth-token string `deadline:account:apiKey:signature`.
    ///
    /// `deadline_unix_secs` is the Unix timestamp (seconds) the token expires at.
    pub fn auth_token(&self, deadline_unix_secs: i64, opts: &TransactOpts) -> Result<String> {
        let account_index = opts.from_account_index.unwrap_or(self.account_index);
        let api_key_index = opts.api_key_index.unwrap_or(self.api_key_index);
        let message = format!("{deadline_unix_secs}:{account_index}:{api_key_index}");
        let elems = bytes_to_field_elems(message.as_bytes())?;
        let msg_hash = fp5_to_le_bytes(&hash_to_fp5(&elems));
        let sig = self.key.sign(&msg_hash)?;
        Ok(format!("{message}:{}", hex::encode(sig)))
    }
}

fn now_unix_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Request types (mirror `types.*TxReq`) and the per-tx signing methods.
// ---------------------------------------------------------------------------

/// Order parameters shared by create / grouped-order requests.
#[derive(Debug, Clone)]
pub struct OrderReq {
    pub market_index: i16,
    pub client_order_index: i64,
    pub base_amount: i64,
    pub price: u32,
    pub is_ask: u8,
    pub order_type: u8,
    pub time_in_force: u8,
    pub reduce_only: u8,
    pub trigger_price: u32,
    pub order_expiry: i64,
}

impl From<OrderReq> for OrderInfo {
    fn from(o: OrderReq) -> Self {
        OrderInfo {
            market_index: o.market_index,
            client_order_index: o.client_order_index,
            base_amount: o.base_amount,
            price: o.price,
            is_ask: o.is_ask,
            order_type: o.order_type,
            time_in_force: o.time_in_force,
            reduce_only: o.reduce_only,
            trigger_price: o.trigger_price,
            order_expiry: o.order_expiry,
        }
    }
}

impl TxClient {
    /// Signs a create-order transaction.
    pub fn create_order(&self, order: OrderReq, opts: &TransactOpts) -> Result<CreateOrder> {
        let r = self.fulfill(opts)?;
        let mut tx = CreateOrder {
            account_index: r.account_index,
            api_key_index: r.api_key_index,
            order: order.into(),
            expired_at: r.expired_at,
            nonce: r.nonce,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: r.attributes,
        };
        sign_tx(&mut tx, &self.key, self.chain_id)?;
        Ok(tx)
    }

    /// Signs a grouped-orders transaction.
    pub fn create_grouped_orders(
        &self,
        grouping_type: u8,
        orders: Vec<OrderReq>,
        opts: &TransactOpts,
    ) -> Result<CreateGroupedOrders> {
        let r = self.fulfill(opts)?;
        let mut tx = CreateGroupedOrders {
            account_index: r.account_index,
            api_key_index: r.api_key_index,
            grouping_type,
            orders: orders.into_iter().map(Into::into).collect(),
            expired_at: r.expired_at,
            nonce: r.nonce,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: r.attributes,
        };
        sign_tx(&mut tx, &self.key, self.chain_id)?;
        Ok(tx)
    }

    /// Signs a cancel-order transaction.
    pub fn cancel_order(
        &self,
        market_index: i16,
        index: i64,
        opts: &TransactOpts,
    ) -> Result<CancelOrder> {
        let r = self.fulfill(opts)?;
        let mut tx = CancelOrder {
            account_index: r.account_index,
            api_key_index: r.api_key_index,
            market_index,
            index,
            expired_at: r.expired_at,
            nonce: r.nonce,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: r.attributes,
        };
        sign_tx(&mut tx, &self.key, self.chain_id)?;
        Ok(tx)
    }

    /// Signs a cancel-all-orders transaction.
    pub fn cancel_all_orders(
        &self,
        time_in_force: u8,
        time: i64,
        opts: &TransactOpts,
    ) -> Result<CancelAllOrders> {
        let r = self.fulfill(opts)?;
        let mut tx = CancelAllOrders {
            account_index: r.account_index,
            api_key_index: r.api_key_index,
            time_in_force,
            time,
            expired_at: r.expired_at,
            nonce: r.nonce,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: r.attributes,
        };
        sign_tx(&mut tx, &self.key, self.chain_id)?;
        Ok(tx)
    }

    /// Signs a modify-order transaction.
    pub fn modify_order(
        &self,
        market_index: i16,
        index: i64,
        base_amount: i64,
        price: u32,
        trigger_price: u32,
        opts: &TransactOpts,
    ) -> Result<ModifyOrder> {
        let r = self.fulfill(opts)?;
        let mut tx = ModifyOrder {
            account_index: r.account_index,
            api_key_index: r.api_key_index,
            market_index,
            index,
            base_amount,
            price,
            trigger_price,
            expired_at: r.expired_at,
            nonce: r.nonce,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: r.attributes,
        };
        sign_tx(&mut tx, &self.key, self.chain_id)?;
        Ok(tx)
    }

    /// Signs a change-pubkey transaction. `pub_key` is the 40-byte new key.
    pub fn change_pub_key(&self, pub_key: Vec<u8>, opts: &TransactOpts) -> Result<ChangePubKey> {
        let r = self.fulfill(opts)?;
        let mut tx = ChangePubKey {
            account_index: r.account_index,
            api_key_index: r.api_key_index,
            pub_key,
            l1_sig: String::new(),
            expired_at: r.expired_at,
            nonce: r.nonce,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: r.attributes,
        };
        sign_tx(&mut tx, &self.key, self.chain_id)?;
        Ok(tx)
    }

    /// Signs a create-sub-account transaction.
    pub fn create_sub_account(&self, opts: &TransactOpts) -> Result<CreateSubAccount> {
        let r = self.fulfill(opts)?;
        let mut tx = CreateSubAccount {
            account_index: r.account_index,
            api_key_index: r.api_key_index,
            expired_at: r.expired_at,
            nonce: r.nonce,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: r.attributes,
        };
        sign_tx(&mut tx, &self.key, self.chain_id)?;
        Ok(tx)
    }

    /// Signs a transfer transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn transfer(
        &self,
        to_account_index: i64,
        asset_index: i16,
        from_route_type: u8,
        to_route_type: u8,
        amount: i64,
        usdc_fee: i64,
        memo: [u8; 32],
        opts: &TransactOpts,
    ) -> Result<Transfer> {
        let r = self.fulfill(opts)?;
        let mut tx = Transfer {
            from_account_index: r.account_index,
            api_key_index: r.api_key_index,
            to_account_index,
            asset_index,
            from_route_type,
            to_route_type,
            amount,
            usdc_fee,
            memo,
            expired_at: r.expired_at,
            nonce: r.nonce,
            sig: Vec::new(),
            l1_sig: String::new(),
            signed_hash: String::new(),
            attributes: r.attributes,
        };
        sign_tx(&mut tx, &self.key, self.chain_id)?;
        Ok(tx)
    }

    /// Signs a withdraw transaction.
    pub fn withdraw(
        &self,
        asset_index: i16,
        route_type: u8,
        amount: u64,
        opts: &TransactOpts,
    ) -> Result<Withdraw> {
        let r = self.fulfill(opts)?;
        let mut tx = Withdraw {
            from_account_index: r.account_index,
            api_key_index: r.api_key_index,
            asset_index,
            route_type,
            amount,
            expired_at: r.expired_at,
            nonce: r.nonce,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: r.attributes,
        };
        sign_tx(&mut tx, &self.key, self.chain_id)?;
        Ok(tx)
    }

    /// Signs an update-leverage transaction.
    pub fn update_leverage(
        &self,
        market_index: i16,
        initial_margin_fraction: u16,
        margin_mode: u8,
        opts: &TransactOpts,
    ) -> Result<UpdateLeverage> {
        let r = self.fulfill(opts)?;
        let mut tx = UpdateLeverage {
            account_index: r.account_index,
            api_key_index: r.api_key_index,
            market_index,
            initial_margin_fraction,
            margin_mode,
            expired_at: r.expired_at,
            nonce: r.nonce,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: r.attributes,
        };
        sign_tx(&mut tx, &self.key, self.chain_id)?;
        Ok(tx)
    }

    /// Signs an update-margin transaction.
    pub fn update_margin(
        &self,
        market_index: i16,
        usdc_amount: i64,
        direction: u8,
        opts: &TransactOpts,
    ) -> Result<UpdateMargin> {
        let r = self.fulfill(opts)?;
        let mut tx = UpdateMargin {
            account_index: r.account_index,
            api_key_index: r.api_key_index,
            market_index,
            usdc_amount,
            direction,
            expired_at: r.expired_at,
            nonce: r.nonce,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: r.attributes,
        };
        sign_tx(&mut tx, &self.key, self.chain_id)?;
        Ok(tx)
    }

    /// Signs an update-account-config transaction.
    pub fn update_account_config(
        &self,
        account_trading_mode: u8,
        opts: &TransactOpts,
    ) -> Result<UpdateAccountConfig> {
        let r = self.fulfill(opts)?;
        let mut tx = UpdateAccountConfig {
            account_index: r.account_index,
            api_key_index: r.api_key_index,
            account_trading_mode,
            expired_at: r.expired_at,
            nonce: r.nonce,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: r.attributes,
        };
        sign_tx(&mut tx, &self.key, self.chain_id)?;
        Ok(tx)
    }

    /// Signs an update-account-asset-config transaction.
    pub fn update_account_asset_config(
        &self,
        asset_index: i16,
        asset_margin_mode: u8,
        opts: &TransactOpts,
    ) -> Result<UpdateAccountAssetConfig> {
        let r = self.fulfill(opts)?;
        let mut tx = UpdateAccountAssetConfig {
            account_index: r.account_index,
            api_key_index: r.api_key_index,
            asset_index,
            asset_margin_mode,
            expired_at: r.expired_at,
            nonce: r.nonce,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: r.attributes,
        };
        sign_tx(&mut tx, &self.key, self.chain_id)?;
        Ok(tx)
    }

    /// Signs an approve-integrator transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn approve_integrator(
        &self,
        integrator_account_index: i64,
        max_perps_taker_fee: u32,
        max_perps_maker_fee: u32,
        max_spot_taker_fee: u32,
        max_spot_maker_fee: u32,
        approval_expiry: i64,
        opts: &TransactOpts,
    ) -> Result<ApproveIntegrator> {
        let r = self.fulfill(opts)?;
        let mut tx = ApproveIntegrator {
            account_index: r.account_index,
            api_key_index: r.api_key_index,
            integrator_account_index,
            max_perps_taker_fee,
            max_perps_maker_fee,
            max_spot_taker_fee,
            max_spot_maker_fee,
            approval_expiry,
            expired_at: r.expired_at,
            nonce: r.nonce,
            sig: Vec::new(),
            l1_sig: String::new(),
            signed_hash: String::new(),
            attributes: r.attributes,
        };
        sign_tx(&mut tx, &self.key, self.chain_id)?;
        Ok(tx)
    }

    /// Signs a create-public-pool transaction.
    pub fn create_public_pool(
        &self,
        operator_fee: i64,
        initial_total_shares: i64,
        min_operator_share_rate: u16,
        opts: &TransactOpts,
    ) -> Result<CreatePublicPool> {
        let r = self.fulfill(opts)?;
        let mut tx = CreatePublicPool {
            account_index: r.account_index,
            api_key_index: r.api_key_index,
            operator_fee,
            initial_total_shares,
            min_operator_share_rate,
            expired_at: r.expired_at,
            nonce: r.nonce,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: r.attributes,
        };
        sign_tx(&mut tx, &self.key, self.chain_id)?;
        Ok(tx)
    }

    /// Signs an update-public-pool transaction.
    pub fn update_public_pool(
        &self,
        public_pool_index: i64,
        status: u8,
        operator_fee: i64,
        min_operator_share_rate: u16,
        opts: &TransactOpts,
    ) -> Result<UpdatePublicPool> {
        let r = self.fulfill(opts)?;
        let mut tx = UpdatePublicPool {
            account_index: r.account_index,
            api_key_index: r.api_key_index,
            public_pool_index,
            status,
            operator_fee,
            min_operator_share_rate,
            expired_at: r.expired_at,
            nonce: r.nonce,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: r.attributes,
        };
        sign_tx(&mut tx, &self.key, self.chain_id)?;
        Ok(tx)
    }

    /// Signs a mint-shares transaction.
    pub fn mint_shares(
        &self,
        public_pool_index: i64,
        share_amount: i64,
        opts: &TransactOpts,
    ) -> Result<MintShares> {
        let r = self.fulfill(opts)?;
        let mut tx = MintShares {
            account_index: r.account_index,
            api_key_index: r.api_key_index,
            public_pool_index,
            share_amount,
            expired_at: r.expired_at,
            nonce: r.nonce,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: r.attributes,
        };
        sign_tx(&mut tx, &self.key, self.chain_id)?;
        Ok(tx)
    }

    /// Signs a burn-shares transaction.
    pub fn burn_shares(
        &self,
        public_pool_index: i64,
        share_amount: i64,
        opts: &TransactOpts,
    ) -> Result<BurnShares> {
        let r = self.fulfill(opts)?;
        let mut tx = BurnShares {
            account_index: r.account_index,
            api_key_index: r.api_key_index,
            public_pool_index,
            share_amount,
            expired_at: r.expired_at,
            nonce: r.nonce,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: r.attributes,
        };
        sign_tx(&mut tx, &self.key, self.chain_id)?;
        Ok(tx)
    }

    /// Signs a stake-assets transaction.
    pub fn stake_assets(
        &self,
        staking_pool_index: i64,
        share_amount: i64,
        opts: &TransactOpts,
    ) -> Result<StakeAssets> {
        let r = self.fulfill(opts)?;
        let mut tx = StakeAssets {
            account_index: r.account_index,
            api_key_index: r.api_key_index,
            staking_pool_index,
            share_amount,
            expired_at: r.expired_at,
            nonce: r.nonce,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: r.attributes,
        };
        sign_tx(&mut tx, &self.key, self.chain_id)?;
        Ok(tx)
    }

    /// Signs an unstake-assets transaction.
    pub fn unstake_assets(
        &self,
        staking_pool_index: i64,
        share_amount: i64,
        opts: &TransactOpts,
    ) -> Result<UnstakeAssets> {
        let r = self.fulfill(opts)?;
        let mut tx = UnstakeAssets {
            account_index: r.account_index,
            api_key_index: r.api_key_index,
            staking_pool_index,
            share_amount,
            expired_at: r.expired_at,
            nonce: r.nonce,
            sig: Vec::new(),
            signed_hash: String::new(),
            attributes: r.attributes,
        };
        sign_tx(&mut tx, &self.key, self.chain_id)?;
        Ok(tx)
    }
}
