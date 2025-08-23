use std::net::SocketAddr;
use std::sync::Arc;
use std::collections::HashMap;

use tokio::net::TcpListener;
use tokio::sync::{RwLock, Mutex};
use tokio::sync::mpsc::UnboundedSender;

use axum::Router;
use axum::routing::{get, put};

use crate::crypto::*;
use crate::transaction::Transaction;
use crate::block::Block;
use crate::storage::Storage;
use crate::client::{Client, Error as ClientError};

mod transactions_api;
mod blocks_api;
mod shards_api;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Client(#[from] ClientError),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("storage error: {0}")]
    Storage(String)
}

#[derive(Debug, Clone)]
pub struct Shard<S: Storage> {
    /// Client used to perform API requests to other shards.
    pub client: Client,

    /// Endpoint on which the API server should be running.
    pub local_address: SocketAddr,

    /// API endpoint which should be announced to other shards.
    pub remote_address: Option<String>,

    /// Blockchain storage.
    pub storage: S,

    /// Shard security rules.
    pub security_rules: ShardSecurityRules
}

#[derive(Debug, Clone)]
pub struct ShardSecurityRules {
    /// Maximal allowed size of transaction's body in bytes.
    ///
    /// Transactions with larger body will be rejected. They still can be
    /// accepted by other shards and validated, so added to the blockchain.
    ///
    /// Default is `33554432` (32 MB).
    pub max_transaction_body_size: u64,

    /// Share pending transactions with other connected shards once new
    /// transaction is received.
    ///
    /// Default is `true`. Disabling it will result in worse overall network
    /// quality.
    pub spread_pending_transactions: bool,

    /// Share pending blocks with other connected shards once new block is
    /// received.
    ///
    /// Default is `true`. Disabling it will result in worse overall network
    /// quality.
    pub spread_pending_blocks: bool,

    /// Share approvals for pending blocks with other connected shards once
    /// new approval is received.
    ///
    /// Default is `true`. Disabling it will result in worse overall network
    /// quality.
    pub spread_pending_blocks_approvals: bool,

    /// Accept shards which were announced using the `PUT /api/v1/shards`
    /// request.
    ///
    /// Default is `true`. Disabling it will result in worse overall network
    /// quality.
    pub accept_shards: bool,

    /// Optional filter function which will be applied to the pending
    /// transactions before adding them to the pool. If `true` is returned
    /// by such function then transaction is accepted, otherwise it will be
    /// dropped.
    ///
    /// This function is useful for applications with custom transaction
    /// formats and rules to filter out malicious or invalid transactions.
    ///
    /// Default is `None`.
    pub transactions_filter: Option<fn(&Transaction, &PublicKey) -> bool>,

    /// Optional filter function which will be applied to the pending blocks
    /// before adding them to the pool. If `true` is returned by such function
    /// then block is accepted, otherwise it will be dropped.
    ///
    /// This function is useful for applications with custom transaction
    /// formats and rules to filter out blocks with malicious or invalid
    /// transactions.
    ///
    /// Default is `None`.
    pub blocks_filter: Option<fn(&Block, &Hash, &PublicKey) -> bool>
}

impl Default for ShardSecurityRules {
    fn default() -> Self {
        Self {
            max_transaction_body_size: 32 * 1024 * 1024,
            spread_pending_transactions: true,
            spread_pending_blocks: true,
            spread_pending_blocks_approvals: true,
            accept_shards: true,
            transactions_filter: None,
            blocks_filter: None
        }
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, PartialEq, Eq)]
enum ShardEvent {
    SharePendingTransaction(Hash),
    SharePendingBlock(Hash),
    SharePendingBlockApproval(Hash, Signature)
}

#[derive(Clone)]
struct ShardState<S: Storage> {
    pub client: Arc<RwLock<Client>>,
    pub storage: Arc<Mutex<S>>,
    pub security_rules: ShardSecurityRules,
    pub pending_transactions: Arc<RwLock<HashMap<[u8; 32], Transaction>>>,
    pub pending_blocks: Arc<RwLock<HashMap<[u8; 32], Block>>>,
    pub events_sender: Arc<UnboundedSender<ShardEvent>>
}

pub async fn serve<S>(shard: Shard<S>) -> Result<(), Error>
where
    S: Storage + Clone + Send + 'static,
    S::Error: Send
{
    #[cfg(feature = "tracing")]
    tracing::info!("bootstrapping shard connections");

    // TODO

    #[cfg(feature = "tracing")]
    tracing::info!("reading local blockchain data");

    let first_block = shard.storage.read_first_block()
        .map_err(|err| Error::Storage(err.to_string()))?
        .map(|block| block.hash())
        .transpose()
        .map_err(|err| Error::Storage(err.to_string()))?
        .map(|hash| hash.to_base64());

    let last_block = shard.storage.read_last_block()
        .map_err(|err| Error::Storage(err.to_string()))?
        .map(|block| block.hash())
        .transpose()
        .map_err(|err| Error::Storage(err.to_string()))?
        .map(|hash| hash.to_base64());

    #[cfg(feature = "tracing")]
    tracing::info!(
        ?first_block,
        ?last_block,
        "synchronizing local blockchain storage"
    );

    shard.client.sync(&shard.storage).await?;

    #[cfg(feature = "tracing")]
    tracing::info!(
        local_address = ?shard.local_address,
        remote_address = ?shard.remote_address,
        "starting shard HTTP API server"
    );

    let (events_sender, _events_listener) = tokio::sync::mpsc::unbounded_channel();

    let router = Router::new()
        .route("/api/v1/transactions", get(transactions_api::get_transactions))
        .route("/api/v1/transactions", put(transactions_api::put_transactions))
        .route("/api/v1/transactions/{hash}", get(transactions_api::get_transactions_hash))
        .route("/api/v1/blocks", get(blocks_api::get_blocks))
        .route("/api/v1/blocks", put(blocks_api::put_blocks))
        .route("/api/v1/blocks/{hash}", get(blocks_api::get_blocks_hash))
        .route("/api/v1/blocks/{hash}", put(blocks_api::put_blocks_hash))
        .route("/api/v1/shards", get(shards_api::get_shards))
        .route("/api/v1/shards", put(shards_api::put_shards))
        .with_state(ShardState {
            client: Arc::new(RwLock::new(shard.client)),
            storage: Arc::new(Mutex::new(shard.storage)),
            security_rules: shard.security_rules,
            pending_transactions: Default::default(),
            pending_blocks: Default::default(),
            events_sender: Arc::new(events_sender)
        });

    let listener = TcpListener::bind(shard.local_address).await?;

    axum::serve(listener, router).await?;

    Ok(())
}
