use std::net::SocketAddr;
use std::sync::Arc;
use std::collections::HashMap;

use tokio::net::TcpListener;
use tokio::sync::{RwLock, Mutex};

use axum::Router;
use axum::routing::{get, put};

use crate::transaction::Transaction;
use crate::block::Block;
use crate::storage::Storage;
use crate::client::Client;

mod transactions_api;
mod blocks_api;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ShardSecurityRules {
    /// Maximal allowed size of transaction's body in bytes.
    ///
    /// Transactions with larger body will be rejected. They still can be
    /// accepted by other shards and validated, so added to the blockchain.
    ///
    /// Default is `33554432` (32 MB).
    pub max_transaction_body_size: u64
}

impl Default for ShardSecurityRules {
    fn default() -> Self {
        Self {
            max_transaction_body_size: 32 * 1024 * 1024
        }
    }
}

#[derive(Clone)]
struct ShardState<S: Storage> {
    pub security_rules: ShardSecurityRules,
    pub storage: Arc<Mutex<S>>,
    pub pending_transactions: Arc<RwLock<HashMap<[u8; 32], Transaction>>>,
    pub pending_blocks: Arc<RwLock<HashMap<[u8; 32], Block>>>
}

pub async fn serve<S>(shard: Shard<S>) -> Result<(), Error>
where
    S: Storage + Clone + Send + 'static,
    S::Error: Send
{
    tracing::info!(
        local_address = ?shard.local_address,
        remote_address = ?shard.remote_address,
        "starting shard server"
    );

    let router = Router::new()
        .route("/api/v1/transactions", get(transactions_api::get_transactions))
        .route("/api/v1/transactions", put(transactions_api::put_transactions))
        .route("/api/v1/transactions/{hash}", get(transactions_api::get_transactions_hash))
        .route("/api/v1/blocks", get(blocks_api::get_blocks))
        .route("/api/v1/blocks", put(blocks_api::put_blocks))
        .route("/api/v1/blocks/{hash}", get(blocks_api::get_blocks_hash))
        .route("/api/v1/blocks/{hash}", put(blocks_api::put_blocks_hash))
        .with_state(ShardState {
            security_rules: shard.security_rules,
            storage: Arc::new(Mutex::new(shard.storage)),
            pending_transactions: Default::default(),
            pending_blocks: Default::default()
        });

    let listener = TcpListener::bind(shard.local_address).await?;

    axum::serve(listener, router).await?;

    Ok(())
}
