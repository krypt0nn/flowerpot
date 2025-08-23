use std::net::SocketAddr;
use std::sync::Arc;
use std::collections::{HashMap, HashSet};
use std::time::Duration;

use futures::TryFutureExt;

use tokio::net::TcpListener;
use tokio::sync::{RwLock, Mutex};
use tokio::sync::mpsc::{UnboundedSender, UnboundedReceiver};
use tokio::runtime::Handle as RuntimeHandle;

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

    #[error(transparent)]
    Tokio(#[from] tokio::task::JoinError),

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

    /// Automatically merge blocks to the local storage if they have enough
    /// approvals. Otherwise merging will happen only in the blockchain
    /// synchronization task.
    ///
    /// Default is `true`.
    pub merge_blocks_without_sync: bool,

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
    pub blocks_filter: Option<fn(&Block, &Hash, &PublicKey) -> bool>,

    /// Interval between pending transactions polling from other connected
    /// shards. This will request list of pending transactions from all the
    /// connected shards and request all the unknown pending transactions to
    /// always keep local pool updated.
    ///
    /// Note that is connected shards did not disable
    /// `spread_pending_transactions` option then our local pool will keep
    /// being updates on its own, so this interval should not be very low.
    /// You can keep it large enough to not to overload the network.
    ///
    /// Default is `20s`.
    pub pending_transactions_sync_interval: Duration,

    /// Interval between pending blocks polling from other connected shards.
    /// This will request list of pending blocks from all the connected shards
    /// and request all the unknown pending transactions to always keep local
    /// pool updated.
    ///
    /// Note that is connected shards did not disable `spread_pending_blocks`
    /// option then our local pool will keep being updates on its own, so this
    /// interval should not be very low. You can keep it large enough to not to
    /// overload the network.
    ///
    /// Default is `30s`.
    pub pending_blocks_sync_interval: Duration,

    /// Interval between blockchain synchronization attempts between our local
    /// storage and all the connected shards.
    ///
    /// Note that in normal situation pending blocks should be merged to the
    /// local storage automatically once enough approvals are received. This
    /// task exist in case some block was not received yet or if it got more
    /// approvals than our currently written one, so just in case.
    ///
    /// Default is `90s`.
    pub blockchain_sync_interval: Duration
}

impl Default for ShardSecurityRules {
    fn default() -> Self {
        Self {
            max_transaction_body_size: 32 * 1024 * 1024,
            spread_pending_transactions: true,
            spread_pending_blocks: true,
            spread_pending_blocks_approvals: true,
            accept_shards: true,
            merge_blocks_without_sync: true,
            transactions_filter: None,
            blocks_filter: None,
            pending_transactions_sync_interval: Duration::from_secs(20),
            pending_blocks_sync_interval: Duration::from_secs(30),
            blockchain_sync_interval: Duration::from_secs(90)
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

/// This function runs many background async tasks at once so multi-thread
/// executor is highly adviced.
pub async fn serve<S>(
    shard: Shard<S>,
    handle: RuntimeHandle
) -> Result<(), Error>
where
    S: Storage + Clone + Send + Sync + 'static,
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

    let (events_sender, events_listener) = tokio::sync::mpsc::unbounded_channel();

    let mut reverse_client = shard.client.clone();

    reverse_client.with_shards([
        format!("http://{}", shard.local_address)
    ]).await?;

    let reverse_client = Arc::new(RwLock::new(reverse_client));

    let client = Arc::new(RwLock::new(shard.client));
    let storage = Arc::new(Mutex::new(shard.storage));
    let pending_transactions = Arc::new(RwLock::new(HashMap::new()));
    let pending_blocks = Arc::new(RwLock::new(HashMap::new()));

    let transactions_sync_interval = shard.security_rules.pending_transactions_sync_interval;
    let blocks_sync_interval = shard.security_rules.pending_blocks_sync_interval;
    let blockchain_sync_interval = shard.security_rules.blockchain_sync_interval;

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
            client: client.clone(),
            storage: storage.clone(),
            security_rules: shard.security_rules,
            pending_transactions: pending_transactions.clone(),
            pending_blocks: pending_blocks.clone(),
            events_sender: Arc::new(events_sender)
        });

    let listener = TcpListener::bind(shard.local_address).await?;

    let results = futures::future::try_join_all([
        // Shard HTTP API server.
        handle.spawn(axum::serve(listener, router)
            .into_future()
            .map_err(Error::from)),

        // Shard events handler.
        handle.spawn(handle_events(
            events_listener,
            client.clone(),
            pending_transactions.clone(),
            pending_blocks.clone()
        )),

        // Pending transactions sync.
        handle.spawn(sync_pending_transactions(
            client.clone(),
            reverse_client.clone(),
            pending_transactions,
            transactions_sync_interval
        )),

        // Pending blocks sync.
        handle.spawn(sync_pending_blocks(
            client.clone(),
            reverse_client,
            pending_blocks,
            blocks_sync_interval
        )),

        // Sync blockchain.
        handle.spawn(sync_blockchain(
            client,
            storage,
            blockchain_sync_interval
        ))
    ]).await?;

    for result in results {
        result?;
    }

    Ok(())
}

async fn handle_events(
    mut events_listener: UnboundedReceiver<ShardEvent>,
    client: Arc<RwLock<Client>>,
    pending_transactions: Arc<RwLock<HashMap<[u8; 32], Transaction>>>,
    pending_blocks: Arc<RwLock<HashMap<[u8; 32], Block>>>
) -> Result<(), Error> {
    while let Some(event) = events_listener.recv().await {
        #[cfg(feature = "tracing")]
        tracing::debug!(?event, "processing shard event");

        match event {
            ShardEvent::SharePendingTransaction(hash) => {
                let transaction = pending_transactions.read().await
                    .get(&hash.0)
                    .cloned();

                if let Some(transaction) = transaction {
                    let result = client.read().await
                        .announce_transaction(&transaction).await;

                    if let Err(err) = result {
                        #[cfg(feature = "tracing")]
                        tracing::error!(
                            hash = hash.to_base64(),
                            ?err,
                            "failed to share pending transaction"
                        );
                    }
                }
            }

            ShardEvent::SharePendingBlock(hash) => {
                let block = pending_blocks.read().await
                    .get(&hash.0)
                    .cloned();

                if let Some(block) = block {
                    let result = client.read().await
                        .announce_block(&block).await;

                    if let Err(err) = result {
                        #[cfg(feature = "tracing")]
                        tracing::error!(
                            hash = hash.to_base64(),
                            ?err,
                            "failed to share pending block"
                        );
                    }
                }
            }

            ShardEvent::SharePendingBlockApproval(hash, sign) => {
                let result = client.read().await
                    .approve_block(&hash, &sign).await;

                if let Err(err) = result {
                    #[cfg(feature = "tracing")]
                    tracing::error!(
                        hash = hash.to_base64(),
                        sign = sign.to_base64(),
                        ?err,
                        "failed to share pending block approval"
                    );
                }
            }
        }
    }

    Ok(())
}

async fn sync_pending_transactions(
    client: Arc<RwLock<Client>>,
    reverse_client: Arc<RwLock<Client>>,
    pending_transactions: Arc<RwLock<HashMap<[u8; 32], Transaction>>>,
    sync_interval: Duration
) -> Result<(), Error> {
    loop {
        let transactions = pending_transactions.read().await
            .keys()
            .map(|hash| Hash::from(*hash))
            .collect::<HashSet<Hash>>();

        let client_guard = client.read().await;

        let result = client_guard.list_pending_transactions().await;

        match result {
            Ok(result) => {
                let reverse_client_guard = reverse_client.read().await;

                for hash in result {
                    if !transactions.contains(&hash) {
                        match client_guard.read_transaction(&hash).await {
                            Ok(Some(transaction)) => {
                                // Use reverse client to not to perform the same verification
                                // steps here again.
                                if let Err(err) = reverse_client_guard.announce_transaction(&transaction).await {
                                    #[cfg(feature = "tracing")]
                                    tracing::error!(
                                        ?err,
                                        hash = hash.to_base64(),
                                        "failed to sync pending transaction using reverse client"
                                    );
                                }
                            }

                            Ok(None) => (),

                            Err(err) => {
                                #[cfg(feature = "tracing")]
                                tracing::error!(
                                    ?err,
                                    hash = hash.to_base64(),
                                    "failed to request pending transaction"
                                );
                            }
                        }
                    }
                }

                drop(reverse_client_guard);
            }

            Err(err) => {
                #[cfg(feature = "tracing")]
                tracing::error!(
                    ?err,
                    "failed to request list of pending transactions"
                );
            }
        }

        drop(client_guard);

        tokio::time::sleep(sync_interval).await;
    }
}

async fn sync_pending_blocks(
    client: Arc<RwLock<Client>>,
    reverse_client: Arc<RwLock<Client>>,
    pending_blocks: Arc<RwLock<HashMap<[u8; 32], Block>>>,
    sync_interval: Duration
) -> Result<(), Error> {
    loop {
        let blocks = pending_blocks.read().await
            .keys()
            .map(|hash| Hash::from(*hash))
            .collect::<HashSet<Hash>>();

        let client_guard = client.read().await;

        let result = client_guard.list_pending_blocks().await;

        match result {
            Ok(result) => {
                let reverse_client_guard = reverse_client.read().await;

                for pending_block in result {
                    if !blocks.contains(&pending_block.block) {
                        match client_guard.read_block(&pending_block.block).await {
                            Ok(Some(block)) => {
                                // Use reverse client to not to perform the same verification
                                // steps here again.
                                if let Err(err) = reverse_client_guard.announce_block(&block).await {
                                    #[cfg(feature = "tracing")]
                                    tracing::error!(
                                        ?err,
                                        "failed to sync pending block using reverse client"
                                    );
                                }
                            }

                            Ok(None) => (),

                            Err(err) => {
                                #[cfg(feature = "tracing")]
                                tracing::error!(
                                    ?err,
                                    ?pending_block,
                                    "failed to request pending block"
                                );
                            }
                        }
                    }
                }

                drop(reverse_client_guard);
            }

            Err(err) => {
                #[cfg(feature = "tracing")]
                tracing::error!(
                    ?err,
                    "failed to request list of pending blocks"
                );
            }
        }

        drop(client_guard);

        tokio::time::sleep(sync_interval).await;
    }
}

async fn sync_blockchain<S: Storage>(
    client: Arc<RwLock<Client>>,
    storage: Arc<Mutex<S>>,
    sync_interval: Duration
) -> Result<(), Error> {
    loop {
        let guard = storage.lock().await;

        client.read().await
            .sync(&*guard).await?;

        drop(guard);

        tokio::time::sleep(sync_interval).await;
    }
}
