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
use crate::block::{Block, BlockContent, BlockStatus};
use crate::storage::Storage;
use crate::client::{Client, Error as ClientError};
use crate::pool::ShardsPool;

mod transactions_api;
mod blocks_api;
mod sync_api;
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

    /// Active/inactive shards pool.
    pub shards: ShardsPool,

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
    pub transactions_filter: Option<fn(&Transaction, &Hash, &PublicKey) -> bool>,

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

    /// Amount of time between shards activity checks. This is needed to keep
    /// active shards pool in good quality.
    ///
    /// Default is `3m`.
    pub shards_heartbeat_interval: Duration,

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
    /// Default is `10s`.
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
    /// Default is `20s`.
    pub pending_blocks_sync_interval: Duration,

    /// Interval between blockchain synchronization attempts between our local
    /// storage and all the connected shards.
    ///
    /// Note that unless `merge_blocks_without_sync` option is disabled pending
    /// blocks should be merged to the local storage automatically once enough
    /// approvals are received. This task exist in case some block was not
    /// received yet or if it got more approvals than our currently written one,
    /// so just in case.
    ///
    /// Default is `60s`.
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
            transactions_filter: None,
            blocks_filter: None,
            shards_heartbeat_interval: Duration::from_secs(3 * 60),
            pending_transactions_sync_interval: Duration::from_secs(10),
            pending_blocks_sync_interval: Duration::from_secs(20),
            blockchain_sync_interval: Duration::from_secs(60)
        }
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, PartialEq, Eq)]
enum ShardEvent {
    /// Try to put provided transaction to the pending transactions pool.
    ///
    /// This transaction **is not verified** yet, verification must happen in
    /// background thread which processes events.
    ///
    /// Generated by `PUT /api/v1/transactions` request.
    TryPutTransaction(Transaction),

    /// Try to put provided block to the pending blocks pool.
    ///
    /// This block **is not verified** yet, verification must happen in
    /// background thread which processes events.
    ///
    /// Generated by `PUT /api/v1/blocks` request.
    TryPutBlock(Block),

    /// Try to add provided block approval to a block.
    ///
    /// This approval **is not verified** yet, verification must happen in
    /// background thread which processes events.
    ///
    /// Generated by `PUT /api/v1/blocks/<hash>` request.
    TryApproveBlock(Hash, Signature),

    /// `PUT /api/v1/transactions`
    ShareTransaction(Transaction),

    /// `PUT /api/v1/blocks`
    ShareBlock(Block),

    /// `PUT /api/v1/blocks/<hash>`
    ShareBlockApproval(Hash, Signature)
}

#[derive(Clone)]
struct ShardState<S: Storage> {
    pub shards: Arc<RwLock<ShardsPool>>,
    pub storage: Arc<Mutex<S>>,
    pub security_rules: Arc<ShardSecurityRules>,
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

    // TODO
    // shard.client.sync(&shard.storage).await?;

    #[cfg(feature = "tracing")]
    tracing::info!(
        local_address = ?shard.local_address,
        remote_address = ?shard.remote_address,
        "starting shard HTTP API server"
    );

    let (events_sender, events_listener) = tokio::sync::mpsc::unbounded_channel();

    let events_sender = Arc::new(events_sender);

    let client = Arc::new(RwLock::new(shard.client));
    let shards = Arc::new(RwLock::new(shard.shards));
    let storage = Arc::new(Mutex::new(shard.storage));
    let security_rules = Arc::new(shard.security_rules);

    let pending_transactions = Arc::new(RwLock::new(HashMap::new()));
    let pending_blocks = Arc::new(RwLock::new(HashMap::new()));

    let shards_heartbeat_interval = security_rules.shards_heartbeat_interval;
    let transactions_sync_interval = security_rules.pending_transactions_sync_interval;
    let blocks_sync_interval = security_rules.pending_blocks_sync_interval;

    let router = Router::new()
        .route("/api/v1/heartbeat", get(async || (axum::http::StatusCode::OK, "")))
        .route("/api/v1/transactions", get(transactions_api::get_transactions))
        .route("/api/v1/transactions", put(transactions_api::put_transactions))
        .route("/api/v1/transactions/{hash}", get(transactions_api::get_transactions_hash))
        .route("/api/v1/blocks", get(blocks_api::get_blocks))
        .route("/api/v1/blocks", put(blocks_api::put_blocks))
        .route("/api/v1/blocks/{hash}", get(blocks_api::get_blocks_hash))
        .route("/api/v1/blocks/{hash}", put(blocks_api::put_blocks_hash))
        .route("/api/v1/sync", get(sync_api::get_sync))
        .route("/api/v1/shards", get(shards_api::get_shards))
        .route("/api/v1/shards", put(shards_api::put_shards))
        .with_state(ShardState {
            shards: shards.clone(),
            storage: storage.clone(),
            security_rules: security_rules.clone(),
            pending_transactions: pending_transactions.clone(),
            pending_blocks: pending_blocks.clone(),
            events_sender: events_sender.clone()
        });

    let listener = TcpListener::bind(shard.local_address).await?;

    let results = futures::future::try_join_all([
        // Shard HTTP API server.
        handle.spawn(axum::serve(listener, router)
            .into_future()
            .map_err(Error::from)),

        // Shard events handler.
        handle.spawn(handle_events(
            events_sender.clone(),
            events_listener,
            client.clone(),
            shards.clone(),
            storage.clone(),
            security_rules,
            pending_transactions.clone(),
            pending_blocks.clone()
        )),

        // Update shards pool.
        handle.spawn(update_shards_pool(
            client.clone(),
            shards.clone(),
            shards_heartbeat_interval
        )),

        // Pending transactions sync.
        handle.spawn(sync_pending_transactions(
            events_sender.clone(),
            client.clone(),
            shards.clone(),
            pending_transactions,
            transactions_sync_interval
        )),

        // Pending blocks sync.
        handle.spawn(sync_pending_blocks(
            events_sender,
            client,
            shards,
            pending_blocks,
            blocks_sync_interval
        )),

        // Sync blockchain.
        // handle.spawn(sync_blockchain(
        //     client,
        //     storage,
        //     blockchain_sync_interval
        // ))
    ]).await?;

    for result in results {
        result?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_events<S: Storage>(
    events_sender: Arc<UnboundedSender<ShardEvent>>,
    mut events_listener: UnboundedReceiver<ShardEvent>,
    client: Arc<RwLock<Client>>,
    shards: Arc<RwLock<ShardsPool>>,
    storage: Arc<Mutex<S>>,
    security_rules: Arc<ShardSecurityRules>,
    pending_transactions: Arc<RwLock<HashMap<[u8; 32], Transaction>>>,
    pending_blocks: Arc<RwLock<HashMap<[u8; 32], Block>>>
) -> Result<(), Error> {
    // TODO: consider using tokio's runtime handle to spawn new tasks instead
    //       of processing them directly there.

    while let Some(event) = events_listener.recv().await {
        #[cfg(feature = "tracing")]
        tracing::debug!(?event, "processing shard event");

        match event {
            ShardEvent::TryPutTransaction(transaction) => {
                if transaction.data.len() as u64 > security_rules.max_transaction_body_size {
                    #[cfg(feature = "tracing")]
                    tracing::warn!(
                        hash = transaction.hash().to_base64(),
                        sign = transaction.sign().to_base64(),
                        size = transaction.data.len(),
                        "rejecting transaction because it's too large"
                    );

                    continue;
                }

                let (is_valid, hash, public_key) = match transaction.verify() {
                    Ok(result) => result,
                    Err(err) => {
                        #[cfg(feature = "tracing")]
                        tracing::error!(?err, "failed to verify transaction");

                        continue;
                    }
                };

                if !is_valid {
                    #[cfg(feature = "tracing")]
                    tracing::warn!(
                        hash = hash.to_base64(),
                        public_key = public_key.to_base64(),
                        "received invalid transaction"
                    );

                    continue;
                }

                if let Some(filter) = &security_rules.transactions_filter
                    && !filter(&transaction, &hash, &public_key)
                {
                    #[cfg(feature = "tracing")]
                    tracing::warn!(
                        hash = hash.to_base64(),
                        public_key = public_key.to_base64(),
                        "filter rejected received transaction"
                    );

                    continue;
                }

                // TODO: check that this transaction is not yet stored
                //       in the blockchain

                pending_transactions.write().await
                    .insert(hash.0, transaction.clone());

                // Create the event to share this block with other shards.
                if security_rules.spread_pending_transactions
                    && events_sender.send(ShardEvent::ShareTransaction(transaction)).is_err()
                {
                    #[cfg(feature = "tracing")]
                    tracing::error!("events handler is down");
                }
            }

            ShardEvent::TryPutBlock(mut block) => {
                let (hash, public_key) = match block.verify() {
                    Ok((true, hash, public_key)) => (hash, public_key),

                    Ok((false, hash, public_key)) => {
                        #[cfg(feature = "tracing")]
                        tracing::warn!(
                            hash = hash.to_base64(),
                            public_key = public_key.to_base64(),
                            "received invalid block"
                        );

                        continue;
                    }

                    Err(err) => {
                        #[cfg(feature = "tracing")]
                        tracing::error!(?err, "failed to verify block");

                        continue;
                    }
                };

                if let Some(filter) = &security_rules.blocks_filter
                    && !filter(&block, &hash, &public_key)
                {
                    #[cfg(feature = "tracing")]
                    tracing::warn!(
                        hash = hash.to_base64(),
                        public_key = public_key.to_base64(),
                        "filter rejected received block"
                    );

                    continue;
                }

                let storage_guard = storage.lock().await;

                // Ignore the block if its parent is not known to the local
                // blockchain storage.
                match storage_guard.has_block(block.previous()) {
                    Ok(true) => (),

                    Ok(false) => {
                        #[cfg(feature = "tracing")]
                        tracing::warn!(
                            hash = hash.to_base64(),
                            public_key = public_key.to_base64(),
                            "attempted to put a block with no stored parent"
                        );

                        continue;
                    }

                    Err(err) => {
                        #[cfg(feature = "tracing")]
                        tracing::error!(
                            hash = hash.to_base64(),
                            public_key = public_key.to_base64(),
                            ?err,
                            "failed to verify if block's parent is stored in the local blockchain"
                        );

                        continue;
                    }
                }

                // Obtain list of current blockchain validators.
                let validators = match storage_guard.get_current_validators() {
                    Ok(validators) => validators,
                    Err(err) => {
                        #[cfg(feature = "tracing")]
                        tracing::error!(
                            ?err,
                            "failed to get list of current blockchain validators"
                        );

                        continue;
                    }
                };

                // Check the block's approval status. If block with the same
                // hash is already stored in the pending blocks list then we
                // will merge its approvals with the received ones in case we
                // have more approvals than in received block.
                let mut approvals = pending_blocks.read().await
                    .get(&hash.0)
                    .map(|block| block.approvals().to_vec())
                    .unwrap_or_default();

                approvals.extend_from_slice(block.approvals());
                approvals.dedup();

                let status = BlockStatus::validate(
                    hash,
                    public_key.clone(),
                    &approvals,
                    &validators
                );

                match status {
                    Ok(BlockStatus::Approved { approvals, .. }) => {
                        #[cfg(feature = "tracing")]
                        tracing::info!(
                            hash = hash.to_base64(),
                            public_key = public_key.to_base64(),
                            "block is already approved, storing it to the local blockchain storage"
                        );

                        // Keep only valid approvals.
                        block.approvals = approvals.into_iter()
                            .map(|(approval, _)| approval)
                            .collect();

                        if let Err(err) = storage_guard.write_block(&block) {
                            #[cfg(feature = "tracing")]
                            tracing::error!(
                                hash = hash.to_base64(),
                                public_key = public_key.to_base64(),
                                ?err,
                                "failed to store block to the local blockchain storage"
                            );

                            continue;
                        }

                        // If the merged block is of transactions type then we
                        // should iterate over them and remove them from the
                        // pending transactions list if there's any.
                        if let BlockContent::Transactions(transactions) = block.content() {
                            let mut guard = pending_transactions.write().await;

                            for transaction in transactions {
                                guard.remove(&transaction.hash().0);
                            }

                            drop(guard);
                        }
                    }

                    Ok(BlockStatus::NotApproved { approvals, .. }) => {
                        #[cfg(feature = "tracing")]
                        tracing::info!(
                            hash = hash.to_base64(),
                            public_key = public_key.to_base64(),
                            "block is stored in the pending blocks list"
                        );

                        // Keep only valid approvals.
                        block.approvals = approvals.into_iter()
                            .map(|(approval, _)| approval)
                            .collect();

                        // Put the block into the pending blocks list.
                        pending_blocks.write().await
                            .insert(hash.0, block.clone());

                        // Create the event to share this block with other shards.
                        if security_rules.spread_pending_blocks
                            && events_sender.send(ShardEvent::ShareBlock(block)).is_err()
                        {
                            #[cfg(feature = "tracing")]
                            tracing::error!("events handler is down");
                        }
                    }

                    Ok(BlockStatus::Invalid) => {
                        #[cfg(feature = "tracing")]
                        tracing::warn!(
                            hash = hash.to_base64(),
                            public_key = public_key.to_base64(),
                            "attempted to put invalid block"
                        );
                    }

                    Err(err) => {
                        #[cfg(feature = "tracing")]
                        tracing::error!(
                            hash = hash.to_base64(),
                            public_key = public_key.to_base64(),
                            ?err,
                            "failed to validate received block status"
                        );
                    }
                }
            }

            ShardEvent::TryApproveBlock(hash, approval) => {
                let public_key = match approval.verify(hash) {
                    Ok((true, public_key)) => public_key,

                    Ok((false, public_key)) => {
                        #[cfg(feature = "tracing")]
                        tracing::warn!(
                            hash = hash.to_base64(),
                            approval = approval.to_base64(),
                            public_key = public_key.to_base64(),
                            "received invalid approval"
                        );

                        continue;
                    }

                    Err(err) => {
                        #[cfg(feature = "tracing")]
                        tracing::error!(
                            hash = hash.to_base64(),
                            approval = approval.to_base64(),
                            ?err,
                            "failed to verify received approval"
                        );

                        continue;
                    }
                };

                // First check the pending blocks list because we expect
                // approval to be sent for one of such blocks.
                let mut pending_blocks_guard = pending_blocks.write().await;

                match pending_blocks_guard.get_mut(&hash.0) {
                    // The block we're working with is pending so we need to
                    // add approval to it if it's valid, and then, if this
                    // approval was the final one according to 2/3 rule, we
                    // need to merge the block to the local blockchain storage.
                    Some(block) => {
                        // I feel like this can be invalid but eeh..
                        if block.sign() == &approval {
                            #[cfg(feature = "tracing")]
                            tracing::warn!(
                                hash = hash.to_base64(),
                                approval = approval.to_base64(),
                                "attempted to self-approve a block"
                            );

                            continue;
                        }

                        // If block doesn't have this approval yet.
                        if !block.approvals.contains(&approval) {
                            let storage_guard = storage.lock().await;

                            // Get list of current validators.
                            let validators = match storage_guard.get_current_validators() {
                                Ok(validators) => validators,
                                Err(err) => {
                                    #[cfg(feature = "tracing")]
                                    tracing::error!(
                                        hash = hash.to_base64(),
                                        ?err,
                                        "failed to get block validators list"
                                    );

                                    continue;
                                }
                            };

                            // Reject approval if it's not made by a real validator.
                            if !validators.contains(&public_key) {
                                #[cfg(feature = "tracing")]
                                tracing::warn!(
                                    hash = hash.to_base64(),
                                    approval = approval.to_base64(),
                                    "attempted to approve pending block with invalid validator"
                                );

                                continue;
                            }

                            // Add it to the block.
                            block.approvals.push(approval.clone());

                            // Approval is valid so we can share it with other
                            // shards.
                            if security_rules.spread_pending_blocks_approvals
                                && events_sender.send(ShardEvent::ShareBlockApproval(hash, approval)).is_err()
                            {
                                #[cfg(feature = "tracing")]
                                tracing::error!("events handler is down");
                            }

                            // Check status of the block.
                            let status = BlockStatus::validate(
                                hash,
                                public_key.clone(),
                                block.approvals(),
                                &validators
                            );

                            // If the block is approved (it now has enough validators)
                            // then we write it to the local blockchain storage.
                            match status {
                                Ok(BlockStatus::Approved { approvals, .. }) => {
                                    #[cfg(feature = "tracing")]
                                    tracing::info!(
                                        hash = hash.to_base64(),
                                        public_key = public_key.to_base64(),
                                        "pending block is approved now, storing it to the local blockchain storage"
                                    );

                                    // Keep only valid approvals.
                                    block.approvals = approvals.into_iter()
                                        .map(|(approval, _)| approval)
                                        .collect();

                                    if let Err(err) = storage_guard.write_block(block) {
                                        #[cfg(feature = "tracing")]
                                        tracing::error!(
                                            hash = hash.to_base64(),
                                            public_key = public_key.to_base64(),
                                            ?err,
                                            "failed to store pending block to the local blockchain storage"
                                        );

                                        continue;
                                    }

                                    // If the merged block is of transactions
                                    // type then we should iterate over them and
                                    // remove them from the pending transactions
                                    // list if there's any.
                                    if let BlockContent::Transactions(transactions) = block.content() {
                                        let mut guard = pending_transactions.write().await;

                                        for transaction in transactions {
                                            guard.remove(&transaction.hash().0);
                                        }

                                        drop(guard);
                                    }

                                    // Remove this block from the pending blocks list.
                                    pending_blocks_guard.remove(&hash.0);
                                }

                                Ok(_) => (),

                                Err(err) => {
                                    #[cfg(feature = "tracing")]
                                    tracing::error!(
                                        hash = hash.to_base64(),
                                        public_key = public_key.to_base64(),
                                        ?err,
                                        "failed to validate updated pending block status"
                                    );
                                }
                            }

                            drop(storage_guard);
                        }
                    }

                    // Otherwise the block is either already stored, means it's
                    // already approved, or unknown. If it's already stored then
                    // we only need to add approval to that block to increase
                    // its weight over other potential blocks which would try to
                    // overwrite the history. If it's unknown then we just
                    // ignore this approval.
                    None => {
                        let storage_guard = storage.lock().await;

                        let mut block = match storage_guard.read_block(&hash) {
                            Ok(Some(block)) => block,

                            Ok(None) => {
                                #[cfg(feature = "tracing")]
                                tracing::warn!(
                                    hash = hash.to_base64(),
                                    approval = approval.to_base64(),
                                    "attempted to approve non-existing block"
                                );

                                continue;
                            }

                            Err(err) => {
                                #[cfg(feature = "tracing")]
                                tracing::error!(
                                    hash = hash.to_base64(),
                                    ?err,
                                    "failed to read block from the local blockchain storage"
                                );

                                continue;
                            }
                        };

                        // I feel like this can be invalid but eeh..
                        if block.sign() == &approval {
                            #[cfg(feature = "tracing")]
                            tracing::warn!(
                                hash = hash.to_base64(),
                                approval = approval.to_base64(),
                                "attempted to self-approve a block"
                            );

                            continue;
                        }

                        // If block doesn't have this approval yet.
                        if !block.approvals.contains(&approval) {
                            // Get list of validators for this block.
                            let validators = match storage_guard.get_validators_before_block(&hash) {
                                Ok(validators) => validators,
                                Err(err) => {
                                    #[cfg(feature = "tracing")]
                                    tracing::error!(
                                        hash = hash.to_base64(),
                                        ?err,
                                        "failed to get block validators list"
                                    );

                                    continue;
                                }
                            };

                            // Reject approval if it's not made by a real validator.
                            if !validators.contains(&public_key) {
                                #[cfg(feature = "tracing")]
                                tracing::warn!(
                                    hash = hash.to_base64(),
                                    approval = approval.to_base64(),
                                    "attempted to approve already written block with invalid validator"
                                );

                                continue;
                            }

                            // Otherwise add it to the block.
                            block.approvals.push(approval.clone());

                            // Approval is valid so we can share it with other
                            // shards.
                            if security_rules.spread_pending_blocks_approvals
                                && events_sender.send(ShardEvent::ShareBlockApproval(hash, approval)).is_err()
                            {
                                #[cfg(feature = "tracing")]
                                tracing::error!("events handler is down");
                            }

                            // Write updated block back to the storage.
                            if let Err(err) = storage_guard.write_block(&block) {
                                #[cfg(feature = "tracing")]
                                tracing::error!(
                                    hash = hash.to_base64(),
                                    ?err,
                                    "failed to write updated block to the local blockchain storage"
                                );

                                continue;
                            }
                        }

                        drop(storage_guard);
                    }
                }

                drop(pending_blocks_guard);
            }

            ShardEvent::ShareTransaction(transaction) => {
                let result = client.read().await
                    .put_transaction(
                        shards.read().await.active(),
                        &transaction
                    ).await;

                if let Err(err) = result {
                    #[cfg(feature = "tracing")]
                    tracing::error!(?err, "failed to share transaction");
                }
            }

            ShardEvent::ShareBlock(block) => {
                let result = client.read().await
                    .put_block(
                        shards.read().await.active(),
                        &block
                    ).await;

                if let Err(err) = result {
                    #[cfg(feature = "tracing")]
                    tracing::error!(?err, "failed to share block");
                }
            }

            ShardEvent::ShareBlockApproval(hash, sign) => {
                let result = client.read().await
                    .approve_block(
                        shards.read().await.active(),
                        &hash,
                        &sign
                    ).await;

                if let Err(err) = result {
                    #[cfg(feature = "tracing")]
                    tracing::error!(
                        hash = hash.to_base64(),
                        sign = sign.to_base64(),
                        ?err,
                        "failed to share block approval"
                    );
                }
            }
        }
    }

    Ok(())
}

async fn update_shards_pool(
    client: Arc<RwLock<Client>>,
    shards: Arc<RwLock<ShardsPool>>,
    interval: Duration
) -> Result<(), Error> {
    loop {
        let mut shards_guard = shards.write().await;
        let client_guard = client.read().await;

        shards_guard.update(&client_guard).await;

        drop(shards_guard);
        drop(client_guard);

        tokio::time::sleep(interval).await;
    }
}

async fn sync_pending_transactions(
    events_sender: Arc<UnboundedSender<ShardEvent>>,
    client: Arc<RwLock<Client>>,
    shards: Arc<RwLock<ShardsPool>>,
    pending_transactions: Arc<RwLock<HashMap<[u8; 32], Transaction>>>,
    sync_interval: Duration
) -> Result<(), Error> {
    loop {
        let mut transactions = pending_transactions.read().await
            .keys()
            .map(|hash| Hash::from(*hash))
            .collect::<HashSet<Hash>>();

        let client_guard = client.read().await;

        // TODO: I can technically do this in parallel.
        for address in shards.read().await.active() {
            let result = client_guard.get_transactions(address).await;

            match result {
                Ok(result) => {
                    for hash in result {
                        if !transactions.contains(&hash) {
                            match client_guard.read_transaction(address, &hash).await {
                                Ok(Some(transaction)) => {
                                    transactions.insert(hash);

                                    if events_sender.send(ShardEvent::TryPutTransaction(transaction)).is_err() {
                                        #[cfg(feature = "tracing")]
                                        tracing::error!("events handler is down");

                                        return Ok(());
                                    }
                                }

                                Ok(None) => (),

                                Err(err) => {
                                    #[cfg(feature = "tracing")]
                                    tracing::error!(
                                        hash = hash.to_base64(),
                                        ?address,
                                        ?err,
                                        "failed to request pending transaction"
                                    );
                                }
                            }
                        }
                    }
                }

                Err(err) => {
                    #[cfg(feature = "tracing")]
                    tracing::error!(
                        ?address,
                        ?err,
                        "failed to request list of pending transactions"
                    );
                }
            }
        }

        drop(client_guard);

        tokio::time::sleep(sync_interval).await;
    }
}

async fn sync_pending_blocks(
    events_sender: Arc<UnboundedSender<ShardEvent>>,
    client: Arc<RwLock<Client>>,
    shards: Arc<RwLock<ShardsPool>>,
    pending_blocks: Arc<RwLock<HashMap<[u8; 32], Block>>>,
    sync_interval: Duration
) -> Result<(), Error> {
    loop {
        let mut blocks = pending_blocks.read().await
            .keys()
            .map(|hash| Hash::from(*hash))
            .collect::<HashSet<Hash>>();

        let client_guard = client.read().await;

        // TODO: I can technically do this in parallel.
        for address in shards.read().await.active() {
            let result = client_guard.get_blocks(address).await;

            match result {
                Ok(result) => {
                    for pending_block in result {
                        if !blocks.contains(&pending_block.block) {
                            match client_guard.read_block(address, &pending_block.block).await {
                                Ok(Some(block)) => {
                                    blocks.insert(pending_block.block);

                                    if events_sender.send(ShardEvent::TryPutBlock(block)).is_err() {
                                        #[cfg(feature = "tracing")]
                                        tracing::error!("events handler is down");

                                        return Ok(());
                                    }
                                }

                                Ok(None) => (),

                                Err(err) => {
                                    #[cfg(feature = "tracing")]
                                    tracing::error!(
                                        ?pending_block,
                                        ?address,
                                        ?err,
                                        "failed to request pending block"
                                    );
                                }
                            }
                        }
                    }
                }

                Err(err) => {
                    #[cfg(feature = "tracing")]
                    tracing::error!(
                        ?address,
                        ?err,
                        "failed to request list of pending blocks"
                    );
                }
            }
        }

        drop(client_guard);

        tokio::time::sleep(sync_interval).await;
    }
}

// async fn sync_blockchain<S: Storage>(
//     client: Arc<RwLock<Client>>,
//     storage: Arc<Mutex<S>>,
//     sync_interval: Duration
// ) -> Result<(), Error> {
//     loop {
//         let guard = storage.lock().await;

//         client.read().await
//             .sync(&*guard).await?;

//         drop(guard);

//         tokio::time::sleep(sync_interval).await;
//     }
// }
