use std::collections::{HashMap, HashSet};
use std::time::{Instant, Duration};

use futures::FutureExt;

use crate::crypto::*;
use crate::transaction::Transaction;
use crate::block::{Block, BlockContent, Error as BlockError};
use crate::client::{Client, Error as ClientError};
use crate::pool::ShardsPool;
use crate::viewer::Viewer;
use crate::security::SecurityRules;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Client(#[from] ClientError),

    #[error("shards pool is empty")]
    ShardsPoolEmpty,

    #[error("shards pool has no valid shards")]
    NoValidShards,

    #[error("failed to create new block: {0}")]
    CreateBlock(#[source] BlockError),

    #[error("failed to create block approval: {0}")]
    ApproveBlock(#[source] k256::ecdsa::Error)
}

#[derive(Debug, Clone)]
pub struct Validator {
    /// Client used to perform API requests to shards.
    pub client: Client,

    /// Active/inactive shards pool.
    pub shards: ShardsPool,

    /// Validator secret key used to sign new blocks.
    pub secret_key: SecretKey,

    /// Security rules.
    pub security_rules: SecurityRules,

    /// Rules used to perform blocks validation.
    pub settings: ValidatorSettings
}

#[derive(Debug, Clone)]
pub struct ValidatorSettings {
    /// Minimal amount of transactions to create a new block.
    ///
    /// Higher number of transactions within a single block means better space
    /// usage due to built-in block compression and better network utilization
    /// in cost of increased block creation time. You should find a balance
    /// according to your application's requirements.
    ///
    /// If `0` is specified then `1` is used instead.
    ///
    /// Default is `1`.
    pub min_transactions_amount: usize,

    /// Maximal amount of transactions to create a block with.
    ///
    /// Very high values are not recommended because each block must be verified
    /// individually and it's computationally difficult to do for large blocks.
    ///
    /// If the value is lower than the minimal transactions amount then it's
    /// increased to match `min_transactions_amount` value.
    ///
    /// Default is `128`.
    pub max_transactions_amount: usize,

    /// Amount of time to wait between shards pool synchronization.
    ///
    /// Default is `3m`.
    pub shards_sync_interval: Duration,

    /// Amount of time to wait between running blocks synchronization, creation
    /// and approving logic.
    ///
    /// It is recommended to keep this value relatively large so that all the
    /// blocks and transactions have enough time to spread across the network.
    /// An actual value highly depends on properties of the network.
    ///
    /// Default is `1m`.
    pub blocks_sync_interval: Duration,

    /// An optional function used to choose which block should be approved from
    /// the provided list of pending blocks.
    ///
    /// If this function is not specified then internal algorithm will be used.
    /// Default is `None`.
    pub blocks_approver: Option<fn(&[&Block]) -> Hash>
}

impl Default for ValidatorSettings {
    fn default() -> Self {
        Self {
            min_transactions_amount: 1,
            max_transactions_amount: 128,
            shards_sync_interval: Duration::from_secs(180),
            blocks_sync_interval: Duration::from_secs(60),
            blocks_approver: None
        }
    }
}

/// Run validator client using provided settings.
///
/// Validator uses a normal client to connect to the provided shards, fetch
/// pending blocks and transactions from them, perform validations, create and
/// publish new blocks, and so on. Validator doesn't use local blockchain
/// storage for that. If you want to have a local storage - then you need to
/// make a local shard node and use it solely in the validator. Validator itself
/// is a thin client by design.
pub async fn serve(mut validator: Validator) -> Result<(), Error> {
    #[cfg(feature = "tracing")]
    tracing::info!("opening network blockchain viewer");

    // Create the in-RAM network blocks viewer using provided shards pool.
    if validator.shards.active().next().is_none() {
        return Err(Error::ShardsPoolEmpty);
    }

    let viewer = Viewer::open(
        validator.client.clone(),
        validator.shards.active(),
        None
    ).await.map_err(Error::Client)?;

    let Some(mut viewer) = viewer else {
        return Err(Error::NoValidShards);
    };

    // Current block number and its hash.
    let mut curr_block_number = 0;
    let mut curr_block_hash;

    // Set of already indexed transactions to prevent double-indexing in blocks.
    let mut indexed_transactions = HashSet::new();

    // Map of pending transactions which should be added to a new block.
    let mut transactions_pool = HashMap::new();

    // Time when the shards pool was updated.
    let mut last_shards_update = Instant::now();

    // Main loop where we create and approve new blocks.
    loop {
        // Sync blocks with the network shards.

        #[cfg(feature = "tracing")]
        tracing::info!("synchronizing viewer state");

        let synced_blocks = sync_viewer(
            &mut viewer,
            &mut indexed_transactions
        ).await;

        curr_block_number += synced_blocks;
        curr_block_hash = viewer.current_block().hash;

        #[cfg(feature = "tracing")]
        tracing::info!(
            ?curr_block_number,
            curr_block_hash = curr_block_hash.to_base64(),
            indexed_transactions = indexed_transactions.len(),
            transactions_pool = transactions_pool.len(),
            "viewer state synchronized"
        );

        // Remove indexed transactions from the pending pool.
        let pool = transactions_pool.keys()
            .copied()
            .collect::<Vec<Hash>>();

        for hash in pool {
            if indexed_transactions.contains(&hash) {
                transactions_pool.remove(&hash);
            }
        }

        // If we've synced new blocks - then we can create a new block from
        // pending transactions.
        if synced_blocks > 0
            && transactions_pool.len() > validator.settings.min_transactions_amount
        {
            let transactions = transactions_pool.values()
                .take(validator.settings.max_transactions_amount)
                .cloned();

            let content = BlockContent::transactions(transactions);

            let block = Block::new(&validator.secret_key, curr_block_hash, content)
                .map_err(Error::CreateBlock)?;

            #[cfg(feature = "tracing")]
            tracing::info!(
                ?curr_block_number,
                curr_block_hash = curr_block_hash.to_base64(),
                created_block_sign = block.sign().to_base64(),
                "create new block"
            );

            if let Err(err) = validator.client.put_block(validator.shards.active(), &block).await {
                #[cfg(feature = "tracing")]
                tracing::error!(
                    ?curr_block_number,
                    curr_block_hash = curr_block_hash.to_base64(),
                    created_block_sign = block.sign().to_base64(),
                    ?err,
                    "failed to put new block"
                );
            }
        }

        // Fetch pending transactions.
        #[cfg(feature = "tracing")]
        tracing::info!("fetching pending transactions");

        let pending_transactions = fetch_transactions(
            &validator,
            &indexed_transactions
        ).await;

        for (hash, transaction) in pending_transactions {
            transactions_pool.insert(hash, transaction);
        }

        // Fetch pending blocks and approve one of them.
        #[cfg(feature = "tracing")]
        tracing::info!("fetching pending blocks");

        let pending_blocks = fetch_blocks(&validator, &curr_block_hash).await;

        let mut keys = pending_blocks.keys()
            .copied()
            .collect::<Vec<Hash>>();

        // Get block with least hash value.
        keys.sort_by(|a, b| b.cmp(a));

        if let Some(hash) = keys.pop() {
            let approval = Signature::create(&validator.secret_key, hash)
                .map_err(Error::ApproveBlock)?;

            #[cfg(feature = "tracing")]
            tracing::info!(
                hash = hash.to_base64(),
                "approve block"
            );

            if let Err(err) = validator.client.approve_block(validator.shards.active(), &hash, &approval).await {
                #[cfg(feature = "tracing")]
                tracing::error!(
                    hash = hash.to_base64(),
                    ?err,
                    "failed to approve block"
                );
            }
        }

        // Update shards pool if enough time passed.
        if last_shards_update.elapsed() > validator.settings.shards_sync_interval {
            #[cfg(feature = "tracing")]
            tracing::info!("updating shards pool");

            validator.shards.update(&validator.client).await;

            last_shards_update = Instant::now();
        }

        tokio::time::sleep(validator.settings.blocks_sync_interval).await;
    }
}

async fn sync_viewer(
    viewer: &mut Viewer,
    transactions: &mut HashSet<Hash>
) -> u64 {
    let mut i = 0;

    loop {
        #[cfg(feature = "tracing")]
        tracing::trace!(
            hash = viewer.current_block().hash.to_base64(),
            public_key = viewer.current_block().public_key.to_base64(),
            "sync current block"
        );

        match viewer.forward().await {
            Some(block) => {
                if let BlockContent::Transactions(value) = block.block.content() {
                    for transaction in value {
                        transactions.insert(transaction.hash());
                    }
                }
            }

            None => break
        }

        i += 1;
    }

    i
}

async fn fetch_transactions(
    validator: &Validator,
    indexed: &HashSet<Hash>
) -> HashMap<Hash, Transaction> {
    let mut transactions = HashMap::new();
    let mut rejected = HashSet::new();
    let mut requests = Vec::new();

    // Get pending transactions' hashes from the active shards.
    for address in validator.shards.active() {
        requests.push(validator.client.get_transactions(address).map(|request| {
            (address.clone(), request)
        }));
    }

    for (address, response) in futures::future::join_all(requests).await {
        match response {
            // Iterate over the fetched transactions.
            Ok(response) => {
                for transaction_hash in response {
                    // If it's not stored yet - try to read it from the shard
                    // and store it in the pool.
                    if !transactions.contains_key(&transaction_hash)
                        && !indexed.contains(&transaction_hash)
                        && !rejected.contains(&transaction_hash)
                    {
                        match validator.client.read_transaction(&address, &transaction_hash).await {
                            Ok(Some(transaction)) => {
                                // Reject larger than allowed transactions.
                                if transaction.data.len() as u64 > validator.security_rules.max_transaction_body_size {
                                    rejected.insert(transaction_hash);

                                    continue;
                                }

                                // Verify the read transaction.
                                match transaction.verify() {
                                    Ok((true, hash, public_key)) => {
                                        // Reject transaction if it's not matched
                                        // by the filter callback.
                                        if let Some(filter) = &validator.security_rules.transactions_filter
                                            && !filter(&transaction, &hash, &public_key)
                                        {
                                            rejected.insert(transaction_hash);

                                            continue;
                                        }

                                        transactions.insert(transaction_hash, transaction);
                                    }

                                    Ok((false, hash, public_key)) => {
                                        #[cfg(feature = "tracing")]
                                        tracing::warn!(
                                            ?address,
                                            hash = hash.to_base64(),
                                            public_key = public_key.to_base64(),
                                            "pending transaction is invalid"
                                        );
                                    }

                                    Err(err) => {
                                        #[cfg(feature = "tracing")]
                                        tracing::error!(
                                            ?address,
                                            hash = transaction_hash.to_base64(),
                                            ?err,
                                            "failed to verify pending transaction"
                                        );
                                    }
                                }
                            }

                            Ok(None) => (),

                            Err(err) => {
                                #[cfg(feature = "tracing")]
                                tracing::error!(
                                    ?address,
                                    hash = transaction_hash.to_base64(),
                                    ?err,
                                    "failed to read pending transaction from the shard"
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
                    "failed to get pending transactions list from the shard"
                );
            }
        }
    }

    transactions
}

async fn fetch_blocks(
    validator: &Validator,
    previous_block: &Hash
) -> HashMap<Hash, Block> {
    let mut blocks = HashMap::new();
    let mut rejected = HashSet::new();
    let mut requests = Vec::new();

    let validator_public_key = validator.secret_key.public_key();

    // Get pending blocks from the active shards.
    for address in validator.shards.active() {
        requests.push(validator.client.get_blocks(address).map(|request| {
            (address.clone(), request)
        }));
    }

    for (address, response) in futures::future::join_all(requests).await {
        match response {
            // Iterate over the fetched blocks.
            Ok(response) => {
                for pending_block in response {
                    // If it's not stored yet - try to read it from the shard
                    // and store it in the pool.
                    if !blocks.contains_key(&pending_block.current_hash)
                        && !rejected.contains(&pending_block.current_hash)
                        && &pending_block.previous_hash == previous_block
                    {
                        match validator.client.read_block(&address, &pending_block.current_hash).await {
                            Ok(Some(block)) => {
                                // Verify the read block.
                                match block.verify() {
                                    Ok((true, hash, public_key)) => {
                                        // Reject block if it's made by the
                                        // current validator (we're not allowed
                                        // to approve our own blocks).
                                        if public_key == validator_public_key {
                                            rejected.insert(hash);

                                            continue;
                                        }

                                        // Reject block if it's not matched
                                        // by the filter callback.
                                        if let Some(filter) = &validator.security_rules.blocks_filter
                                            && !filter(&block, &hash, &public_key)
                                        {
                                            rejected.insert(hash);

                                            continue;
                                        }

                                        blocks.insert(hash, block);
                                    }

                                    Ok((false, hash, public_key)) => {
                                        #[cfg(feature = "tracing")]
                                        tracing::warn!(
                                            ?address,
                                            hash = hash.to_base64(),
                                            public_key = public_key.to_base64(),
                                            "pending block is invalid"
                                        );
                                    }

                                    Err(err) => {
                                        #[cfg(feature = "tracing")]
                                        tracing::error!(
                                            ?address,
                                            hash = pending_block.current_hash.to_base64(),
                                            ?err,
                                            "failed to verify pending block"
                                        );
                                    }
                                }
                            }

                            Ok(None) => (),

                            Err(err) => {
                                #[cfg(feature = "tracing")]
                                tracing::error!(
                                    ?address,
                                    hash = pending_block.current_hash.to_base64(),
                                    ?err,
                                    "failed to read pending block from the shard"
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
                    "failed to get pending blocks list from the shard"
                );
            }
        }
    }

    blocks
}
