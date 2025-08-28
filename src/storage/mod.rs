use std::iter::FusedIterator;

use crate::crypto::*;
use crate::block::{Block, Error as BlockError};
use crate::client::{Client, Error as ClientError};
use crate::pool::ShardsPool;
use crate::viewer::Viewer;

#[cfg(feature = "file_storage")]
pub mod file_storage;

pub trait Storage {
    type Error: std::error::Error;

    /// Get hash of the root block if it's available.
    fn root_block(&self) -> Result<Option<Hash>, Self::Error>;

    /// Get hash of the tail block if it's available.
    fn tail_block(&self) -> Result<Option<Hash>, Self::Error>;

    /// Check if blockchain has block with given hash.
    fn has_block(&self, hash: &Hash) -> Result<bool, Self::Error>;

    /// Get hash of a block next to the one with provided hash. Return
    /// `Ok(None)` if there's no block next to the requested one.
    ///
    /// Next block from the default hash (zeros) must return the root block
    /// of the blockchain if it's available.
    ///
    /// ```text,no_run
    /// [curr_block] <--- [next_block]
    ///                   ^^^^^^^^^^^^ returned value
    /// ```
    fn next_block(&self, hash: &Hash) -> Result<Option<Hash>, Self::Error>;

    /// Read block from its hash. Return `Ok(None)` if there's no such block.
    fn read_block(&self, hash: &Hash) -> Result<Option<Block>, Self::Error>;

    /// Write block to the blockchain.
    ///
    /// This method must automatically prune excess blocks if this one modifies
    /// the history, and write all the transactions from the block's content if
    /// there's any. History modifications, block and stored transactions must
    /// be verified outside of this trait so this method must work without extra
    /// verifications, even if the block is not valid.
    fn write_block(&self, block: &Block) -> Result<(), Self::Error>;

    /// Get iterator over all the blocks stored in the current storage.
    #[inline]
    fn blocks(&self) -> StorageIter<'_, Self> where Self: Sized {
        StorageIter::new(self)
    }

    /// Get list of blockchain validators at the point in time when the block
    /// with provided hash didn't exist yet. This is needed because validators
    /// can change over time and we want to know which validators existed at any
    /// point in time.
    ///
    /// The "didn't exist" rule means that if the block with provided hash
    /// changes validators list then this method should return *previous
    /// validators* list - so validators who can approve creation of the block
    /// with provided hash.
    ///
    /// Return `Ok(None)` if requested block is not stored in the local storage.
    fn get_validators_before_block(
        &self,
        hash: &Hash
    ) -> Result<Option<Vec<PublicKey>>, Self::Error>;

    /// Similar to `get_validators_before_block` but this method should return
    /// list of validators after the block with provided hash was added to
    /// the blockchain.
    ///
    /// Return `Ok(None)` if requested block is not stored in the local storage.
    fn get_validators_after_block(
        &self,
        hash: &Hash
    ) -> Result<Option<Vec<PublicKey>>, Self::Error>;

    /// Get list of current blockchain validators.
    fn get_current_validators(&self) -> Result<Vec<PublicKey>, Self::Error>;
}

pub struct StorageIter<'storage, S: Storage> {
    storage: &'storage S,
    curr_block: Hash
}

impl<'storage, S: Storage> StorageIter<'storage, S> {
    #[inline]
    pub fn new(storage: &'storage S) -> Self {
        Self::new_since(storage, Hash::default())
    }

    #[inline]
    pub fn new_since(
        storage: &'storage S,
        block_hash: impl Into<Hash>
    ) -> Self {
        Self {
            storage,
            curr_block: block_hash.into()
        }
    }
}

impl<S: Storage> Iterator for StorageIter<'_, S> {
    type Item = Result<Block, S::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.storage.next_block(&self.curr_block) {
            Ok(Some(next_block)) => {
                match self.storage.read_block(&next_block) {
                    Ok(Some(block)) => {
                        self.curr_block = next_block;

                        Some(Ok(block))
                    }

                    Ok(None) => None,
                    Err(err) => Some(Err(err))
                }
            }

            Ok(None) => None,
            Err(err) => Some(Err(err))
        }
    }
}

impl<S: Storage> FusedIterator for StorageIter<'_, S> {}

#[derive(Debug, thiserror::Error)]
pub enum SyncError<S: Storage> {
    #[error("client error: {0}")]
    Client(#[from] ClientError),

    #[error("block error: {0}")]
    Block(#[source] BlockError),

    #[error("storage error: {0}")]
    Storage(#[source] S::Error)
}

/// Synchronize provided storage with blockchain stored by provided shards using
/// provided client for API requests.
///
/// This is potentially a very heavy function which should be executed in
/// background.
pub async fn sync<S: Storage>(
    client: Client,
    shards: &ShardsPool,
    storage: &S
) -> Result<(), SyncError<S>> {
    let mut curr_local_block_hash = storage.root_block()
        .map_err(SyncError::Storage)?;

    let viewer = Viewer::open(client, shards.active(), curr_local_block_hash).await
        .map_err(SyncError::Client)?;

    let Some(mut viewer) = viewer else {
        return Ok(());
    };

    let mut storage_block = match curr_local_block_hash {
        Some(curr_local_block_hash) => storage.read_block(&curr_local_block_hash)
            .map_err(SyncError::Storage)?,

        None => None
    };

    let mut network_block = viewer.current_block();

    loop {
        match &mut storage_block {
            // If we have a block in the local storage then we should weight
            // our block against the one received from the network and if the
            // received one is better than ours - merge it.
            //
            // Blocks returned from the viewer are 100% valid (we assume so),
            // and we assume that our locally stored blocks are also 100%
            // valid (which can be wrong!!! but still).
            Some(storage_block) => {
                // Verify the local block (it's really only needed to obtain
                // its hash).
                let (is_valid, storage_block_hash, _) = storage_block.verify()
                    .map_err(SyncError::Block)?;

                // If for some reason local block is invalid then we obviously
                // immediately swap it.
                let mut storage_block_updated = false;

                if !is_valid {
                    *storage_block = network_block.block.clone();
                    curr_local_block_hash = Some(network_block.hash);

                    storage_block_updated = true;
                }

                // Then we will try to merge approvals from the network block
                // into our local one. There's a chance that network block has
                // some new approvals which we can utilize locally.
                for approval in network_block.block.approvals() {
                    if !storage_block.approvals.contains(approval) {
                        storage_block.approvals.push(approval.clone());

                        storage_block_updated = true;
                    }
                }

                // Then we count approvals in both local and network blocks.
                let storage_block_approvals = storage_block.approvals().len();
                let network_block_approvals = network_block.block.approvals().len();

                // If our local block has less approvals than the remote one
                // then we swap them. Otherwise, if the amount is equal BUT
                // remote block has lower hash value then we also should swap
                // them.
                if storage_block_approvals < network_block_approvals
                    || (storage_block_approvals == network_block_approvals
                        && network_block.hash < storage_block_hash)
                {
                    *storage_block = network_block.block.clone();
                    curr_local_block_hash = Some(network_block.hash);

                    storage_block_updated = true;
                }

                // Write updated local block to the storage if needed.
                if storage_block_updated {
                    storage.write_block(storage_block)
                        .map_err(SyncError::Storage)?;
                }
            }

            // Otherwise we should merge the network block into our local
            // storage.
            None => {
                storage.write_block(&network_block.block)
                    .map_err(SyncError::Storage)?;
            }
        }

        // Try to read the next block from the network or break the loop.
        match viewer.forward().await {
            Some(next_block) => network_block = next_block,
            None => break
        }

        // Try to read the next local storage block if we could read the next
        // block from the network.
        if let Some(curr_block) = &mut curr_local_block_hash {
            match storage.next_block(curr_block).map_err(SyncError::Storage)? {
                Some(next_block) => *curr_block = next_block,
                None => curr_local_block_hash = None
            }
        }

        storage_block = match curr_local_block_hash {
            Some(hash) => storage.read_block(&hash)
                .map_err(SyncError::Storage)?,

            None => None
        };
    }

    Ok(())
}
