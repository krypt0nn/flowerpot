use std::iter::FusedIterator;

use crate::crypto::*;
use crate::block::*;

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
