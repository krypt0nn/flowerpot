// SPDX-License-Identifier: GPL-3.0-or-later
//
// libflowerpot
// Copyright (C) 2025  Nikita Podvirnyi <krypt0nn@vk.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use std::iter::FusedIterator;

use crate::crypto::hash::Hash;
use crate::crypto::sign::VerifyingKey;
use crate::block::{Block, BlockContent};

// FIXME: `write_block` must update the same block if the new variant has more
//        approvals.
//
// TODO: test for the upper case and add tests for different block content
//       types.

#[cfg(feature = "ram_storage")]
pub mod ram_storage;

#[cfg(feature = "sqlite_storage")]
pub mod sqlite_storage;

pub trait Storage: Clone {
    type Error: std::error::Error + Send + 'static;

    /// Get hash of the root block if it's available.
    fn root_block(&self) -> Result<Option<Hash>, Self::Error>;

    /// Get hash of the tail block if it's available.
    fn tail_block(&self) -> Result<Option<Hash>, Self::Error>;

    /// Check if blockchain has block with given hash.
    fn has_block(&self, hash: &Hash) -> Result<bool, Self::Error> {
        Ok(self.read_block(hash)?.is_some())
    }

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

    /// Get hash of a block previous to the one with provided hash. Return
    /// `Ok(None)` if there's no block with provided hash.
    ///
    /// Previous block of the root block of the blockchain must be the
    /// default hash (zeros).
    fn prev_block(&self, hash: &Hash) -> Result<Option<Hash>, Self::Error> {
        match self.read_block(hash)? {
            Some(block) => Ok(Some(*block.previous())),
            None => Ok(None)
        }
    }

    /// Read block from its hash. Return `Ok(None)` if there's no such block.
    fn read_block(&self, hash: &Hash) -> Result<Option<Block>, Self::Error>;

    /// Write block to the blockchain.
    ///
    /// This method must automatically prune excess blocks if this one modifies
    /// the history, and write all the transactions from the block's content if
    /// there's any. History modifications, block and stored transactions must
    /// be verified outside of this trait so this method must work without extra
    /// verifications, even if the block is not valid.
    ///
    /// Return `Ok(true)` if the blockchain history was modified, otherwise
    /// `Ok(false)`.
    ///
    /// # Blocks writing rules
    ///
    /// - If a block with the same hash is already stored then do nothing.
    /// - If there's no blocks in the storage then
    ///     - If the block is of the root type - store it;
    ///     - Otherwise reject it.
    /// - If there's no block with the provided block's previous hash then
    ///   reject it because it's out of the history.
    /// - If the provided block's previous hash is stored and the provided block
    ///   is not stored yet then
    ///     - If the previous block is the tail block of the history then we
    ///       simply push it to the end of the blockchain.
    ///     - If the previous block is not the tail block of the history then we
    ///       remove all the following blocks and overwrite the history.
    fn write_block(&self, block: &Block) -> Result<bool, Self::Error>;

    /// Get iterator over all the blocks stored in the current storage.
    #[inline]
    fn history(&self) -> StorageHistoryIter<'_, Self> where Self: Sized {
        StorageHistoryIter::new(self)
    }

    /// Get iterator over all the blocks stored in the current storage.
    #[inline]
    fn blocks(&self) -> StorageBlocksIter<'_, Self> where Self: Sized {
        StorageBlocksIter::new(self)
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
    /// By default the root block's signer is the only existing validator.
    ///
    /// Return `Ok(None)` if requested block is not stored in the local storage.
    ///
    /// > Note: the default implementation is suboptimal and custom
    /// > implementations are recommended.
    fn get_validators_before_block(
        &self,
        hash: &Hash
    ) -> Result<Option<Vec<VerifyingKey>>, Self::Error> {
        let Some(block) = self.read_block(hash)? else {
            return Ok(None);
        };

        let mut block = self.read_block(block.previous())?;

        while let Some(inner) = &block {
            if let BlockContent::Validators(validators) = inner.content() {
                return Ok(Some(validators.to_vec()));
            }

            block = self.read_block(inner.previous())?;
        }

        let Some(root_block) = self.root_block()? else {
            return Ok(Some(vec![]));
        };

        let Some(root_block) = self.read_block(&root_block)? else {
            return Ok(Some(vec![]));
        };

        let Ok((_, _, public_key)) = root_block.verify() else {
            return Ok(Some(vec![]));
        };

        Ok(Some(vec![public_key]))
    }

    /// Similar to `get_validators_before_block` but this method should return
    /// list of validators after the block with provided hash was added to
    /// the blockchain.
    ///
    /// By default the root block's signer is the only existing validator.
    ///
    /// Return `Ok(None)` if requested block is not stored in the local storage.
    ///
    /// > Note: the default implementation is suboptimal and custom
    /// > implementations are recommended.
    fn get_validators_after_block(
        &self,
        hash: &Hash
    ) -> Result<Option<Vec<VerifyingKey>>, Self::Error> {
        if !self.has_block(hash)? {
            return Ok(None);
        }

        let mut block = self.read_block(hash)?;

        while let Some(inner) = &block {
            if let BlockContent::Validators(validators) = inner.content() {
                return Ok(Some(validators.to_vec()));
            }

            block = self.read_block(inner.previous())?;
        }

        let Some(root_block) = self.root_block()? else {
            return Ok(Some(vec![]));
        };

        let Some(root_block) = self.read_block(&root_block)? else {
            return Ok(Some(vec![]));
        };

        let Ok((_, _, public_key)) = root_block.verify() else {
            return Ok(Some(vec![]));
        };

        Ok(Some(vec![public_key]))
    }

    /// Get list of current blockchain validators.
    ///
    /// By default the root block's signer is the only existing validator.
    fn get_current_validators(&self) -> Result<Vec<VerifyingKey>, Self::Error> {
        let Some(tail_block) = self.tail_block()? else {
            // No tail block => blockchain is empty, no validators available.
            return Ok(vec![]);
        };

        // Can return `None` only if `read_block` decided that tail block
        // doesn't exist which shouldn't happen.
        if let Some(validators) = self.get_validators_after_block(&tail_block)? {
            return Ok(validators);
        }

        // Fallback value.
        Ok(vec![])
    }
}

#[derive(Debug, Clone)]
pub struct StorageHistoryIter<'storage, S: Storage> {
    storage: &'storage S,
    current_block: Hash
}

impl<'storage, S: Storage> StorageHistoryIter<'storage, S> {
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
            current_block: block_hash.into()
        }
    }

    #[inline(always)]
    pub const fn storage(&self) -> &'storage S {
        self.storage
    }
}

impl<S: Storage> Iterator for StorageHistoryIter<'_, S> {
    type Item = Result<Hash, S::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.storage.next_block(&self.current_block) {
            Ok(Some(next_block)) => {
                self.current_block = next_block;

                Some(Ok(next_block))
            }

            Ok(None) => None,
            Err(err) => Some(Err(err))
        }
    }
}

impl<S: Storage> FusedIterator for StorageHistoryIter<'_, S> {}

#[derive(Debug, Clone)]
pub struct StorageBlocksIter<'storage, S: Storage>(StorageHistoryIter<'storage, S>);

impl<'storage, S: Storage> StorageBlocksIter<'storage, S> {
    #[inline]
    pub fn new(storage: &'storage S) -> Self {
        Self(StorageHistoryIter::new(storage))
    }

    #[inline]
    pub fn new_since(
        storage: &'storage S,
        block_hash: impl Into<Hash>
    ) -> Self {
        Self(StorageHistoryIter::new_since(storage, block_hash))
    }
}

impl<S: Storage> Iterator for StorageBlocksIter<'_, S> {
    type Item = Result<Block, S::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let hash = match self.0.next()? {
            Ok(hash) => hash,
            Err(err) => return Some(Err(err))
        };

        match self.0.storage.read_block(&hash) {
            Ok(Some(block)) => Some(Ok(block)),
            Ok(None) => None,
            Err(err) => Some(Err(err))
        }
    }
}

impl<S: Storage> FusedIterator for StorageBlocksIter<'_, S> {}

impl<'storage, S: Storage> From<StorageHistoryIter<'storage, S>>
for StorageBlocksIter<'storage, S> {
    #[inline(always)]
    fn from(value: StorageHistoryIter<'storage, S>) -> Self {
        Self(value)
    }
}

#[cfg(test)]
pub fn test_storage<S: Storage>(storage: &S) -> Result<(), S::Error> {
    use rand_chacha::ChaCha8Rng;
    use rand_chacha::rand_core::SeedableRng;

    use crate::crypto::sign::SigningKey;
    use crate::block::BlockContent;

    // Obvious checks for empty storage.

    assert!(storage.root_block()?.is_none());
    assert!(storage.tail_block()?.is_none());
    assert!(!storage.has_block(&Hash::default())?);
    assert!(storage.next_block(&Hash::default())?.is_none());
    assert!(storage.read_block(&Hash::default())?.is_none());
    assert_eq!(storage.blocks().count(), 0);
    assert!(storage.get_current_validators()?.is_empty());

    // Prepare test blocks.

    let mut rng = ChaCha8Rng::seed_from_u64(123);

    let signing_key = SigningKey::random(&mut rng);

    let block_1 = Block::new(
        &signing_key,
        Hash::default(),
        BlockContent::data("Block 1".as_bytes())
    ).unwrap();

    assert!(block_1.is_root());

    let block_1_hash = block_1.hash().unwrap();

    let block_2 = Block::new(
        &signing_key,
        block_1_hash,
        BlockContent::data("Block 2".as_bytes())
    ).unwrap();

    let block_2_hash = block_2.hash().unwrap();

    let block_3 = Block::new(
        &signing_key,
        block_2_hash,
        BlockContent::data("Block 3".as_bytes())
    ).unwrap();

    let block_3_hash = block_3.hash().unwrap();

    // Prepare alternative test blocks.

    let signing_key_alt = SigningKey::random(&mut rng);

    let block_1_alt = Block::new(
        &signing_key_alt,
        Hash::default(),
        BlockContent::data("Alternative block 1".as_bytes())
    ).unwrap();

    assert!(block_1_alt.is_root());

    let block_1_alt_hash = block_1_alt.hash().unwrap();

    let block_2_alt = Block::new(
        &signing_key_alt,
        block_1_hash,
        BlockContent::data("Alternative block 2".as_bytes())
    ).unwrap();

    let block_2_alt_hash = block_2_alt.hash().unwrap();

    let block_3_alt = Block::new(
        &signing_key_alt,
        block_2_hash,
        BlockContent::data("Alternative block 3".as_bytes())
    ).unwrap();

    let block_3_alt_hash = block_3_alt.hash().unwrap();

    // 1. Out of order writing.
    //
    // Block 2 must be rejected by the method since it's not a root block type.

    storage.write_block(&block_2)?;

    assert!(storage.root_block()?.is_none());
    assert!(storage.tail_block()?.is_none());

    assert!(!storage.has_block(&Hash::default())?);
    assert!(!storage.has_block(&block_2_hash)?);

    assert!(storage.next_block(&Hash::default())?.is_none());
    assert!(storage.next_block(&block_2_hash)?.is_none());

    assert!(storage.read_block(&Hash::default())?.is_none());
    assert!(storage.read_block(&block_2_hash)?.is_none());

    assert_eq!(storage.blocks().count(), 0);

    // 2. Out of order writing.
    //
    // Block 3 must be rejected by the method since block 2 is not stored yet.
    // Block 1 must be written successfully.

    storage.write_block(&block_1)?;
    storage.write_block(&block_3)?;

    assert_eq!(storage.root_block()?, Some(block_1_hash));
    assert_eq!(storage.tail_block()?, Some(block_1_hash));

    assert!(!storage.has_block(&Hash::default())?);
    assert!(storage.has_block(&block_1_hash)?);
    assert!(!storage.has_block(&block_2_hash)?);
    assert!(!storage.has_block(&block_3_hash)?);

    assert_eq!(storage.next_block(&Hash::default())?, Some(block_1_hash));
    assert!(storage.next_block(&block_1_hash)?.is_none());
    assert!(storage.next_block(&block_2_hash)?.is_none());
    assert!(storage.next_block(&block_3_hash)?.is_none());

    assert!(storage.read_block(&Hash::default())?.is_none());
    assert_eq!(storage.read_block(&block_1_hash)?, Some(block_1.clone()));
    assert!(storage.read_block(&block_2_hash)?.is_none());
    assert!(storage.read_block(&block_3_hash)?.is_none());

    assert_eq!(storage.blocks().count(), 1);

    // 3. In-order writing.
    //
    // Blocks 2 and 3 must be written to the storage successfully.

    storage.write_block(&block_2)?;
    storage.write_block(&block_3)?;

    assert_eq!(storage.root_block()?, Some(block_1_hash));
    assert_eq!(storage.tail_block()?, Some(block_3_hash));

    assert!(!storage.has_block(&Hash::default())?);
    assert!(storage.has_block(&block_1_hash)?);
    assert!(storage.has_block(&block_2_hash)?);
    assert!(storage.has_block(&block_3_hash)?);

    assert_eq!(storage.next_block(&Hash::default())?, Some(block_1_hash));
    assert_eq!(storage.next_block(&block_1_hash)?, Some(block_2_hash));
    assert_eq!(storage.next_block(&block_2_hash)?, Some(block_3_hash));
    assert!(storage.next_block(&block_3_hash)?.is_none());

    assert!(storage.prev_block(&Hash::default())?.is_none());
    assert_eq!(storage.prev_block(&block_1_hash)?, Some(Hash::default()));
    assert_eq!(storage.prev_block(&block_2_hash)?, Some(block_1_hash));
    assert_eq!(storage.prev_block(&block_3_hash)?, Some(block_2_hash));

    assert!(storage.read_block(&Hash::default())?.is_none());
    assert_eq!(storage.read_block(&block_1_hash)?, Some(block_1.clone()));
    assert_eq!(storage.read_block(&block_2_hash)?, Some(block_2.clone()));
    assert_eq!(storage.read_block(&block_3_hash)?, Some(block_3.clone()));

    assert_eq!(storage.blocks().count(), 3);

    assert_eq!(
        storage.get_current_validators()?,
        vec![signing_key.verifying_key()]
    );

    // 4. Tail block modification.
    //
    // Block 3 must be correctly replaced by the alternative block 3.
    // Original block 3 must be removed completely.

    storage.write_block(&block_3_alt)?;

    assert_eq!(storage.root_block()?, Some(block_1_hash));
    assert_eq!(storage.tail_block()?, Some(block_3_alt_hash));

    assert!(!storage.has_block(&Hash::default())?);
    assert!(storage.has_block(&block_1_hash)?);
    assert!(storage.has_block(&block_2_hash)?);
    assert!(!storage.has_block(&block_3_hash)?);
    assert!(storage.has_block(&block_3_alt_hash)?);

    assert_eq!(storage.next_block(&Hash::default())?, Some(block_1_hash));
    assert_eq!(storage.next_block(&block_1_hash)?, Some(block_2_hash));
    assert_eq!(storage.next_block(&block_2_hash)?, Some(block_3_alt_hash));
    assert!(storage.next_block(&block_3_hash)?.is_none());
    assert!(storage.next_block(&block_3_alt_hash)?.is_none());

    assert!(storage.read_block(&Hash::default())?.is_none());
    assert_eq!(storage.read_block(&block_1_hash)?, Some(block_1.clone()));
    assert_eq!(storage.read_block(&block_2_hash)?, Some(block_2.clone()));
    assert!(storage.read_block(&block_3_hash)?.is_none());
    assert_eq!(storage.read_block(&block_3_alt_hash)?, Some(block_3_alt.clone()));

    assert_eq!(storage.blocks().count(), 3);

    // 5. Middle block modification.
    //
    // Block 2 must be correctly replaced by the alternative block 2.
    // Alternative block 3 must be removed completely since its previous hash
    // is not correct anymore.

    storage.write_block(&block_2_alt)?;

    assert_eq!(storage.root_block()?, Some(block_1_hash));
    assert_eq!(storage.tail_block()?, Some(block_2_alt_hash));

    assert!(!storage.has_block(&Hash::default())?);
    assert!(storage.has_block(&block_1_hash)?);
    assert!(!storage.has_block(&block_2_hash)?);
    assert!(storage.has_block(&block_2_alt_hash)?);
    assert!(!storage.has_block(&block_3_hash)?);
    assert!(!storage.has_block(&block_3_alt_hash)?);

    assert_eq!(storage.next_block(&Hash::default())?, Some(block_1_hash));
    assert_eq!(storage.next_block(&block_1_hash)?, Some(block_2_alt_hash));

    assert!(storage.next_block(&block_2_hash)?.is_none());
    assert!(storage.next_block(&block_2_alt_hash)?.is_none());
    assert!(storage.next_block(&block_3_hash)?.is_none());
    assert!(storage.next_block(&block_3_alt_hash)?.is_none());

    assert!(storage.read_block(&Hash::default())?.is_none());
    assert_eq!(storage.read_block(&block_1_hash)?, Some(block_1.clone()));

    assert!(storage.read_block(&block_2_hash)?.is_none());
    assert_eq!(storage.read_block(&block_2_alt_hash)?, Some(block_2_alt.clone()));

    assert!(storage.read_block(&block_3_hash)?.is_none());
    assert!(storage.read_block(&block_3_alt_hash)?.is_none());

    assert_eq!(storage.blocks().count(), 2);

    // 6. Root block modification.
    //
    // Block 1 must be correctly replaced by the alternative block 1.
    // Alternative block 2 must be removed completely since its previous hash
    // is not correct anymore. No blocks but the alternative block 1 must remain
    // in the history at that point.

    storage.write_block(&block_1_alt)?;

    assert_eq!(storage.root_block()?, Some(block_1_alt_hash));
    assert_eq!(storage.tail_block()?, Some(block_1_alt_hash));

    assert!(!storage.has_block(&Hash::default())?);
    assert!(!storage.has_block(&block_1_hash)?);
    assert!(storage.has_block(&block_1_alt_hash)?);
    assert!(!storage.has_block(&block_2_hash)?);
    assert!(!storage.has_block(&block_2_alt_hash)?);
    assert!(!storage.has_block(&block_3_hash)?);
    assert!(!storage.has_block(&block_3_alt_hash)?);

    assert_eq!(storage.next_block(&Hash::default())?, Some(block_1_alt_hash));

    assert!(storage.next_block(&block_1_hash)?.is_none());
    assert!(storage.next_block(&block_1_alt_hash)?.is_none());
    assert!(storage.next_block(&block_2_hash)?.is_none());
    assert!(storage.next_block(&block_2_alt_hash)?.is_none());
    assert!(storage.next_block(&block_3_hash)?.is_none());
    assert!(storage.next_block(&block_3_alt_hash)?.is_none());

    assert!(storage.read_block(&Hash::default())?.is_none());

    assert!(storage.read_block(&block_1_hash)?.is_none());
    assert_eq!(storage.read_block(&block_1_alt_hash)?, Some(block_1_alt.clone()));

    assert!(storage.read_block(&block_2_hash)?.is_none());
    assert!(storage.read_block(&block_2_alt_hash)?.is_none());

    assert!(storage.read_block(&block_3_hash)?.is_none());
    assert!(storage.read_block(&block_3_alt_hash)?.is_none());

    assert_eq!(storage.blocks().count(), 1);

    assert_eq!(
        storage.get_current_validators()?,
        vec![signing_key_alt.verifying_key()]
    );

    // Prepare validator blocks.

    let validator_1 = SigningKey::random(&mut rng);
    let validator_2 = SigningKey::random(&mut rng);
    let validator_3 = SigningKey::random(&mut rng);

    let block_2_alt = Block::new(
        &signing_key_alt,
        block_1_alt_hash,
        BlockContent::validators([validator_1.verifying_key()])
    ).unwrap();

    let block_2_alt_hash = block_2_alt.hash().unwrap();

    let block_3_alt = Block::new(
        &validator_1,
        block_2_alt_hash,
        BlockContent::validators([
            validator_2.verifying_key(),
            validator_3.verifying_key()
        ])
    ).unwrap();

    let block_3_alt_hash = block_3_alt.hash().unwrap();

    // 7. Validator blocks.

    storage.write_block(&block_2_alt)?;
    storage.write_block(&block_3_alt)?;

    // Block 1 (root)
    assert_eq!(
        storage.get_validators_before_block(&block_1_alt_hash)?,
        Some(vec![signing_key_alt.verifying_key()])
    );

    assert_eq!(
        storage.get_validators_after_block(&block_1_alt_hash)?,
        Some(vec![signing_key_alt.verifying_key()])
    );

    // Block 2 (root -> validator 1)
    assert_eq!(
        storage.get_validators_before_block(&block_2_alt_hash)?,
        Some(vec![signing_key_alt.verifying_key()])
    );

    assert_eq!(
        storage.get_validators_after_block(&block_2_alt_hash)?,
        Some(vec![validator_1.verifying_key()])
    );

    // Block 3 (validator 1 -> validators 2 and 3)
    assert_eq!(
        storage.get_validators_before_block(&block_3_alt_hash)?,
        Some(vec![validator_1.verifying_key()])
    );

    assert_eq!(
        storage.get_validators_after_block(&block_3_alt_hash)?,
        Some(vec![
            validator_2.verifying_key(),
            validator_3.verifying_key()
        ])
    );

    // Current validators (block 3)
    assert_eq!(
        storage.get_current_validators()?,
        vec![
            validator_2.verifying_key(),
            validator_3.verifying_key()
        ]
    );

    Ok(())
}
