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

use crate::crypto::hash::Hash;
use crate::blob::Blob;
use crate::block::Block;

#[cfg(feature = "ram_storage")]
pub mod ram_storage;

#[cfg(feature = "sqlite_storage")]
pub mod sqlite_storage;

/// Possible block writing outcomes according to the standard algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StorageWriteResult {
    /// Block is appended to the end of the chain.
    Success,

    /// Provided block is not verified or is in some sort invalid.
    BlockInvalid,

    /// Provided block is already stored.
    BlockAlreadyStored,

    /// Provided block has blobs with the same hash value.
    BlockHasDuplicateBlobs,

    /// Provided block has blobs which are already stored in previous blocks.
    BlockHasDuplicateHistoryBlobs,

    /// Storage has no blocks and provided block is not a root block.
    NotRootBlock,

    /// Provided block cannot be chained to any other stored block (there's no
    /// block with its prev_hash hash).
    OutOfHistoryBlock
}

pub type StorageError = Box<dyn std::error::Error>;

pub trait Storage {
    /// Get hash of the root block if it's available.
    ///
    /// The result must be equal to the `Storage::next_block(Hash::ZERO)`.
    fn root_block(&self) -> Result<Option<Hash>, StorageError>;

    /// Get hash of the tail block if it's available.
    fn tail_block(&self) -> Result<Option<Hash>, StorageError>;

    /// Check if storage has a block with given hash.
    fn has_block(&self, hash: &Hash) -> Result<bool, StorageError> {
        Ok(self.read_block(hash)?.is_some())
    }

    /// Get hash of a block next to the one with provided hash. Return
    /// `Ok(None)` if there's no block next to the requested one.
    ///
    /// Next block from the default hash (`Hash::ZERO`) must return the root
    /// block if it's available and be equal to the `Storage::root_block()`.
    ///
    /// ```text,no_run
    /// [curr_block] <--- [next_block]
    ///                   ^^^^^^^^^^^^ returned value
    /// ```
    fn next_block(&self, hash: &Hash) -> Result<Option<Hash>, StorageError>;

    /// Get hash of a block previous to the one with provided hash. Return
    /// `Ok(None)` if there's no block with provided hash.
    ///
    /// Previous block of the root block must be the default hash
    /// (`Hash::ZERO`).
    fn prev_block(&self, hash: &Hash) -> Result<Option<Hash>, StorageError> {
        match self.read_block(hash)? {
            Some(block) => Ok(Some(*block.prev_hash())),
            None => Ok(None)
        }
    }

    /// Read block from its hash. Return `Ok(None)` if there's no such block.
    fn read_block(&self, hash: &Hash) -> Result<Option<Block>, StorageError>;

    /// Try to write a block to the storage.
    ///
    /// This method must automatically prune excess blocks if this one modifies
    /// the history. History modifications, block and stored blobs must be
    /// verified outside of this trait so this method should work without extra
    /// verifications (but they still can be implemented if wanted).
    ///
    /// Blobs with the same hash must not be allowed. If a new block is
    /// attempting to be added to the history, then this method must return
    /// `Ok(false)` if some blob in this new block is already stored in some
    /// previous block.
    ///
    /// Return `Ok(true)` if stored history was modified, otherwise `Ok(false)`.
    ///
    /// # Blocks writing rules
    ///
    /// - If a block with the same hash is already stored then reject it and
    ///   return `StorageWriteResult::BlockAlreadyStored`.
    /// - If the provided block has blobs with duplicate hashes then it must
    ///   be rejected and return `StorageWriteResult::BlockHasDuplicateBlobs`.
    /// - If there's no blocks in the storage then:
    ///     - If the block is of the root type - store it and return
    ///       `StorageWriteResult::Success`;
    ///     - Otherwise reject it and return `StorageWriteResult::NotRootBlock`.
    /// - If there's no block with the provided block's previous hash then
    ///   reject it because it's out of the history (can't be chained to any
    ///   other block) and return `StorageWriteResult::OutOfHistoryBlock`.
    /// - If the provided block's previous hash is stored and the provided block
    ///   is not stored yet then:
    ///     - If the previous block is the tail block of the history then:
    ///         - If any block blob hash is stored on the chain already then
    ///           the block must be rejected, return
    ///           `StorageWriteResult::BlockHasDuplicateHistoryBlobs`;
    ///         - Otherwise write this block to the end of the chain and return
    ///           `StorageWriteResult::Success`.
    ///     - If the previous block is not the tail block of the history then:
    ///         - Remove all the following blocks;
    ///         - If there's no duplicate messages then append the new block to
    ///           the chain;
    ///         - Otherwise revert blocks removal, reject new block and return
    ///           `StorageWriteResult::BlockHasDuplicateHistoryBlobs`.
    fn write_block(
        &self,
        block: &Block
    ) -> Result<StorageWriteResult, StorageError>;

    /// Check if storage has a blob with given hash. `Ok(true)` is returned only
    /// if the blob is physically stored and can be read.
    fn has_blob(&self, hash: &Hash) -> Result<bool, StorageError> {
        Ok(self.find_blob(hash)?.is_some())
    }

    /// Find block hash to which blob with provided hash is attached. Return
    /// `Ok(None)` if there's no such blob.
    ///
    /// This method will return block hash for provided blob hash even if the
    /// blob with this hash *is not stored* in the storage.
    fn find_blob(
        &self,
        hash: &Hash
    ) -> Result<Option<Hash>, StorageError> {
        let mut curr_block = self.root_block()?;

        while let Some(block_hash) = &curr_block {
            if let Some(block) = self.read_block(block_hash)? {
                if block.blobs().contains(hash) {
                    return Ok(Some(*block_hash));
                }

                for blob in block.inline_blobs() {
                    if blob.hash() == hash {
                        return Ok(Some(*block_hash));
                    }
                }
            }

            curr_block = self.next_block(block_hash)?;
        }

        Ok(None)
    }

    /// Read blob from its hash. Return `Ok(None)` if blob with provided hash
    /// is not stored.
    fn read_blob(
        &self,
        hash: &Hash
    ) -> Result<Option<Blob>, StorageError> {
        let Some(block) = self.find_blob(hash)? else {
            return Ok(None);
        };

        let Some(block) = self.read_block(&block)? else {
            return Ok(None);
        };

        Ok(block.inline_blobs()
            .iter()
            .find(|tr| tr.hash() == hash)
            .cloned())
    }

    /// Try to write a blob to the storage.
    ///
    /// Return `Ok(true)` if blob was successfully written to the storage or
    /// it was stored already.
    ///
    /// Return `Ok(false)` if blob was not written.
    fn write_blob(&self, blob: &Blob) -> Result<bool, StorageError>;
}

impl<T> Storage for Box<T> where T: Storage {
    #[inline]
    fn root_block(&self) -> Result<Option<Hash>, StorageError> {
        T::root_block(self)
    }

    #[inline]
    fn tail_block(&self) -> Result<Option<Hash>, StorageError> {
        T::tail_block(self)
    }

    #[inline]
    fn has_block(&self, hash: &Hash) -> Result<bool, StorageError> {
        T::has_block(self, hash)
    }

    #[inline]
    fn next_block(&self, hash: &Hash) -> Result<Option<Hash>, StorageError> {
        T::next_block(self, hash)
    }

    #[inline]
    fn prev_block(&self, hash: &Hash) -> Result<Option<Hash>, StorageError> {
        T::prev_block(self, hash)
    }

    #[inline]
    fn read_block(&self, hash: &Hash) -> Result<Option<Block>, StorageError> {
        T::read_block(self, hash)
    }

    #[inline]
    fn write_block(
        &self,
        block: &Block
    ) -> Result<StorageWriteResult, StorageError> {
        T::write_block(self, block)
    }

    #[inline]
    fn has_blob(&self, hash: &Hash) -> Result<bool, StorageError> {
        T::has_blob(self, hash)
    }

    #[inline]
    fn find_blob(
        &self,
        hash: &Hash
    ) -> Result<Option<Hash>, StorageError> {
        T::find_blob(self, hash)
    }

    #[inline]
    fn read_blob(
        &self,
        hash: &Hash
    ) -> Result<Option<Blob>, StorageError> {
        T::read_blob(self, hash)
    }

    #[inline]
    fn write_blob(&self, blob: &Blob) -> Result<bool, StorageError> {
        T::write_blob(self, blob)
    }
}

#[cfg(test)]
pub fn test_storage<S: Storage>(
    storage: &S
) -> Result<(), Box<dyn std::error::Error>> {
    use rand_chacha::ChaCha8Rng;
    use rand_chacha::rand_core::SeedableRng;

    use crate::crypto::sign::SigningKey;

    // Obvious checks for empty storage.

    assert!(storage.root_block()?.is_none());
    assert!(storage.tail_block()?.is_none());
    assert!(!storage.has_block(&Hash::ZERO)?);
    assert!(storage.next_block(&Hash::ZERO)?.is_none());
    assert!(storage.read_block(&Hash::ZERO)?.is_none());
    assert!(!storage.has_blob(&Hash::ZERO)?);
    assert!(storage.find_blob(&Hash::ZERO)?.is_none());
    assert!(storage.read_blob(&Hash::ZERO)?.is_none());

    // Prepare test messages.

    let mut rng = ChaCha8Rng::seed_from_u64(123);

    let signing_key = SigningKey::random(&mut rng);

    let blob_1 = Blob::create(&signing_key, b"Blob 1".as_slice())?;
    let blob_2 = Blob::create(&signing_key, b"Blob 2".as_slice())?;
    let blob_3 = Blob::create(&signing_key, b"Blob 3".as_slice())?;

    // Prepare test blocks.

    let block_1 = Block::builder()
        .sign(&signing_key)
        .unwrap();

    assert!(block_1.is_root());
    assert_eq!(block_1.prev_hash(), &Hash::ZERO);

    let block_2 = Block::builder()
        .with_prev_hash(block_1.hash())
        .with_inline_blobs([blob_1.clone()])
        .sign(&signing_key)?;

    let block_3 = Block::builder()
        .with_prev_hash(block_2.hash())
        .with_inline_blobs([blob_2.clone(), blob_3.clone()])
        .sign(&signing_key)?;

    assert!(!block_2.is_root());
    assert!(!block_3.is_root());

    // 1. Out of order writing without root block stored.
    //
    // Block 2 must be rejected by the method since it's not a root block type.

    assert_eq!(
        storage.write_block(&block_2)?,
        StorageWriteResult::NotRootBlock
    );

    assert!(storage.root_block()?.is_none());
    assert!(storage.tail_block()?.is_none());

    assert!(!storage.has_block(&Hash::ZERO)?);
    assert!(!storage.has_block(block_1.hash())?);

    assert!(storage.next_block(&Hash::ZERO)?.is_none());
    assert!(storage.next_block(block_2.hash())?.is_none());

    assert!(storage.read_block(&Hash::ZERO)?.is_none());
    assert!(storage.read_block(block_2.hash())?.is_none());

    // 2. Out of order writing with root block stored.
    //
    // Block 3 must be rejected by the method since block 2 is not stored yet.
    // Block 1 must be written successfully.

    assert_eq!(
        storage.write_block(&block_1)?,
        StorageWriteResult::Success
    );

    assert_eq!(
        storage.write_block(&block_3)?,
        StorageWriteResult::OutOfHistoryBlock
    );

    assert_eq!(storage.root_block()?, Some(*block_1.hash()));
    assert_eq!(storage.tail_block()?, Some(*block_1.hash()));

    assert!(!storage.has_block(&Hash::ZERO)?);
    assert!(storage.has_block(block_1.hash())?);
    assert!(!storage.has_block(block_2.hash())?);
    assert!(!storage.has_block(block_3.hash())?);

    assert_eq!(storage.next_block(&Hash::ZERO)?, Some(*block_1.hash()));
    assert!(storage.next_block(block_1.hash())?.is_none());
    assert!(storage.next_block(block_2.hash())?.is_none());
    assert!(storage.next_block(block_3.hash())?.is_none());

    assert!(storage.read_block(&Hash::ZERO)?.is_none());
    assert_eq!(storage.read_block(block_1.hash())?.as_ref(), Some(&block_1));
    assert!(storage.read_block(block_2.hash())?.is_none());
    assert!(storage.read_block(block_3.hash())?.is_none());

    assert!(!storage.has_blob(blob_1.hash())?);
    assert!(!storage.has_blob(blob_2.hash())?);
    assert!(!storage.has_blob(blob_3.hash())?);

    assert!(storage.find_blob(blob_1.hash())?.is_none());
    assert!(storage.find_blob(blob_2.hash())?.is_none());
    assert!(storage.find_blob(blob_3.hash())?.is_none());

    assert!(storage.read_blob(blob_1.hash())?.is_none());
    assert!(storage.read_blob(blob_2.hash())?.is_none());
    assert!(storage.read_blob(blob_3.hash())?.is_none());

    // 3. In-order writing.
    //
    // Blocks 2 and 3 must be written to the storage successfully. Messages 1-3
    // must be available.

    assert_eq!(
        storage.write_block(&block_2)?,
        StorageWriteResult::Success
    );

    assert_eq!(
        storage.write_block(&block_3)?,
        StorageWriteResult::Success
    );

    assert_eq!(storage.root_block()?, Some(*block_1.hash()));
    assert_eq!(storage.tail_block()?, Some(*block_3.hash()));

    assert!(!storage.has_block(&Hash::ZERO)?);
    assert!(storage.has_block(block_1.hash())?);
    assert!(storage.has_block(block_2.hash())?);
    assert!(storage.has_block(block_3.hash())?);

    assert_eq!(storage.next_block(&Hash::ZERO)?, Some(*block_1.hash()));
    assert_eq!(storage.next_block(block_1.hash())?, Some(*block_2.hash()));
    assert_eq!(storage.next_block(block_2.hash())?, Some(*block_3.hash()));
    assert!(storage.next_block(block_3.hash())?.is_none());

    assert!(storage.prev_block(&Hash::ZERO)?.is_none());
    assert_eq!(storage.prev_block(block_1.hash())?, Some(Hash::ZERO));
    assert_eq!(storage.prev_block(block_2.hash())?, Some(*block_1.hash()));
    assert_eq!(storage.prev_block(block_3.hash())?, Some(*block_2.hash()));

    assert!(storage.read_block(&Hash::ZERO)?.is_none());
    assert_eq!(storage.read_block(block_1.hash())?.as_ref(), Some(&block_1));
    assert_eq!(storage.read_block(block_2.hash())?.as_ref(), Some(&block_2));
    assert_eq!(storage.read_block(block_3.hash())?.as_ref(), Some(&block_3));

    assert!(storage.has_blob(blob_1.hash())?);
    assert!(storage.has_blob(blob_2.hash())?);
    assert!(storage.has_blob(blob_3.hash())?);

    assert_eq!(storage.find_blob(blob_1.hash())?, Some(*block_2.hash()));
    assert_eq!(storage.find_blob(blob_2.hash())?, Some(*block_3.hash()));
    assert_eq!(storage.find_blob(blob_3.hash())?, Some(*block_3.hash()));

    assert_eq!(storage.read_blob(blob_1.hash())?.as_ref(), Some(&blob_1));
    assert_eq!(storage.read_blob(blob_2.hash())?.as_ref(), Some(&blob_2));
    assert_eq!(storage.read_blob(blob_3.hash())?.as_ref(), Some(&blob_3));

    // 4. Tail block modification.
    //
    // Block 3 must be correctly replaced by the alternative block 3.
    // Original block 3 must be removed completely. Message 3 must disappear
    // from the storage.

    let block_3_alt = Block::builder()
        .with_prev_hash(block_2.hash())
        .with_inline_blobs([blob_2.clone()])
        .sign(&signing_key)?;

    assert_eq!(
        storage.write_block(&block_3_alt)?,
        StorageWriteResult::Success
    );

    assert_eq!(storage.root_block()?, Some(*block_1.hash()));
    assert_eq!(storage.tail_block()?, Some(*block_3_alt.hash()));

    assert!(!storage.has_block(&Hash::ZERO)?);
    assert!(storage.has_block(block_1.hash())?);
    assert!(storage.has_block(block_2.hash())?);
    assert!(!storage.has_block(block_3.hash())?);
    assert!(storage.has_block(block_3_alt.hash())?);

    assert_eq!(storage.next_block(&Hash::ZERO)?, Some(*block_1.hash()));
    assert_eq!(storage.next_block(block_1.hash())?, Some(*block_2.hash()));
    assert_eq!(storage.next_block(block_2.hash())?, Some(*block_3_alt.hash()));
    assert!(storage.next_block(block_3.hash())?.is_none());
    assert!(storage.next_block(block_3_alt.hash())?.is_none());

    assert!(storage.read_block(&Hash::default())?.is_none());
    assert_eq!(storage.read_block(block_1.hash())?.as_ref(), Some(&block_1));
    assert_eq!(storage.read_block(block_2.hash())?.as_ref(), Some(&block_2));
    assert!(storage.read_block(block_3.hash())?.is_none());
    assert_eq!(storage.read_block(block_3_alt.hash())?.as_ref(), Some(&block_3_alt));

    assert!(storage.has_blob(blob_1.hash())?);
    assert!(storage.has_blob(blob_2.hash())?);
    assert!(!storage.has_blob(blob_3.hash())?);

    assert_eq!(storage.find_blob(blob_1.hash())?, Some(*block_2.hash()));
    assert_eq!(storage.find_blob(blob_2.hash())?, Some(*block_3_alt.hash()));
    assert!(storage.find_blob(blob_3.hash())?.is_none());

    assert_eq!(storage.read_blob(blob_1.hash())?.as_ref(), Some(&blob_1));
    assert_eq!(storage.read_blob(blob_2.hash())?.as_ref(), Some(&blob_2));
    assert!(storage.read_blob(blob_3.hash())?.is_none());

    // 5. Middle block modification.
    //
    // Block 2 must be correctly replaced by the alternative block 2.
    // Alternative block 3 must be removed completely since its previous hash
    // is not correct anymore. Message 1 must disappear since it was stored in
    // previous block 2.

    let block_2_alt = Block::builder()
        .with_prev_hash(block_1.hash())
        .with_inline_blobs([blob_2.clone()])
        .sign(&signing_key)?;

    assert_eq!(
        storage.write_block(&block_2_alt)?,
        StorageWriteResult::Success
    );

    assert_eq!(storage.root_block()?, Some(*block_1.hash()));
    assert_eq!(storage.tail_block()?, Some(*block_2_alt.hash()));

    assert!(!storage.has_block(&Hash::ZERO)?);
    assert!(storage.has_block(block_1.hash())?);
    assert!(!storage.has_block(block_2.hash())?);
    assert!(storage.has_block(block_2_alt.hash())?);
    assert!(!storage.has_block(block_3.hash())?);
    assert!(!storage.has_block(block_3_alt.hash())?);

    assert_eq!(storage.next_block(&Hash::ZERO)?, Some(*block_1.hash()));
    assert_eq!(storage.next_block(block_1.hash())?, Some(*block_2_alt.hash()));

    assert!(storage.next_block(block_2.hash())?.is_none());
    assert!(storage.next_block(block_2_alt.hash())?.is_none());
    assert!(storage.next_block(block_3.hash())?.is_none());
    assert!(storage.next_block(block_3_alt.hash())?.is_none());

    assert!(storage.read_block(&Hash::ZERO)?.is_none());
    assert_eq!(storage.read_block(block_1.hash())?.as_ref(), Some(&block_1));

    assert!(storage.read_block(block_2.hash())?.is_none());
    assert_eq!(storage.read_block(block_2_alt.hash())?.as_ref(), Some(&block_2_alt));

    assert!(storage.read_block(block_3.hash())?.is_none());
    assert!(storage.read_block(block_3_alt.hash())?.is_none());

    assert!(!storage.has_blob(blob_1.hash())?);
    assert!(storage.has_blob(blob_2.hash())?);
    assert!(!storage.has_blob(blob_3.hash())?);

    assert!(storage.find_blob(blob_1.hash())?.is_none());
    assert_eq!(storage.find_blob(blob_2.hash())?, Some(*block_2_alt.hash()));
    assert!(storage.find_blob(blob_3.hash())?.is_none());

    assert!(storage.read_blob(blob_1.hash())?.is_none());
    assert_eq!(storage.read_blob(blob_2.hash())?.as_ref(), Some(&blob_2));
    assert!(storage.read_blob(blob_3.hash())?.is_none());

    // 6. Root block modification.
    //
    // Block 1 must be correctly replaced by the alternative block 1.
    // Alternative block 2 must be removed completely since its previous hash
    // is not correct anymore. No blocks but the alternative block 1 must remain
    // in the history at that point. All the messages must disappear.

    let block_1_alt = Block::builder()
        .with_inline_blobs([blob_1.clone()])
        .sign(&signing_key)?;

    assert_eq!(
        storage.write_block(&block_1_alt)?,
        StorageWriteResult::Success
    );

    assert_eq!(storage.root_block()?, Some(*block_1_alt.hash()));
    assert_eq!(storage.tail_block()?, Some(*block_1_alt.hash()));

    assert!(!storage.has_block(&Hash::ZERO)?);
    assert!(!storage.has_block(block_1.hash())?);
    assert!(storage.has_block(block_1_alt.hash())?);
    assert!(!storage.has_block(block_2.hash())?);
    assert!(!storage.has_block(block_2_alt.hash())?);
    assert!(!storage.has_block(block_3.hash())?);
    assert!(!storage.has_block(block_3_alt.hash())?);

    assert_eq!(storage.next_block(&Hash::ZERO)?, Some(*block_1_alt.hash()));

    assert!(storage.next_block(block_1.hash())?.is_none());
    assert!(storage.next_block(block_1_alt.hash())?.is_none());
    assert!(storage.next_block(block_2.hash())?.is_none());
    assert!(storage.next_block(block_2_alt.hash())?.is_none());
    assert!(storage.next_block(block_3.hash())?.is_none());
    assert!(storage.next_block(block_3_alt.hash())?.is_none());

    assert!(storage.read_block(&Hash::ZERO)?.is_none());

    assert!(storage.read_block(block_1.hash())?.is_none());
    assert_eq!(storage.read_block(block_1_alt.hash())?.as_ref(), Some(&block_1_alt));

    assert!(storage.read_block(block_2.hash())?.is_none());
    assert!(storage.read_block(block_2_alt.hash())?.is_none());

    assert!(storage.read_block(block_3.hash())?.is_none());
    assert!(storage.read_block(block_3_alt.hash())?.is_none());

    assert!(storage.has_blob(blob_1.hash())?);
    assert!(!storage.has_blob(blob_2.hash())?);
    assert!(!storage.has_blob(blob_3.hash())?);

    assert_eq!(storage.find_blob(blob_1.hash())?, Some(*block_1_alt.hash()));
    assert!(storage.find_blob(blob_2.hash())?.is_none());
    assert!(storage.find_blob(blob_3.hash())?.is_none());

    assert_eq!(storage.read_blob(blob_1.hash())?.as_ref(), Some(&blob_1));
    assert!(storage.read_blob(blob_2.hash())?.is_none());
    assert!(storage.read_blob(blob_3.hash())?.is_none());

    // 7. Try to write blocks with the same messages.
    //
    // New alternative block 2 must be correctly written, but new alternative
    // block 3 must be rejected since it contains the same message.

    let new_block_2_alt = Block::builder()
        .with_prev_hash(block_1_alt.hash())
        .with_inline_blobs([blob_2.clone()])
        .sign(&signing_key)?;

    let new_block_3_alt = Block::builder()
        .with_prev_hash(new_block_2_alt.hash())
        .with_inline_blobs([
            blob_3.clone(),
            blob_1.clone() // repeat block_1_alt
        ])
        .sign(&signing_key)?;

    assert_eq!(
        storage.write_block(&new_block_2_alt)?,
        StorageWriteResult::Success
    );

    assert_eq!(
        storage.write_block(&new_block_3_alt)?,
        StorageWriteResult::BlockHasDuplicateHistoryBlobs
    );

    assert!(storage.has_block(block_1_alt.hash())?);
    assert!(storage.has_block(new_block_2_alt.hash())?);
    assert!(!storage.has_block(new_block_3_alt.hash())?);

    assert!(storage.has_blob(blob_1.hash())?);
    assert!(storage.has_blob(blob_2.hash())?);
    assert!(!storage.has_blob(blob_3.hash())?);

    assert_eq!(storage.find_blob(blob_1.hash())?, Some(*block_1_alt.hash()));
    assert_eq!(storage.find_blob(blob_2.hash())?, Some(*new_block_2_alt.hash()));
    assert!(storage.find_blob(blob_3.hash())?.is_none());

    assert_eq!(storage.read_blob(blob_1.hash())?.as_ref(), Some(&blob_1));
    assert_eq!(storage.read_blob(blob_2.hash())?.as_ref(), Some(&blob_2));
    assert!(storage.read_blob(blob_3.hash())?.is_none());

    Ok(())
}
