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
use crate::message::Message;
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

    /// Provided block has messages with the same hash value.
    BlockHasDuplicateMessages,

    /// Provided block has messages which are already stored in previous blocks.
    BlockHasDuplicateHistoryMessages,

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

    /// Try to read a block with provided hash. Return `Ok(None)` if there's no
    /// such block stored in the current storage.
    fn read_block(&self, hash: &Hash) -> Result<Option<Block>, StorageError>;

    /// Try to write a block to the storage.
    ///
    /// This method must automatically prune excess blocks if this one modifies
    /// the history. History modifications, block and stored messages must be
    /// verified outside of this trait so this method should work without extra
    /// verifications (but they still can be implemented if wanted).
    ///
    /// Messages with the same hash must not be allowed. If a new block is
    /// attempting to be added to the history, then this method must return
    /// `Ok(false)` if some message in this new block is already stored in some
    /// previous block.
    ///
    /// Return `Ok(true)` if stored history was modified, otherwise `Ok(false)`.
    ///
    /// # Blocks writing rules
    ///
    /// - If a block with the same hash is already stored then reject it and
    ///   return `StorageWriteResult::BlockAlreadyStored`.
    /// - If the provided block has messages with duplicate hashes then it must
    ///   be rejected and return
    ///   `StorageWriteResult::BlockHasDuplicateMessages`.
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
    ///         - If any block message hash is stored on the chain already then
    ///           the block must be rejected, return
    ///           `StorageWriteResult::BlockHasDuplicateHistoryMessages`;
    ///         - Otherwise write this block to the end of the chain and return
    ///           `StorageWriteResult::Success`.
    ///     - If the previous block is not the tail block of the history then:
    ///         - Remove all the following blocks;
    ///         - If there's no duplicate messages then append the new block to
    ///           the chain;
    ///         - Otherwise revert blocks removal, reject new block and return
    ///           `StorageWriteResult::BlockHasDuplicateHistoryMessages`.
    fn write_block(
        &self,
        block: &Block
    ) -> Result<StorageWriteResult, StorageError>;

    /// Check if current storage has a block which references a message with
    /// provided hash.
    ///
    /// Even if a block has message with this hash *stored* as inline message,
    /// this method will return `Ok(false)`.
    fn is_message_referenced(&self, hash: &Hash) -> Result<bool, StorageError> {
        let mut curr_block = self.root_block()?;

        while let Some(block_hash) = &curr_block {
            if let Some(block) = self.read_block(block_hash)?
                && block.ref_messages().contains(hash)
            {
                return Ok(true);
            }

            curr_block = self.next_block(block_hash)?;
        }

        Ok(false)
    }

    /// Check if current storage has a block which has a message with provided
    /// hash attached to it as inline message.
    ///
    /// This method will return `Ok(false)` even if a message with provided hash
    /// is referenced in some block.
    fn is_message_stored(&self, hash: &Hash) -> Result<bool, StorageError> {
        let mut curr_block = self.root_block()?;

        while let Some(block_hash) = &curr_block {
            if let Some(block) = self.read_block(block_hash)? {
                let has_ref = block.inline_messages()
                    .iter()
                    .any(|message| message.hash() == hash);

                if has_ref {
                    return Ok(true);
                }
            }

            curr_block = self.next_block(block_hash)?;
        }

        Ok(false)
    }

    /// Check if current storage has a block which either stores a message with
    /// provided hash or references it.
    fn has_message(&self, hash: &Hash) -> Result<bool, StorageError> {
        let mut curr_block = self.root_block()?;

        while let Some(block_hash) = &curr_block {
            if let Some(block) = self.read_block(block_hash)? {
                if block.ref_messages().contains(hash) {
                    return Ok(true);
                }

                for message in block.inline_messages() {
                    if message.hash() == hash {
                        return Ok(true);
                    }
                }
            }

            curr_block = self.next_block(block_hash)?;
        }

        Ok(false)
    }

    /// Find block hash to which message with provided hash is attached or being
    /// referenced in. Return `Ok(None)` if there's no such message or block.
    ///
    /// This method will return block hash for provided message hash even if the
    /// message with this hash *is not stored* in the storage and only being
    /// referenced in a block.
    fn find_message(
        &self,
        hash: &Hash
    ) -> Result<Option<Hash>, StorageError> {
        let mut curr_block = self.root_block()?;

        while let Some(block_hash) = &curr_block {
            if let Some(block) = self.read_block(block_hash)? {
                if block.ref_messages().contains(hash) {
                    return Ok(Some(*block_hash));
                }

                for message in block.inline_messages() {
                    if message.hash() == hash {
                        return Ok(Some(*block_hash));
                    }
                }
            }

            curr_block = self.next_block(block_hash)?;
        }

        Ok(None)
    }

    /// Try to read a message with provided hash. Return `Ok(None)` if message
    /// with provided hash is not stored in the current storage.
    fn read_message(
        &self,
        hash: &Hash
    ) -> Result<Option<Message>, StorageError> {
        let Some(block) = self.find_message(hash)? else {
            return Ok(None);
        };

        let Some(block) = self.read_block(&block)? else {
            return Ok(None);
        };

        Ok(block.inline_messages()
            .iter()
            .find(|tr| tr.hash() == hash)
            .cloned())
    }

    /// Try to write a message to the current storage.
    ///
    /// Return `Ok(true)` if message was successfully written to the storage or
    /// it was stored already.
    ///
    /// Return `Ok(false)` if message was not written.
    fn write_message(&self, message: &Message) -> Result<bool, StorageError>;
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
    fn is_message_referenced(&self, hash: &Hash) -> Result<bool, StorageError> {
        T::is_message_referenced(self, hash)
    }

    #[inline]
    fn is_message_stored(&self, hash: &Hash) -> Result<bool, StorageError> {
        T::is_message_stored(self, hash)
    }

    #[inline]
    fn has_message(&self, hash: &Hash) -> Result<bool, StorageError> {
        T::has_message(self, hash)
    }

    #[inline]
    fn find_message(&self, hash: &Hash) -> Result<Option<Hash>, StorageError> {
        T::find_message(self, hash)
    }

    #[inline]
    fn read_message(
        &self,
        hash: &Hash
    ) -> Result<Option<Message>, StorageError> {
        T::read_message(self, hash)
    }

    #[inline]
    fn write_message(&self, blob: &Message) -> Result<bool, StorageError> {
        T::write_message(self, blob)
    }
}

impl<T> From<T> for Box<dyn Storage> where T: Storage + 'static {
    #[inline]
    fn from(storage: T) -> Self {
        Box::new(storage)
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
    assert!(!storage.has_message(&Hash::ZERO)?);
    assert!(storage.find_message(&Hash::ZERO)?.is_none());
    assert!(storage.read_message(&Hash::ZERO)?.is_none());

    // Prepare test messages.

    let mut rng = ChaCha8Rng::seed_from_u64(123);

    let signing_key = SigningKey::random(&mut rng);

    let message_1 = Message::create(&signing_key, b"Message 1".as_slice())?;
    let message_2 = Message::create(&signing_key, b"Message 2".as_slice())?;
    let message_3 = Message::create(&signing_key, b"Message 3".as_slice())?;

    // Prepare test blocks.

    let block_1 = Block::builder()
        .sign(&signing_key)
        .unwrap();

    assert!(block_1.is_root());
    assert_eq!(block_1.prev_hash(), &Hash::ZERO);

    let block_2 = Block::builder()
        .with_prev_hash(block_1.hash())
        .with_inline_messages([message_1.clone()])
        .sign(&signing_key)?;

    let block_3 = Block::builder()
        .with_prev_hash(block_2.hash())
        .with_inline_messages([message_2.clone(), message_3.clone()])
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

    assert!(!storage.has_message(message_1.hash())?);
    assert!(!storage.has_message(message_2.hash())?);
    assert!(!storage.has_message(message_3.hash())?);

    assert!(storage.find_message(message_1.hash())?.is_none());
    assert!(storage.find_message(message_2.hash())?.is_none());
    assert!(storage.find_message(message_3.hash())?.is_none());

    assert!(storage.read_message(message_1.hash())?.is_none());
    assert!(storage.read_message(message_2.hash())?.is_none());
    assert!(storage.read_message(message_3.hash())?.is_none());

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

    assert!(storage.has_message(message_1.hash())?);
    assert!(storage.has_message(message_2.hash())?);
    assert!(storage.has_message(message_3.hash())?);

    assert_eq!(storage.find_message(message_1.hash())?, Some(*block_2.hash()));
    assert_eq!(storage.find_message(message_2.hash())?, Some(*block_3.hash()));
    assert_eq!(storage.find_message(message_3.hash())?, Some(*block_3.hash()));

    assert_eq!(storage.read_message(message_1.hash())?.as_ref(), Some(&message_1));
    assert_eq!(storage.read_message(message_2.hash())?.as_ref(), Some(&message_2));
    assert_eq!(storage.read_message(message_3.hash())?.as_ref(), Some(&message_3));

    // 4. Tail block modification.
    //
    // Block 3 must be correctly replaced by the alternative block 3.
    // Original block 3 must be removed completely. Message 3 must disappear
    // from the storage.

    let block_3_alt = Block::builder()
        .with_prev_hash(block_2.hash())
        .with_inline_messages([message_2.clone()])
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

    assert!(storage.has_message(message_1.hash())?);
    assert!(storage.has_message(message_2.hash())?);
    assert!(!storage.has_message(message_3.hash())?);

    assert_eq!(storage.find_message(message_1.hash())?, Some(*block_2.hash()));
    assert_eq!(storage.find_message(message_2.hash())?, Some(*block_3_alt.hash()));
    assert!(storage.find_message(message_3.hash())?.is_none());

    assert_eq!(storage.read_message(message_1.hash())?.as_ref(), Some(&message_1));
    assert_eq!(storage.read_message(message_2.hash())?.as_ref(), Some(&message_2));
    assert!(storage.read_message(message_3.hash())?.is_none());

    // 5. Middle block modification.
    //
    // Block 2 must be correctly replaced by the alternative block 2.
    // Alternative block 3 must be removed completely since its previous hash
    // is not correct anymore. Message 1 must disappear since it was stored in
    // previous block 2.

    let block_2_alt = Block::builder()
        .with_prev_hash(block_1.hash())
        .with_inline_messages([message_2.clone()])
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

    assert!(!storage.has_message(message_1.hash())?);
    assert!(storage.has_message(message_2.hash())?);
    assert!(!storage.has_message(message_3.hash())?);

    assert!(storage.find_message(message_1.hash())?.is_none());
    assert_eq!(storage.find_message(message_2.hash())?, Some(*block_2_alt.hash()));
    assert!(storage.find_message(message_3.hash())?.is_none());

    assert!(storage.read_message(message_1.hash())?.is_none());
    assert_eq!(storage.read_message(message_2.hash())?.as_ref(), Some(&message_2));
    assert!(storage.read_message(message_3.hash())?.is_none());

    // 6. Root block modification.
    //
    // Block 1 must be correctly replaced by the alternative block 1.
    // Alternative block 2 must be removed completely since its previous hash
    // is not correct anymore. No blocks but the alternative block 1 must remain
    // in the history at that point. All the messages must disappear.

    let block_1_alt = Block::builder()
        .with_inline_messages([message_1.clone()])
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

    assert!(storage.has_message(message_1.hash())?);
    assert!(!storage.has_message(message_2.hash())?);
    assert!(!storage.has_message(message_3.hash())?);

    assert_eq!(storage.find_message(message_1.hash())?, Some(*block_1_alt.hash()));
    assert!(storage.find_message(message_2.hash())?.is_none());
    assert!(storage.find_message(message_3.hash())?.is_none());

    assert_eq!(storage.read_message(message_1.hash())?.as_ref(), Some(&message_1));
    assert!(storage.read_message(message_2.hash())?.is_none());
    assert!(storage.read_message(message_3.hash())?.is_none());

    // 7. Try to write blocks with the same messages.
    //
    // New alternative block 2 must be correctly written, but new alternative
    // block 3 must be rejected since it contains the same message.

    let new_block_2_alt = Block::builder()
        .with_prev_hash(block_1_alt.hash())
        .with_inline_messages([message_2.clone()])
        .sign(&signing_key)?;

    let new_block_3_alt = Block::builder()
        .with_prev_hash(new_block_2_alt.hash())
        .with_inline_messages([
            message_3.clone(),
            message_1.clone() // repeat block_1_alt
        ])
        .sign(&signing_key)?;

    assert_eq!(
        storage.write_block(&new_block_2_alt)?,
        StorageWriteResult::Success
    );

    assert_eq!(
        storage.write_block(&new_block_3_alt)?,
        StorageWriteResult::BlockHasDuplicateHistoryMessages
    );

    assert!(storage.has_block(block_1_alt.hash())?);
    assert!(storage.has_block(new_block_2_alt.hash())?);
    assert!(!storage.has_block(new_block_3_alt.hash())?);

    assert!(storage.has_message(message_1.hash())?);
    assert!(storage.has_message(message_2.hash())?);
    assert!(!storage.has_message(message_3.hash())?);

    assert_eq!(storage.find_message(message_1.hash())?, Some(*block_1_alt.hash()));
    assert_eq!(storage.find_message(message_2.hash())?, Some(*new_block_2_alt.hash()));
    assert!(storage.find_message(message_3.hash())?.is_none());

    assert_eq!(storage.read_message(message_1.hash())?.as_ref(), Some(&message_1));
    assert_eq!(storage.read_message(message_2.hash())?.as_ref(), Some(&message_2));
    assert!(storage.read_message(message_3.hash())?.is_none());

    Ok(())
}
