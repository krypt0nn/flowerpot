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

use std::collections::HashSet;

use crate::crypto::hash::Hash;
use crate::crypto::sign::SignatureError;
use crate::blob::Message;
use crate::block::Block;
use crate::storage::{Storage, StorageError, StorageWriteResult};

#[derive(Debug, thiserror::Error)]
pub enum TrackerError {
    #[error(transparent)]
    Storage(StorageError),

    #[error("failed to verify block signature: {0}")]
    Signature(#[from] SignatureError)
}

/// Tracker is a special struct that keeps track of the blocks history in the
/// blockchain and synchronizes it with a storage if it's provided.
pub enum Tracker {
    /// Data + metadata tracker.
    Full(Box<dyn Storage + Send>),

    /// Metadata-only tracker.
    HeadOnly {
        /// List of messages indexed in the blocks.
        ///
        /// This table is needed to prevent double-indexing of messages.
        messages: HashSet<Hash>,

        /// List of blocks hashes in historic order.
        blocks: Vec<Hash>
    }
}

impl Default for Tracker {
    fn default() -> Self {
        Self::HeadOnly {
            messages: HashSet::new(),
            blocks: Vec::new()
        }
    }
}

impl Tracker {
    /// Create new tracker from provided blockchain storage.
    #[inline]
    pub fn from_storage(storage: impl Storage + Send + 'static) -> Self {
        Self::Full(Box::new(storage))
    }

    /// Get reference to the blockchain storage if the tracker owns it.
    #[inline]
    pub fn storage(&self) -> Option<&dyn Storage> {
        match self {
            Self::Full(storage) => Some(storage.as_ref()),
            Self::HeadOnly { .. } => None
        }
    }

    /// Try to get the root block of the blockchain.
    pub fn get_root_block(&self) -> Result<Option<Hash>, TrackerError> {
        match self {
            Self::Full(storage) => storage.root_block()
                .map_err(TrackerError::Storage),

            Self::HeadOnly { blocks, .. } => Ok(blocks.first().copied())
        }
    }

    /// Try to get the tail block of the blockchain.
    pub fn get_tail_block(&self) -> Result<Option<Hash>, TrackerError> {
        match self {
            Self::Full(storage) => storage.tail_block()
                .map_err(TrackerError::Storage),

            Self::HeadOnly { blocks, .. } => Ok(blocks.last().copied())
        }
    }

    /// Try to check if message with provided hash is stored in the blockchain.
    pub fn has_message(&self, hash: &Hash) -> Result<bool, TrackerError> {
        match self {
            Self::Full(storage) => storage.has_message(hash)
                .map_err(TrackerError::Storage),

            Self::HeadOnly { messages, .. } => {
                Ok(messages.contains(hash))
            }
        }
    }

    /// Try to check if block with provided hash is stored in the blockchain.
    pub fn has_block(&self, hash: &Hash) -> Result<bool, TrackerError> {
        match self {
            Self::Full(storage) => storage.has_block(hash)
                .map_err(TrackerError::Storage),

            Self::HeadOnly { blocks, .. } => Ok(blocks.contains(hash))
        }
    }

    /// Try to read message from the underlying blockchain storage.
    ///
    /// This method will return `Ok(Some(..))` *only* if tracker has a storage.
    /// Head-only tracker doesn't store any actual data besides the hashes and
    /// cannot read transactions.
    pub fn read_message(
        &self,
        hash: &Hash
    ) -> Result<Option<Message>, TrackerError> {
        match self {
            Self::Full(storage) => storage.read_message(hash)
                .map_err(TrackerError::Storage),

            Self::HeadOnly { .. } => Ok(None)
        }
    }

    /// Try to read block from the underlying blockchain storage.
    ///
    /// This method will return `Ok(Some(..))` *only* if tracker has a storage.
    /// Head-only tracker doesn't store any actual data besides the hashes and
    /// cannot read block.
    pub fn read_block(
        &self,
        hash: &Hash
    ) -> Result<Option<Block>, TrackerError> {
        match self {
            Self::Full(storage) => storage.read_block(hash)
                .map_err(TrackerError::Storage),

            Self::HeadOnly { .. } => Ok(None)
        }
    }

    /// Try to get a part of the known blockchain history. Returned slice will
    /// *not* contain the `since_block` hash and be at most `max_length` values
    /// long.
    pub fn get_history(
        &self,
        since_block: Hash,
        max_length: usize
    ) -> Result<Box<[Hash]>, TrackerError> {
        match self {
            Self::Full(storage) => {
                let mut history = Vec::with_capacity(max_length);
                let mut curr_block = since_block;

                while history.len() < max_length {
                    let block = storage.next_block(&curr_block)
                        .map_err(TrackerError::Storage)?;

                    let Some(block) = block else {
                        break;
                    };

                    curr_block = block;

                    history.push(block);
                }

                Ok(history.into_boxed_slice())
            }

            Self::HeadOnly { blocks, .. } => {
                let history = blocks.iter()
                    .skip_while(|hash| hash != &&since_block)
                    .skip(1)
                    .take(max_length)
                    .copied()
                    .collect();

                Ok(history)
            }
        }
    }

    /// Try to write provided block to the tracker's metadata and, if provided,
    /// the underlying blockchain storage.
    ///
    /// **Note:** this method doesn't verify the block and just attempts to
    /// write it to the metadata / storage. All the checks must happen outside
    /// of this method!
    pub fn try_write_block(
        &mut self,
        block: &Block
    ) -> Result<StorageWriteResult, TrackerError> {
        #[cfg(feature = "tracing")]
        tracing::debug!(
            curr_hash = block.hash().to_base64(),
            prev_hash = block.prev_hash().to_base64(),
            "trying to write block to the tracker"
        );

        // Try to get the tail block of the blockchain.
        match self.get_tail_block()? {
            // If there exist a tail block then we need to modify the existing
            // history.
            Some(tail_block) => {
                #[cfg(feature = "tracing")]
                tracing::debug!(
                    hash = tail_block.to_base64(),
                    "tail block found"
                );

                // If the block is the next one to our tail block then we simply
                // need to push it to the end of the history and that's it.
                if block.prev_hash() == &tail_block {
                    #[cfg(feature = "tracing")]
                    tracing::debug!(
                        curr_hash = block.hash().to_base64(),
                        prev_hash = block.prev_hash().to_base64(),
                        tail_block = tail_block.to_base64(),
                        "trying to write block to the end of the known blockchain history, no modifications needed"
                    );

                    match self {
                        Self::Full(storage) => storage.write_block(block)
                            .map_err(TrackerError::Storage),

                        Self::HeadOnly { messages, blocks, .. } => {
                            // Store this block in the history.
                            blocks.push(*block.hash());

                            // Update indexed messages table.
                            let mut written = Vec::with_capacity(block.messages().len());

                            for message in block.messages() {
                                // If it happened that message was already
                                // indexed then revert this change and reject
                                // the block.
                                if !messages.insert(*message.hash()) {
                                    #[cfg(feature = "tracing")]
                                    tracing::warn!(
                                        curr_hash = block.hash().to_base64(),
                                        prev_hash = block.prev_hash().to_base64(),
                                        message_hash = message.hash().to_base64(),
                                        "received block contained already indexed messages, rejecting it"
                                    );

                                    // Remove only written messages because
                                    // they're guaranteed to not to be indexed
                                    // before by previous blocks, while future
                                    // messages are not checked yet.
                                    for hash in written {
                                        messages.remove(&hash);
                                    }

                                    return Ok(StorageWriteResult::BlockHasDuplicateHistoryMessages);
                                }

                                else {
                                    written.push(*message.hash());
                                }
                            }

                            Ok(StorageWriteResult::Success)
                        }
                    }
                }

                // Otherwise this block wants to update the blockchain history.
                // We must determine whether it's allowed to.
                else {
                    #[cfg(feature = "tracing")]
                    tracing::debug!(
                        curr_hash = block.hash().to_base64(),
                        prev_hash = block.prev_hash().to_base64(),
                        tail_block = tail_block.to_base64(),
                        "trying to modify existing blockchain history"
                    );

                    todo!("history modification")
                }
            }

            // If there's no tail block - then there's no root block either,
            // thus we can store received block as the root one, if it is of
            // root type.
            None if block.is_root() => {
                #[cfg(feature = "tracing")]
                tracing::debug!(
                    curr_hash = block.hash().to_base64(),
                    prev_hash = block.prev_hash().to_base64(),
                    "no root block found but received block is of root type, writing it to the tracker"
                );

                match self {
                    Self::Full(storage) => storage.write_block(block)
                        .map_err(TrackerError::Storage),

                    Self::HeadOnly { messages, blocks } => {
                        // Clear the containers just in case.
                        blocks.clear();
                        messages.clear();

                        // Store this block in the history.
                        blocks.push(*block.hash());

                        for message in block.messages() {
                            // If it happened that transaction was
                            // already indexed then revert this change
                            // and reject the block.
                            if !messages.insert(*message.hash()) {
                                #[cfg(feature = "tracing")]
                                tracing::warn!(
                                    curr_hash = block.hash().to_base64(),
                                    prev_hash = block.prev_hash().to_base64(),
                                    "received block contained already indexed messages, rejecting it"
                                );

                                blocks.clear();
                                messages.clear();

                                return Ok(StorageWriteResult::BlockHasDuplicateMessages);
                            }
                        }

                        Ok(StorageWriteResult::Success)
                    }
                }
            }

            // Received block is not of a root type, thus we can't use it as a
            // root block of the blockchain and have to reject.
            None => {
                #[cfg(feature = "tracing")]
                tracing::debug!(
                    curr_hash = block.hash().to_base64(),
                    prev_hash = block.prev_hash().to_base64(),
                    "no root block found and received block is not of a root type"
                );

                Ok(StorageWriteResult::NotRootBlock)
            }
        }
    }
}
