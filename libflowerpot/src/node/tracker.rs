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
use crate::crypto::sign::{VerifyingKey, SignatureError};
use crate::block::{Block, BlockContent};
use crate::storage::Storage;

#[derive(Debug, thiserror::Error)]
pub enum TrackerError<S: Storage> {
    #[error(transparent)]
    Storage(S::Error),

    #[error("failed to verify block signature: {0}")]
    Signature(#[from] SignatureError)
}

/// Tracker is a special struct that keeps track of the blocks history in the
/// blockchain and synchronizes it with a storage if it's provided.
pub enum Tracker<S: Storage> {
    /// Data + metadata tracker.
    Full(S),

    /// Metadata-only tracker.
    HeadOnly {
        /// List of blockchain blocks hashes.
        blocks: Vec<Hash>,

        /// List of transactions indexed in the blocks from the blockchain.
        ///
        /// This table is needed to prevent double-indexing of transactions.
        transactions: HashSet<Hash>,

        /// List of the blockchain validators for the next block in the history.
        validators: Vec<VerifyingKey>
    }
}

impl<S: Storage> Default for Tracker<S> {
    fn default() -> Self {
        Self::HeadOnly {
            blocks: Vec::new(),
            transactions: HashSet::new(),
            validators: Vec::new()
        }
    }
}

impl<S: Storage> Tracker<S> {
    /// Create new tracker from provided blockchain storage.
    #[inline(always)]
    pub const fn from_storage(storage: S) -> Self {
        Self::Full(storage)
    }

    /// Try to get the root block of the blockchain.
    pub fn get_root_block(&self) -> Result<Option<Hash>, TrackerError<S>> {
        match self {
            Self::Full(storage) => storage.root_block()
                .map_err(TrackerError::Storage),

            Self::HeadOnly { blocks, .. } => Ok(blocks.first().copied())
        }
    }

    /// Try to get the tail block of the blockchain.
    pub fn get_tail_block(&self) -> Result<Option<Hash>, TrackerError<S>> {
        match self {
            Self::Full(storage) => storage.tail_block()
                .map_err(TrackerError::Storage),

            Self::HeadOnly { blocks, .. } => Ok(blocks.last().copied())
        }
    }

    /// Try to check if transaction with provided hash is stored in the
    /// blockchain.
    pub fn has_transaction(
        &self,
        hash: &Hash
    ) -> Result<bool, TrackerError<S>> {
        match self {
            Self::Full(storage) => storage.has_transaction(hash)
                .map_err(TrackerError::Storage),

            Self::HeadOnly { transactions, .. } => {
                Ok(transactions.contains(hash))
            }
        }
    }

    /// Try to check if block with provided hash is stored in the blockchain.
    pub fn has_block(&self, hash: &Hash) -> Result<bool, TrackerError<S>> {
        match self {
            Self::Full(storage) => storage.has_block(hash)
                .map_err(TrackerError::Storage),

            Self::HeadOnly { blocks, .. } => Ok(blocks.contains(hash))
        }
    }

    /// Try to get a part of the known blockchain history.
    ///
    /// `offset = 0` is the root block of the blockchain.
    pub fn get_history(
        &self,
        offset: usize,
        max_length: usize
    ) -> Result<Box<[Hash]>, TrackerError<S>> {
        match self {
            Self::Full(storage) => {
                // FIXME: highly suboptimal since by default requires to iterate
                // over the whole storage to reach the offset position.

                storage.history()
                    .skip(offset)
                    .take(max_length)
                    .collect::<Result<Box<[Hash]>, _>>()
                    .map_err(TrackerError::Storage)
            }

            Self::HeadOnly { blocks, .. } => {
                let history = blocks.iter()
                    .skip(offset)
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
    /// **It is expected that the block is already validated.** This method
    /// doesn't verify the block. It calculates the distance and compares it
    /// with another blocks to choose the best fork possible, or just pushes
    /// this block to the end of the blockchain if there's no forks in it.
    ///
    /// Return `Ok(true)` if the blockchain history was modified. Otherwise
    /// return `Ok(false)`.
    pub fn try_write_block(
        &mut self,
        block: &Block
    ) -> Result<bool, TrackerError<S>> {
        // Try to get the tail block of the blockchain.
        match self.get_tail_block()? {
            // If there exist a tail block then we need to modify the existing
            // history.
            Some(tail_block) => {
                // If the block is the next one to our tail block then we simply
                // need to push it to the end of the history and that's it.
                if block.previous_hash() == &tail_block {
                    match self {
                        Self::Full(storage) => storage.write_block(block)
                            .map_err(TrackerError::Storage),

                        Self::HeadOnly { blocks, transactions, validators } => {
                            // Store this block in the history.
                            blocks.push(*block.current_hash());

                            // Check the block's content.
                            match block.content() {
                                BlockContent::Data(_) => (),

                                // If it contains transactions - then index these.
                                BlockContent::Transactions(content) => {
                                    let mut written = Vec::with_capacity(content.len());

                                    for transaction in content {
                                        let hash = *transaction.hash();

                                        // If it happened that transaction was
                                        // already indexed then revert this
                                        // change and reject the block.
                                        if !transactions.insert(hash) {
                                            // Remove only written transactions
                                            // because they're guaranteed to not
                                            // to be indexed before by previous
                                            // blocks, while future transactions
                                            // are not checked yet.
                                            for hash in written {
                                                transactions.remove(&hash);
                                            }

                                            return Ok(false);
                                        }

                                        else {
                                            written.push(hash);
                                        }
                                    }
                                }

                                // If it contains validators - then use them.
                                BlockContent::Validators(content) => {
                                    *validators = content.to_vec();
                                }
                            }

                            Ok(true)
                        }
                    }
                }

                // Otherwise this block wants to update the blockchain history.
                // We must determine whether it's allowed to.
                else {
                    todo!("history modification")
                }
            }

            // If there's no tail block - then there's no root block either,
            // thus we can store received block as the root one, if it is of
            // root type.
            None if block.is_root() => {
                match self {
                    Self::Full(storage) => storage.write_block(block)
                        .map_err(TrackerError::Storage),

                    Self::HeadOnly { blocks, transactions, validators } => {
                        // Derive the block's author.
                        let (is_valid, author) = block.verify()?;

                        // Reject the block if it happened to be invalid.
                        if !is_valid {
                            return Ok(false);
                        }

                        // Clear the containers just in case.
                        blocks.clear();
                        transactions.clear();
                        validators.clear();

                        // Store this block in the history.
                        blocks.push(*block.current_hash());

                        // Store the block's author as the blockchain validator.
                        validators.push(author);

                        // Check the block's content.
                        match block.content() {
                            BlockContent::Data(_) => (),

                            // If it contains transactions - then index these.
                            BlockContent::Transactions(content) => {
                                for transaction in content {
                                    // If it happened that transaction was
                                    // already indexed then revert this change
                                    // and reject the block.
                                    if !transactions.insert(*transaction.hash()) {
                                        blocks.clear();
                                        transactions.clear();
                                        validators.clear();

                                        return Ok(false);
                                    }
                                }
                            }

                            // If it contains validators - then use them instead
                            // of the block's author.
                            BlockContent::Validators(content) => {
                                *validators = content.to_vec();
                            }
                        }

                        Ok(true)
                    }
                }
            }

            // Received block is not of a root type, thus we can't use it as a
            // root block of the blockchain and have to reject.
            None => Ok(false)
        }
    }
}
