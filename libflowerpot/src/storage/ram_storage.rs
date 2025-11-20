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

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock, RwLockReadGuard};

use crate::crypto::hash::Hash;
use crate::crypto::sign::SignatureError;
use crate::message::Message;
use crate::block::Block;

use super::{Storage, StorageWriteResult, StorageError};

#[derive(Debug, thiserror::Error)]
pub enum RamStorageError {
    #[error("failed to lock internal data")]
    Lock,

    #[error("failed to verify signature: {0}")]
    Signature(#[from] SignatureError)
}

#[inline]
fn has_message(
    blocks: &RwLockReadGuard<'_, HashMap<Hash, Block>>,
    messages: &RwLockReadGuard<'_, HashMap<Hash, Message>>,
    hash: &Hash
) -> bool {
    if messages.contains_key(hash) {
        return true;
    }

    for block in blocks.values() {
        if block.ref_messages().contains(hash) {
            return true;
        }

        let has_ref = block.inline_messages()
            .iter()
            .any(|message| message.hash() == hash);

        if has_ref {
            return true;
        }
    }

    false
}

#[inline]
fn find_message(
    blocks: &RwLockReadGuard<'_, HashMap<Hash, Block>>,
    hash: &Hash
) -> Option<Hash> {
    for (block_hash, block) in blocks.iter() {
        if block.ref_messages().contains(hash) {
            return Some(*block_hash);
        }

        let has_ref = block.inline_messages()
            .iter()
            .any(|message| message.hash() == hash);

        if has_ref {
            return Some(*block_hash);
        }
    }

    None
}

#[inline]
fn read_message(
    blocks: &RwLockReadGuard<'_, HashMap<Hash, Block>>,
    messages: &RwLockReadGuard<'_, HashMap<Hash, Message>>,
    hash: &Hash
) -> Option<Message> {
    if let Some(message) = messages.get(hash).cloned() {
        return Some(message);
    }

    for block in blocks.values() {
        let message = block.inline_messages()
            .iter()
            .find(|message| message.hash() == hash);

        if let Some(message) = message.cloned() {
            return Some(message);
        }
    }

    None
}

#[derive(Default, Debug, Clone)]
pub struct RamStorage {
    /// Table of stored blocks.
    blocks: Arc<RwLock<HashMap<Hash, Block>>>,

    /// Table of stored messages.
    messages: Arc<RwLock<HashMap<Hash, Message>>>,

    /// List of blocks hashes in historical order.
    history: Arc<RwLock<Vec<Hash>>>
}

impl RamStorage {
    /// Try to make a storage from the provided blocks chain.
    /// Return `Ok(Some(..))` if the chain is valid and ordered properly,
    /// `Ok(None)` if storage couldn't write some of the blocks due to invalid
    /// order.
    pub fn new<T: Into<Block>>(
        history: impl IntoIterator<Item = T>
    ) -> Result<Option<Self>, StorageError> {
        let storage = Self::default();

        for block in history {
            if storage.write_block(&block.into())? != StorageWriteResult::Success {
                return Ok(None);
            }
        }

        Ok(Some(storage))
    }
}

impl Storage for RamStorage {
    fn root_block(&self) -> Result<Option<Hash>, StorageError> {
        let Ok(lock) = self.history.read() else {
            return Err(Box::new(RamStorageError::Lock) as StorageError);
        };

        Ok(lock.first().copied())
    }

    fn tail_block(&self) -> Result<Option<Hash>, StorageError> {
        let Ok(lock) = self.history.read() else {
            return Err(Box::new(RamStorageError::Lock) as StorageError);
        };

        Ok(lock.last().copied())
    }

    fn has_block(&self, hash: &Hash) -> Result<bool, StorageError> {
        let Ok(lock) = self.blocks.read() else {
            return Err(Box::new(RamStorageError::Lock) as StorageError);
        };

        Ok(lock.contains_key(hash))
    }

    fn next_block(&self, hash: &Hash) -> Result<Option<Hash>, StorageError> {
        if hash == &Hash::default() {
            return self.root_block();
        }

        let Ok(history) = self.history.read() else {
            return Err(Box::new(RamStorageError::Lock) as StorageError);
        };

        match history.iter().position(|block| block == hash) {
            Some(offset) => Ok(history.get(offset + 1).copied()),
            None => Ok(None)
        }
    }

    fn prev_block(&self, hash: &Hash) -> Result<Option<Hash>, StorageError> {
        if hash == &Hash::default() {
            return Ok(None)
        }

        let Ok(history) = self.history.read() else {
            return Err(Box::new(RamStorageError::Lock) as StorageError);
        };

        match history.iter().position(|block| block == hash) {
            Some(0) => Ok(Some(Hash::default())),
            Some(offset) => Ok(Some(history[offset - 1])),
            None => Ok(None)
        }
    }

    fn read_block(&self, hash: &Hash) -> Result<Option<Block>, StorageError> {
        let Ok(blocks) = self.blocks.read() else {
            return Err(Box::new(RamStorageError::Lock) as StorageError);
        };

        Ok(blocks.get(hash).cloned())
    }

    fn write_block(&self, block: &Block) -> Result<StorageWriteResult, StorageError> {
        let (
            Ok(mut blocks),
            Ok(mut history)
        ) = (
            self.blocks.write(),
            self.history.write()
        ) else {
            return Err(Box::new(RamStorageError::Lock) as StorageError);
        };

        #[inline]
        fn block_has_duplicate_messages(block: &Block) -> bool {
            let mut messages = HashSet::new();

            for hash in block.ref_messages() {
                if !messages.insert(hash) {
                    return true;
                }
            }

            for message in block.inline_messages() {
                if !messages.insert(message.hash()) {
                    return true;
                }
            }

            false
        }

        #[inline]
        fn block_has_duplicate_messages_in_history(
            block: &Block,
            blocks: &HashMap<Hash, Block>,
            history: &[Hash]
        ) -> bool {
            let mut messages = HashSet::new();

            for hash in block.ref_messages() {
                if !messages.insert(hash) {
                    return true;
                }
            }

            for message in block.inline_messages() {
                if !messages.insert(message.hash()) {
                    return true;
                }
            }

            for hash in history {
                if let Some(block) = blocks.get(hash) {
                    for hash in block.ref_messages() {
                        if !messages.insert(hash) {
                            return true;
                        }
                    }

                    for message in block.inline_messages() {
                        if !messages.insert(message.hash()) {
                            return true;
                        }
                    }
                }
            }

            false
        }

        // Ignore block if it's already stored.
        if blocks.contains_key(block.hash()) {
            Ok(StorageWriteResult::BlockAlreadyStored)
        }

        // Ignore block if it has duplicate messages in it.
        else if block_has_duplicate_messages(block) {
            Ok(StorageWriteResult::BlockHasDuplicateMessages)
        }

        // Attempt to store the root block of the blockchain.
        else if history.is_empty() || block.is_root() {
            // But reject it if it's not of a root type.
            if !block.is_root() {
                return Ok(StorageWriteResult::NotRootBlock);
            }

            let (is_valid, _) = block.verify()?;

            // Although it's not a part of convention for this method why would
            // we need an invalid block stored here?
            if !is_valid {
                return Ok(StorageWriteResult::BlockInvalid);
            }

            history.clear();
            blocks.clear();

            history.push(*block.hash());
            blocks.insert(*block.hash(), block.clone());

            Ok(StorageWriteResult::Success)
        }

        // Reject out-of-history blocks.
        else if !blocks.contains_key(block.prev_hash()) {
            Ok(StorageWriteResult::OutOfHistoryBlock)
        }

        // At that point we're sure that the block is not stored and its
        // previous block is stored.
        //
        // If the previous block is the last block of the history then we add
        // the new one to the end of the blockchain.
        else if history.last() == Some(block.prev_hash()) {
            // Reject this block if it contains duplicate messages.
            if block_has_duplicate_messages_in_history(block, &blocks, &history) {
                return Ok(StorageWriteResult::BlockHasDuplicateHistoryMessages);
            }

            history.push(*block.hash());
            blocks.insert(*block.hash(), block.clone());

            Ok(StorageWriteResult::Success)
        }

        // Otherwise we need to modify the history.
        else {
            // Find the index of the previous block.
            let n = history.len();
            let mut i = n - 1;

            while &history[i] != block.prev_hash() {
                if i == 0 {
                    break;
                }

                i -= 1;
            }

            // Check that the new block has no duplicate messages.
            if block_has_duplicate_messages_in_history(
                block,
                &blocks,
                if i < n { &history[..i] }
                    else if n > 0 { &history[..n - 1] }
                    else { &history }
            ) {
                return Ok(StorageWriteResult::BlockHasDuplicateHistoryMessages);
            }

            // Remove all the following blocks.
            i += 1;

            while i < n {
                if let Some(block) = history.pop() {
                    blocks.remove(&block);
                }

                i += 1;
            }

            // Push new block to the history.
            history.push(*block.hash());
            blocks.insert(*block.hash(), block.clone());

            Ok(StorageWriteResult::Success)
        }
    }

    fn is_message_referenced(&self, hash: &Hash) -> Result<bool, StorageError> {
        let blocks = self.blocks.read()
            .map_err(|_| RamStorageError::Lock)?;

        for block in blocks.values() {
            if block.ref_messages().contains(hash) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn is_message_stored(&self, hash: &Hash) -> Result<bool, StorageError> {
        let blocks = self.blocks.read()
            .map_err(|_| RamStorageError::Lock)?;

        for block in blocks.values() {
            let has_ref = block.inline_messages()
                .iter()
                .any(|message| message.hash() == hash);

            if has_ref {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn has_message(
        &self,
        hash: &Hash
    ) -> Result<bool, StorageError> {
        let blocks = self.blocks.read()
            .map_err(|_| RamStorageError::Lock)?;

        let messages = self.messages.read()
            .map_err(|_| RamStorageError::Lock)?;

        Ok(has_message(&blocks, &messages, hash))
    }

    fn find_message(
        &self,
        hash: &Hash
    ) -> Result<Option<Hash>, StorageError> {
        let lock = self.blocks.read()
            .map_err(|_| RamStorageError::Lock)?;

        Ok(find_message(&lock, hash))
    }

    fn read_message(
        &self,
        hash: &Hash
    ) -> Result<Option<Message>, StorageError> {
        let blocks = self.blocks.read()
            .map_err(|_| RamStorageError::Lock)?;

        let messages = self.messages.read()
            .map_err(|_| RamStorageError::Lock)?;

        Ok(read_message(&blocks, &messages, hash))
    }

    fn write_message(&self, message: &Message) -> Result<bool, StorageError> {
        let blocks = self.blocks.read()
            .map_err(|_| RamStorageError::Lock)?;

        let messages = self.messages.read()
            .map_err(|_| RamStorageError::Lock)?;

        // Do not store a message which is already stored in some block as
        // inline message.
        if has_message(&blocks, &messages, message.hash()) {
            return Ok(true);
        }

        drop(blocks);
        drop(messages);

        let mut messages = self.messages.write()
            .map_err(|_| RamStorageError::Lock)?;

        messages.insert(*message.hash(), message.clone());

        Ok(true)
    }
}

#[test]
fn test() -> Result<(), Box<dyn std::error::Error>> {
    let storage = RamStorage::default();

    super::test_storage(&storage)?;

    Ok(())
}
