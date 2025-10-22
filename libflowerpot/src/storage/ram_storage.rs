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
use crate::crypto::sign::{VerifyingKey, SignatureError};
use crate::transaction::Transaction;
use crate::block::{Block, BlockContent};

use super::Storage;

#[derive(Debug, thiserror::Error)]
pub enum RamStorageError {
    #[error("failed to lock internal data")]
    Lock,

    #[error("failed to verify signature: {0}")]
    Signature(#[from] SignatureError)
}

fn has_transaction(
    blocks: &RwLockReadGuard<'_, HashMap<Hash, Block>>,
    transaction: &Hash
) -> bool {
    for block in blocks.values() {
        if let BlockContent::Transactions(transactions) = block.content()
            && transactions.iter().any(|tr| tr.hash() == transaction)
        {
            return true;
        }
    }

    false
}

fn find_transaction(
    blocks: &RwLockReadGuard<'_, HashMap<Hash, Block>>,
    transaction: &Hash
) -> Option<Hash> {
    for (block_hash, block) in blocks.iter() {
        if let BlockContent::Transactions(transactions) = block.content()
            && transactions.iter().any(|tr| tr.hash() == transaction)
        {
            return Some(*block_hash);
        }
    }

    None
}

fn read_transaction(
    blocks: &RwLockReadGuard<'_, HashMap<Hash, Block>>,
    transaction: &Hash
) -> Option<Transaction> {
    for block in blocks.values() {
        if let BlockContent::Transactions(transactions) = block.content() {
            let transaction = transactions.iter()
                .find(|tr| tr.hash() == transaction);

            if let Some(transaction) = transaction.cloned() {
                return Some(transaction);
            }
        }
    }

    None
}

#[derive(Default, Debug, Clone)]
pub struct RamStorage {
    blocks: Arc<RwLock<HashMap<Hash, Block>>>,
    history: Arc<RwLock<Vec<Hash>>>,
    root_validator: Arc<RwLock<Option<VerifyingKey>>>
}

impl RamStorage {
    /// Try to make a storage from the provided blocks chain.
    /// Return `Ok(Some(..))` if the chain is valid and ordered properly,
    /// `Ok(None)` if storage couldn't write some of the blocks due to invalid
    /// order.
    pub fn new<T: Into<Block>>(
        history: impl IntoIterator<Item = T>
    ) -> Result<Option<Self>, RamStorageError> {
        let storage = Self::default();

        for block in history {
            if !storage.write_block(&block.into())? {
                return Ok(None);
            }
        }

        Ok(Some(storage))
    }
}

impl Storage for RamStorage {
    type Error = RamStorageError;

    fn root_block(&self) -> Result<Option<Hash>, Self::Error> {
        let Ok(lock) = self.history.read() else {
            return Err(RamStorageError::Lock);
        };

        Ok(lock.first().copied())
    }

    fn tail_block(&self) -> Result<Option<Hash>, Self::Error> {
        let Ok(lock) = self.history.read() else {
            return Err(RamStorageError::Lock);
        };

        Ok(lock.last().copied())
    }

    fn has_block(&self, hash: &Hash) -> Result<bool, Self::Error> {
        let Ok(lock) = self.blocks.read() else {
            return Err(RamStorageError::Lock);
        };

        Ok(lock.contains_key(hash))
    }

    fn next_block(&self, hash: &Hash) -> Result<Option<Hash>, Self::Error> {
        if hash == &Hash::default() {
            return self.root_block();
        }

        let Ok(history) = self.history.read() else {
            return Err(RamStorageError::Lock);
        };

        match history.iter().position(|block| block == hash) {
            Some(offset) => Ok(history.get(offset + 1).copied()),
            None => Ok(None)
        }
    }

    fn prev_block(&self, hash: &Hash) -> Result<Option<Hash>, Self::Error> {
        if hash == &Hash::default() {
            return Ok(None)
        }

        let Ok(history) = self.history.read() else {
            return Err(RamStorageError::Lock);
        };

        match history.iter().position(|block| block == hash) {
            Some(0) => Ok(Some(Hash::default())),
            Some(offset) => Ok(Some(history[offset - 1])),
            None => Ok(None)
        }
    }

    fn read_block(&self, hash: &Hash) -> Result<Option<Block>, Self::Error> {
        let Ok(blocks) = self.blocks.read() else {
            return Err(RamStorageError::Lock);
        };

        Ok(blocks.get(hash).cloned())
    }

    fn write_block(&self, block: &Block) -> Result<bool, Self::Error> {
        fn has_duplicate_transactions(
            blocks: &RwLockReadGuard<'_, HashMap<Hash, Block>>,
            transactions: &[Transaction]
        ) -> bool {
            let mut hashes = HashSet::new();

            for transaction in transactions {
                let hash = transaction.hash();

                if !hashes.insert(hash) || has_transaction(blocks, hash) {
                    return true;
                }
            }

            false
        }

        // Check that there's no duplicate transactions.
        if let BlockContent::Transactions(transactions) = block.content() {
            let Ok(blocks) = self.blocks.read() else {
                return Err(RamStorageError::Lock);
            };

            if has_duplicate_transactions(&blocks, transactions) {
                return Ok(false);
            }
        }

        let (
            Ok(mut blocks),
            Ok(mut history)
        ) = (
            self.blocks.write(),
            self.history.write()
        ) else {
            return Err(RamStorageError::Lock);
        };

        let hash = *block.current_hash();

        // Ignore block if it's already stored.
        if blocks.contains_key(&hash) {
            return Ok(false);
        }

        // Attempt to store the root block of the blockchain.
        else if history.is_empty() || block.is_root() {
            // But reject it if it's not of a root type.
            if !block.is_root() {
                return Ok(false);
            }

            let (is_valid, public_key) = block.verify()?;

            // Although it's not a part of convention for this method why would
            // we need an invalid block stored here?
            if !is_valid {
                return Ok(false);
            }

            let Ok(mut root_validator) = self.root_validator.write() else {
                return Err(RamStorageError::Lock);
            };

            history.clear();
            blocks.clear();

            history.push(hash);
            blocks.insert(hash, block.clone());
            root_validator.replace(public_key);
        }

        // Reject out-of-history blocks.
        else if !blocks.contains_key(block.previous_hash()) {
            return Ok(false);
        }

        // At that point we're sure that the block is not stored and its
        // previous block is stored.
        //
        // If the previous block is the last block of the history then we add
        // the new one to the end of the blockchain.
        else if history.last() == Some(block.previous_hash()) {
            history.push(hash);
            blocks.insert(hash, block.clone());
        }

        // Otherwise we need to modify the history.
        else {
            // Find the index of the previous block.
            let mut i = 0;

            while &history[i] != block.previous_hash() {
                i += 1;
            }

            // Remove all the following blocks.
            let n = history.len();

            i += 1;

            while i < n {
                if let Some(block) = history.pop() {
                    blocks.remove(&block);
                }

                i += 1;
            }

            // Push new block to the history.
            history.push(hash);
            blocks.insert(hash, block.clone());
        }

        Ok(true)
    }

    #[inline]
    fn has_transaction(
        &self,
        transaction: &Hash
    ) -> Result<bool, Self::Error> {
        let lock = self.blocks.read()
            .map_err(|_| RamStorageError::Lock)?;

        Ok(has_transaction(&lock, transaction))
    }

    #[inline]
    fn find_transaction(
        &self,
        transaction: &Hash
    ) -> Result<Option<Hash>, Self::Error> {
        let lock = self.blocks.read()
            .map_err(|_| RamStorageError::Lock)?;

        Ok(find_transaction(&lock, transaction))
    }

    #[inline]
    fn read_transaction(
        &self,
        transaction: &Hash
    ) -> Result<Option<Transaction>, Self::Error> {
        let lock = self.blocks.read()
            .map_err(|_| RamStorageError::Lock)?;

        Ok(read_transaction(&lock, transaction))
    }

    fn get_validators_before_block(
        &self,
        hash: &Hash
    ) -> Result<Option<Vec<VerifyingKey>>, Self::Error> {
        let (
            Ok(blocks),
            Ok(history)
        ) = (
            self.blocks.read(),
            self.history.read()
        ) else {
            return Err(RamStorageError::Lock);
        };

        // No block - no validators.
        if !blocks.contains_key(hash) {
            return Ok(None);
        }

        // Find index of the queried block.
        let mut i = 0;
        let n = history.len();

        while i < n {
            if &history[i] == hash {
                break;
            }

            i += 1;
        }

        loop {
            // If we're looking at the root block of the blockchain then the
            // validators for it are the signer of this block.
            if i == 0 {
                let Ok(Some(root_validator)) = self.root_validator.read().as_deref().cloned() else {
                    return Err(RamStorageError::Lock);
                };

                return Ok(Some(vec![root_validator]));
            }

            // Otherwise we're looking for the validators type block and return
            // its content once it's found.
            else {
                i -= 1;

                if let BlockContent::Validators(validators) = blocks[&history[i]].content() {
                    return Ok(Some(validators.to_vec()));
                }
            }
        }
    }

    fn get_validators_after_block(
        &self,
        hash: &Hash
    ) -> Result<Option<Vec<VerifyingKey>>, Self::Error> {
        let (
            Ok(blocks),
            Ok(history)
        ) = (
            self.blocks.read(),
            self.history.read()
        ) else {
            return Err(RamStorageError::Lock);
        };

        // No block - no validators.
        if !blocks.contains_key(hash) {
            return Ok(None);
        }

        // Find index of the queried block.
        let mut i = 0;
        let n = history.len();

        while i < n {
            if &history[i] == hash {
                break;
            }

            i += 1;
        }

        loop {
            // If current block is of validators type then we return its
            // content.
            if let BlockContent::Validators(validators) = blocks[&history[i]].content() {
                return Ok(Some(validators.to_vec()));
            }

            // If we're looking at the root block of the blockchain then the
            // validator is the signer of this block.
            else if i == 0 {
                let Ok(Some(root_validator)) = self.root_validator.read().as_deref().cloned() else {
                    return Err(RamStorageError::Lock);
                };

                return Ok(Some(vec![root_validator]));
            }

            i -= 1;
        }
    }
}

#[test]
fn test() -> Result<(), RamStorageError> {
    let storage = RamStorage::default();

    super::test_storage(&storage)?;

    let restored_storage = RamStorage::new(storage.blocks().flatten())?.unwrap();

    assert_eq!(
        storage.blocks().flatten().collect::<Vec<_>>(),
        restored_storage.blocks().flatten().collect::<Vec<_>>()
    );

    Ok(())
}
