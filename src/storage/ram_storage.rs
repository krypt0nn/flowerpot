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

use std::collections::HashMap;
use std::sync::RwLock;

use crate::crypto::*;
use crate::block::{Block, BlockContent, Error as BlockError};

use super::Storage;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to lock internal data")]
    Lock,

    #[error(transparent)]
    Block(#[from] BlockError)
}

#[derive(Default, Debug)]
pub struct RamStorage {
    blocks: RwLock<HashMap<Hash, Block>>,
    history: RwLock<Vec<Hash>>,
    root_validator: RwLock<Option<PublicKey>>
}

impl RamStorage {
    /// Try to make a storage from the provided blocks chain.
    /// Return `Ok(Some(..))` if the chain is valid and ordered properly,
    /// `Ok(None)` if storage couldn't write some of the blocks due to invalid
    /// order.
    pub fn new<T: Into<Block>>(
        history: impl IntoIterator<Item = T>
    ) -> Result<Option<Self>, Error> {
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
    type Error = Error;

    fn root_block(&self) -> Result<Option<Hash>, Self::Error> {
        let Ok(lock) = self.history.read() else {
            return Err(Error::Lock);
        };

        Ok(lock.first().copied())
    }

    fn tail_block(&self) -> Result<Option<Hash>, Self::Error> {
        let Ok(lock) = self.history.read() else {
            return Err(Error::Lock);
        };

        Ok(lock.last().copied())
    }

    fn has_block(&self, hash: &Hash) -> Result<bool, Self::Error> {
        let Ok(lock) = self.blocks.read() else {
            return Err(Error::Lock);
        };

        Ok(lock.contains_key(hash))
    }

    fn next_block(&self, hash: &Hash) -> Result<Option<Hash>, Self::Error> {
        if hash == &Hash::default() {
            return self.root_block();
        }

        let Ok(history) = self.history.read() else {
            return Err(Error::Lock);
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
            return Err(Error::Lock);
        };

        match history.iter().position(|block| block == hash) {
            Some(0) => Ok(Some(Hash::default())),
            Some(offset) => Ok(Some(history[offset - 1])),
            None => Ok(None)
        }
    }

    fn read_block(&self, hash: &Hash) -> Result<Option<Block>, Self::Error> {
        let Ok(blocks) = self.blocks.read() else {
            return Err(Error::Lock);
        };

        Ok(blocks.get(hash).cloned())
    }

    fn write_block(&self, block: &Block) -> Result<bool, Self::Error> {
        let (
            Ok(mut blocks),
            Ok(mut history)
        ) = (
            self.blocks.write(),
            self.history.write()
        ) else {
            return Err(Error::Lock);
        };

        let hash = block.hash()?;

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

            let (is_valid, _, public_key) = block.verify()?;

            // Although it's not a part of convention for this method why would
            // we need an invalid block stored here?
            if !is_valid {
                return Ok(false);
            }

            let Ok(mut root_validator) = self.root_validator.write() else {
                return Err(Error::Lock);
            };

            history.clear();
            blocks.clear();

            history.push(hash);
            blocks.insert(hash, block.clone());
            root_validator.replace(public_key);
        }

        // Reject out-of-history blocks.
        else if !blocks.contains_key(block.previous()) {
            return Ok(false);
        }

        // At that point we're sure that the block is not stored and its
        // previous block is stored.
        //
        // If the previous block is the last block of the history then we add
        // the new one to the end of the blockchain.
        else if history.last() == Some(&block.previous) {
            history.push(hash);
            blocks.insert(hash, block.clone());
        }

        // Otherwise we need to modify the history.
        else {
            // Find the index of the previous block.
            let mut i = 0;

            while &history[i] != block.previous() {
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

    fn get_validators_before_block(
        &self,
        hash: &Hash
    ) -> Result<Option<Vec<PublicKey>>, Self::Error> {
        let (
            Ok(blocks),
            Ok(history)
        ) = (
            self.blocks.read(),
            self.history.read()
        ) else {
            return Err(Error::Lock);
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
                    return Err(Error::Lock);
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
    ) -> Result<Option<Vec<PublicKey>>, Self::Error> {
        let (
            Ok(blocks),
            Ok(history)
        ) = (
            self.blocks.read(),
            self.history.read()
        ) else {
            return Err(Error::Lock);
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
                    return Err(Error::Lock);
                };

                return Ok(Some(vec![root_validator]));
            }

            i -= 1;
        }
    }
}

#[test]
fn test() -> Result<(), Error> {
    let storage = RamStorage::default();

    super::test_storage(&storage)?;

    let restored_storage = RamStorage::new(storage.blocks().flatten())?.unwrap();

    assert_eq!(
        storage.blocks().flatten().collect::<Vec<_>>(),
        restored_storage.blocks().flatten().collect::<Vec<_>>()
    );

    Ok(())
}
