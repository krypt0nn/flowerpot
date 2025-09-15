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

use std::collections::{HashMap, HashSet, VecDeque};

use futures::FutureExt;

use crate::crypto::*;
use crate::block::{Block, BlockContent, BlockStatus, Error as BlockError};
use crate::client::{Client, SyncResult, Error as ClientError};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to validate block: {0}")]
    BlockValidate(#[source] BlockError)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidBlock {
    pub block: Block,
    pub hash: Hash,
    pub public_key: PublicKey
}

/// Viewer is a wrapper around the client node which implements in-RAM
/// traversal of the network-stored blockchain. In viewer you provide a
/// client node and a list of shards addresses, and using these shards' API
/// viewer goes through the blockchain, verifies blocks and provides them to
/// this struct's user.
///
/// This struct will silently ignore any shard-related errors and simply remove
/// shards if they returned invalid results.
pub struct Viewer {
    client: Client,
    shards: HashSet<String>,
    root_block: Hash,
    curr_block: ValidBlock,
    validators: Box<[PublicKey]>,
    blocks_pool: VecDeque<ValidBlock>
}

impl Viewer {
    /// Open viewer using provided client and shards.
    ///
    /// `root_block` specifies hash of the expected root block of the
    /// blockchain. Before opening the viewer will request root blocks from
    /// every provided shard. If `root_block` is specified, then shards with
    /// only provided root block's hash will be kept. Otherwise, the most often
    /// root block will be chosen as the target one and other shards will be
    /// removed as well. This operation is needed to ensure that viewer is
    /// looking at the same blockchain in all the shards.
    ///
    /// It is always recommended to provide the `root_block`, but is not
    /// required.
    ///
    /// Return `Ok(None)` if none of provided shards contain at least one valid
    /// block.
    pub async fn open<T: ToString>(
        client: impl Into<Client>,
        shards: impl IntoIterator<Item = T>,
        root_block: Option<Hash>
    ) -> Result<Option<Self>, ClientError> {
        let client: Client = client.into();

        let mut shards = shards.into_iter()
            .map(|address| address.to_string())
            .collect::<HashSet<String>>();

        let mut results = Vec::with_capacity(shards.len());

        for address in &shards {
            let request = client.get_blockchain(address, None, Some(1));

            results.push(request.map(|result| {
                (address.clone(), result)
            }));
        }

        let mut blocks_hashes: HashMap<[u8; 32], usize> = HashMap::new();

        // Iterate over all the requested blockchains, count root blocks, remove
        // shards with invalid ones.
        for (address, result) in futures::future::join_all(results).await {
            match result {
                Ok(SyncResult::Blocks(mut blocks)) => {
                    if !blocks.is_empty() {
                        let block = blocks.remove(0);

                        // This should never happen because `get_blockchain`
                        // guarantees that in our case the first returned block
                        // must be the root block.
                        if !block.is_root() {
                            shards.remove(&address);

                            continue;
                        }

                        // TODO: do we really need to return an error here?
                        let hash = block.hash()
                            .map_err(ClientError::ClientBlockHash)?;

                        // Skip all the shards with different root block.
                        if let Some(root_block) = &root_block
                            && &hash != root_block
                        {
                            shards.remove(&address);

                            continue;
                        }

                        // Increment this hash appearance to choose the target
                        // root block as the most often one if it's not
                        // specified.
                        *blocks_hashes.entry(hash.0).or_default() += 1;
                    }
                }

                Ok(SyncResult::BlockNotFound) => (),

                Ok(_) => {
                    #[cfg(feature = "tracing")]
                    tracing::error!(?address, "failed to read root block of the shard's blockchain");

                    shards.remove(&address);
                }

                Err(err) => {
                    #[cfg(feature = "tracing")]
                    tracing::error!(?address, ?err, "failed to read root block of the shard's blockchain");

                    shards.remove(&address);
                }
            }
        }

        // Choose the root block's hash by either using given one or taking the
        // most often appearing one.
        let root_block = match root_block {
            Some(root_block) => root_block,
            None => {
                let root_block = blocks_hashes.iter()
                    .max_by_key(|(_, n)| *n)
                    .map(|(hash, _)| Hash::from(*hash));

                // No result found means there's no root block in all the
                // provided shards so nothing to look at.
                let Some(root_block) = root_block else {
                    return Ok(None);
                };

                root_block
            }
        };

        // Request this block.
        let mut curr_block = None;
        let mut broken_shards = Vec::new();

        for address in &shards {
            let Some(block) = client.read_block(address, &root_block).await? else {
                broken_shards.push(address.clone());

                continue;
            };

            let (valid, hash, public_key) = block.verify()
                .map_err(ClientError::ClientBlockVerify)?;

            if !valid {
                continue;
            }

            curr_block = Some(ValidBlock {
                block,
                hash,
                public_key
            });

            break;
        }

        for address in broken_shards {
            shards.remove(&address);
        }

        // Report back if we couldn't request the root block for some reason.
        // This normally shouldn't be a thing.
        let Some(curr_block) = curr_block else {
            return Ok(None);
        };

        // Until validators block given the author of the root block is the sole
        // validator of the whole blockchain.
        let mut validators = vec![
            curr_block.public_key.clone()
        ].into_boxed_slice();

        // If root block if the validators block - then use the validators from
        // here.
        if let BlockContent::Validators(value) = curr_block.block.content() {
            validators = value.clone();
        }

        Ok(Some(Self {
            client,
            shards,
            root_block,
            curr_block,
            validators,
            blocks_pool: VecDeque::new()
        }))
    }

    #[inline(always)]
    pub fn client(&self) -> &Client {
        &self.client
    }

    #[inline(always)]
    pub fn shards(&self) -> &HashSet<String> {
        &self.shards
    }

    #[inline(always)]
    pub fn root_block(&self) -> &Hash {
        &self.root_block
    }

    #[inline(always)]
    pub fn into_client(self) -> Client {
        self.client
    }

    /// Get currently selected block.
    #[inline(always)]
    pub fn current_block(&self) -> &ValidBlock {
        &self.curr_block
    }

    /// Get list of blockchain validators at the current history point.
    #[inline(always)]
    pub fn validators(&self) -> &[PublicKey] {
        &self.validators
    }

    /// Get pool of prefetched blocks.
    #[inline]
    pub fn blocks_pool(&self) -> &VecDeque<ValidBlock> {
        &self.blocks_pool
    }

    /// Try to read the next block of the blockchain. Return `Some` with the new
    /// block if it was read, otherwise return `None` if there's no new block
    /// available yet. All the errors are handled silently and if `tracing`
    /// feature is enabled are reported there.
    ///
    /// Note that this method removes broken shards from the list, so eventually
    /// viewer can have no more shards to work with.
    pub async fn forward(&mut self) -> Option<&ValidBlock> {
        // Use the blocks pool if it's available.
        if let Some(block) = self.blocks_pool.pop_front() {
            // Update validators list if the new block is of validators type.
            if let BlockContent::Validators(validators) = block.block.content() {
                self.validators = validators.clone();
            }

            self.curr_block = block;

            return Some(&self.curr_block);
        }

        // At that point we either don't have blocks pool, or it was cleared
        // because one of the blocks there was invalid. In both cases we have to
        // fetch blockchain history from the shards.

        let mut broken_shards = Vec::new();

        for address in &self.shards {
            let result = self.client.get_blockchain(
                address,
                Some(self.curr_block.hash),
                None
            ).await;

            match result {
                Ok(SyncResult::Blocks(blocks)) => {
                    // Process received blocks chain and keep only valid and
                    // approved ones.
                    let mut valid_blocks = Vec::with_capacity(blocks.len());

                    for mut block in blocks {
                        match block.validate(&self.validators) {
                            Ok(BlockStatus::Approved { hash, public_key, approvals, .. }) => {
                                // Reset the approvals list because remotely fetched block
                                // could contain invalid approvals.
                                block.approvals = approvals.into_iter()
                                    .map(|(approval, _)| approval)
                                    .collect();

                                valid_blocks.push(ValidBlock {
                                    hash,
                                    public_key,
                                    block
                                });
                            }

                            // If shard returned us invalid block or block with
                            // not enough approvals the we consider this shard
                            // malicious and remove it.
                            Ok(BlockStatus::NotApproved { .. }) | Ok(BlockStatus::Invalid) => {
                                broken_shards.push(address.clone());

                                break;
                            }

                            Err(err) => {
                                #[cfg(feature = "tracing")]
                                tracing::error!(
                                    ?err,
                                    "failed to validate received block"
                                );

                                break;
                            }
                        }
                    }

                    // Merge received valid blocks with current blocks pool by
                    // either appending them to the pool or replacing existing
                    // chain using scoring algorithm.

                    let n = self.blocks_pool.len();
                    let m = valid_blocks.len();

                    let mut i = 0;

                    // Compare common blocks.
                    while i < n.min(m) {
                        let curr_block = &self.blocks_pool[i];
                        let new_block = &valid_blocks[i];

                        // Start comparing the blocks if they're different.
                        if curr_block.hash != new_block.hash
                            && new_block.block.previous() == curr_block.block.previous()
                        {
                            let curr_approvals = curr_block.block.approvals().len();
                            let new_approvals = new_block.block.approvals().len();

                            // Replace the whole blocks pool starting from the
                            // current block if newly received chain has more
                            // approvals than our current one, or if amount of
                            // approvals is equal but the new block has smaller
                            // hash value.
                            let should_replace = new_approvals > curr_approvals
                                || (new_approvals == curr_approvals && new_block.hash < curr_block.hash);

                            if should_replace {
                                self.blocks_pool.truncate(i);
                                self.blocks_pool.extend(valid_blocks[i..].iter().cloned());

                                i = m;

                                break;
                            }
                        }

                        i += 1;
                    }

                    // If the pointer didn't meet the end of the received blocks
                    // chain yet and received chain is longer then the known one
                    // then we can merge remaining blocks to the pool.
                    if i < m && n < m {
                        self.blocks_pool.extend(valid_blocks[i..].iter().cloned());
                    }
                }

                // Some shard-related error, so remove it anyway.
                Ok(result) => {
                    #[cfg(feature = "tracing")]
                    tracing::error!(
                        ?address,
                        after_block = self.curr_block.hash.to_base64(),
                        ?result,
                        "failed to request blockchain from a shard"
                    );

                    broken_shards.push(address.clone());
                }

                Err(err) => {
                    #[cfg(feature = "tracing")]
                    tracing::error!(
                        ?address,
                        after_block = self.curr_block.hash.to_base64(),
                        ?err,
                        "failed to request blockchain from a shard"
                    );

                    broken_shards.push(address.clone());
                }
            }
        }

        // Remove the broken shards.
        for address in broken_shards {
            self.shards.remove(&address);
        }

        // Use the blocks pool if it's available.
        let block = self.blocks_pool.pop_front()?;

        // Update validators list if the new block is of validators type.
        if let BlockContent::Validators(validators) = block.block.content() {
            self.validators = validators.clone();
        }

        self.curr_block = block;

        Some(&self.curr_block)
    }

    /// Continuously call the `forward` method until the block with `block_hash`
    /// is met or the end of the blockchain is reached.
    ///
    /// Return `Some` with the current block being `block_hash`, otherwise
    /// return `None`.
    pub async fn forward_to(&mut self, block_hash: &Hash) -> Option<&ValidBlock> {
        while &self.curr_block.hash != block_hash {
            self.forward().await?;
        }

        Some(&self.curr_block)
    }
}
