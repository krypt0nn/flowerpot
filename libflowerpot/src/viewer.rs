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

use std::collections::VecDeque;

use crate::crypto::hash::Hash;
use crate::crypto::sign::{VerifyingKey, SignatureError};
use crate::block::{Block, BlockContent, BlockStatus};
use crate::storage::Storage;
use crate::protocol::packets::Packet;
use crate::protocol::network::{PacketStream, PacketStreamError};

#[derive(Debug, thiserror::Error)]
pub enum ViewerError {
    #[error(transparent)]
    PacketStream(PacketStreamError),

    #[error(transparent)]
    Signature(#[from] SignatureError),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("stream returned invalid block")]
    InvalidBlock,

    #[error("stream returned invalid history")]
    InvalidHistory,

    #[error("viewers within the batched viewer are out of sync")]
    BatchedViewerOutOfSync
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidBlock {
    pub block: Block,
    pub verifying_key: VerifyingKey
}

/// Viewer is a helper struct which uses the underlying packet stream connection
/// to traverse blockchain history known to the remote node.
pub struct Viewer<'stream> {
    stream: &'stream mut PacketStream,

    /// Root block of the blockchain.
    root_block: Hash,

    /// List of blocks we need to fetch.
    pending_blocks: (u64, VecDeque<Hash>),

    /// Hash of the previously fetched block.
    prev_block: Hash,

    /// List of current blockchain validators.
    validators: Vec<(VerifyingKey, u8)>
}

impl<'stream> Viewer<'stream> {
    const MAX_HISTORY_LENGTH: u64 = 1024;

    /// Open viewer of the blockchain history known to the node with provided
    /// packet stream connection.
    pub fn open(
        stream: &'stream mut PacketStream,
        root_block: Hash
    ) -> Result<Self, ViewerError> {
        // Ask for the root block of the blockchain.
        stream.send(&Packet::AskBlock {
            root_block,
            target_block: root_block
        }).map_err(ViewerError::PacketStream)?;

        let root_block_packet = stream.peek(|packet| {
            if let Packet::Block {
                root_block: received_root_block,
                block
            } = packet {
                return received_root_block == &root_block
                    && block.is_root();
            }

            false
        }).map_err(ViewerError::PacketStream)?;

        let Packet::Block { block, .. } = root_block_packet else {
            return Err(ViewerError::InvalidBlock);
        };

        // Verify the root block and obtain its author.
        let (is_valid, public_key) = block.verify()?;

        if !is_valid || block.current_hash() != &root_block {
            return Err(ViewerError::InvalidBlock);
        }

        Ok(Self {
            stream,
            root_block,
            pending_blocks: (0, VecDeque::from([*block.current_hash()])),
            prev_block: Hash::default(),
            validators: vec![(public_key, 0)]
        })
    }

    /// Open viewer using blocks stored in the provided storage. We will assume
    /// that all the blocks in that storage are validates and that the provided
    /// stream's endpoint has the same history.
    ///
    /// Return `Ok(None)` if storage doesn't have any blocks.
    pub fn open_from_storage<S: Storage>(
        stream: &'stream mut PacketStream,
        storage: &S
    )  -> Result<Option<Self>, ViewerError> {
        // Try to read root block from the storage.
        let root_block = storage.root_block()
            .map_err(|err| ViewerError::Storage(err.to_string()))?;

        let Some(root_block) = root_block else {
            return Ok(None);
        };

        // Try to read tail block from the storage.
        let tail_block = storage.tail_block()
            .map_err(|err| ViewerError::Storage(err.to_string()))?;

        let Some(mut tail_block) = tail_block else {
            return Ok(None);
        };

        // If there's more than 1 block in the storage - then we will try to
        // read the previous block from the tail one, because it's fixated and
        // according to the protocol agreement cannot be modified, while tail
        // block can be.
        if root_block != tail_block {
            tail_block = storage.prev_block(&tail_block)
                .map_err(|err| ViewerError::Storage(err.to_string()))?
                .unwrap_or(tail_block);
        }

        // Try to read list of validators after the selected tail block.
        let validators = storage.get_validators_after_block(&tail_block)
            .map_err(|err| ViewerError::Storage(err.to_string()))?;

        let Some(validators) = validators else {
            return Ok(None);
        };

        // Find the tail block's index.
        let mut i = 0;
        let mut prev_block = Hash::default();

        for hash in storage.history() {
            let hash = hash.map_err(|err| ViewerError::Storage(err.to_string()))?;

            if hash == tail_block {
                break;
            }

            i += 1;
            prev_block = hash;
        }

        Ok(Some(Self {
            stream,
            root_block,
            pending_blocks: (i, VecDeque::from([tail_block])), // TODO: should be the next block from the tail
            prev_block,
            validators: validators.into_iter()
                .map(|validator| (validator, 0)) // FIXME: 0 is not correct
                .collect()
        }))
    }

    /// Get root block of the viewer's blockchain.
    #[inline(always)]
    pub const fn root_block(&self) -> &Hash {
        &self.root_block
    }

    /// Current viewer block offset.
    #[inline(always)]
    pub const fn offset(&self) -> u64 {
        self.pending_blocks.0
    }

    /// Hash of the previously fetched block.
    ///
    /// This method will return a hash of the block which was fetched by the
    /// last `forward` method call.
    #[inline(always)]
    pub const fn prev_block(&self) -> &Hash {
        &self.prev_block
    }

    /// Get list of current block validators.
    pub fn current_validators(
        &self
    ) -> impl ExactSizeIterator<Item = &VerifyingKey> {
        self.validators.iter().map(|(validator, _)| validator)
    }

    /// Request the next block of the blockchain history known to the underlying
    /// node, verify and return it. If we've reached the end of the known
    /// history then `None` is returned.
    pub fn forward(&mut self) -> Result<Option<ValidBlock>, ViewerError> {
        // Read the pending block hash.
        let pending_block = match self.pending_blocks.1.front() {
            // Directly if we have pending blocks history.
            Some(block) => *block,

            // Or by asking the network node.
            None => {
                // Ask and peak the history packet.
                self.stream.send(&Packet::AskHistory {
                    root_block: self.root_block,
                    offset: self.pending_blocks.0,
                    max_length: Self::MAX_HISTORY_LENGTH
                }).map_err(ViewerError::PacketStream)?;

                let history = self.stream.peek(|packet| {
                    if let Packet::History {
                        root_block: received_root_block,
                        offset: received_offset,
                        ..
                    } = packet {
                        return received_root_block == &self.root_block
                            && received_offset == &self.pending_blocks.0;
                    }

                    false
                }).map_err(ViewerError::PacketStream)?;

                let Packet::History { history, .. } = history else {
                    return Err(ViewerError::InvalidHistory);
                };

                // We've reached the end of the known history.
                if history.is_empty() {
                    return Ok(None);
                }

                // Extend the local history pool and return the first entry
                // (a pending block).
                let pending_block = history[0];

                self.pending_blocks.1.extend(history);

                pending_block
            }
        };

        // Request and peek the pending block.
        self.stream.send(Packet::AskBlock {
            root_block: self.root_block,
            target_block: pending_block
        }).map_err(ViewerError::PacketStream)?;

        let packet = self.stream.peek(|packet| {
            if let Packet::Block {
                root_block: received_root_block,
                ..
            } = packet {
                return received_root_block == &self.root_block;
            }

            false
        }).map_err(ViewerError::PacketStream)?;

        let Packet::Block { mut block, .. } = packet else {
            return Err(ViewerError::InvalidBlock);
        };

        // Decline the block if it doesn't match the previously stored block.
        if block.previous_hash() != &self.prev_block {
            return Err(ViewerError::InvalidBlock);
        }

        // Validate the received block.
        let validators = self.current_validators()
            .cloned()
            .collect::<Vec<_>>();

        let status = block.validate(&validators)?;

        let BlockStatus::Approved {
            hash,
            verifying_key,
            approvals,
            ..
        } = status else {
            return Err(ViewerError::InvalidBlock);
        };

        // Update validators last seen counters.
        for (verifying_key, counter) in &mut self.validators {
            if approvals.iter().any(|(_, validator)| validator == verifying_key) {
                *counter = 0;
            } else {
                *counter = counter.saturating_add(1);
            }
        }

        // According to the protocol, if validator didn't participate in
        // network maintenance it must be forcely removed from the list.
        self.validators.retain(|(_, counter)| *counter < 32);

        // Update received block's approvals (some could be invalid).
        block.approvals = approvals.iter()
            .map(|(sign, _)| sign.clone())
            .collect();

        // Update validators list if it was updated by this block.
        if let BlockContent::Validators(validators) = block.content() {
            self.validators = validators.iter()
                .map(|validator| (validator.clone(), 0))
                .collect();
        }

        // Shift pending blocks history forward and return obtained block.
        self.pending_blocks.0 += 1;
        self.pending_blocks.1.pop_front();
        self.prev_block = hash;

        Ok(Some(ValidBlock {
            block,
            verifying_key
        }))
    }
}

/// Batched viewer is a helper struct which takes multiple `Viewer`-s and allows
/// iterating through the commonly known blockchain history, selecting the best
/// fork according to the protocol agreements.
pub struct BatchedViewer<'stream> {
    viewers: Vec<Viewer<'stream>>,
    root_block: Hash,
    prev_block: Hash
}

impl<'stream> BatchedViewer<'stream> {
    /// Open batched viewer of the blockchain history known to the provided
    /// nodes' packet streams
    pub fn open(
        streams: impl IntoIterator<Item = &'stream mut PacketStream>,
        root_block: Hash
    ) -> Result<Self, ViewerError> {
        let mut viewers = Vec::new();

        for stream in streams {
            viewers.push(Viewer::open(stream, root_block)?);
        }

        Ok(Self {
            viewers,
            root_block,
            prev_block: Hash::default()
        })
    }

    /// Open batched viewer using blocks stored in the provided storage. We will
    /// assume that all the blocks in that storage are validates and that the
    /// provided streams' endpoints have the same history.
    ///
    /// Return `Ok(None)` if storage doesn't have any blocks or no remote node
    /// viewers available.
    pub fn open_from_storage<S: Storage>(
        streams: impl IntoIterator<Item = &'stream mut PacketStream>,
        storage: &S
    )  -> Result<Option<Self>, ViewerError>
    where
        S::Error: 'static
    {
        let mut viewers = Vec::new();
        let mut prev_block = Hash::default();

        let root_block = storage.root_block()
            .map_err(|err| ViewerError::Storage(err.to_string()))?;

        let Some(root_block) = root_block else {
            return Ok(None);
        };

        // TODO: prioritize streams with higher offset value instead of the
        //       first stream in the list as it currently happens.
        for stream in streams {
            let Some(viewer) = Viewer::open_from_storage(stream, storage)? else {
                return Ok(None);
            };

            let viewer_prev_block = viewer.prev_block();

            // Update the locally stored prev block.
            if prev_block == Hash::default() {
                prev_block = *viewer_prev_block;
            }

            // Ignore remote node with different history overview.
            else if &prev_block != viewer_prev_block {
                continue;
            }

            viewers.push(viewer);
        }

        if viewers.is_empty() {
            return Ok(None);
        }

        Ok(Some(Self {
            viewers,
            root_block,
            prev_block
        }))
    }

    /// Get root block of the viewer's blockchain.
    pub const fn root_block(&self) -> &Hash {
        &self.root_block
    }

    /// Current viewer block offset.
    pub fn offset(&self) -> u64 {
        todo!("fetch from viewers")
    }

    /// Hash of the previously fetched block.
    ///
    /// This method will return a hash of the block which was fetched by the
    /// last `forward` method call.
    #[inline(always)]
    pub const fn prev_block(&self) -> &Hash {
        &self.prev_block
    }

    /// Get list of current block validators.
    pub fn current_validators(
        &self
    ) -> Result<Vec<VerifyingKey>, ViewerError> {
        let mut validators = Vec::new();

        for viewer in &self.viewers {
            let viewer_validators = viewer.current_validators()
                .cloned()
                .collect::<Vec<VerifyingKey>>();

            if validators.is_empty() {
                validators = viewer_validators;
            }

            else if validators != viewer_validators {
                return Err(ViewerError::BatchedViewerOutOfSync);
            }
        }

        Ok(validators)
    }

    /// Request the next block of the blockchain history known to the underlying
    /// nodes, verify and return it. If we've reached the end of the known
    /// history then `Ok(None)` is returned.
    pub fn forward(
        &mut self
    ) -> Result<Option<ValidBlock>, ViewerError> {
        let mut curr_block: Option<ValidBlock> = None;

        for viewer in &mut self.viewers {
            let block = viewer.forward()?;

            if let Some(block) = block {
                dbg!(block.block.previous_hash());
                dbg!(self.prev_block);

                if block.block.previous_hash() != &self.prev_block {
                    // TODO: remove the viewer (has different history than us)

                    continue;
                }

                if let Some(curr_block) = &mut curr_block {
                    let curr_distance = crate::block_validator_distance(
                        self.prev_block,
                        &curr_block.verifying_key
                    );

                    let new_distance = crate::block_validator_distance(
                        self.prev_block,
                        &block.verifying_key
                    );

                    if new_distance < curr_distance {
                        *curr_block = block;
                    }
                }

                else {
                    curr_block = Some(block);
                }
            }
        }

        let Some(block) = curr_block else {
            return Ok(None);
        };

        dbg!(block.block.current_hash());

        self.prev_block = *block.block.current_hash();

        Ok(Some(block))
    }

    /// Request the next block of the blockchain history known to the underlying
    /// nodes and provided storage, verify and return it. If we've reached the
    /// end of the known history then `Ok(None)` is returned.
    ///
    /// > Note that this method does not modify the provided storage if new
    /// > blocks are received from the network. Only read operations are used.
    pub fn forward_with_storage<T: Storage>(
        &mut self,
        storage: &T
    ) -> Result<Option<ValidBlock>, ViewerError>
    where
        T::Error: 'static
    {
        let storage_block = storage.next_block(&self.prev_block)
            .map_err(|err| ViewerError::Storage(err.to_string()))?
            .and_then(|block| {
                storage.read_block(&block)
                    .transpose()
            })
            .transpose()
            .map_err(|err| ViewerError::Storage(err.to_string()))?
            .map(|block| {
                match block.verify() {
                    Ok((false, _)) => Ok(None),

                    Ok((true, verifying_key)) => {
                        Ok(Some(ValidBlock {
                            block,
                            verifying_key
                        }))
                    }

                    Err(err) => Err(err)
                }
            })
            .transpose()?
            .flatten();

        let network_block = self.forward()?;

        dbg!(storage_block.as_ref().map(|b| b.block.current_hash()));
        dbg!(network_block.as_ref().map(|b| b.block.current_hash()));

        match (network_block, storage_block) {
            (Some(network_block), Some(storage_block)) => {
                let network_distance = crate::block_validator_distance(
                    self.prev_block,
                    &network_block.verifying_key
                );

                let storage_distance = crate::block_validator_distance(
                    self.prev_block,
                    &storage_block.verifying_key
                );

                if network_distance < storage_distance {
                    self.prev_block = *network_block.block.current_hash();

                    Ok(Some(network_block))
                }

                else {
                    self.prev_block = *storage_block.block.current_hash();

                    Ok(Some(storage_block))
                }
            }

            (Some(block), None) |
            (None, Some(block)) => {
                self.prev_block = *block.block.current_hash();

                Ok(Some(block))
            }

            (None, None) => Ok(None)
        }
    }
}
