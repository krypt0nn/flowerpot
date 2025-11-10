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
use crate::block::Block;
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

/// Viewer is a helper struct that uses the underlying packet stream connection
/// to traverse blockchain history known to the remote node.
///
/// The consensus is that:
///
/// 1. The author of the root block is the sole authority of the blockchain,
///    and all the following blocks must be signed by them.
/// 2. Timestamp of the following block must be greater or equal to the previous
///    block's timestamp.
/// 3. If multiple following block candidates available, then one with the
///    least timestamp value is chosen, with respect to (2). This is needed to
///    prevent massive history rewrites.
pub struct Viewer<'stream> {
    stream: &'stream mut PacketStream,

    /// Root block of the blockchain.
    root_block: Hash,

    /// Verifying key of the blockchain authority.
    authority: VerifyingKey,

    /// List of blocks we need to fetch.
    pending_blocks: (u64, VecDeque<Hash>),

    /// Hash of the previously fetched block.
    prev_block: Hash
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
        let (is_valid, verifying_key) = block.verify()?;

        if !is_valid || !block.is_root() || block.hash() != &root_block {
            return Err(ViewerError::InvalidBlock);
        }

        Ok(Self {
            stream,
            root_block,
            authority: verifying_key,
            pending_blocks: (0, VecDeque::from([*block.hash()])),
            prev_block: *block.prev_hash()
        })
    }

    /// Open viewer using blocks stored in the provided storage. We will assume
    /// that all the blocks in that storage are verified.
    ///
    /// Return `Ok(None)` if storage doesn't have any blocks.
    pub fn open_from_storage<S: Storage>(
        stream: &'stream mut PacketStream,
        storage: &S
    )  -> Result<Option<Self>, ViewerError> {
        // Try to read root block from the storage.
        //
        // TODO: can be flattened into iter syntax somehow...
        let root_block = match storage.root_block() {
            Ok(Some(root_block)) => match storage.read_block(&root_block) {
                Ok(Some(root_block)) => root_block,

                Ok(None) => return Ok(None),
                Err(err) => return Err(ViewerError::Storage(err.to_string()))
            }

            Ok(None) => return Ok(None),
            Err(err) => return Err(ViewerError::Storage(err.to_string()))
        };

        // Verify this block.
        let (is_valid, verifying_key) = root_block.verify()?;

        if !is_valid || !root_block.is_root() {
            return Ok(None);
        }

        // TODO: we need to compare the storage blocks AGAINST the network
        //       blocks to find potential differences!!!

        // Try to read tail block from the storage.
        let tail_block = storage.tail_block()
            .map_err(|err| ViewerError::Storage(err.to_string()))?;

        let Some(tail_block) = tail_block else {
            return Ok(None);
        };

        // Find the tail block's index.
        let mut i = 0;
        let mut prev_block = *root_block.prev_hash();

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
            root_block: *root_block.hash(),
            authority: verifying_key,
            pending_blocks: (i, VecDeque::from([tail_block])),
            prev_block
        }))
    }

    /// Get root block of the viewer's blockchain.
    #[inline(always)]
    pub const fn root_block(&self) -> &Hash {
        &self.root_block
    }

    /// Get verifying key of the viewer's blockchain authority.
    #[inline(always)]
    pub const fn verifying_key(&self) -> &VerifyingKey {
        &self.authority
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

        let Packet::Block { block, .. } = packet else {
            return Err(ViewerError::InvalidBlock);
        };

        // Decline the block if it doesn't match the previously stored block.
        if block.prev_hash() != &self.prev_block {
            return Err(ViewerError::InvalidBlock);
        }

        // Verify the block and its author.
        let (is_valid, verifying_key) = block.verify()?;

        if !is_valid || verifying_key != self.authority {
            return Err(ViewerError::InvalidBlock);
        }

        // Shift pending blocks history forward and return obtained block.
        self.pending_blocks.0 += 1;
        self.pending_blocks.1.pop_front();
        self.prev_block = *block.hash();

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
                if block.block.prev_hash() != &self.prev_block {
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

        self.prev_block = *block.block.hash();

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
                    self.prev_block = *network_block.block.hash();

                    Ok(Some(network_block))
                }

                else {
                    self.prev_block = *storage_block.block.hash();

                    Ok(Some(storage_block))
                }
            }

            (Some(block), None) |
            (None, Some(block)) => {
                self.prev_block = *block.block.hash();

                Ok(Some(block))
            }

            (None, None) => Ok(None)
        }
    }
}
