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
use crate::storage::{Storage, StorageError};
use crate::protocol::packets::Packet;
use crate::protocol::network::{PacketStream, PacketStreamError};

#[derive(Debug, thiserror::Error)]
pub enum ViewerError {
    #[error(transparent)]
    PacketStream(PacketStreamError),

    #[error(transparent)]
    Signature(#[from] SignatureError),

    #[error(transparent)]
    Storage(StorageError),

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
/// 1. All the blocks of the blockchain must be signed by a single validator.
/// 2. Timestamp of the following block must be greater or equal to the previous
///    block's timestamp.
/// 3. If multiple following block candidates available, then one with the
///    least timestamp value is chosen, with respect to (2). This is needed to
///    prevent massive history rewrites.
pub struct Viewer<'stream> {
    stream: &'stream mut PacketStream,

    /// Root block of the blockchain.
    root_block: Hash,

    /// Verifying key of the blockchain validator.
    verifying_key: VerifyingKey,

    /// List of blocks we need to fetch.
    pending_blocks: VecDeque<Hash>,

    /// Hash of the previously fetched block and its creation timestamp.
    prev_block: (Hash, time::UtcDateTime)
}

impl<'stream> Viewer<'stream> {
    const MAX_HISTORY_LENGTH: u64 = 1024;

    /// Open viewer of the blockchain history known to the node with provided
    /// packet stream connection.
    pub fn open(
        stream: &'stream mut PacketStream,
        root_block: impl Into<Hash>,
        verifying_key: impl Into<VerifyingKey>
    ) -> Result<Self, ViewerError> {
        let root_block: Hash = root_block.into();
        let verifying_key: VerifyingKey = verifying_key.into();

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
                return received_root_block == &root_block && block.is_root();
            }

            false
        }).map_err(ViewerError::PacketStream)?;

        let Packet::Block { block, .. } = root_block_packet else {
            return Err(ViewerError::InvalidBlock);
        };

        // Verify the root block and obtain its author.
        let (is_valid, block_verifying_key) = block.verify()?;

        if !is_valid
            || !block.is_root()
            || block.hash() != &root_block
            || block_verifying_key != verifying_key
        {
            return Err(ViewerError::InvalidBlock);
        }

        Ok(Self {
            stream,
            root_block,
            verifying_key,
            pending_blocks: VecDeque::from([*block.hash()]),
            prev_block: (*block.prev_hash(), time::UtcDateTime::UNIX_EPOCH)
        })
    }

    /// Open viewer using blocks stored in the provided storage. We will assume
    /// that all the blocks in that storage are verified.
    ///
    /// Return `Ok(None)` if storage doesn't have any blocks.
    ///
    /// **Security notice:** this method will assume that the root block's
    /// signer is the validator of the blockchain.
    pub fn open_from_storage(
        stream: &'stream mut PacketStream,
        storage: &dyn Storage
    )  -> Result<Option<Self>, ViewerError> {
        // Try to read root block from the storage.
        //
        // TODO: can be flattened into iter syntax somehow...
        let root_block = match storage.root_block() {
            Ok(Some(root_block)) => match storage.read_block(&root_block) {
                Ok(Some(root_block)) => root_block,

                Ok(None) => return Ok(None),
                Err(err) => return Err(ViewerError::Storage(err))
            }

            Ok(None) => return Ok(None),
            Err(err) => return Err(ViewerError::Storage(err))
        };

        // Verify this block.
        let (is_valid, verifying_key) = root_block.verify()?;

        if !is_valid || !root_block.is_root() {
            return Ok(None);
        }

        // TODO: we need to compare the storage blocks AGAINST the network
        //       blocks to find potential differences!!!

        // Try to read tail block hash from the storage.
        let tail_block = storage.tail_block()
            .map_err(ViewerError::Storage)?;

        let Some(tail_block) = tail_block else {
            return Ok(None);
        };

        let tail_block = storage.read_block(&tail_block)
            .map_err(ViewerError::Storage)?;

        let Some(tail_block) = tail_block else {
            return Ok(None);
        };

        Ok(Some(Self {
            stream,
            root_block: *root_block.hash(),
            verifying_key,
            pending_blocks: VecDeque::from([]),
            prev_block: (*tail_block.hash(), *tail_block.timestamp())
        }))
    }

    /// Get root block of the viewer's blockchain.
    #[inline(always)]
    pub const fn root_block(&self) -> &Hash {
        &self.root_block
    }

    /// Get verifying key of the viewer's blockchain validator.
    #[inline(always)]
    pub const fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Hash of the previously fetched block.
    ///
    /// This method will return a hash of the block which was fetched by the
    /// last `forward` method call.
    #[inline(always)]
    pub const fn prev_block(&self) -> &Hash {
        &self.prev_block.0
    }

    /// Request the next block of the blockchain history known to the underlying
    /// node, verify and return it. If we've reached the end of the known
    /// history then `None` is returned.
    pub fn forward(&mut self) -> Result<Option<ValidBlock>, ViewerError> {
        // Read the pending block hash.
        let pending_block = match self.pending_blocks.front() {
            // Directly if we have pending blocks history.
            Some(block) => *block,

            // Or by asking the network node.
            None => {
                // Ask and peak the history packet.
                self.stream.send(&Packet::AskHistory {
                    root_block: self.root_block,
                    since_block: self.prev_block.0,
                    max_length: Self::MAX_HISTORY_LENGTH
                }).map_err(ViewerError::PacketStream)?;

                let history = self.stream.peek(|packet| {
                    if let Packet::History {
                        root_block: received_root_block,
                        since_block: received_since_block,
                        ..
                    } = packet {
                        return received_root_block == &self.root_block
                            && received_since_block == &self.prev_block.0;
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

                // Extend on full history because the front hash will be removed
                // lated in the code. This will also prevent missing this hash
                // in case some of the following code breaks.
                self.pending_blocks.extend(history);

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
                block: received_block
            } = packet {
                return received_root_block == &self.root_block
                    && received_block.hash() == &pending_block;
            }

            false
        }).map_err(ViewerError::PacketStream)?;

        let Packet::Block { block, .. } = packet else {
            return Err(ViewerError::InvalidBlock);
        };

        // Decline the block if it doesn't match the previously stored block or
        // if its creation time is lower than one for the previous block.
        if block.prev_hash() != &self.prev_block.0
            || block.timestamp() < &self.prev_block.1
        {
            return Err(ViewerError::InvalidBlock);
        }

        // Verify the block and its author.
        let (is_valid, verifying_key) = block.verify()?;

        if !is_valid || verifying_key != self.verifying_key {
            return Err(ViewerError::InvalidBlock);
        }

        // Shift pending blocks history forward and return obtained block.
        self.pending_blocks.pop_front();
        self.prev_block = (*block.hash(), *block.timestamp());

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
    /// List of batched network blockchain viewers.
    viewers: Vec<Viewer<'stream>>,

    /// Root block of the blockchain.
    root_block: Hash,

    /// Verifying key of the blockchain validator.
    verifying_key: VerifyingKey,

    /// Hash of the previously fetched block.
    prev_block: Hash
}

impl<'stream> BatchedViewer<'stream> {
    /// Open batched viewer of the blockchain history known to the provided
    /// nodes' packet streams
    ///
    /// Return `Ok(None)` if no remote node viewers available.
    pub fn open(
        streams: impl IntoIterator<Item = &'stream mut PacketStream>,
        root_block: impl Into<Hash>,
        verifying_key: impl Into<VerifyingKey>
    ) -> Result<Option<Self>, ViewerError> {
        let root_block: Hash = root_block.into();
        let verifying_key: VerifyingKey = verifying_key.into();

        let mut viewers = Vec::new();

        for stream in streams {
            viewers.push(Viewer::open(
                stream,
                root_block,
                verifying_key.clone()
            )?);
        }

        if viewers.is_empty() {
            return Ok(None);
        }

        Ok(Some(Self {
            viewers,
            root_block,
            verifying_key,
            prev_block: Hash::ZERO
        }))
    }

    /// Open batched viewer using blocks stored in the provided storage. We will
    /// assume that all the blocks in that storage are validates and that the
    /// provided streams' endpoints have the same history.
    ///
    /// Return `Ok(None)` if storage doesn't have any blocks. Viewer will be
    /// returned even if no streams are available (in that case only `storage`
    /// blocks will be returned).
    ///
    /// **Security notice:** this method will assume that the root block's
    /// signer is the validator of the blockchain.
    pub fn open_from_storage(
        streams: impl IntoIterator<Item = &'stream mut PacketStream>,
        storage: &dyn Storage
    )  -> Result<Option<Self>, ViewerError> {
        let mut viewers = Vec::new();
        let mut prev_block = Hash::ZERO;

        // Read the root block from the storage.
        let root_block = storage.root_block()
            .map_err(ViewerError::Storage)?;

        let Some(root_block) = root_block else {
            return Ok(None);
        };

        let root_block = storage.read_block(&root_block)
            .map_err(ViewerError::Storage)?;

        let Some(root_block) = root_block else {
            return Ok(None);
        };

        // Verify root block and obtain its verifying key.
        let (is_valid, verifying_key) = root_block.verify()?;

        if !is_valid || !root_block.is_root() {
            return Ok(None);
        }

        // Build viewers for provided streams.
        for stream in streams {
            let Some(viewer) = Viewer::open_from_storage(stream, storage)? else {
                return Ok(None);
            };

            let viewer_prev_block = viewer.prev_block();

            // Update the locally stored prev block.
            if prev_block == Hash::ZERO {
                prev_block = *viewer_prev_block;
            }

            // Ignore remote node with different history overview.
            else if &prev_block != viewer_prev_block {
                continue;
            }

            viewers.push(viewer);
        }

        // Update prev_block hash to be the tail block of the storage if we
        // couldn't make any network viewer.
        if viewers.is_empty() {
            let tail_block = storage.tail_block()
                .map_err(ViewerError::Storage)?;

            let Some(tail_block) = tail_block else {
                return Ok(None);
            };

            prev_block = tail_block;
        }

        Ok(Some(Self {
            viewers,
            root_block: *root_block.hash(),
            verifying_key,
            prev_block
        }))
    }

    /// Get root block of the viewer's blockchain.
    #[inline(always)]
    pub const fn root_block(&self) -> &Hash {
        &self.root_block
    }

    /// Get verifying key of the viewer's blockchain validator.
    #[inline(always)]
    pub const fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
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

                // Update currently selected block variant to the one with
                // lowest timestamp.
                if let Some(curr_block) = &mut curr_block {
                    if curr_block.block.timestamp() > block.block.timestamp() {
                        *curr_block = block;
                    }
                }

                // Select the first block if none is selected yet.
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
    pub fn forward_with_storage(
        &mut self,
        storage: &dyn Storage
    ) -> Result<Option<ValidBlock>, ViewerError> {
        let storage_block = storage.next_block(&self.prev_block)
            .map_err(ViewerError::Storage)?
            .and_then(|block| {
                storage.read_block(&block)
                    .transpose()
            })
            .transpose()
            .map_err(ViewerError::Storage)?
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
                // Select block variant with lowest timestamp.
                if network_block.block.timestamp() < storage_block.block.timestamp() {
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
