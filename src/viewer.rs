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

use crate::crypto::*;
use crate::block::{Block, BlockContent, BlockStatus, Error as BlockError};
use crate::network::Stream;
use crate::protocol::{Packet, PacketStream, PacketStreamError};

#[derive(Debug, thiserror::Error)]
pub enum ViewerError<S: Stream> {
    #[error(transparent)]
    PacketStream(PacketStreamError<S>),

    #[error(transparent)]
    Block(BlockError),

    #[error("stream returned invalid block")]
    InvalidBlock,

    #[error("stream returned invalid history")]
    InvalidHistory
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidBlock {
    pub block: Block,
    pub hash: Hash,
    pub public_key: PublicKey
}

/// Viewer is a helper struct which uses the underlying packet stream connection
/// to traverse blockchain history known to the remote node.
pub struct Viewer<'stream, S: Stream> {
    stream: &'stream mut PacketStream<S>,
    root_block: Hash,
    current_block: (u64, Hash),
    pending_history: VecDeque<Hash>,
    validators: Vec<(PublicKey, u8)>
}

impl<'stream, S: Stream> Viewer<'stream, S> {
    const MAX_HISTORY_LENGTH: u64 = 1024;

    /// Open viewer of the blockchain history known to the node with provided
    /// packet stream connection.
    pub async fn open(
        stream: &'stream mut PacketStream<S>,
        root_block: Hash
    ) -> Result<Self, ViewerError<S>> {
        // Ask for the root block of the blockchain.
        stream.send(&Packet::AskBlock {
            root_block,
            target_block: root_block
        }).await.map_err(ViewerError::PacketStream)?;

        let root_block_packet = stream.peek(|packet| {
            if let Packet::Block {
                root_block: received_root_block,
                block
            } = packet {
                return received_root_block == &root_block
                    && block.is_root();
            }

            false
        }).await.map_err(ViewerError::PacketStream)?;

        let Packet::Block { block, .. } = root_block_packet else {
            return Err(ViewerError::InvalidBlock);
        };

        // Verify the root block and obtain its author.
        let (is_valid, hash, public_key) = block.verify()
            .map_err(ViewerError::Block)?;

        if !is_valid || hash != root_block {
            return Err(ViewerError::InvalidBlock);
        }

        Ok(Self {
            stream,
            root_block,
            current_block: (0, hash),
            pending_history: VecDeque::new(),
            validators: vec![(public_key, 0)]
        })
    }

    /// Get list of current block validators.
    pub fn current_validators(
        &self
    ) -> impl ExactSizeIterator<Item = &PublicKey> {
        self.validators.iter().map(|(validator, _)| validator)
    }

    /// Request the next block of the blockchain history known to the underlying
    /// node, verify and return it. If we've reached the end of the known
    /// history then `None` is returned.
    pub async fn forward(&mut self) -> Result<Option<ValidBlock>, ViewerError<S>> {
        // Ask for the blockchain history if the history pool is empty.
        let pending_hash = if let Some(hash) = self.pending_history.pop_front() {
            hash
        } else {
            self.stream.send(&Packet::AskHistory {
                root_block: self.root_block,
                offset: self.current_block.0,
                max_length: Self::MAX_HISTORY_LENGTH
            }).await.map_err(ViewerError::PacketStream)?;

            let history = self.stream.peek(|packet| {
                if let Packet::History {
                    root_block: received_root_block,
                    offset: received_offset,
                    ..
                } = packet {
                    return received_root_block == &self.root_block
                        && received_offset == &self.current_block.0;
                }

                false
            }).await.map_err(ViewerError::PacketStream)?;

            let Packet::History { history, .. } = history else {
                return Err(ViewerError::InvalidHistory);
            };

            // We've reached the end of the known history.
            if history.len() < 2 {
                return Ok(None);
            }

            // First block of the history is different from what we expected.
            if history[0] != self.current_block.1 {
                return Err(ViewerError::InvalidHistory);
            }

            if history.len() > 2 {
                self.pending_history.extend(&history[2..]);
            }

            history[1]
        };

        // Request the block.
        self.stream.send(Packet::AskBlock {
            root_block: self.root_block,
            target_block: pending_hash
        }).await.map_err(ViewerError::PacketStream)?;

        let packet = self.stream.peek(|packet| {
            if let Packet::Block {
                root_block: received_root_block,
                ..
            } = packet {
                return received_root_block == &self.root_block;
            }

            false
        }).await.map_err(ViewerError::PacketStream)?;

        let Packet::Block { mut block, .. } = packet else {
            return Err(ViewerError::InvalidBlock);
        };

        // Validate the received block.
        let validators = self.current_validators()
            .cloned()
            .collect::<Vec<_>>();

        let status = block.validate(&validators)
            .map_err(ViewerError::Block)?;

        let BlockStatus::Approved {
            hash,
            public_key,
            approvals,
            ..
        } = status else {
            return Err(ViewerError::InvalidBlock);
        };

        // Update validators last seen counters.
        for (public_key, counter) in &mut self.validators {
            if approvals.iter().any(|(_, validator)| validator == public_key) {
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

        // Update current block info.
        self.current_block.0 += 1;
        self.current_block.1 = hash;

        Ok(Some(ValidBlock {
            block,
            hash,
            public_key
        }))
    }
}

/// Batched viewer is a helper struct which takes multiple `Viewer`-s and allows
/// iterating through the commonly known blockchain history, selecting the best
/// fork according to the protocol agreements.
pub struct BatchedViewer<'stream, S: Stream> {
    viewers: Vec<Viewer<'stream, S>>,
    prev_block: Hash
}

impl<'stream, S: Stream> BatchedViewer<'stream, S> {
    /// Open batched viewer of the blockchain history known to the provided
    /// nodes' packet streams
    pub async fn open(
        streams: impl IntoIterator<Item = &'stream mut PacketStream<S>>,
        root_block: Hash
    ) -> Result<Self, ViewerError<S>> {
        let mut viewers = Vec::new();

        for stream in streams {
            viewers.push(Viewer::open(stream, root_block).await?);
        }

        Ok(Self {
            viewers,
            prev_block: root_block
        })
    }

    /// Request the next block of the blockchain history known to the underlying
    /// nodes, verify and return it. If we've reached the end of the known
    /// history then `None` is returned.
    pub async fn forward(
        &mut self
    ) -> Result<Option<ValidBlock>, ViewerError<S>> {
        let mut curr_block: Option<ValidBlock> = None;

        for viewer in &mut self.viewers {
            let block = viewer.forward().await?;

            if let Some(block) = block {
                if block.block.previous() != &self.prev_block {
                    // TODO: remove the viewer (has different history than us)

                    continue;
                }

                if let Some(curr_block) = &mut curr_block {
                    let curr_distance = crate::block_validator_distance(
                        &self.prev_block,
                        &curr_block.public_key
                    );

                    let new_distance = crate::block_validator_distance(
                        &self.prev_block,
                        &block.public_key
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

        self.prev_block = block.hash;

        Ok(Some(block))
    }
}
