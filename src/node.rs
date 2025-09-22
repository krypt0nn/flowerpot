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

use std::collections::{HashMap, VecDeque};

use crate::crypto::*;
use crate::block::{Block, BlockContent, BlockStatus, Error as BlockError};
use crate::transaction::Transaction;
use crate::storage::Storage;
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
    ///
    /// This is a helper struct which can be used to traverse through the block
    /// known to some node. This can be used to perform blockchain
    /// synchronization.
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

#[derive(Debug,thiserror::Error)]
pub enum NodeError<T: Stream, F: Storage> {
    #[error(transparent)]
    PacketStream(PacketStreamError<T>),

    #[error(transparent)]
    Viewer(ViewerError<T>),

    #[error(transparent)]
    Storage(F::Error),

    #[error(transparent)]
    Block(BlockError)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeOptions {
    /// Maximal length of the `History` packet which will be sent as a response
    /// on the `AskHistory` packet.
    ///
    /// The `History` packet scales linearly with abount 32 bytes per history
    /// entry, so it doesn't take much space and network bandwidth to be sent.
    /// It is not recommended to keep this value low - this will result in
    /// increased amount of `AskHistory` packets.
    ///
    /// Default is `1024`.
    pub max_history_length: usize,

    /// Accept incoming pending blocks and store them in the memory until
    /// approved.
    ///
    /// If disabled your node will not act as a normal blockchain node and
    /// reduce overall network quality.
    ///
    /// Default is `true`.
    pub accept_pending_blocks: bool,

    /// Accept incoming pending transactions and store them in the memory until
    /// approved.
    ///
    /// If disabled your node will not act as a normal blockchain node and
    /// reduce overall network quality.
    ///
    /// Default is `true`.
    pub accept_pending_transactions: bool
}

impl Default for NodeOptions {
    fn default() -> Self {
        Self {
            max_history_length: 1024,
            accept_pending_blocks: true,
            accept_pending_transactions: true
        }
    }
}

pub struct Node<T: Stream, F: Storage> {
    root_block: Hash,
    streams: HashMap<[u8; 32], PacketStream<T>>,
    stream_i: usize,
    storage: Option<F>,
    history: Vec<Hash>,
    pending_blocks: HashMap<Hash, Block>,
    pending_transactions: HashMap<Hash, Transaction>
}

impl<T: Stream, F: Storage> Node<T, F> {
    /// Create new empty node.
    pub fn new(root_block: impl Into<Hash>) -> Result<Self, NodeError<T, F>> {
        Ok(Self {
            root_block: root_block.into(),
            streams: HashMap::new(),
            stream_i: 0,
            storage: None,
            history: Vec::new(),
            pending_blocks: HashMap::new(),
            pending_transactions: HashMap::new()
        })
    }

    /// Add new connection.
    pub fn add_connection(&mut self, stream: PacketStream<T>) -> &mut Self {
        if !self.streams.contains_key(stream.endpoint_id()) {
            self.streams.insert(*stream.endpoint_id(), stream);
        }

        self
    }

    /// Add blockchain storage to the node.
    pub fn attach_storage(&mut self, storage: F) -> &mut Self {
        self.storage = Some(storage);

        self
    }

    /// Synchronize blockchain history with all the available connections and,
    /// if provided, local blockchain storage.
    ///
    /// This method performs **full blockchain synchronization** starting from
    /// the root block.
    ///
    /// Protocol agreements:
    ///
    /// 1. Block becomes approved once it gets 2/3 approvals of total validators
    ///    number for this block, besides the block's author. This ensures that
    ///    the block is following the standard shared by majority of the network
    ///    controlling nodes.
    /// 2. Once there's a new approved block which references the previous one -
    ///    the previous block cannot be replaced even if replacing block gets
    ///    more approvals or has higher validator priority. This block is then
    ///    considered "fixated", and this is needed to prevent validators from
    ///    doing massive history rewrites. **(NOT IMPLEMENTED)**
    /// 3. Until current block is fixated a new block can replace it if the xor
    ///    distance between the previous block (which is fixated) and the new
    ///    block author's public key hash is lower than for the current block.
    ///    Assuming block hashes are distributed uniformally this should allow
    ///    all the validators to get about equal amount of blocks they can
    ///    create and fixate on average.
    /// 4. If validator didn't participate in approving of the last 32 blocks
    ///    then it's forcely removed from the network. This is needed to prevent
    ///    people from creating validators which don't participate in the
    ///    network maintenance and break the 2/3 validators rule.
    pub async fn sync(&mut self) -> Result<(), NodeError<T, F>> {
        if self.streams.is_empty() {
            return Ok(());
        }

        let mut viewers = Vec::with_capacity(self.streams.len());

        for stream in self.streams.values_mut() {
            let viewer = Viewer::open(stream, self.root_block).await
                .map_err(NodeError::Viewer)?;

            viewers.push(viewer);
        }

        // Iterate through all the available viewers and using these two
        // block pointers synchronize the history.
        let mut prev_block = self.root_block;
        let mut curr_block: Option<ValidBlock> = None;
        let mut history = Vec::with_capacity(self.history.len());

        loop {
            history.push(prev_block);

            // Select current block from all the available viewers.
            for viewer in &mut viewers {
                let block = viewer.forward().await
                    .map_err(NodeError::Viewer)?;

                if let Some(block) = block {
                    if block.block.previous() != &prev_block {
                        // TODO: remove the viewer (has different history than us)

                        continue;
                    }

                    if let Some(curr_block) = &mut curr_block {
                        let curr_distance = crate::block_validator_distance(
                            &prev_block,
                            &curr_block.public_key
                        );

                        let new_distance = crate::block_validator_distance(
                            &prev_block,
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

            // If storage is available - then compare selected current block
            // with the stored one, or write it to the storage if there's none.
            if let Some(storage) = &self.storage {
                let storage_block = storage.next_block(&prev_block)
                    .map_err(NodeError::Storage)?
                    .and_then(|block| {
                        storage.read_block(&block)
                            .transpose()
                    })
                    .transpose()
                    .map_err(NodeError::Storage)?
                    .map(|block| {
                        match block.verify() {
                            Ok((false, _, _)) => Ok(None),

                            Ok((true, hash, public_key)) => {
                                Ok(Some(ValidBlock {
                                    block,
                                    hash,
                                    public_key
                                }))
                            }

                            Err(err) => Err(err)
                        }
                    })
                    .transpose()
                    .map_err(NodeError::Block)?
                    .flatten();

                match (&mut curr_block, storage_block) {
                    (Some(curr_block), Some(storage_block)) => {
                        let curr_distance = crate::block_validator_distance(
                            &prev_block,
                            &curr_block.public_key
                        );

                        let new_distance = crate::block_validator_distance(
                            &prev_block,
                            &storage_block.public_key
                        );

                        if new_distance < curr_distance {
                            *curr_block = storage_block;
                        } else {
                            storage.write_block(&curr_block.block)
                                .map_err(NodeError::Storage)?;
                        }
                    }

                    (Some(curr_block), None) => {
                        storage.write_block(&curr_block.block)
                            .map_err(NodeError::Storage)?;
                    }

                    (None, Some(storage_block)) => {
                        curr_block = Some(storage_block);
                    }

                    (None, None) => ()
                }
            }

            // Break the sync loop if no block found.
            let Some(block) = curr_block else {
                break;
            };

            prev_block = block.hash;
            curr_block = None;
        }

        self.history = history;

        Ok(())
    }

    /// Read packet from connected streams and process it.
    pub async fn listen(
        &mut self,
        options: &NodeOptions
    ) -> Result<(), NodeError<T, F>> {
        // Not using futures::select or similar methods here because they're not
        // cancel safe. Some more complicated approach is needed.

        let mut stream = self.streams.values_mut()
            .nth(self.stream_i);

        if stream.is_none() {
            if self.stream_i == 0 {
                return Ok(());
            }

            self.stream_i = 0;

            stream = self.streams.values_mut().next();
        }

        let Some(stream) = stream else {
            return Ok(());
        };

        self.stream_i += 1;

        // TODO: timeout support
        let packet = stream.recv().await
            .map_err(NodeError::PacketStream)?;

        match packet {
            Packet::AskHistory {
                root_block,
                offset,
                max_length
            } if root_block == self.root_block => {
                let history = self.history.iter()
                    .skip(offset as usize)
                    .take(options.max_history_length.min(max_length as usize))
                    .copied()
                    .collect();

                stream.send(Packet::History {
                    root_block,
                    offset,
                    history
                }).await.map_err(NodeError::PacketStream)?;
            }

            Packet::AskPendingBlocks {
                root_block
            } if root_block == self.root_block => {
                let pending_blocks = self.pending_blocks.iter()
                    .map(|(hash, block)| {
                        let approvals = block.approvals()
                            .to_vec()
                            .into_boxed_slice();

                        (*hash, approvals)
                    })
                    .collect();

                stream.send(Packet::PendingBlocks {
                    root_block,
                    pending_blocks
                }).await.map_err(NodeError::PacketStream)?;
            }

            Packet::AskPendingTransactions {
                root_block
            } if root_block == self.root_block => {
                let pending_transactions = self.pending_transactions.keys()
                    .copied()
                    .collect();

                stream.send(Packet::PendingTransactions {
                    root_block,
                    pending_transactions
                }).await.map_err(NodeError::PacketStream)?;
            }

            Packet::AskBlock {
                root_block,
                target_block
            } if root_block == self.root_block => {
                if let Some(block) = self.pending_blocks.get(&target_block) {
                    stream.send(Packet::Block {
                        root_block,
                        block: block.clone()
                    }).await.map_err(NodeError::PacketStream)?;
                }

                else if let Some(storage) = &self.storage
                    && let Some(block) = storage.read_block(&target_block).map_err(NodeError::Storage)?
                {
                    stream.send(Packet::Block {
                        root_block,
                        block
                    }).await.map_err(NodeError::PacketStream)?;
                }
            }

            Packet::AskTransaction {
                root_block,
                transaction
            } if root_block == self.root_block => {
                if let Some(transaction) = self.pending_transactions.get(&transaction) {
                    stream.send(Packet::Transaction {
                        root_block,
                        transaction: transaction.clone()
                    }).await.map_err(NodeError::PacketStream)?;
                }
            }

            _ => ()
        }

        Ok(())
    }
}
