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

use crate::crypto::*;
use crate::block::{Block, Error as BlockError};
use crate::transaction::Transaction;
use crate::storage::Storage;
use crate::network::Stream;
use crate::protocol::{Packet, PacketStream, PacketStreamError};
use crate::viewer::{BatchedViewer, ViewerError};

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
    pub async fn sync(&mut self) -> Result<(), NodeError<T, F>>
    where
        F::Error: 'static
    {
        if self.streams.is_empty() {
            return Ok(());
        }

        let mut viewer = match &self.storage {
            Some(storage) => {
                let viewer = BatchedViewer::open_from_storage(
                    self.streams.values_mut(),
                    storage
                ).await.map_err(NodeError::Viewer)?;

                match viewer {
                    Some(viewer) => viewer,

                    // Fallback to network viewer if storage is empty.
                    None => {
                        BatchedViewer::open(
                            self.streams.values_mut(),
                            self.root_block
                        ).await.map_err(NodeError::Viewer)?
                    }
                }
            }

            None => {
                BatchedViewer::open(
                    self.streams.values_mut(),
                    self.root_block
                ).await.map_err(NodeError::Viewer)?
            }
        };

        let mut history = Vec::with_capacity(self.history.len());

        history.push(self.root_block);

        loop {
            let block = match &self.storage {
                Some(storage) => viewer.forward_with_storage(storage).await
                    .map_err(NodeError::Viewer)?,

                None => viewer.forward().await
                    .map_err(NodeError::Viewer)?
            };

            let Some(block) = block else {
                break;
            };

            if let Some(storage) = &self.storage {
                storage.write_block(&block.block)
                    .map_err(NodeError::Storage)?;
            }

            history.push(block.hash);
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
