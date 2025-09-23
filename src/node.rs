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
use std::sync::Arc;

use spin::RwLock;

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
    storage: Option<F>,
    is_synced: bool,
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
            storage: None,
            is_synced: false,
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
        #[cfg(feature = "tracing")]
        tracing::info!("synchronizing node state");

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

        self.is_synced = true;
        self.history = history;

        Ok(())
    }

    /// Start the node server.
    ///
    /// This method will use the provided `spawner` callback to spawn background
    /// async tasks which will be listening to the available packet streams and
    /// process incoming packets. The method itself will be listening for new
    /// connections and continue spawning the tasks.
    ///
    /// All the non-critical errors will be silenced and displayed in tracing
    /// logs only.
    pub async fn start(
        mut self,
        options: NodeOptions,
        mut spawner: impl FnMut(Box<dyn std::future::Future<Output = ()>>)
    ) -> Result<(), NodeError<T, F>>
    where
        T: 'static,
        F: 'static
    {
        #[cfg(feature = "tracing")]
        tracing::info!("starting the node");

        if !self.is_synced {
            #[cfg(feature = "tracing")]
            tracing::info!("syncing the node");

            self.sync().await?;
        }

        let mut existing_streams = HashSet::new();

        let history = Arc::new(RwLock::new(self.history));
        let pending_blocks = Arc::new(RwLock::new(self.pending_blocks));
        let pending_transactions = Arc::new(RwLock::new(self.pending_transactions));

        for (endpoint_id, mut stream) in self.streams {
            #[cfg(feature = "tracing")]
            tracing::info!(
                endpoint_id = base64_encode(endpoint_id),
                "spawn endpoint listener"
            );

            existing_streams.insert(endpoint_id);

            let root_block = self.root_block;
            let storage = self.storage.clone();

            let history = history.clone();
            let pending_blocks = pending_blocks.clone();
            let pending_transactions = pending_transactions.clone();

            spawner(Box::new(async move {
                loop {
                    // TODO: timeout support
                    let packet = stream.recv().await;

                    match packet {
                        Ok(packet) => {
                            match packet {
                                Packet::AskHistory {
                                    root_block: received_root_block,
                                    offset,
                                    max_length
                                } if received_root_block == root_block => {
                                    let history = history.read()
                                        .iter()
                                        .skip(offset as usize)
                                        .take(options.max_history_length.min(max_length as usize))
                                        .copied()
                                        .collect();

                                    if let Err(err) = stream.send(Packet::History {
                                        root_block,
                                        offset,
                                        history
                                    }).await {
                                        #[cfg(feature = "tracing")]
                                        tracing::error!(
                                            err = err.to_string(),
                                            "failed to send packet to the packets stream"
                                        );

                                        break;
                                    }
                                }

                                Packet::AskPendingBlocks {
                                    root_block: received_root_block
                                } if received_root_block == root_block => {
                                    let pending_blocks = pending_blocks.read()
                                        .iter()
                                        .map(|(hash, block)| {
                                            let approvals = block.approvals()
                                                .to_vec()
                                                .into_boxed_slice();

                                            (*hash, approvals)
                                        })
                                        .collect();

                                    if let Err(err) = stream.send(Packet::PendingBlocks {
                                        root_block,
                                        pending_blocks
                                    }).await {
                                        #[cfg(feature = "tracing")]
                                        tracing::error!(
                                            err = err.to_string(),
                                            "failed to send packet to the packets stream"
                                        );

                                        break;
                                    }
                                }

                                Packet::AskPendingTransactions {
                                    root_block: received_root_block
                                } if received_root_block == root_block => {
                                    let pending_transactions = pending_transactions.read()
                                        .keys()
                                        .copied()
                                        .collect();

                                    if let Err(err) = stream.send(Packet::PendingTransactions {
                                        root_block,
                                        pending_transactions
                                    }).await {
                                        #[cfg(feature = "tracing")]
                                        tracing::error!(
                                            err = err.to_string(),
                                            "failed to send packet to the packets stream"
                                        );

                                        break;
                                    }
                                }

                                Packet::AskBlock {
                                    root_block: received_root_block,
                                    target_block
                                } if received_root_block == root_block => {
                                    if let Some(block) = pending_blocks.read().get(&target_block) {
                                        if let Err(err) = stream.send(Packet::Block {
                                            root_block,
                                            block: block.clone()
                                        }).await {
                                            #[cfg(feature = "tracing")]
                                            tracing::error!(
                                                err = err.to_string(),
                                                "failed to send packet to the packets stream"
                                            );

                                            break;
                                        }
                                    }

                                    else if let Some(storage) = &storage {
                                        match storage.read_block(&target_block) {
                                            Ok(Some(block)) => {
                                                if let Err(err) = stream.send(Packet::Block {
                                                    root_block,
                                                    block
                                                }).await {
                                                    #[cfg(feature = "tracing")]
                                                    tracing::error!(
                                                        err = err.to_string(),
                                                        "failed to send packet to the packets stream"
                                                    );

                                                    break;
                                                }
                                            }

                                            Ok(None) => (),

                                            Err(err) => {
                                                #[cfg(feature = "tracing")]
                                                tracing::error!(
                                                    ?err,
                                                    "failed to read block from the storage"
                                                );

                                                break;
                                            }
                                        }
                                    }
                                }

                                Packet::AskTransaction {
                                    root_block: received_root_block,
                                    transaction
                                } if received_root_block == root_block => {
                                    #[allow(clippy::collapsible_if)]
                                    if let Some(transaction) = pending_transactions.read().get(&transaction) {
                                        if let Err(err) = stream.send(Packet::Transaction {
                                            root_block,
                                            transaction: transaction.clone()
                                        }).await {
                                            #[cfg(feature = "tracing")]
                                            tracing::error!(
                                                err = err.to_string(),
                                                "failed to send packet to the packets stream"
                                            );

                                            break;
                                        }
                                    }
                                }

                                _ => ()
                            }
                        }

                        Err(err) => {
                            #[cfg(feature = "tracing")]
                            tracing::error!(
                                err = err.to_string(),
                                "failed to read packet from the packets stream"
                            );

                            break;
                        }
                    }
                }
            }));
        }

        Ok(())
    }
}

/// A helper struct connected to the running node. It can be used to perform
/// client-side operations like announcing transactions to the network.
pub struct NodeHandler {

}
