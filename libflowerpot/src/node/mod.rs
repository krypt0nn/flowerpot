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
use std::time::Duration;
use std::sync::mpsc::Sender;
use std::sync::Arc;

use spin::{RwLock, RwLockReadGuard};

use crate::crypto::base64;
use crate::crypto::hash::Hash;
use crate::crypto::sign::{Signature, SigningKey, VerifyingKey};
use crate::transaction::Transaction;
use crate::block::{Block, BlockContent, BlockDecodeError};
use crate::storage::Storage;
use crate::protocol::packets::Packet;
use crate::protocol::network::{PacketStream, PacketStreamError};
use crate::viewer::{BatchedViewer, ViewerError};

mod validator;
mod handlers;

#[derive(Debug, thiserror::Error)]
pub enum NodeError<S: Storage> {
    #[error(transparent)]
    PacketStream(PacketStreamError),

    #[error(transparent)]
    Viewer(ViewerError),

    #[error(transparent)]
    Storage(S::Error),

    #[error(transparent)]
    Block(BlockDecodeError)
}

#[derive(Debug, Clone, Copy)]
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

    /// Maximal size in bytes of a transaction.
    ///
    /// Bigger transactions will be rejected immediately upon receiving.
    ///
    /// It is recommended to keep this value high enough because network nodes
    /// spend gas to add transactions to the blockchain which already limits
    /// how many data they can practically send to the network.
    ///
    /// > This is applied to the `Transaction` packets only.
    ///
    /// Default is `33554432` bytes (32 MB).
    pub max_transaction_size: usize,

    /// Accept incoming transactions.
    ///
    /// This option disables the `Transaction` packet processing.
    ///
    /// If disabled your node will not act as a normal blockchain node and
    /// reduce overall network quality.
    ///
    /// Default is `true`.
    pub accept_transactions: bool,

    /// Accept incoming blocks.
    ///
    /// This option disables the `Block` packet processing.
    ///
    /// If disabled your node will not act as a normal blockchain node and
    /// reduce overall network quality.
    ///
    /// Default is `true`.
    pub accept_blocks: bool,

    /// Resolve missing transactions and fetch them from the remote nodes.
    ///
    /// Nodes exchange special `PendingTransactions` and `PendingBlocks` packets
    /// to share list of known pending transactions and blocks' hashes. If this
    /// option is disabled, then upon receiving such packet we won't try to
    /// find out which transactions we're missing and won't try to fetch them.
    ///
    /// This option is the main mechanism of pending transactions
    /// synchronization in the network.
    ///
    /// If disabled your node will not act as a normal blockchain node and
    /// reduce overall network quality.
    ///
    /// Default is `true`.
    pub fetch_pending_transactions: bool,

    /// Resolve missing transactions and fetch them from the remote nodes.
    ///
    /// Nodes exchange special `PendingTransactions` and `PendingBlocks` packets
    /// to share list of known pending transactions and blocks' hashes. If this
    /// option is disabled, then upon receiving such packet we won't try to
    /// find out which blocks we're missing and won't try to fetch them.
    ///
    /// This option is the main mechanism of pending blocks synchronization in
    /// the network.
    ///
    /// If disabled your node will not act as a normal blockchain node and
    /// reduce overall network quality.
    ///
    /// Default is `true`.
    pub fetch_pending_blocks: bool,

    /// When specified this function will be used to filter incoming
    /// transactions and accept only those for which the provided function
    /// returned `true`.
    ///
    /// This option is needed when you use blockchain for your own application
    /// and you want to accept transactions of special format only.
    ///
    /// This filter function is applied to the `Transaction` packets only.
    /// It is not applied to the blocks, so you'd need to specify the
    /// `blocks_filter` as well.
    ///
    /// Default is `None`.
    pub transactions_filter: Option<fn(&Hash, &VerifyingKey, &Transaction) -> bool>,

    /// When specified this function will be used to filter incoming blocks
    /// and accept only those for which the provided function returned `true`.
    ///
    /// This option is needed when you use blockchain for your own application
    /// and you want to accept blocks of special format only.
    ///
    /// This filter function is applied to the `Block` packets only.
    ///
    /// Default is `None`.
    pub blocks_filter: Option<fn(&Hash, &VerifyingKey, &Block) -> bool>,

    /// Amount of time a validator thread will wait before starting the
    /// consensus mechanism. This time is needed so that the node can
    /// synchronize all the pending data. It is recommended to keep this value
    /// relatively high, as it will be used only initially and won't affect
    /// further algorithm work.
    ///
    /// Default is `1m`.
    pub validator_warmup_time: Duration,

    /// Minimal amount of transactions needed to form a new block.
    ///
    /// Default is `1`.
    pub validator_min_transactions_num: usize,

    /// Maximal amount of transactions needed to form a new block.
    ///
    /// Default is `128`.
    pub validator_max_transactions_num: usize,

    /// Amount of time validator will wait to receive pending blocks from other
    /// validators.
    ///
    /// It is recommended to keep this value reasonably high so that blocks can
    /// be shared between the network nodes. Making this value small will also
    /// result in approving many different blocks which can be abused by
    /// malicious validators.
    ///
    /// Default is `20s`.
    pub validator_blocks_await_time: Duration,

    /// Amount of time validator will wait for other validators to send their
    /// block approvals until starting a new validation round.
    ///
    /// Default is `10s`.
    pub validator_block_approvals_await_time: Duration
}

impl Default for NodeOptions {
    fn default() -> Self {
        Self {
            max_history_length: 1024,
            max_transaction_size: 32 * 1024 * 1024,
            accept_transactions: true,
            accept_blocks: true,
            fetch_pending_transactions: true,
            fetch_pending_blocks: true,
            blocks_filter: None,
            transactions_filter: None,
            validator_warmup_time: Duration::from_secs(60),
            validator_min_transactions_num: 1,
            validator_max_transactions_num: 128,
            validator_blocks_await_time: Duration::from_secs(20),
            validator_block_approvals_await_time: Duration::from_secs(10)
        }
    }
}

pub struct Node<S: Storage> {
    root_block: Hash,
    streams: HashMap<[u8; 32], PacketStream>,
    storage: Option<S>,
    owned_validators: Vec<SigningKey>,

    history: Vec<Hash>,
    validators: Vec<VerifyingKey>,
    current_distance: Hash,

    indexed_transactions: HashSet<Hash>,
    pending_transactions: HashMap<Hash, Transaction>,
    pending_blocks: HashMap<Hash, Block>
}

impl<S: Storage> Node<S> {
    /// Create new empty node.
    pub fn new(root_block: impl Into<Hash>) -> Self {
        Self {
            root_block: root_block.into(),
            streams: HashMap::new(),
            storage: None,
            owned_validators: Vec::new(),

            history: Vec::new(),
            validators: Vec::new(),
            current_distance: Hash::from([0xFF; 32]),

            indexed_transactions: HashSet::new(),
            pending_transactions: HashMap::new(),
            pending_blocks: HashMap::new()
        }
    }

    /// Add new packet stream.
    pub fn add_stream(&mut self, stream: PacketStream) -> &mut Self {
        if !self.streams.contains_key(stream.peer_id()) {
            self.streams.insert(*stream.peer_id(), stream);
        }

        self
    }

    /// Add blockchain storage to the node.
    pub fn attach_storage(&mut self, storage: S) -> &mut Self {
        self.storage = Some(storage);

        self
    }

    /// Add validator signing key.
    ///
    /// If set, node will start a background task to create new blocks and send
    /// approvals for other validators' nodes.
    ///
    /// Multiple validator keys are allowed to be stored.
    pub fn add_validator(
        &mut self,
        validator: impl Into<SigningKey>
    ) -> &mut Self {
        let validator: SigningKey = validator.into();

        if !self.owned_validators.contains(&validator) {
            self.owned_validators.push(validator);
        }

        self
    }

    /// Synchronize blockchain history with all the available connections and,
    /// if provided, local blockchain storage.
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
    pub fn sync(&mut self) -> Result<(), NodeError<S>>
    where
        S::Error: 'static
    {
        #[cfg(feature = "tracing")]
        tracing::info!("synchronizing node state");

        if self.streams.is_empty() && self.storage.is_none() {
            return Ok(());
        }

        let mut viewer = match &self.storage {
            Some(storage) => {
                let viewer = BatchedViewer::open_from_storage(
                    self.streams.values_mut(),
                    storage
                ).map_err(NodeError::Viewer)?;

                match viewer {
                    Some(viewer) => viewer,

                    // Fallback to network viewer if storage is empty.
                    None => {
                        BatchedViewer::open(
                            self.streams.values_mut(),
                            self.root_block
                        ).map_err(NodeError::Viewer)?
                    }
                }
            }

            None => {
                BatchedViewer::open(
                    self.streams.values_mut(),
                    self.root_block
                ).map_err(NodeError::Viewer)?
            }
        };

        let mut history = Vec::with_capacity(self.history.len());

        loop {
            let block = match &self.storage {
                Some(storage) => viewer.forward_with_storage(storage)
                    .map_err(NodeError::Viewer)?,

                None => viewer.forward()
                    .map_err(NodeError::Viewer)?
            };

            let Some(block) = block else {
                break;
            };

            #[cfg(feature = "tracing")]
            tracing::debug!(
                curr_block_hash = block.block.current_hash().to_base64(),
                prev_block_hash = block.block.previous_hash().to_base64(),
                author = block.verifying_key.to_base64(),
                "read block"
            );

            // Index stored transactions.
            if let BlockContent::Transactions(transactions) = block.block.content() {
                for transaction in transactions {
                    self.indexed_transactions.insert(*transaction.hash());
                }
            }

            // If storage is available - then update it.
            if let Some(storage) = &self.storage {
                storage.write_block(&block.block)
                    .map_err(NodeError::Storage)?;
            }

            history.push(*block.block.current_hash());
        }

        self.validators = viewer.current_validators()
            .map_err(NodeError::Viewer)?;

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
    pub fn start(
        self,
        options: NodeOptions
    ) -> Result<NodeHandler<S>, NodeError<S>>
    where
        S: Send + 'static,
        S::Error: Send + 'static
    {
        #[cfg(feature = "tracing")]
        tracing::info!("starting the node");

        let handler = NodeHandler {
            streams: Arc::new(RwLock::new(HashMap::with_capacity(self.streams.len()))),
            options,

            root_block: self.root_block,
            storage: self.storage.clone(),

            history: Arc::new(RwLock::new(self.history)),
            current_distance: Arc::new(RwLock::new(self.current_distance)),
            validators: Arc::new(RwLock::new(self.validators)),

            indexed_transactions: Arc::new(RwLock::new(self.indexed_transactions)),
            pending_transactions: Arc::new(RwLock::new(self.pending_transactions)),
            pending_blocks: Arc::new(RwLock::new(self.pending_blocks))
        };

        // Add streams to the handler.
        for (endpoint_id, stream) in self.streams {
            #[cfg(feature = "tracing")]
            tracing::info!(
                endpoint_id = base64::encode(endpoint_id),
                "adding connection"
            );

            handler.add_stream(stream);
        }

        // Start validator thread if any keys are provided.
        if !self.owned_validators.is_empty() {
            let handler = handler.clone();
            let validators = self.owned_validators;

            std::thread::spawn(move || {
                validator::run(handler, validators);
            });
        }

        #[cfg(feature = "tracing")]
        tracing::info!("node started");

        Ok(handler)
    }
}

/// A helper struct connected to the running node. It can be used to perform
/// client-side operations like announcing transactions to the network.
#[derive(Debug, Clone)]
pub struct NodeHandler<S> {
    streams: Arc<RwLock<HashMap<[u8; 32], Sender<Packet>>>>,
    options: NodeOptions,

    root_block: Hash,
    storage: Option<S>,

    history: Arc<RwLock<Vec<Hash>>>,
    current_distance: Arc<RwLock<Hash>>,
    validators: Arc<RwLock<Vec<VerifyingKey>>>,

    indexed_transactions: Arc<RwLock<HashSet<Hash>>>,
    pending_transactions: Arc<RwLock<HashMap<Hash, Transaction>>>,
    pending_blocks: Arc<RwLock<HashMap<Hash, Block>>>
}

impl<S: Storage> NodeHandler<S> {
    /// Add new packet stream to the node connections pool.
    pub fn add_stream(&self, stream: PacketStream)
    where
        S: Send + 'static
    {
        let (sender, receiver) = std::sync::mpsc::channel();

        let peer_id = *stream.peer_id();

        #[cfg(feature = "tracing")]
        tracing::debug!(
            local_id = base64::encode(stream.local_id()),
            peer_id = base64::encode(peer_id),
            "adding connection"
        );

        let state = handlers::NodeState {
            handler: self.clone(),
            stream,
            receiver
        };

        std::thread::spawn(move || {
            handlers::handle(state);
        });

        self.streams.write().insert(peer_id, sender);
    }

    /// Get list of available streams' endpoint IDs.
    pub fn streams(&self) -> Box<[[u8; 32]]> {
        self.streams.read()
            .keys()
            .cloned()
            .collect::<Box<[[u8; 32]]>>()
    }

    /// Get list of known blockchain history.
    #[inline]
    pub fn history(&self) -> RwLockReadGuard<'_, Vec<Hash>> {
        self.history.read()
    }

    /// Get list of current blockchain validators.
    #[inline]
    pub fn validators(&self) -> RwLockReadGuard<'_, Vec<VerifyingKey>> {
        self.validators.read()
    }

    /// Get table of known pending transactions.
    #[inline]
    pub fn pending_transactions(
        &self
    ) -> RwLockReadGuard<'_, HashMap<Hash, Transaction>> {
        self.pending_transactions.read()
    }

    /// Get table of known pending blocks.
    #[inline]
    pub fn pending_blocks(
        &self
    ) -> RwLockReadGuard<'_, HashMap<Hash, Block>> {
        self.pending_blocks.read()
    }

    fn send(&self, packet: Packet) {
        let mut disconnected = Vec::new();

        let lock = self.streams.read();

        for (endpoint_id, sender) in lock.iter() {
            if sender.send(packet.clone()).is_err() {
                disconnected.push(*endpoint_id);
            }
        }

        drop(lock);

        for endpoint_id in disconnected {
            self.streams.write().remove(&endpoint_id);
        }
    }

    /// Ask connected nodes to share their pending transactions.
    pub fn ask_pending_transactions(&self) {
        self.send(Packet::AskPendingTransactions {
            root_block: self.root_block
        });
    }

    /// Ask connected nodes to share their pending blocks.
    pub fn ask_pending_blocks(&self) {
        self.send(Packet::AskPendingBlocks {
            root_block: self.root_block
        });
    }

    /// Send transaction to all the connected nodes.
    pub fn send_transaction(
        &self,
        transaction: impl Into<Transaction>
    ) {
        self.send(Packet::Transaction {
            root_block: self.root_block,
            transaction: transaction.into()
        });
    }

    /// Send block to all the connected nodes.
    pub fn send_block(
        &self,
        block: impl Into<Block>
    ) {
        self.send(Packet::Block {
            root_block: self.root_block,
            block: block.into()
        });
    }

    /// Send block approval to all the connected nodes.
    pub fn send_block_approval(
        &self,
        block: impl Into<Hash>,
        approval: impl Into<Signature>
    ) {
        self.send(Packet::ApproveBlock {
            root_block: self.root_block,
            target_block: block.into(),
            approval: approval.into()
        });
    }
}
