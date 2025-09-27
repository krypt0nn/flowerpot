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
use std::sync::mpsc::{Sender, TryRecvError};
use std::sync::Arc;

use spin::{RwLock, RwLockWriteGuard};

use crate::crypto::base64;
use crate::crypto::hash::Hash;
use crate::crypto::sign::VerifyingKey;
use crate::transaction::Transaction;
use crate::block::{Block, BlockContent, BlockStatus, Error as BlockError};
use crate::storage::Storage;
use crate::protocol::packets::Packet;
use crate::protocol::network::{PacketStream, PacketStreamError};
use crate::viewer::{BatchedViewer, ViewerError};

#[derive(Debug,thiserror::Error)]
pub enum NodeError<S: Storage> {
    #[error(transparent)]
    PacketStream(PacketStreamError),

    #[error(transparent)]
    Viewer(ViewerError),

    #[error(transparent)]
    Storage(S::Error),

    #[error(transparent)]
    Block(BlockError)
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
    /// Default is `33554432` bytes (128 MB).
    pub max_transaction_size: usize,

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
    pub accept_pending_transactions: bool,

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
    pub blocks_filter: Option<fn(&Hash, &VerifyingKey, &Block) -> bool>
}

impl Default for NodeOptions {
    fn default() -> Self {
        Self {
            max_history_length: 1024,
            max_transaction_size: 32 * 1024 * 1024,
            accept_pending_blocks: true,
            accept_pending_transactions: true,
            blocks_filter: None,
            transactions_filter: None
        }
    }
}

pub struct Node<S: Storage> {
    root_block: Hash,
    streams: HashMap<[u8; 32], PacketStream>,
    storage: Option<S>,
    history: Vec<Hash>,
    validators: Vec<VerifyingKey>,
    current_distance: [u8; 32],
    indexed_transactions: HashSet<Hash>,
    pending_blocks: HashMap<Hash, Block>,
    pending_transactions: HashMap<Hash, Transaction>
}

impl<S: Storage> Node<S> {
    /// Create new empty node.
    pub fn new(root_block: impl Into<Hash>) -> Self {
        Self {
            root_block: root_block.into(),
            streams: HashMap::new(),
            storage: None,
            history: Vec::new(),
            validators: Vec::new(),
            current_distance: [0xFF; 32],
            indexed_transactions: HashSet::new(),
            pending_blocks: HashMap::new(),
            pending_transactions: HashMap::new()
        }
    }

    /// Add new connection.
    pub fn add_connection(&mut self, stream: PacketStream) -> &mut Self {
        if !self.streams.contains_key(stream.endpoint_id()) {
            self.streams.insert(*stream.endpoint_id(), stream);
        }

        self
    }

    /// Add blockchain storage to the node.
    pub fn attach_storage(&mut self, storage: S) -> &mut Self {
        self.storage = Some(storage);

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
    pub async fn sync(&mut self) -> Result<(), NodeError<S>>
    where
        S::Error: 'static
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

            // Index stored transactions.
            if let BlockContent::Transactions(transactions) = block.block.content() {
                for transaction in transactions {
                    self.indexed_transactions.insert(transaction.hash());
                }
            }

            // If storage is available - then update it.
            if let Some(storage) = &self.storage {
                storage.write_block(&block.block)
                    .map_err(NodeError::Storage)?;
            }

            history.push(block.hash);
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
    pub async fn start(
        self,
        options: NodeOptions,
        mut spawner: impl FnMut(Box<dyn std::future::Future<Output = ()>>)
    ) -> Result<NodeHandler, NodeError<S>>
    where
        S: 'static
    {
        #[cfg(feature = "tracing")]
        tracing::info!("starting the node");

        let mut existing_streams = HashMap::<[u8; 32], Sender<Packet>>::new();

        let history = Arc::new(RwLock::new(self.history));
        let validators = Arc::new(RwLock::new(self.validators));
        let current_distance = Arc::new(RwLock::new(self.current_distance));
        let indexed_transactions = Arc::new(RwLock::new(self.indexed_transactions));
        let pending_blocks = Arc::new(RwLock::new(self.pending_blocks));
        let pending_transactions = Arc::new(RwLock::new(self.pending_transactions));

        let (handler_sender, handler_receiver) = std::sync::mpsc::channel::<Packet>();

        for (endpoint_id, mut stream) in self.streams {
            let (stream_sender, stream_receiver) = std::sync::mpsc::channel::<Packet>();

            existing_streams.insert(endpoint_id, stream_sender);

            let endpoint_id = base64::encode(endpoint_id);

            #[cfg(feature = "tracing")]
            tracing::info!(
                ?endpoint_id,
                "spawn endpoint listener"
            );

            let root_block = self.root_block;
            let storage = self.storage.clone();

            let history = history.clone();
            let validators = validators.clone();
            let current_distance = current_distance.clone();
            let indexed_transactions = indexed_transactions.clone();
            let pending_blocks = pending_blocks.clone();
            let pending_transactions = pending_transactions.clone();

            /// Try to write provided block to the blockchain. This function
            /// does not verify the block and only performs the writing itself.
            ///
            /// Before writing the block it will be compared with the current
            /// one to attempt unfixed block replacement.
            #[allow(clippy::too_many_arguments)]
            fn try_write_block<S: Storage>(
                block: Block,
                hash: Hash,
                verifying_key: &VerifyingKey,
                mut history: RwLockWriteGuard<'_, Vec<Hash>>,
                mut validators: RwLockWriteGuard<'_, Vec<VerifyingKey>>,
                mut current_distance: RwLockWriteGuard<'_, [u8; 32]>,
                mut indexed_transactions: RwLockWriteGuard<'_, HashSet<Hash>>,
                mut pending_blocks: RwLockWriteGuard<'_, HashMap<Hash, Block>>,
                mut pending_transactions: RwLockWriteGuard<'_, HashMap<Hash, Transaction>>,
                storage: Option<&S>
            ) {
                let n = history.len();

                // Distance between the previous block and the new block's
                // author.
                let new_distance = crate::block_validator_distance(
                    &history[n - 2],
                    verifying_key
                );

                // If this block is a *replacement* for the last block of the
                // blockchain - then we must compare its xor distance to decide
                // what to do.
                if n > 1 && &history[n - 2] == block.previous() {
                    // Reject new block if the current one is closer to the
                    // previous one.
                    if  *current_distance <= new_distance
                        || (*current_distance == new_distance && history[n - 2] <= hash)
                    {
                        #[cfg(feature = "tracing")]
                        tracing::warn!(
                            hash = hash.to_base64(),
                            "attempted to modify the blockchain history with more distant block"
                        );

                        return;
                    }
                }

                // If this block is a continuation of the blockchain then we
                // simply push it to the end of the history, update the storage
                // and validators list, remove related pending transactions.
                //
                // Otherwise we are not allowed to modify the blockchain history
                // and thus just abort this function.
                else if &history[n - 1] != block.previous() {
                    #[cfg(feature = "tracing")]
                    tracing::warn!(
                        hash = hash.to_base64(),
                        "attempted to modify the blockchain history or write out of the known history (out of sync node?)"
                    );

                    return;
                }

                // Try to write this block to the blockchain storage.
                if let Some(storage) = storage {
                    match storage.write_block(&block) {
                        Ok(true) => (),

                        Ok(false) => {
                            #[cfg(feature = "tracing")]
                            tracing::warn!(
                                hash = hash.to_base64(),
                                "attempted to write new block to the blockchain storage but history was not modified"
                            );

                            return;
                        }

                        Err(err) => {
                            #[cfg(feature = "tracing")]
                            tracing::error!(
                                ?err,
                                hash = hash.to_base64(),
                                "failed to write new block to the blockchain storage"
                            );

                            return;
                        }
                    }
                }

                // Update in-RAM blocks history.
                history.push(hash);

                // Update validators list.
                if let BlockContent::Validators(new_validators) = block.content() {
                    *validators = new_validators.to_vec();
                }

                // Update current block's distance.
                *current_distance = new_distance;

                // Remove this block from the pending blocks pool.
                pending_blocks.remove(&hash);

                // Remove related pending transactions.
                if let BlockContent::Transactions(transactions) = block.content() {
                    for transaction in transactions {
                        let hash = transaction.hash();

                        pending_transactions.remove(&hash);
                        indexed_transactions.insert(hash);
                    }
                }
            }

            spawner(Box::new(async move {
                // Ask remote node to share pending blocks and transactions.
                if let Err(err) = stream.send(Packet::AskPendingTransactions {
                    root_block
                }) {
                    #[cfg(feature = "tracing")]
                    tracing::error!(
                        err = err.to_string(),
                        ?endpoint_id,
                        "failed to send packet to the packets stream"
                    );

                    return;
                }

                if let Err(err) = stream.send(Packet::AskPendingBlocks {
                    root_block
                }) {
                    #[cfg(feature = "tracing")]
                    tracing::error!(
                        err = err.to_string(),
                        ?endpoint_id,
                        "failed to send packet to the packets stream"
                    );

                    return;
                }

                // Process incoming packets in a loop.
                loop {
                    // Send packets to the remote node.
                    loop {
                        match stream_receiver.try_recv() {
                            Ok(packet) => {
                                if let Err(err) = stream.send(packet) {
                                    #[cfg(feature = "tracing")]
                                    tracing::error!(
                                        err = err.to_string(),
                                        ?endpoint_id,
                                        "failed to send packet to the packets stream"
                                    );

                                    return;
                                }
                            }

                            Err(TryRecvError::Disconnected) => {
                                #[cfg(feature = "tracing")]
                                tracing::info!(
                                    ?endpoint_id,
                                    "local node went offline, terminating connection"
                                );

                                return;
                            }

                            Err(TryRecvError::Empty) => break
                        }
                    }

                    // Read packet from the remote endpoint.
                    // TODO: timeout support
                    let packet = stream.recv();

                    // Process received packet.
                    match packet {
                        Ok(packet) => {
                            match packet {
                                // If we were asked to share the blockchain
                                // history.
                                Packet::AskHistory {
                                    root_block: received_root_block,
                                    offset,
                                    max_length
                                } if received_root_block == root_block => {
                                    // Then read max allowed amount of blocks'
                                    // hashes.
                                    let history = history.read()
                                        .iter()
                                        .skip(offset as usize)
                                        .take(options.max_history_length.min(max_length as usize))
                                        .copied()
                                        .collect();

                                    // And try to send them back to the
                                    // requester.
                                    if let Err(err) = stream.send(Packet::History {
                                        root_block,
                                        offset,
                                        history
                                    }) {
                                        #[cfg(feature = "tracing")]
                                        tracing::error!(
                                            err = err.to_string(),
                                            ?endpoint_id,
                                            "failed to send packet to the packets stream"
                                        );

                                        break;
                                    }
                                }

                                // If we were asked to send the pending blocks
                                // list.
                                Packet::AskPendingBlocks {
                                    root_block: received_root_block
                                } if received_root_block == root_block => {
                                    let pending_blocks = pending_blocks.read()
                                    // Then collect their hashes and approvals.
                                        .iter()
                                        .map(|(hash, block)| {
                                            let approvals = block.approvals()
                                                .to_vec()
                                                .into_boxed_slice();

                                            (*hash, approvals)
                                        })
                                        .collect();

                                    // And try to send it back to the requester.
                                    if let Err(err) = stream.send(Packet::PendingBlocks {
                                        root_block,
                                        pending_blocks
                                    }) {
                                        #[cfg(feature = "tracing")]
                                        tracing::error!(
                                            err = err.to_string(),
                                            ?endpoint_id,
                                            "failed to send packet to the packets stream"
                                        );

                                        break;
                                    }
                                }

                                // If we were asked to send the pending
                                // transactions list.
                                Packet::AskPendingTransactions {
                                    root_block: received_root_block
                                } if received_root_block == root_block => {
                                    // Then collect their hashes.
                                    let pending_transactions = pending_transactions.read()
                                        .keys()
                                        .copied()
                                        .collect();

                                    // And try to send it back to the requester.
                                    if let Err(err) = stream.send(Packet::PendingTransactions {
                                        root_block,
                                        pending_transactions
                                    }) {
                                        #[cfg(feature = "tracing")]
                                        tracing::error!(
                                            err = err.to_string(),
                                            ?endpoint_id,
                                            "failed to send packet to the packets stream"
                                        );

                                        break;
                                    }
                                }

                                // If we were asked to send a block of the
                                // blockchain.
                                Packet::AskBlock {
                                    root_block: received_root_block,
                                    target_block
                                } if received_root_block == root_block => {
                                    // If this block is pending.
                                    if let Some(block) = pending_blocks.read().get(&target_block) {
                                        // Then try to send it back.
                                        if let Err(err) = stream.send(Packet::Block {
                                            root_block,
                                            block: block.clone()
                                        }) {
                                            #[cfg(feature = "tracing")]
                                            tracing::error!(
                                                err = err.to_string(),
                                                ?endpoint_id,
                                                "failed to send packet to the packets stream"
                                            );

                                            break;
                                        }
                                    }

                                    // Otherwise, if we have a storage available.
                                    else if let Some(storage) = &storage {
                                        // Then try to read block from that storage.
                                        match storage.read_block(&target_block) {
                                            // If we've found the block.
                                            Ok(Some(block)) => {
                                                // Then try to send it back.
                                                if let Err(err) = stream.send(Packet::Block {
                                                    root_block,
                                                    block
                                                }) {
                                                    #[cfg(feature = "tracing")]
                                                    tracing::error!(
                                                        err = err.to_string(),
                                                        ?endpoint_id,
                                                        "failed to send packet to the packets stream"
                                                    );

                                                    break;
                                                }
                                            }

                                            // If block doesn't exist - then do
                                            // nothing.
                                            Ok(None) => (),

                                            // And if we failed - log it.
                                            Err(err) => {
                                                #[cfg(feature = "tracing")]
                                                tracing::error!(
                                                    ?err,
                                                    ?endpoint_id,
                                                    "failed to read block from the storage"
                                                );

                                                break;
                                            }
                                        }
                                    }
                                }

                                // If we received some block.
                                Packet::Block {
                                    root_block: received_root_block,
                                    mut block
                                } if received_root_block == root_block => {
                                    // Verify the block and obtain its hash.
                                    let (is_valid, hash, verifying_key) = match block.verify() {
                                        Ok(result) => result,
                                        Err(err) => {
                                            #[cfg(feature = "tracing")]
                                            tracing::error!(
                                                ?err,
                                                ?endpoint_id,
                                                "failed to verify received block"
                                            );

                                            continue;
                                        }
                                    };

                                    // Skip the block if it's invalid.
                                    if !is_valid || !validators.read().contains(&verifying_key) {
                                        #[cfg(feature = "tracing")]
                                        tracing::warn!(
                                            ?endpoint_id,
                                            hash = hash.to_base64(),
                                            verifying_key = verifying_key.to_base64(),
                                            "received invalid block"
                                        );

                                        continue;
                                    }

                                    // Check if we already have this block, and
                                    // if we do - then merge approvals because
                                    // already stored block can have more than
                                    // in what we received.
                                    if let Some(curr_block) = pending_blocks.read().get(&hash) {
                                        for approval in curr_block.approvals() {
                                            if !block.approvals.contains(approval) {
                                                block.approvals.push(approval.clone());
                                            }
                                        }
                                    }

                                    // Check this block using the provided filter.
                                    if let Some(filter) = &options.blocks_filter
                                        && !filter(&hash, &verifying_key, &block)
                                    {
                                        #[cfg(feature = "tracing")]
                                        tracing::debug!(
                                            ?endpoint_id,
                                            hash = hash.to_base64(),
                                            verifying_key = verifying_key.to_base64(),
                                            "received block which was filtered out"
                                        );

                                        continue;
                                    }

                                    // Check the block's approval status.
                                    let status = BlockStatus::validate(
                                        hash,
                                        verifying_key,
                                        block.approvals(),
                                        validators.read().iter()
                                    );

                                    match status {
                                        // Block is valid and approved by enough validators.
                                        Ok(BlockStatus::Approved {
                                            hash,
                                            verifying_key,
                                            approvals,
                                            ..
                                        }) => {
                                            // Update received block's approvals list
                                            // to remove any invalid signatures.
                                            block.approvals = approvals.into_iter()
                                                .map(|(approval, _)| approval)
                                                .collect();

                                            // Try to write this block.
                                            try_write_block(
                                                block,
                                                hash,
                                                &verifying_key,
                                                history.write(),
                                                validators.write(),
                                                current_distance.write(),
                                                indexed_transactions.write(),
                                                pending_blocks.write(),
                                                pending_transactions.write(),
                                                storage.as_ref()
                                            );
                                        }

                                        // Block is valid but not approved by enough validators.
                                        Ok(BlockStatus::NotApproved {
                                            approvals,
                                            ..
                                        }) => {
                                            // Try to read the last block of the blockchain.
                                            if let Some(last_block) = history.read().last() {
                                                // Update received block's approvals list
                                                // to remove any invalid signatures.
                                                block.approvals = approvals.into_iter()
                                                    .map(|(approval, _)| approval)
                                                    .collect();

                                                // If this block is the potential new block
                                                // for the blockchain then, if options allow
                                                // it, we should store it in the pending
                                                // blocks pool.
                                                if last_block == block.previous()
                                                    && options.accept_pending_blocks
                                                {
                                                    pending_blocks.write()
                                                        .insert(hash, block);

                                                    // TODO: if we didn't have this block
                                                    // stored before - then we should send
                                                    // it to all the other connected nodes.
                                                }
                                            }
                                        }

                                        // Block is invalid.
                                        Ok(BlockStatus::Invalid) => {
                                            #[cfg(feature = "tracing")]
                                            tracing::warn!(
                                                ?endpoint_id,
                                                hash = hash.to_base64(),
                                                "received invalid block"
                                            );
                                        }

                                        // Failed to check the block.
                                        Err(err) => {
                                            #[cfg(feature = "tracing")]
                                            tracing::error!(
                                                ?err,
                                                ?endpoint_id,
                                                hash = hash.to_base64(),
                                                "failed to validate received block"
                                            );
                                        }
                                    }
                                }

                                // If we were asked to send transaction.
                                Packet::AskTransaction {
                                    root_block: received_root_block,
                                    transaction
                                } if received_root_block == root_block => {
                                    // If it is a pending transaction.
                                    let transaction = pending_transactions.read()
                                        .get(&transaction)
                                        .cloned();

                                    #[allow(clippy::collapsible_if)]
                                    if let Some(transaction) = transaction {
                                        // Then try to send it back.
                                        if let Err(err) = stream.send(Packet::Transaction {
                                            root_block,
                                            transaction: transaction.clone()
                                        }) {
                                            #[cfg(feature = "tracing")]
                                            tracing::error!(
                                                err = err.to_string(),
                                                ?endpoint_id,
                                                "failed to send packet to the packets stream"
                                            );

                                            break;
                                        }
                                    }
                                }

                                // If we received some transaction.
                                Packet::Transaction {
                                    root_block: received_root_block,
                                    transaction
                                } if received_root_block == root_block
                                    && options.accept_pending_transactions => {
                                    // TODO: check if this transaction is already
                                    // stored in some block!!!!!!!!!

                                    // Reject large transactions.
                                    if transaction.data().len() > options.max_transaction_size {
                                        #[cfg(feature = "tracing")]
                                        tracing::warn!(
                                            ?endpoint_id,
                                            "received too large transaction"
                                        );

                                        continue;
                                    }

                                    // Verify received transaction.
                                    let (is_valid, hash, verifying_key) = match transaction.verify() {
                                        Ok(result) => result,
                                        Err(err) => {
                                            #[cfg(feature = "tracing")]
                                            tracing::error!(
                                                ?err,
                                                ?endpoint_id,
                                                "failed to verify received transaction"
                                            );

                                            continue;
                                        }
                                    };

                                    // Skip transaction if it's invalid.
                                    if !is_valid {
                                        #[cfg(feature = "tracing")]
                                        tracing::warn!(
                                            ?endpoint_id,
                                            hash = hash.to_base64(),
                                            verifying_key = verifying_key.to_base64(),
                                            "received invalid transaction"
                                        );

                                        continue;
                                    }

                                    // Reject already indexed transactions.
                                    if indexed_transactions.read().contains(&hash)
                                        || pending_transactions.read().contains_key(&hash)
                                    {
                                        #[cfg(feature = "tracing")]
                                        tracing::trace!(
                                            ?endpoint_id,
                                            hash = hash.to_base64(),
                                            verifying_key = verifying_key.to_base64(),
                                            "received already indexed transaction"
                                        );

                                        continue;
                                    }

                                    // Check this transaction using the provided filter.
                                    if let Some(filter) = &options.transactions_filter
                                        && !filter(&hash, &verifying_key, &transaction)
                                    {
                                        #[cfg(feature = "tracing")]
                                        tracing::debug!(
                                            ?endpoint_id,
                                            hash = hash.to_base64(),
                                            verifying_key = verifying_key.to_base64(),
                                            "received transaction which was filtered out"
                                        );

                                        continue;
                                    }

                                    pending_transactions.write()
                                        .insert(hash, transaction);
                                }

                                // If we received block approval.
                                Packet::ApproveBlock {
                                    root_block: received_root_block,
                                    target_block,
                                    approval
                                } if received_root_block == root_block => {
                                    // Verify approval.
                                    let (is_valid, verifying_key) = match approval.verify(target_block) {
                                        Ok(result) => result,
                                        Err(err) => {
                                            #[cfg(feature = "tracing")]
                                            tracing::error!(
                                                ?err,
                                                ?endpoint_id,
                                                target_block = target_block.to_base64(),
                                                approval = approval.to_base64(),
                                                "failed to verify received block approval"
                                            );

                                            continue;
                                        }
                                    };

                                    // Skip approval if it's invalid.
                                    if !is_valid || !validators.read().contains(&verifying_key) {
                                        #[cfg(feature = "tracing")]
                                        tracing::warn!(
                                            ?endpoint_id,
                                            target_block = target_block.to_base64(),
                                            verifying_key = verifying_key.to_base64(),
                                            "received invalid block approval"
                                        );

                                        continue;
                                    }

                                    // Add this approval to the block if we have it.
                                    let mut lock = pending_blocks.write();
                                    let mut write_block = None;

                                    if let Some(block) = lock.get_mut(&target_block)
                                        && !block.approvals.contains(&approval)
                                    {
                                        #[cfg(feature = "tracing")]
                                        tracing::info!(
                                            ?endpoint_id,
                                            target_block = target_block.to_base64(),
                                            verifying_key = verifying_key.to_base64(),
                                            "added new approval to the pending block"
                                        );

                                        block.approvals.push(approval);

                                        // Verify this block (mainly to obtain
                                        // its public key).
                                        let (is_valid, hash, verifying_key) = match block.verify() {
                                            Ok(result) => result,
                                            Err(err) => {
                                                #[cfg(feature = "tracing")]
                                                tracing::error!(
                                                    ?err,
                                                    ?endpoint_id,
                                                    "failed to verify block"
                                                );

                                                continue;
                                            }
                                        };

                                        // Skip the block if it's invalid.
                                        if !is_valid || !validators.read().contains(&verifying_key) {
                                            #[cfg(feature = "tracing")]
                                            tracing::error!(
                                                ?endpoint_id,
                                                hash = hash.to_base64(),
                                                verifying_key = verifying_key.to_base64(),
                                                "approved a pending block which turned to be invalid (how did it get here?)"
                                            );

                                            continue;
                                        }

                                        // Validate the block.
                                        let status = BlockStatus::validate(
                                            hash,
                                            verifying_key,
                                            block.approvals(),
                                            validators.read().as_slice()
                                        );

                                        match status {
                                            Ok(BlockStatus::Approved {
                                                hash,
                                                verifying_key,
                                                approvals,
                                                ..
                                            }) => {
                                                // Update block's approvals list
                                                // to remove any invalid signatures.
                                                block.approvals = approvals.into_iter()
                                                    .map(|(approval, _)| approval)
                                                    .collect();

                                                // Order this block to be written.
                                                write_block = Some((hash, verifying_key));
                                            }

                                            Err(err) => {
                                                #[cfg(feature = "tracing")]
                                                tracing::warn!(
                                                    ?err,
                                                    ?endpoint_id,
                                                    hash = hash.to_base64(),
                                                    "failed to validate newly approved block"
                                                );

                                                continue;
                                            }

                                            _ => ()
                                        }
                                    }

                                    drop(lock);

                                    // If we've approved that this block can now
                                    // be written to the blockchain storage.
                                    if let Some((hash, public_key)) = write_block {
                                        let mut pending_blocks = pending_blocks.write();

                                        // Try to write this block.
                                        if let Some(block) = pending_blocks.remove(&hash) {
                                            try_write_block(
                                                block,
                                                hash,
                                                &public_key,
                                                history.write(),
                                                validators.write(),
                                                current_distance.write(),
                                                indexed_transactions.write(),
                                                pending_blocks,
                                                pending_transactions.write(),
                                                storage.as_ref()
                                            );
                                        }
                                    }

                                    // TODO: resend this approval (or the block itself)
                                    // to other connected nodes!!!
                                }

                                _ => ()
                            }
                        }

                        Err(err) => {
                            #[cfg(feature = "tracing")]
                            tracing::error!(
                                err = err.to_string(),
                                ?endpoint_id,
                                "failed to read packet from the packets stream"
                            );

                            break;
                        }
                    }
                }
            }));
        }

        spawner(Box::new(async move {
            while let Ok(packet) = handler_receiver.recv() {
                for sender in existing_streams.values() {
                    let _ = sender.send(packet.clone());
                }
            }
        }));

        Ok(NodeHandler(handler_sender))
    }
}

/// A helper struct connected to the running node. It can be used to perform
/// client-side operations like announcing transactions to the network.
#[derive(Debug, Clone)]
pub struct NodeHandler(Sender<Packet>);

impl NodeHandler {
    /// Send transaction to all the connected nodes.
    pub fn send_transaction(
        &self,
        root_block: impl Into<Hash>,
        transaction: impl Into<Transaction>
    ) -> bool {
        self.0.send(Packet::Transaction {
            root_block: root_block.into(),
            transaction: transaction.into()
        }).is_ok()
    }
}
