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
use std::time::Duration;
use std::sync::Arc;

use spin::{Mutex, RwLock};
use flume::Sender;

use crate::crypto::base64;
use crate::crypto::hash::Hash;
use crate::crypto::sign::{SigningKey, VerifyingKey};
use crate::blob::Message;
use crate::block::{Block, BlockDecodeError};
use crate::storage::StorageError;
use crate::protocol::packets::Packet;
use crate::protocol::network::{PacketStream, PacketStreamError};
use crate::viewer::{BatchedViewer, ViewerError};

pub mod tracker;

mod validator;
mod handlers;

use tracker::{Tracker, TrackerError};

#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    #[error(transparent)]
    PacketStream(PacketStreamError),

    #[error(transparent)]
    Tracker(TrackerError),

    #[error(transparent)]
    Viewer(ViewerError),

    #[error(transparent)]
    Storage(StorageError),

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

    /// Maximal size in bytes of a user message.
    ///
    /// Bigger messages will be rejected immediately upon receiving.
    ///
    /// > This is applied to the `Message` packets only.
    ///
    /// Default is `33554432` bytes (32 MiB).
    pub max_message_size: usize,

    /// Accept incoming messages.
    ///
    /// This option disables the `Message` packet processing.
    ///
    /// If disabled your node will not act as a normal blockchain node and
    /// reduce overall network quality.
    ///
    /// Default is `true`.
    pub accept_messages: bool,

    /// Accept incoming blocks.
    ///
    /// This option disables the `Block` packet processing.
    ///
    /// If disabled your node will not act as a normal blockchain node and
    /// reduce overall network quality.
    ///
    /// Default is `true`.
    pub accept_blocks: bool,

    /// Resolve missing messages and fetch them from remote nodes.
    ///
    /// Nodes exchange special `PendingMessages` and `PendingBlocks` packets
    /// to share lists of known pending messages' and blocks' hashes. If this
    /// option is disabled, then upon receiving such packet we won't try to
    /// find out which messages we're missing and won't try to fetch them.
    ///
    /// This option is the main mechanism of pending messages synchronization in
    /// the network.
    ///
    /// If disabled your node will not act as a normal blockchain node and
    /// reduce overall network quality.
    ///
    /// Default is `true`.
    pub fetch_pending_messages: bool,

    /// When specified this function will be used to filter incoming messages
    /// and accept only those for which the provided function returned `true`.
    ///
    /// This filter function is applied to the `Message` packets only. It is not
    /// applied to the blocks, so you'd need to specify the `blocks_filter` as
    /// well.
    ///
    /// The function's inputs are
    /// `(root_block_hash, message, message_verifying_key)`.
    ///
    /// Default is `None` (every message is accepted).
    pub messages_filter: Option<fn(&Hash, &Message, &VerifyingKey) -> bool>,

    /// Amount of time a validator thread will wait before starting to create
    /// new blocks. This time is needed so that the node can synchronize all the
    /// pending data. It is recommended to keep this value relatively high, as
    /// it will be used only initially and won't affect further algorithm work.
    ///
    /// Default is `1m`.
    pub validator_warmup_time: Duration,

    /// Amount of time a validator thread will wait before trying to make a new
    /// block. This timeout is needed because validator thread will lock node
    /// handler and prevent other threads to access internal structures which
    /// are needed for the node to function normally.
    ///
    /// Default is `10s`.
    pub validator_wait_time: Duration,

    /// Minimal amount of messages needed to form a new block.
    ///
    /// Default is `1`.
    pub validator_min_messages_num: usize,

    /// Maximal amount of messages needed to form a new block.
    ///
    /// Default is `128`.
    pub validator_max_messages_num: usize
}

impl Default for NodeOptions {
    fn default() -> Self {
        Self {
            max_history_length: 1024,
            max_message_size: 32 * 1024 * 1024,
            accept_messages: true,
            accept_blocks: true,
            fetch_pending_messages: true,
            messages_filter: None,
            validator_warmup_time: Duration::from_secs(60),
            validator_wait_time: Duration::from_secs(10),
            validator_min_messages_num: 1,
            validator_max_messages_num: 128
        }
    }
}

#[derive(Default)]
pub struct Node {
    /// Table of connections to other nodes.
    ///
    /// `[remote_id] => [stream]`
    streams: HashMap<[u8; 32], PacketStream>,

    /// Table of validators signing keys for owned blockchains. These are used
    /// by the node to issue new blocks and send them to the network.
    ///
    /// `[root_block] => [signing_key]`
    validators: HashMap<Hash, SigningKey>,

    /// Table of blockchain history trackers which are used to keep track of
    /// blocks history and, if possible, query messages and other data.
    ///
    /// It is expected that for each blockchain we already know its validator
    /// verifying key and, if possible, its root block hash.
    ///
    /// `[root_block] => ([verifying_key], [tracker])`
    trackers: HashMap<Hash, (VerifyingKey, Tracker)>
}

impl Node {
    /// Add new packet stream.
    pub fn add_stream(&mut self, stream: PacketStream) -> &mut Self {
        self.streams.insert(*stream.peer_id(), stream);

        self
    }

    /// Add validator signing key.
    ///
    /// If set, node will start a background task to issue new blocks for a
    /// blockchain with provided root block hash.
    pub fn add_validator(
        &mut self,
        root_block: impl Into<Hash>,
        signing_key: impl Into<SigningKey>
    ) -> &mut Self {
        self.validators.insert(root_block.into(), signing_key.into());

        self
    }

    /// Add tracker to the node.
    ///
    /// Root block hash will be queried from the tracker. If `root_block`
    /// argument is provided, then it will be used if `tracker` has no root
    /// block stored. If both argument and `tracker` have root block hash, then
    /// they will be compared, and tracker will be rejected on mismatch.
    ///
    /// Verifying key will be queried from the root block's signature if it's
    /// available in provided `tracker` and compared against `verifying_key`
    /// argument value if it's provided.
    ///
    /// Trackers with attached storages are prioritized.
    pub fn add_tracker(
        &mut self,
        tracker: Tracker,
        mut root_block: Option<Hash>,
        mut verifying_key: Option<VerifyingKey>
    ) -> &mut Self {
        // Try to query root block from the provided tracker.
        if let Ok(Some(tracker_root_block)) = tracker.get_root_block() {
            // If both `root_block` and tracker have root block hash, then
            // compare them and return from method if they dismatch.
            if let Some(root_block) = root_block
                && root_block != tracker_root_block
            {
                return self;
            }

            // Store the tracker's root block hash.
            root_block = Some(tracker_root_block);
        }

        // Reject current method if no root block hash found.
        let Some(root_block) = root_block else {
            return self;
        };

        // Try to query root block from the provided tracker.
        if let Ok(Some(root_block)) = tracker.read_block(&root_block) {
            // Verify its signature.
            let Ok((is_valid, tracker_verifying_key)) = root_block.verify() else {
                return self;
            };

            // Return from method if stored root block is invalid.
            if !is_valid {
                return self;
            }

            // If both `verifying_key` is provided and tracker has root block,
            // then compare its validator with provided verifying key and return
            // from method if they dismatch.
            if let Some(verifying_key) = verifying_key
                && verifying_key != tracker_verifying_key
            {
                return self;
            }

            // Store the tracker's verifying key.
            verifying_key = Some(tracker_verifying_key);
        }

        // Reject current method if no verifying key found.
        let Some(verifying_key) = verifying_key else {
            return self;
        };

        // Replace existing tracker if it doesn't have storage or insert a new
        // one.
        match self.trackers.get(&root_block) {
            Some(curr_tracker) => {
                if curr_tracker.1.storage().is_none() {
                    self.trackers.insert(root_block, (verifying_key, tracker));
                }
            }

            None => {
                self.trackers.insert(root_block, (verifying_key, tracker));
            }
        }

        self
    }

    /// Synchronize stored trackers with their blockchains using available
    /// network connections.
    pub fn sync(&mut self) -> Result<(), NodeError> {
        #[cfg(feature = "tracing")]
        tracing::info!("synchronizing node trackers");

        for (root_block, (verifying_key, tracker)) in self.trackers.iter_mut() {
            #[cfg(feature = "tracing")]
            tracing::info!(
                root_block = root_block.to_base64(),
                verifying_key = verifying_key.to_base64(),
                "synchronizing tracker"
            );

            // Open batched viewer using available connections and known
            // blockchain info.
            let viewer = match tracker.storage() {
                Some(storage) => {
                    BatchedViewer::open_from_storage(
                        self.streams.values_mut(),
                        storage
                    ).map_err(NodeError::Viewer)?
                },

                None => {
                    BatchedViewer::open(
                        self.streams.values_mut(),
                        root_block,
                        verifying_key.clone()
                    ).map_err(NodeError::Viewer)?
                }
            };

            let Some(mut viewer) = viewer else {
                return Ok(());
            };

            loop {
                let block = match tracker.storage() {
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
                    hash = block.block.hash().to_base64(),
                    timestamp = block.block.timestamp().unix_timestamp(),
                    "read block"
                );

                // Try to write received block to the tracker.
                tracker.try_write_block(&block.block)
                    .map_err(NodeError::Tracker)?;
            }
        }

        Ok(())
    }

    /// Start the node.
    ///
    /// This method will spawn background tasks to listen to incoming packets
    /// and process them using provided options.
    ///
    /// All the non-critical errors will be silenced and displayed in tracing
    /// logs only.
    pub fn start(
        self,
        options: NodeOptions
    ) -> Result<NodeHandler, NodeError> {
        #[cfg(feature = "tracing")]
        tracing::info!("starting the node");

        // Prepare pending messages table.
        let mut pending_messages = HashMap::with_capacity(self.trackers.len());

        for root_block in self.trackers.keys().copied() {
            pending_messages.insert(root_block, HashMap::new());
        }

        // Create the node handler.
        let handler = NodeHandler {
            streams: Arc::new(RwLock::new(HashMap::with_capacity(self.streams.len()))),
            pending_messages: Arc::new(RwLock::new(pending_messages)),
            trackers: Arc::new(Mutex::new(self.trackers)),
            options: Arc::new(options)
        };

        // Add streams to the handler.
        for (endpoint_id, stream) in self.streams {
            #[cfg(feature = "tracing")]
            tracing::info!(
                endpoint_id = base64::encode(endpoint_id),
                "add node connection"
            );

            handler.add_stream(stream);
        }

        // Start validator threads.
        for (root_block, signing_key) in self.validators {
            let handler = handler.clone();

            std::thread::spawn(move || {
                validator::run(handler, root_block, signing_key);
            });
        }

        #[cfg(feature = "tracing")]
        tracing::info!("node started");

        Ok(handler)
    }
}

/// A helper struct that can be used to perform client-side operations with the
/// running node server.
#[derive(Clone)]
pub struct NodeHandler {
    /// Table of connections to other nodes.
    ///
    /// `[remote_id] => [stream]`
    streams: Arc<RwLock<HashMap<[u8; 32], Sender<Packet>>>>,

    /// Table of pending messages which are meant to be added into a new block.
    ///
    /// `[root_block] => ([hash] => [message])`
    pending_messages: Arc<RwLock<HashMap<Hash, HashMap<Hash, Message>>>>,

    /// Table of blockchain history trackers which are used to keep track of
    /// blocks history and, if possible, query messages and other data.
    ///
    /// It is expected that for each blockchain we already know its validator
    /// verifying key and, if possible, its root block hash.
    ///
    /// `[root_block] => ([verifying_key], [tracker])`
    trackers: Arc<Mutex<HashMap<Hash, (VerifyingKey, Tracker)>>>,

    /// Node options used by the underlying packets handlers.
    options: Arc<NodeOptions>
}

impl NodeHandler {
    /// Add new packet stream to the node connections pool.
    pub fn add_stream(&self, stream: PacketStream) {
        let (sender, receiver) = flume::unbounded();

        let peer_id = *stream.peer_id();

        #[cfg(feature = "tracing")]
        tracing::debug!(
            local_id = base64::encode(stream.local_id()),
            peer_id = base64::encode(peer_id),
            "add node connection"
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

    /// Get list of peer IDs of available packet streams.
    pub fn streams(&self) -> Box<[[u8; 32]]> {
        self.streams.read()
            .keys()
            .cloned()
            .collect()
    }

    /// Get table of pending messages stored for a blockchain with provided
    /// root block hash and run provided callback with it.
    pub fn map_pending_messages<T>(
        &self,
        root_block: impl AsRef<Hash>,
        callback: impl FnOnce(&HashMap<Hash, Message>) -> T
    ) -> Option<T> {
        self.pending_messages.read()
            .get(root_block.as_ref())
            .map(callback)
    }

    /// Get mutable table of pending messages stored for a blockchain with
    /// provided root block hash and run provided callback with it.
    pub fn map_pending_messages_mut<T>(
        &self,
        root_block: impl AsRef<Hash>,
        callback: impl FnOnce(&mut HashMap<Hash, Message>) -> T
    ) -> Option<T> {
        self.pending_messages.write()
            .get_mut(root_block.as_ref())
            .map(callback)
    }

    /// Get verifying key and a tracker reference for a blockchain with provided
    /// root block hash and run provided callback with them.
    pub fn map_tracker<T>(
        &self,
        root_block: impl AsRef<Hash>,
        callback: impl FnOnce(&VerifyingKey, &mut Tracker) -> T
    ) -> Option<T> {
        self.trackers.lock()
            .get_mut(root_block.as_ref())
            .map(|(verifying_key, tracker)| callback(verifying_key, tracker))
    }

    /// Send packet to all the available streams.
    fn send(&self, packet: Packet) {
        let mut disconnected = Vec::new();

        let lock = self.streams.read();

        for (endpoint_id, sender) in lock.iter() {
            if sender.send(packet.clone()).is_err() {
                disconnected.push(*endpoint_id);
            }
        }

        drop(lock);

        if !disconnected.is_empty() {
            let mut lock = self.streams.write();

            for endpoint_id in disconnected {
                lock.remove(&endpoint_id);
            }
        }
    }

    /// Ask connected nodes to share their pending messages for a blockchain
    /// with provided root block hash.
    pub fn ask_pending_messages(&self, root_block: impl Into<Hash>) {
        let root_block: Hash = root_block.into();

        let known_messages = self.pending_messages.read()
            .get(&root_block)
            .map(|messages| {
                messages.keys()
                    .copied()
                    .collect::<Box<[Hash]>>()
            })
            .unwrap_or_default();

        self.send(Packet::AskPendingMessages {
            root_block,
            known_messages
        });
    }

    /// Send message to all the connected nodes which host a blockchain with
    /// provided root block hash.
    pub fn send_message(
        &self,
        root_block: impl Into<Hash>,
        message: Message
    ) {
        let root_block: Hash = root_block.into();

        self.send(Packet::Message {
            root_block,
            message
        });
    }

    /// Send block to all the connected nodes which host a blockchain with
    /// provided root block hash.
    pub fn send_block(
        &self,
        root_block: impl Into<Hash>,
        block: Block
    ) {
        let root_block: Hash = root_block.into();

        self.send(Packet::Block {
            root_block,
            block
        });
    }
}
