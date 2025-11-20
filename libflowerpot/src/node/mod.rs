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
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;
use std::sync::Arc;

use spin::{Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::crypto::base64;
use crate::crypto::hash::Hash;
use crate::crypto::key_exchange::SecretKey;
use crate::crypto::sign::{SigningKey, VerifyingKey};
use crate::message::Message;
use crate::block::{Block, BlockDecodeError};
use crate::address::Address;
use crate::storage::{Storage, StorageError};
use crate::protocol::packets::Packet;
use crate::protocol::network::{
    PacketStream, PacketStreamOptions, PacketStreamError
};
use crate::viewer::{BatchedViewer, ViewerError};

// mod validator;
mod handlers;

#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    #[error("failed to initialize tcp connection: {0}")]
    TcpStream(std::io::Error),

    #[error(transparent)]
    PacketStream(PacketStreamError),

    #[error(transparent)]
    Viewer(ViewerError),

    #[error(transparent)]
    Storage(StorageError),

    #[error(transparent)]
    Block(BlockDecodeError)
}

/// Default function for the `validator_inline_messages_filter` node option.
///
/// It always inlines messages sent by the blockchain validator, and inlines
/// all the client messages which are shorter than `4 KiB`.
pub fn default_validator_inline_messages_filter(
    address: &Address,
    message: &Message,
    author: &VerifyingKey
) -> bool {
    message.data().len() <= 4096 || address.verifying_key() == author
}

#[derive(Debug, Clone, Copy)]
pub struct NodeOptions {
    /// Maximal amount of blocks included to the `History` packet which will be
    /// sent as a response on the `AskHistory` packet.
    ///
    /// Default is `32`.
    pub max_history_length: usize,

    /// Maximal size of a `Message` packet which will be accepted. Larger
    /// messages will be silently ignored.
    ///
    /// Default is `32 MiB`.
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
    /// The function's inputs are
    /// `(address, message, blob_verifying_key)`.
    ///
    /// Default is `None` (every message is accepted).
    pub messages_filter: Option<fn(&Address, &Message, &VerifyingKey) -> bool>,

    /// Amount of time a validator thread will wait before trying to make a new
    /// block. This timeout is needed because validator thread will lock node
    /// handler and prevent other threads to access internal structures which
    /// are needed for the node to function normally. It's also adviced against
    /// issuing new blocks very frequently and recommended to try to batch
    /// multiple blobs within a single block.
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
    pub validator_max_messages_num: usize,

    /// When specified this function will be used by the validator thread to
    /// decide whether a message should be inlined within a new history block.
    ///
    /// Message will be inlined if provided function returns `true`.
    ///
    /// Default is `default_validator_inline_messages_filter()`.
    pub validator_inline_messages_filter: fn(&Address, &Message, &VerifyingKey) -> bool
}

impl Default for NodeOptions {
    fn default() -> Self {
        Self {
            max_history_length: 32,
            max_message_size: 32 * 1024 * 1024,
            accept_messages: true,
            accept_blocks: true,
            fetch_pending_messages: true,
            messages_filter: None,
            validator_wait_time: Duration::from_secs(10),
            validator_min_messages_num: 1,
            validator_max_messages_num: 128,
            validator_inline_messages_filter: default_validator_inline_messages_filter
        }
    }
}

#[derive(Default)]
pub struct Node {
    /// Table of connections to other nodes.
    ///
    /// `[peer_id] => [stream]`
    streams: HashMap<[u8; 32], PacketStream>,

    /// Table of validators signing keys for owned blockchains. These are used
    /// by the node to issue new blocks and send them to the network.
    ///
    /// `[address] => [signing_key]`
    validators: HashMap<Address, SigningKey>,

    /// Table of blockchain history storages which are used to keep track of
    /// blocks history, query messages and so on.
    ///
    /// `[address] => [storage]`
    storages: HashMap<Address, Box<dyn Storage + Send>>
}

impl Node {
    /// Try to initialize packet stream with provided socket address.
    pub fn init_stream(
        &mut self,
        secret_key: impl AsRef<SecretKey>,
        options: impl AsRef<PacketStreamOptions>,
        addr: impl ToSocketAddrs
    ) -> Result<(), NodeError> {
        let stream = TcpStream::connect(addr)
            .map_err(NodeError::TcpStream)?;

        let stream = PacketStream::init(secret_key, options.as_ref(), stream)
            .map_err(NodeError::PacketStream)?;

        self.streams.insert(*stream.peer_id(), stream);

        Ok(())
    }

    /// Try to initialize packet stream with provided socket address and ignore
    /// any errors.
    pub fn try_init_stream(
        self,
        secret_key: impl AsRef<SecretKey>,
        options: impl AsRef<PacketStreamOptions>,
        addr: impl ToSocketAddrs
    ) -> Self {
        let Ok(stream) = TcpStream::connect(addr) else {
            return self;
        };

        let Ok(stream) = PacketStream::init(secret_key, options.as_ref(), stream) else {
            return self;
        };

        self.add_stream(stream)
    }

    /// Add new packet stream.
    #[inline]
    pub fn add_stream(mut self, stream: PacketStream) -> Self {
        self.streams.insert(*stream.peer_id(), stream);

        self
    }

    /// Add validator signing key.
    ///
    /// If set, node will start a background task to issue new blocks for a
    /// blockchain with provided address.
    #[inline]
    pub fn add_validator(
        mut self,
        address: impl Into<Address>,
        signing_key: impl Into<SigningKey>
    ) -> Self {
        self.validators.insert(address.into(), signing_key.into());

        self
    }

    /// Add blockchain storage to the node.
    #[inline]
    pub fn add_storage(
        mut self,
        address: impl Into<Address>,
        storage: impl Into<Box<dyn Storage + Send>>
    ) -> Self {
        self.storages.insert(address.into(), storage.into());

        self
    }

    /// Try to synchronize blockchain storages.
    pub fn sync(&mut self) -> Result<(), NodeError> {
        #[cfg(feature = "tracing")]
        tracing::info!("synchronizing node storages");

        // Iterate over available storages.
        for (address, storage) in self.storages.iter_mut() {
            #[cfg(feature = "tracing")]
            tracing::info!(
                ?address,
                "synchronizing storage"
            );

            // Create batched viewer using available connections.
            //
            // FIXME: this won't work if streams don't share blockchain with
            //        provided address and will LOCK THE WHOLE THREAD!!!!!!!!!
            let mut viewer = BatchedViewer::new(
                self.streams.values_mut(),
                address.clone()
            );

            loop {
                // Fetch next block using network nodes and local storage.
                let block = viewer.forward_with_storage(storage.as_ref())
                    .map_err(NodeError::Viewer)?;

                let Some(block) = block else {
                    break;
                };

                #[cfg(feature = "tracing")]
                tracing::debug!(
                    hash = block.hash().to_base64(),
                    timestamp = block.timestamp().unix_timestamp(),
                    "read block"
                );

                // Write fetched block to the storage.
                storage.write_block(&block)
                    .map_err(NodeError::Storage)?;
            }
        }

        Ok(())
    }

    /// Start the node.
    ///
    /// This method will spawn background threads to listen to incoming packets
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
        let mut pending_messages = HashMap::with_capacity(self.storages.len());

        for address in self.storages.keys() {
            pending_messages.insert(address.clone(), HashMap::new());
        }

        // Create the node handler.
        let handler = NodeHandler {
            streams: Arc::new(RwLock::new(HashMap::with_capacity(self.streams.len()))),
            pending_messages: Arc::new(RwLock::new(pending_messages)),
            storages: Arc::new(Mutex::new(self.storages)),
            options: Arc::new(options)
        };

        // Add streams to the handler.
        for (peer_id, stream) in self.streams {
            #[cfg(feature = "tracing")]
            tracing::info!(
                peer_id = base64::encode(peer_id),
                "add node connection"
            );

            handler.add_stream(stream);
        }

        // Start validator threads.
        // for (root_block, signing_key) in self.validators {
        //     let handler = handler.clone();

        //     std::thread::spawn(move || {
        //         validator::run(handler, root_block, signing_key);
        //     });
        // }

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
    /// `[peer_id] => [stream]`
    #[allow(clippy::type_complexity)]
    streams: Arc<RwLock<HashMap<[u8; 32], Arc<Mutex<PacketStream>>>>>,

    /// Table of pending messages which are meant to be added into a new block.
    ///
    /// `[address] => ([hash] => [message])`
    pending_messages: Arc<RwLock<HashMap<Address, HashMap<Hash, Message>>>>,

    /// Table of blockchain history storages which are used to keep track of
    /// blocks history, query messages and so on.
    ///
    /// `[address] => [storage]`
    storages: Arc<Mutex<HashMap<Address, Box<dyn Storage + Send>>>>,

    /// Node options used by the underlying packets handlers.
    options: Arc<NodeOptions>
}

impl NodeHandler {
    /// Add new packet stream to the node connections pool.
    pub fn add_stream(&self, stream: PacketStream) {
        let peer_id = *stream.peer_id();

        #[cfg(feature = "tracing")]
        tracing::debug!(
            local_id = base64::encode(stream.local_id()),
            peer_id = base64::encode(peer_id),
            "add node connection"
        );

        let stream = Arc::new(Mutex::new(stream));

        let state = handlers::NodeState {
            stream: Arc::downgrade(&stream),
            handler: self.clone()
        };

        std::thread::spawn(move || {
            handlers::handle(state);
        });

        self.streams.write().insert(peer_id, stream);
    }

    /// Get table of available packet streams.
    #[inline]
    pub fn streams(
        &self
    ) -> RwLockReadGuard<'_, HashMap<[u8; 32], Arc<Mutex<PacketStream>>>> {
        self.streams.read()
    }

    /// Get mutable table of available packet streams.
    #[inline]
    pub fn streams_mut(
        &self
    ) -> RwLockWriteGuard<'_, HashMap<[u8; 32], Arc<Mutex<PacketStream>>>> {
        self.streams.write()
    }

    /// Get table of pending messages stored for a blockchain with provided
    /// address and run provided callback with it.
    pub fn map_pending_messages<T>(
        &self,
        address: impl AsRef<Address>,
        callback: impl FnOnce(&HashMap<Hash, Message>) -> T
    ) -> Option<T> {
        self.pending_messages.read()
            .get(address.as_ref())
            .map(callback)
    }

    /// Get mutable table of pending messages stored for a blockchain with
    /// provided address and run provided callback with it.
    pub fn map_pending_messages_mut<T>(
        &self,
        address: impl AsRef<Address>,
        callback: impl FnOnce(&mut HashMap<Hash, Message>) -> T
    ) -> Option<T> {
        self.pending_messages.write()
            .get_mut(address.as_ref())
            .map(callback)
    }

    /// Get mutable storage reference for a blockchain with provided address and
    /// run provided callback with them.
    pub fn map_storage<T>(
        &self,
        address: impl AsRef<Address>,
        callback: impl FnOnce(&mut dyn Storage) -> T
    ) -> Option<T> {
        self.storages.lock()
            .get_mut(address.as_ref())
            .map(|storage| callback(storage.as_mut()))
    }

    /// Send packet to all the available streams.
    ///
    /// This is a blocking method which will wait until all the streams will
    /// receive the packet.
    fn send(&self, packet: Packet) {
        let mut disconnected = Vec::new();

        let lock = self.streams.read();

        for (peer_id, sender) in lock.iter() {
            if sender.lock().send(packet.clone()).is_err() {
                disconnected.push(*peer_id);
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
    /// with provided address.
    ///
    /// This is a blocking method which will wait until all the streams will
    /// receive the packet.
    pub fn ask_pending_messages(&self, address: impl Into<Address>) {
        let address: Address = address.into();

        let except = self.pending_messages.read()
            .get(&address)
            .map(|messages| {
                messages.keys()
                    .copied()
                    .collect::<Box<[Hash]>>()
            })
            .unwrap_or_default();

        self.send(Packet::AskPendingMessages {
            address,
            except
        });
    }

    /// Send message to all the connected nodes which host a blockchain with
    /// provided address.
    ///
    /// This is a blocking method which will wait until all the streams will
    /// receive the message.
    pub fn send_message(
        &self,
        address: impl Into<Address>,
        message: Message
    ) {
        self.send(Packet::Message {
            address: address.into(),
            message
        });
    }

    /// Send block to all the connected nodes which host a blockchain with
    /// provided address.
    ///
    /// This is a blocking method which will wait until all the streams will
    /// receive the block.
    pub fn send_block(
        &self,
        address: impl Into<Address>,
        block: Block
    ) {
        self.send(Packet::Block {
            address: address.into(),
            block
        });
    }
}
