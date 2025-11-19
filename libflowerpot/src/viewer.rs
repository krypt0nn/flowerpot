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

use crate::crypto::base64;
use crate::crypto::hash::Hash;
use crate::crypto::sign::SignatureError;
use crate::block::Block;
use crate::address::Address;
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

    #[error("stream returned block belonging to a different blockchain")]
    WrongAddress,

    #[error("stream returned invalid history")]
    InvalidHistory
}

/// Viewer is a helper struct that uses the underlying packet stream connection
/// to traverse blockchain history known to the remote node.
pub struct Viewer<'stream> {
    stream: &'stream mut PacketStream,

    /// Blockchain address.
    address: Address,

    /// Hash of the previously fetched block.
    last_fetched_block: Hash,

    /// Prefetched blockchain history.
    prefetch_history: VecDeque<Block>,

    /// Maximal amount of history blocks to prefetch. Prefetched blocks will be
    /// stored in RAM until used, and blocks can potentially contain large
    /// inline blobs, so it's not recommended to set this value really high.
    max_prefetch_length: u64
}

impl<'stream> Viewer<'stream> {
    /// Create new viewer of the blockchain history known to the node with
    /// provided packet stream connection.
    #[inline]
    pub fn new(
        stream: &'stream mut PacketStream,
        address: Address
    ) -> Self {
        Self::new_after(stream, address, Hash::ZERO)
    }

    /// Create new viewer which will return a blockchain history after a block
    /// with provided hash (so skip validation of all the previous blocks).
    #[inline]
    pub fn new_after(
        stream: &'stream mut PacketStream,
        address: Address,
        block_hash: impl Into<Hash>
    ) -> Self {
        Self {
            stream,
            address,
            last_fetched_block: block_hash.into(),
            prefetch_history: VecDeque::new(),
            max_prefetch_length: 8
        }
    }

    /// Set maximal amount of history blocks to fetch from remote node.
    #[inline]
    pub fn with_max_prefetch_length(
        mut self,
        max_prefetch_length: u64
    ) -> Self {
        self.max_prefetch_length = max_prefetch_length;

        self
    }

    /// Get blockchain address.
    #[inline]
    pub const fn address(&self) -> &Address {
        &self.address
    }

    /// Hash of the previously fetched block.
    ///
    /// This method will return a hash of the block which was fetched by the
    /// last `forward` method call.
    #[inline]
    pub const fn last_fetched_block(&self) -> &Hash {
        &self.last_fetched_block
    }

    /// Request the next block of the blockchain history known to the underlying
    /// node, verify and return it. If we've reached the end of the known
    /// history then `None` is returned.
    pub fn forward(&mut self) -> Result<Option<Block>, ViewerError> {
        #[cfg(feature = "tracing")]
        tracing::trace!(
            address = self.address.to_base64(),
            last_fetched_block = self.last_fetched_block.to_base64(),
            "fetch next blockchain block"
        );

        // If prefetch buffer is empty then try to fill it.
        if self.prefetch_history.is_empty() {
            #[cfg(feature = "tracing")]
            tracing::trace!(
                address = self.address.to_base64(),
                last_fetched_block = self.last_fetched_block.to_base64(),
                local_id = base64::encode(self.stream.local_id()),
                peer_id = base64::encode(self.stream.peer_id()),
                "ask remote node to share blockchain history"
            );

            // Ask remote node to share blockchain history.
            self.stream.send(&Packet::AskHistory {
                address: self.address.clone(),
                since_block: self.last_fetched_block,
                max_length: self.max_prefetch_length
            }).map_err(ViewerError::PacketStream)?;

            #[cfg(feature = "tracing")]
            tracing::trace!(
                address = self.address.to_base64(),
                last_fetched_block = self.last_fetched_block.to_base64(),
                local_id = base64::encode(self.stream.local_id()),
                peer_id = base64::encode(self.stream.peer_id()),
                "waiting for blockchain history packet"
            );

            // Wait for the history packet.
            let history = self.stream.peek(|packet| {
                if let Packet::History {
                    address: received_address,
                    since_block: received_since_block,
                    ..
                } = packet {
                    return received_address == &self.address
                        && received_since_block == &self.last_fetched_block;
                }

                false
            }).map_err(ViewerError::PacketStream)?;

            let Packet::History { history, .. } = history else {
                return Err(ViewerError::InvalidHistory);
            };

            // Store the prefetch history.
            self.prefetch_history = history.into_iter()
                .take(self.max_prefetch_length as usize)
                .collect();

            #[cfg(feature = "tracing")]
            tracing::trace!(
                address = self.address.to_base64(),
                last_fetched_block = self.last_fetched_block.to_base64(),
                prefetch_history = ?self.prefetch_history.iter()
                    .map(|block| block.hash().to_base64())
                    .collect::<Vec<String>>(),
                "updated prefetched history buffer"
            );
        }

        // Process the block from prefetched history if it's available.
        if let Some(block) = self.prefetch_history.pop_front() {
            #[cfg(feature = "tracing")]
            tracing::trace!(
                address = self.address.to_base64(),
                last_fetched_block = self.last_fetched_block.to_base64(),
                block_hash = block.hash().to_base64(),
                "take prefetched block"
            );

            // Reject block if it doesn't reference previously fetched block.
            if block.prev_hash() != &self.last_fetched_block {
                #[cfg(feature = "tracing")]
                tracing::warn!(
                    address = self.address.to_base64(),
                    last_fetched_block = self.last_fetched_block.to_base64(),
                    block_hash = block.hash().to_base64(),
                    prev_block_hash = block.prev_hash().to_base64(),
                    "prefetched block has wrong previous block hash"
                );

                self.prefetch_history.clear();

                return Err(ViewerError::InvalidBlock);
            }

            // Verify the block signature and derive its blockchain address.
            let (is_valid, address) = block.verify()?;

            // Reject block if it's invalid.
            if !is_valid {
                #[cfg(feature = "tracing")]
                tracing::warn!(
                    address = self.address.to_base64(),
                    last_fetched_block = self.last_fetched_block.to_base64(),
                    block_hash = block.hash().to_base64(),
                    "prefetched block is invalid"
                );

                self.prefetch_history.clear();

                return Err(ViewerError::InvalidBlock);
            }

            // Reject block if it belongs to a different blockchain
            // (malicious remote client).
            if address != self.address {
                #[cfg(feature = "tracing")]
                tracing::warn!(
                    address = self.address.to_base64(),
                    last_fetched_block = self.last_fetched_block.to_base64(),
                    block_hash = block.hash().to_base64(),
                    "prefetched block belongs to a different blockchain"
                );

                self.prefetch_history.clear();

                return Err(ViewerError::WrongAddress);
            }

            // Return valid block.
            self.last_fetched_block = *block.hash();

            return Ok(Some(block));
        }

        Ok(None)
    }
}

/// Batched viewer is a helper struct which takes multiple `Viewer`-s and allows
/// iterating through the commonly known blockchain history, selecting the best
/// fork according to the protocol agreements.
pub struct BatchedViewer<'stream> {
    /// List of batched network blockchain viewers.
    viewers: Vec<Viewer<'stream>>,

    /// Blockchain address.
    address: Address,

    /// Hash of the previously fetched block.
    last_fetched_block: Hash
}

impl<'stream> BatchedViewer<'stream> {
    /// Create new batched viewer of the blockchain history known to the
    /// provided nodes' packet streams.
    #[inline]
    pub fn new(
        streams: impl IntoIterator<Item = &'stream mut PacketStream>,
        address: Address
    ) -> Self {
        Self::new_after(streams, address, Hash::ZERO)
    }

    /// Create new batched viewer which will return a blockchain history after
    /// a block with provided hash (so skip validation of all the previous
    /// blocks).
    pub fn new_after(
        streams: impl IntoIterator<Item = &'stream mut PacketStream>,
        address: Address,
        block_hash: impl Into<Hash>
    ) -> Self {
        let block_hash: Hash = block_hash.into();

        let mut viewers = Vec::new();

        for stream in streams {
            viewers.push(Viewer::new_after(
                stream,
                address.clone(),
                block_hash
            ));
        }

        Self {
            viewers,
            address,
            last_fetched_block: block_hash
        }
    }

    /// Get blockchain address.
    #[inline]
    pub const fn address(&self) -> &Address {
        &self.address
    }

    /// Hash of the previously fetched block.
    ///
    /// This method will return a hash of the block which was fetched by the
    /// last `forward` method call.
    #[inline]
    pub const fn last_fetched_block(&self) -> &Hash {
        &self.last_fetched_block
    }

    /// Request the next block of the blockchain history known to the underlying
    /// nodes, verify and return it. If we've reached the end of the known
    /// history then `Ok(None)` is returned.
    pub fn forward(
        &mut self
    ) -> Result<Option<Block>, ViewerError> {
        let mut next_block: Option<Block> = None;

        for viewer in &mut self.viewers {
            if let Some(block) = viewer.forward()? {
                if block.prev_hash() != &self.last_fetched_block {
                    continue;
                }

                next_block = match next_block {
                    Some(next_block) if next_block.timestamp() >= block.timestamp() => Some(next_block),
                    _ => Some(block)
                };
            }
        }

        let Some(next_block) = next_block else {
            return Ok(None);
        };

        self.last_fetched_block = *next_block.hash();

        Ok(Some(next_block))
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
    ) -> Result<Option<Block>, ViewerError> {
        let storage_block = storage.next_block(&self.last_fetched_block)
            .map_err(ViewerError::Storage)?
            .and_then(|block| {
                storage.read_block(&block)
                    .transpose()
            })
            .transpose()
            .map_err(ViewerError::Storage)?
            .map(|block| {
                let (is_valid, address) = block.verify()
                    .map_err(ViewerError::Signature)?;

                // Just silence the error, storage can potentially be updated
                // after we fetch a normal block from the network.
                if !is_valid || address != self.address {
                    Ok::<_, ViewerError>(None)
                } else {
                    Ok(Some(block))
                }
            })
            .transpose()?
            .flatten();

        let network_block = self.forward()?;

        match (network_block, storage_block) {
            (Some(network_block), Some(storage_block)) => {
                // Select block variant with greater timestamp.
                if storage_block.timestamp() >= network_block.timestamp() {
                    self.last_fetched_block = *storage_block.hash();

                    Ok(Some(storage_block))
                }

                else {
                    self.last_fetched_block = *network_block.hash();

                    Ok(Some(network_block))
                }
            }

            (Some(block), None) |
            (None, Some(block)) => {
                self.last_fetched_block = *block.hash();

                Ok(Some(block))
            }

            (None, None) => Ok(None)
        }
    }
}
