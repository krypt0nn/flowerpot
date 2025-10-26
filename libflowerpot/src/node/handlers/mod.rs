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

use std::sync::mpsc::{Receiver, TryRecvError};

use crate::crypto::base64;
use crate::storage::Storage;
use crate::protocol::packets::Packet;
use crate::protocol::network::PacketStream;

use super::NodeHandler;

mod ask_history;
mod ask_pending_transactions;
mod pending_transactions;
mod ask_pending_blocks;
mod pending_blocks;
mod ask_transaction;
mod transaction;
mod ask_block;
mod block;
mod approve_block;

pub struct NodeState<S: Storage> {
    pub handler: NodeHandler<S>,
    pub stream: PacketStream,
    pub receiver: Receiver<Packet>
}

impl<S: Storage> NodeState<S> {
    /// Send packet to every connected node besides the current one.
    pub fn broadcast(&self, packet: Packet) {
        #[cfg(feature = "tracing")]
        tracing::debug!(
            local_id = base64::encode(self.stream.local_id()),
            peer_id = base64::encode(self.stream.peer_id()),
            "broadcast packet"
        );

        let mut disconnected = Vec::new();

        let lock = self.handler.streams.read();

        for (endpoint_id, sender) in lock.iter() {
            if endpoint_id != self.stream.peer_id()
                && sender.send(packet.clone()).is_err()
            {
                disconnected.push(*endpoint_id);
            }
        }

        drop(lock);

        for endpoint_id in disconnected {
            self.handler.streams.write().remove(&endpoint_id);
        }
    }
}

/// Handle connection.
pub fn handle<S: Storage>(mut state: NodeState<S>) {
    // Ask remote node to share pending transactions if we support
    // their storing.
    if state.handler.options.accept_transactions &&
        let Err(err) = state.stream.send(Packet::AskPendingTransactions {
            root_block: state.handler.root_block
        })
    {
        #[cfg(feature = "tracing")]
        tracing::error!(
            ?err,
            local_id = base64::encode(state.stream.local_id()),
            peer_id = base64::encode(state.stream.peer_id()),
            "failed to send packet to the packets stream"
        );

        return;
    }

    // Ask remote node to share pending blocks if we support their
    // storing.
    if state.handler.options.accept_blocks &&
        let Err(err) = state.stream.send(Packet::AskPendingBlocks {
            root_block: state.handler.root_block
        })
    {
        #[cfg(feature = "tracing")]
        tracing::error!(
            ?err,
            local_id = base64::encode(state.stream.local_id()),
            peer_id = base64::encode(state.stream.peer_id()),
            "failed to send packet to the packets stream"
        );

        return;
    }

    // Process incoming packets in a loop.
    loop {
        // Send packets to the remote node.
        loop {
            match state.receiver.try_recv() {
                Ok(packet) => {
                    #[cfg(feature = "tracing")]
                    tracing::debug!(
                        local_id = base64::encode(state.stream.local_id()),
                        peer_id = base64::encode(state.stream.peer_id()),
                        "broadcasting packet"
                    );

                    if let Err(err) = state.stream.send(packet) {
                        #[cfg(feature = "tracing")]
                        tracing::error!(
                            ?err,
                            local_id = base64::encode(state.stream.local_id()),
                            peer_id = base64::encode(state.stream.peer_id()),
                            "failed to send packet to the packets stream"
                        );

                        return;
                    }
                }

                Err(TryRecvError::Disconnected) => {
                    #[cfg(feature = "tracing")]
                    tracing::info!(
                        local_id = base64::encode(state.stream.local_id()),
                        peer_id = base64::encode(state.stream.peer_id()),
                        "local node went offline, terminating connection"
                    );

                    return;
                }

                Err(TryRecvError::Empty) => break
            }
        }

        // Read packet from the remote endpoint.
        // TODO: timeout support
        let packet = state.stream.recv();

        // Process received packet.
        match packet {
            Ok(packet) => {
                match packet {
                    // If we were asked to share the blockchain history.
                    Packet::AskHistory {
                        root_block: received_root_block,
                        offset,
                        max_length
                    } if received_root_block == state.handler.root_block => {
                        if !ask_history::handle(&mut state, offset, max_length) {
                            return;
                        }
                    }

                    // If we were asked to send the pending transactions list.
                    Packet::AskPendingTransactions {
                        root_block: received_root_block
                    } if received_root_block == state.handler.root_block => {
                        if !ask_pending_transactions::handle(&mut state) {
                            return;
                        }
                    }

                    // If we received list of available pending transactions.
                    Packet::PendingTransactions {
                        root_block: received_root_block,
                        pending_transactions
                    } if received_root_block == state.handler.root_block
                        && state.handler.options.fetch_pending_transactions
                    => {
                        if !pending_transactions::handle(
                            &mut state,
                            pending_transactions
                        ) {
                            return;
                        }
                    }

                    // If we were asked to send the pending blocks list.
                    Packet::AskPendingBlocks {
                        root_block: received_root_block
                    } if received_root_block == state.handler.root_block => {
                        if !ask_pending_blocks::handle(&mut state) {
                            return;
                        }
                    }

                    // If we received list of available pending blocks.
                    Packet::PendingBlocks {
                        root_block: received_root_block,
                        pending_blocks
                    } if received_root_block == state.handler.root_block
                        && state.handler.options.fetch_pending_transactions
                    => {
                        if !pending_blocks::handle(&mut state, pending_blocks) {
                            return;
                        }
                    }

                    // If we were asked to send transaction.
                    Packet::AskTransaction {
                        root_block: received_root_block,
                        transaction
                    } if received_root_block == state.handler.root_block => {
                        if !ask_transaction::handle(&mut state, transaction) {
                            return;
                        }
                    }

                    // If we received some transaction.
                    Packet::Transaction {
                        root_block: received_root_block,
                        transaction
                    } if received_root_block == state.handler.root_block
                        && state.handler.options.accept_transactions
                    => {
                        if !transaction::handle(&mut state, transaction) {
                            return;
                        }
                    }

                    // If we were asked to send a block of the blockchain.
                    Packet::AskBlock {
                        root_block: received_root_block,
                        target_block
                    } if received_root_block == state.handler.root_block => {
                        if !ask_block::handle(&mut state, target_block) {
                            return;
                        }
                    }

                    // If we received some block.
                    Packet::Block {
                        root_block: received_root_block,
                        block
                    } if received_root_block == state.handler.root_block
                        && state.handler.options.accept_blocks
                    => {
                        if !block::handle(&mut state, block) {
                            return;
                        }
                    }

                    // If we received block approval.
                    Packet::ApproveBlock {
                        root_block: received_root_block,
                        target_block,
                        approval
                    } if received_root_block == state.handler.root_block => {
                        if !approve_block::handle(
                            &mut state,
                            target_block,
                            approval
                        ) {
                            return;
                        }
                    }

                    _ => ()
                }
            }

            Err(err) => {
                #[cfg(feature = "tracing")]
                tracing::error!(
                    ?err,
                    local_id = base64::encode(state.stream.local_id()),
                    peer_id = base64::encode(state.stream.peer_id()),
                    "failed to read packet from the packets stream"
                );

                break;
            }
        }
    }
}
