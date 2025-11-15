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

use flume::{Receiver, TryRecvError};

use crate::crypto::base64;
use crate::protocol::packets::Packet;
use crate::protocol::network::PacketStream;

use super::NodeHandler;

mod ask_history;
mod ask_pending_messages;
mod pending_messages;
mod ask_message;
mod message;
mod ask_block;
mod block;

pub struct NodeState {
    pub handler: NodeHandler,
    pub stream: PacketStream,
    pub receiver: Receiver<Packet>
}

impl NodeState {
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

        if !disconnected.is_empty() {
            let mut lock = self.handler.streams.write();

            for endpoint_id in disconnected {
                lock.remove(&endpoint_id);
            }
        }
    }
}

/// Handle connection.
pub fn handle(mut state: NodeState) {
    // Ask remote node to share pending messages if we support their storing.
    // if state.handler.options.accept_messages &&
    //     let Err(err) = state.stream.send(Packet::AskPendingMessages {
    //         root_block: state.handler.root_block
    //     })
    // {
    //     #[cfg(feature = "tracing")]
    //     tracing::error!(
    //         ?err,
    //         local_id = base64::encode(state.stream.local_id()),
    //         peer_id = base64::encode(state.stream.peer_id()),
    //         "failed to send packet to the packets stream"
    //     );

    //     return;
    // }

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
                        root_block,
                        since_block,
                        max_length
                    } => {
                        if !ask_history::handle(
                            &mut state,
                            root_block,
                            since_block,
                            max_length
                        ) {
                            return;
                        }
                    }

                    // If we were asked to send the pending messages list.
                    Packet::AskPendingMessages {
                        root_block,
                        known_messages
                    } => {
                        if !ask_pending_messages::handle(
                            &mut state,
                            root_block,
                            &known_messages
                        ) {
                            return;
                        }
                    }

                    // If we received list of available pending messages.
                    Packet::PendingMessages {
                        root_block,
                        pending_messages
                    } if state.handler.options.fetch_pending_messages => {
                        if !pending_messages::handle(
                            &mut state,
                            root_block,
                            pending_messages
                        ) {
                            return;
                        }
                    }

                    // If we were asked to send message.
                    Packet::AskMessage {
                        root_block,
                        message
                    } => {
                        if !ask_message::handle(
                            &mut state,
                            root_block,
                            message
                        ) {
                            return;
                        }
                    }

                    // If we received some message.
                    Packet::Message {
                        root_block,
                        message
                    } if state.handler.options.accept_messages => {
                        if !message::handle(
                            &mut state,
                            root_block,
                            message
                        ) {
                            return;
                        }
                    }

                    // If we were asked to send a block of the blockchain.
                    Packet::AskBlock {
                        root_block,
                        target_block
                    } => {
                        if !ask_block::handle(
                            &mut state,
                            root_block,
                            target_block
                        ) {
                            return;
                        }
                    }

                    // If we received some block.
                    Packet::Block {
                        root_block,
                        block
                    } if state.handler.options.accept_blocks => {
                        if !block::handle(
                            &mut state,
                            root_block,
                            block
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
