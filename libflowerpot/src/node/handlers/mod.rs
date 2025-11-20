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

use std::sync::Weak;
use std::time::Duration;

use spin::Mutex;

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

/// Amount of time a packet stream processing thread will sleep between locking
/// and unlocking the packet stream so other threads could access it.
const THREAD_SLEEP_DURATION: Duration = Duration::from_millis(50);

pub struct NodeState {
    pub stream: Weak<Mutex<PacketStream>>,
    pub handler: NodeHandler
}

impl NodeState {
    /// Send packet to every connected node besides the current one.
    pub fn broadcast(&self, packet: Packet) {
        let (local_id, peer_id) = match self.stream.upgrade() {
            Some(stream) => {
                let lock = stream.lock();

                let local_id = *lock.local_id();
                let peer_id = *lock.peer_id();

                (Some(local_id), Some(peer_id))
            }

            None => (None, None)
        };

        #[cfg(feature = "tracing")]
        tracing::debug!(
            local_id = ?local_id.map(base64::encode),
            peer_id = ?peer_id.map(base64::encode),
            "broadcast packet"
        );

        let mut disconnected = Vec::new();

        let lock = self.handler.streams.read();

        for (sender_peer_id, sender) in lock.iter() {
            let mut sender = sender.lock();

            if Some(sender_peer_id) != peer_id.as_ref()
                && sender.send(packet.clone()).is_err()
            {
                disconnected.push(*sender_peer_id);
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
    if let Some(stream) = state.stream.upgrade() {
        let mut stream = stream.lock();
        let storages = state.handler.storages.lock();

        for address in storages.keys() {
            #[cfg(feature = "tracing")]
            tracing::debug!(
                local_id = base64::encode(stream.local_id()),
                peer_id = base64::encode(stream.peer_id()),
                ?address,
                "ask pending messages"
            );

            if state.handler.options.accept_messages &&
                state.handler.options.fetch_pending_messages &&
                let Err(err) = stream.send(Packet::AskPendingMessages {
                    address: address.clone(),
                    except: Box::new([])
                })
            {
                #[cfg(feature = "tracing")]
                tracing::error!(
                    ?err,
                    local_id = base64::encode(stream.local_id()),
                    peer_id = base64::encode(stream.peer_id()),
                    "failed to send packet to the packets stream"
                );

                return;
            }
        }
    }

    // Process incoming packets in a loop while the stream is still stored
    // in a node handler.
    while let Some(stream) = state.stream.upgrade() {
        // Allow other threads to access stream for some time.
        std::thread::sleep(THREAD_SLEEP_DURATION);

        let mut stream = stream.lock();

        // Try to read packet from the remote endpoint.
        let Some(packet) = stream.try_recv().transpose() else {
            continue;
        };

        // Process received packet.
        match packet {
            Ok(packet) => {
                match packet {
                    Packet::AskHistory {
                        address,
                        since_block,
                        max_length
                    } => {
                        if !ask_history::handle(
                            &mut state,
                            &mut stream,
                            address,
                            since_block,
                            max_length
                        ) {
                            return;
                        }
                    }

                    Packet::AskPendingMessages {
                        address,
                        except
                    } => {
                        if !ask_pending_messages::handle(
                            &mut state,
                            &mut stream,
                            address,
                            &except
                        ) {
                            return;
                        }
                    }

                    Packet::PendingMessages {
                        address,
                        messages
                    } if state.handler.options.fetch_pending_messages => {
                        if !pending_messages::handle(
                            &mut state,
                            &mut stream,
                            address,
                            messages
                        ) {
                            return;
                        }
                    }

                    Packet::AskMessage {
                        address,
                        hash
                    } => {
                        if !ask_message::handle(
                            &mut state,
                            &mut stream,
                            address,
                            hash
                        ) {
                            return;
                        }
                    }

                    Packet::Message {
                        address,
                        message
                    } if state.handler.options.accept_messages => {
                        if !message::handle(
                            &mut state,
                            &mut stream,
                            address,
                            message
                        ) {
                            return;
                        }
                    }

                    Packet::AskBlock {
                        address,
                        hash
                    } => {
                        if !ask_block::handle(
                            &mut state,
                            &mut stream,
                            address,
                            hash
                        ) {
                            return;
                        }
                    }

                    Packet::Block {
                        address,
                        block
                    } if state.handler.options.accept_blocks => {
                        if !block::handle(
                            &mut state,
                            &mut stream,
                            address,
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
                    local_id = base64::encode(stream.local_id()),
                    peer_id = base64::encode(stream.peer_id()),
                    "failed to read packet from the packets stream"
                );

                break;
            }
        }
    }
}
