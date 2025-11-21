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

use std::time::Duration;
use std::collections::HashMap;
use std::sync::{Arc, Weak, Mutex, RwLock};

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
    pub stream: Arc<Mutex<PacketStream>>,
    pub handler: NodeHandler
}

/// Broadcast packet to all the streams besides the ones with given peer IDs.
pub fn broadcast(
    streams: &RwLock<HashMap<[u8; 32], Weak<Mutex<PacketStream>>>>,
    except: &[[u8; 32]],
    packet: &Packet
) {
    #[cfg(feature = "tracing")]
    tracing::debug!("broadcast packet");

    let mut disconnected = Vec::new();

    let lock = streams.read()
        .expect("failed to lock streams table");

    for (peer_id, sender) in lock.iter() {
        if except.contains(peer_id) {
            continue;
        }

        match sender.upgrade() {
            Some(sender) => {
                let mut lock = sender.lock()
                    .expect("failed to lock packet streams");

                if lock.send(packet.clone()).is_err() {
                    disconnected.push(*peer_id);
                }
            }

            None => disconnected.push(*peer_id)
        }
    }

    drop(lock);

    if !disconnected.is_empty() {
        let mut lock = streams.write()
            .expect("failed to lock streams table");

        for peer_id in disconnected {
            lock.remove(&peer_id);
        }
    }
}

/// Handle connection.
pub fn handle(state: NodeState) {
    // Ask remote node to share pending messages if we support their storing.
    let mut stream = state.stream.lock()
        .expect("failed to lock packet stream");

    let storages = state.handler.storages.lock()
        .expect("failed to lock storages table");

    for address in storages.keys() {
        #[cfg(feature = "tracing")]
        tracing::debug!(
            local_id = base64::encode(stream.local_id()),
            peer_id = base64::encode(stream.peer_id()),
            address = address.to_base64(),
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

    drop(stream);
    drop(storages);

    // Process incoming packets in a loop while the stream is still stored
    // in a node handler.
    loop {
        // Allow other threads to access stream for some time.
        std::thread::sleep(THREAD_SLEEP_DURATION);

        let mut stream = state.stream.lock()
            .expect("failed to lock packet stream");

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
                            &mut stream,
                            &state.handler,
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
                            &mut stream,
                            &state.handler,
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
                            &mut stream,
                            &state.handler,
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
                            &mut stream,
                            &state.handler,
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
                            &mut stream,
                            &state.handler,
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
                            &mut stream,
                            &state.handler,
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
                            &mut stream,
                            &state.handler,
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
