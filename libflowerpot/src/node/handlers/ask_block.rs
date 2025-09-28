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

use crate::crypto::base64;
use crate::crypto::hash::Hash;
use crate::storage::Storage;
use crate::protocol::packets::Packet;

use super::NodeState;

/// Handle `AskBlock` packet.
///
/// Return `false` is critical error occured and node connection must be
/// terminated.
pub fn handle<S: Storage>(
    state: &mut NodeState<S>,
    target_block: Hash
) -> bool {
    #[cfg(feature = "tracing")]
    tracing::debug!(
        local_id = base64::encode(state.stream.local_id()),
        peer_id = base64::encode(state.stream.peer_id()),
        root_block = state.handler.root_block.to_base64(),
        target_block = target_block.to_base64(),
        "handle AskBlock packet"
    );

    // If this block is pending.
    if let Some(block) = state.handler.pending_blocks.read().get(&target_block) {
        // Then try to send it back.
        if let Err(err) = state.stream.send(Packet::Block {
            root_block: state.handler.root_block,
            block: block.clone()
        }) {
            #[cfg(feature = "tracing")]
            tracing::error!(
                ?err,
                local_id = base64::encode(state.stream.local_id()),
                peer_id = base64::encode(state.stream.peer_id()),
                "failed to send Block packet"
            );

            return false;
        }
    }

    // Otherwise, if we have a storage available.
    else if let Some(storage) = &state.handler.storage {
        // Then try to read block from that storage.
        match storage.read_block(&target_block) {
            // If we've found the block.
            Ok(Some(block)) => {
                // Then try to send it back.
                if let Err(err) = state.stream.send(Packet::Block {
                    root_block: state.handler.root_block,
                    block
                }) {
                    #[cfg(feature = "tracing")]
                    tracing::error!(
                        ?err,
                        local_id = base64::encode(state.stream.local_id()),
                        peer_id = base64::encode(state.stream.peer_id()),
                        "failed to send Block packet"
                    );

                    return false;
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
                    local_id = base64::encode(state.stream.local_id()),
                    peer_id = base64::encode(state.stream.peer_id()),
                    "failed to read block from the storage"
                );

                return false;
            }
        }
    }

    true
}
