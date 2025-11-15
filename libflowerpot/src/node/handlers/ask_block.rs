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
use crate::protocol::packets::Packet;

use super::NodeState;

/// Handle `AskBlock` packet.
///
/// Return `false` if critical error occured and node connection must be
/// terminated.
pub fn handle(
    state: &mut NodeState,
    root_block: Hash,
    target_block: Hash
) -> bool {
    #[cfg(feature = "tracing")]
    tracing::debug!(
        local_id = base64::encode(state.stream.local_id()),
        peer_id = base64::encode(state.stream.peer_id()),
        root_block = root_block.to_base64(),
        target_block = target_block.to_base64(),
        "handle AskBlock packet"
    );

    // Try to read block from tracker.
    let result = state.handler.map_tracker(root_block, |_, tracker| {
        tracker.read_block(&target_block).transpose()
    }).flatten().transpose();

    match result {
        // Send it back to the requester if message is found.
        Ok(Some(block)) => {
            if let Err(err) = state.stream.send(Packet::Block {
                root_block,
                block
            }) {
                #[cfg(feature = "tracing")]
                tracing::error!(
                    ?err,
                    local_id = base64::encode(state.stream.local_id()),
                    peer_id = base64::encode(state.stream.peer_id()),
                    root_block = root_block.to_base64(),
                    target_block = target_block.to_base64(),
                    "failed to send Block packet"
                );

                return false;
            }
        }

        Ok(None) => (),

        Err(err) => {
            #[cfg(feature = "tracing")]
            tracing::warn!(
                ?err,
                local_id = base64::encode(state.stream.local_id()),
                peer_id = base64::encode(state.stream.peer_id()),
                root_block = root_block.to_base64(),
                target_block = target_block.to_base64(),
                "failed to read block from tracker"
            );

            return true;
        }
    }

    true
}
