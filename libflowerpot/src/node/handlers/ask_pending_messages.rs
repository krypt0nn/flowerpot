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

/// Handle `AskPendingMessages` packet.
///
/// Return `false` if critical error occured and node connection must be
/// terminated.
pub fn handle(
    state: &mut NodeState,
    root_block: Hash,
    known_messages: Box<[Hash]>
) -> bool {
    #[cfg(feature = "tracing")]
    tracing::debug!(
        local_id = base64::encode(state.stream.local_id()),
        peer_id = base64::encode(state.stream.peer_id()),
        root_block = root_block.to_base64(),
        "handle AskPendingMessages packet"
    );

    // Get list of pending messages.
    let pending_messages = state.handler.map_pending_messages(
        root_block,
        |pending_messages| {
            pending_messages.keys()
                .filter(|hash| !known_messages.contains(hash))
                .copied()
                .collect::<Box<[Hash]>>()
        }
    );

    // Try to send it back to the requester.
    if let Err(err) = state.stream.send(Packet::PendingMessages {
        root_block,
        pending_messages: pending_messages.unwrap_or_default()
    }) {
        #[cfg(feature = "tracing")]
        tracing::error!(
            ?err,
            local_id = base64::encode(state.stream.local_id()),
            peer_id = base64::encode(state.stream.peer_id()),
            root_block = root_block.to_base64(),
            "failed to send PendingMessages packet"
        );

        return false;
    }

    true
}
