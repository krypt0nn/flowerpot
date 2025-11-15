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

// TODO: some option to reject messages for untracked blockchains.

/// Handle `PendingMessages` packet.
///
/// Return `false` if critical error occured and node connection must be
/// terminated.
pub fn handle(
    state: &mut NodeState,
    root_block: Hash,
    pending_messages: Box<[Hash]>
) -> bool {
    #[cfg(feature = "tracing")]
    tracing::debug!(
        local_id = base64::encode(state.stream.local_id()),
        peer_id = base64::encode(state.stream.peer_id()),
        root_block = root_block.to_base64(),
        pending_messages = ?pending_messages.iter()
            .map(|hash| hash.to_base64())
            .collect::<Box<[String]>>(),
        "handle PendingMessages packet"
    );

    let lock = state.handler.pending_messages.read();

    for message in pending_messages {
        let is_available = match lock.get(&root_block) {
            Some(values) => values.contains_key(&message),
            None => false
        };

        #[allow(clippy::collapsible_if)]
        if !is_available {
            if let Err(err) = state.stream.send(Packet::AskMessage {
                root_block,
                message
            }) {
                #[cfg(feature = "tracing")]
                tracing::error!(
                    ?err,
                    local_id = base64::encode(state.stream.local_id()),
                    peer_id = base64::encode(state.stream.peer_id()),
                    root_block = root_block.to_base64(),
                    "failed to send AskMessage packet"
                );

                return false;
            }
        }
    }

    true
}
