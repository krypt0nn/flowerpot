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

/// Handle `AskHistory` packet.
///
/// Return `false` if critical error occured and node connection must be
/// terminated.
pub fn handle(
    state: &mut NodeState,
    root_block: Hash,
    since_block: Hash,
    max_length: u64
) -> bool {
    #[cfg(feature = "tracing")]
    tracing::debug!(
        local_id = base64::encode(state.stream.local_id()),
        peer_id = base64::encode(state.stream.peer_id()),
        root_block = root_block.to_base64(),
        since_block = since_block.to_base64(),
        ?max_length,
        "handle AskHistory packet"
    );

    // Read known blockchain history.
    let max_history_length = state.handler.options.max_history_length;

    let history = state.handler.map_tracker(root_block, move |_, tracker| {
        tracker.get_history(
            since_block,
            (max_length as usize).min(max_history_length)
        )
    });

    let Some(history) = history else {
        #[cfg(feature = "tracing")]
        tracing::debug!(
            local_id = base64::encode(state.stream.local_id()),
            peer_id = base64::encode(state.stream.peer_id()),
            root_block = root_block.to_base64(),
            since_block = since_block.to_base64(),
            ?max_length,
            "history for this blockchain is not available"
        );

        return true;
    };

    let history = match history {
        Ok(history) => history,
        Err(err) => {
            #[cfg(feature = "tracing")]
            tracing::warn!(
                ?err,
                local_id = base64::encode(state.stream.local_id()),
                peer_id = base64::encode(state.stream.peer_id()),
                root_block = root_block.to_base64(),
                since_block = since_block.to_base64(),
                ?max_length,
                "failed to read blockchain history"
            );

            return true;
        }
    };

    // Try to send this history back to the requester.
    if let Err(err) = state.stream.send(Packet::History {
        root_block,
        since_block,
        history
    }) {
        #[cfg(feature = "tracing")]
        tracing::error!(
            ?err,
            local_id = base64::encode(state.stream.local_id()),
            peer_id = base64::encode(state.stream.peer_id()),
            root_block = root_block.to_base64(),
            since_block = since_block.to_base64(),
            ?max_length,
            "failed to send History packet"
        );

        return false;
    }

    true
}
