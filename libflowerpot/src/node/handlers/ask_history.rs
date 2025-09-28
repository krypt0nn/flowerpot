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
use crate::storage::Storage;
use crate::protocol::packets::Packet;

use super::NodeState;

/// Handle `AskHistory` packet.
///
/// Return `false` is critical error occured and node connection must be
/// terminated.
pub fn handle<S: Storage>(
    state: &mut NodeState<S>,
    offset: u64,
    max_length: u64
) -> bool {
    #[cfg(feature = "tracing")]
    tracing::debug!(
        local_id = base64::encode(state.stream.local_id()),
        peer_id = base64::encode(state.stream.peer_id()),
        root_block = state.handler.root_block.to_base64(),
        ?offset,
        ?max_length,
        "handle AskHistory packet"
    );

    // Then read max allowed amount of blocks' hashes.
    let history = state.handler.history.read()
        .iter()
        .skip(offset as usize)
        .take(state.handler.options.max_history_length.min(max_length as usize))
        .copied()
        .collect();

    // And try to send them back to the requester.
    if let Err(err) = state.stream.send(Packet::History {
        root_block: state.handler.root_block,
        offset,
        history
    }) {
        #[cfg(feature = "tracing")]
        tracing::error!(
            ?err,
            local_id = base64::encode(state.stream.local_id()),
            peer_id = base64::encode(state.stream.peer_id()),
            "failed to send packet to the packets stream"
        );

        return false;
    }

    true
}
