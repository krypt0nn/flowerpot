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
use crate::crypto::sign::Signature;
use crate::storage::Storage;
use crate::protocol::packets::Packet;

use super::NodeState;

/// Handle `PendingBlocks` packet.
///
/// Return `false` is critical error occured and node connection must be
/// terminated.
pub fn handle<S: Storage>(
    state: &mut NodeState<S>,
    pending_blocks: Box<[(Hash, Box<[Signature]>)]>
) -> bool {
    #[cfg(feature = "tracing")]
    tracing::debug!(
        local_id = base64::encode(state.stream.local_id()),
        peer_id = base64::encode(state.stream.peer_id()),
        root_block = state.handler.root_block.to_base64(),
        ?pending_blocks,
        "handle PendingBlocks packet"
    );

    let lock = state.handler.pending_blocks.read();

    for (block, _) in pending_blocks {
        // TODO: do not ask for blocks if it has the same approvals as the
        // currently having one.

        #[allow(clippy::collapsible_if)]
        if !lock.contains_key(&block) {
            if let Err(err) = state.stream.send(Packet::AskBlock {
                root_block: state.handler.root_block,
                target_block: block
            }) {
                #[cfg(feature = "tracing")]
                tracing::error!(
                    ?err,
                    local_id = base64::encode(state.stream.local_id()),
                    peer_id = base64::encode(state.stream.peer_id()),
                    ?block,
                    "failed to send AskBlock packet"
                );

                return false;
            }
        }
    }

    true
}
