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
use crate::address::Address;
use crate::protocol::network::PacketStream;
use crate::protocol::packets::Packet;

use super::NodeState;

/// Handle `AskBlock` packet.
///
/// Return `false` if critical error occured and node connection must be
/// terminated.
pub fn handle(
    state: &mut NodeState,
    stream: &mut PacketStream,
    address: Address,
    hash: Hash
) -> bool {
    #[cfg(feature = "tracing")]
    tracing::debug!(
        local_id = base64::encode(stream.local_id()),
        peer_id = base64::encode(stream.peer_id()),
        ?address,
        ?hash,
        "handle AskBlock packet"
    );

    // Try to read block from a storage.
    let result = state.handler.map_storage(&address, |storage| {
        storage.read_block(&hash).transpose()
    }).flatten().transpose();

    match result {
        // Send it back to the requester if block is found.
        Ok(Some(block)) => {
            if let Err(err) = stream.send(Packet::Block {
                address: address.clone(),
                block
            }) {
                #[cfg(feature = "tracing")]
                tracing::error!(
                    ?err,
                    local_id = base64::encode(stream.local_id()),
                    peer_id = base64::encode(stream.peer_id()),
                    ?address,
                    ?hash,
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
                local_id = base64::encode(stream.local_id()),
                peer_id = base64::encode(stream.peer_id()),
                ?address,
                ?hash,
                "failed to read block from tracker"
            );

            return true;
        }
    }

    true
}
