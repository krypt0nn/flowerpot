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
use crate::node::NodeHandler;

/// Handle `AskMessage` packet.
///
/// Return `false` if critical error occured and node connection must be
/// terminated.
pub fn handle(
    stream: &mut PacketStream,
    handler: &NodeHandler,
    address: Address,
    message: Hash
) -> bool {
    #[cfg(feature = "tracing")]
    tracing::debug!(
        local_id = base64::encode(stream.local_id()),
        peer_id = base64::encode(stream.peer_id()),
        address = address.to_base64(),
        message = message.to_base64(),
        "handle AskMessage packet"
    );

    // Try to read requested message from pending messages pool.
    let mut value = handler.map_pending_messages(
        &address,
        |pending_messages| pending_messages.get(&message).cloned()
    ).flatten();

    // If it's not available there then try to read it from a storage.
    if value.is_none() {
        let result = handler.map_storage(&address, |storage| {
            storage.read_message(&message).transpose()
        }).flatten().transpose();

        match result {
            Ok(message) => value = message,

            Err(err) => {
                #[cfg(feature = "tracing")]
                tracing::warn!(
                    ?err,
                    local_id = base64::encode(stream.local_id()),
                    peer_id = base64::encode(stream.peer_id()),
                    address = address.to_base64(),
                    message = message.to_base64(),
                    "failed to read message from a storage"
                );

                return true;
            }
        }
    }

    // Send it back to the requester if message is found.
    #[allow(clippy::collapsible_if)]
    if let Some(value) = value {
        if let Err(err) = stream.send(Packet::Message {
            address: address.clone(),
            message: value
        }) {
            #[cfg(feature = "tracing")]
            tracing::error!(
                ?err,
                local_id = base64::encode(stream.local_id()),
                peer_id = base64::encode(stream.peer_id()),
                address = address.to_base64(),
                message = message.to_base64(),
                "failed to send Message packet"
            );

            return false;
        }
    }

    true
}
