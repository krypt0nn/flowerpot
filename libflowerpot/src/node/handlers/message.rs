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
use crate::message::Message;
use crate::address::Address;
use crate::protocol::network::PacketStream;
use crate::protocol::packets::Packet;

use super::NodeState;

/// Handle `Message` packet.
///
/// Return `false` if critical error occured and node connection must be
/// terminated.
pub fn handle(
    state: &mut NodeState,
    stream: &mut PacketStream,
    address: Address,
    message: Message
) -> bool {
    let message_size = message.data().len();

    #[cfg(feature = "tracing")]
    tracing::debug!(
        local_id = base64::encode(stream.local_id()),
        peer_id = base64::encode(stream.peer_id()),
        ?address,
        message_hash = message.hash().to_base64(),
        ?message_size,
        "handle Message packet"
    );

    // Reject large messages.
    if message_size > state.handler.options.max_message_size {
        #[cfg(feature = "tracing")]
        tracing::warn!(
            local_id = base64::encode(stream.local_id()),
            peer_id = base64::encode(stream.peer_id()),
            ?address,
            message_hash = message.hash().to_base64(),
            ?message_size,
            "received message is too large"
        );

        return true;
    }

    // Verify received message.
    let (is_valid, verifying_key) = match message.verify() {
        Ok(result) => result,
        Err(err) => {
            #[cfg(feature = "tracing")]
            tracing::error!(
                ?err,
                local_id = base64::encode(stream.local_id()),
                peer_id = base64::encode(stream.peer_id()),
                ?address,
                message_hash = message.hash().to_base64(),
                ?message_size,
                "failed to verify received message"
            );

            return true;
        }
    };

    // Skip message if it's invalid.
    if !is_valid {
        #[cfg(feature = "tracing")]
        tracing::warn!(
            local_id = base64::encode(stream.local_id()),
            peer_id = base64::encode(stream.peer_id()),
            ?address,
            verifying_key = verifying_key.to_base64(),
            message_hash = message.hash().to_base64(),
            ?message_size,
            "received invalid message"
        );

        return true;
    }

    // Skip pending messages.
    let is_pending = state.handler.map_pending_messages(
        &address,
        |pending_messages| pending_messages.contains_key(message.hash())
    );

    if is_pending == Some(true) {
        #[cfg(feature = "tracing")]
        tracing::trace!(
            local_id = base64::encode(stream.local_id()),
            peer_id = base64::encode(stream.peer_id()),
            ?address,
            verifying_key = verifying_key.to_base64(),
            message_hash = message.hash().to_base64(),
            ?message_size,
            "received message is already stored in the pending messages pool"
        );

        return true;
    }

    // Check this message using the provided filter.
    if let Some(filter) = &state.handler.options.messages_filter
        && !filter(&address, &message, &verifying_key)
    {
        #[cfg(feature = "tracing")]
        tracing::debug!(
            local_id = base64::encode(stream.local_id()),
            peer_id = base64::encode(stream.peer_id()),
            ?address,
            verifying_key = verifying_key.to_base64(),
            message_hash = message.hash().to_base64(),
            ?message_size,
            "received message which was filtered out"
        );

        return true;
    }

    // Skip message if it's already stored in the storage.
    let is_stored = state.handler.map_storage(
        &address,
        |storage| storage.is_message_stored(message.hash())
    ).transpose();

    match is_stored {
        Ok(Some(true)) => {
            #[cfg(feature = "tracing")]
            tracing::trace!(
                local_id = base64::encode(stream.local_id()),
                peer_id = base64::encode(stream.peer_id()),
                ?address,
                verifying_key = verifying_key.to_base64(),
                message_hash = message.hash().to_base64(),
                ?message_size,
                "received message is already stored in the storage"
            );

            return true;
        }

        Err(err) => {
            #[cfg(feature = "tracing")]
            tracing::warn!(
                ?err,
                local_id = base64::encode(stream.local_id()),
                peer_id = base64::encode(stream.peer_id()),
                ?address,
                verifying_key = verifying_key.to_base64(),
                message_hash = message.hash().to_base64(),
                ?message_size,
                "failed to check if received message is already stored in the storage"
            );

            return true;
        }

        _ => ()
    }

    #[cfg(feature = "tracing")]
    tracing::info!(
        local_id = base64::encode(stream.local_id()),
        peer_id = base64::encode(stream.peer_id()),
        ?address,
        verifying_key = verifying_key.to_base64(),
        message_hash = message.hash().to_base64(),
        ?message_size,
        "received new pending message"
    );

    // Insert message to the pending messages pool.
    let message_clone = message.clone();

    state.handler.map_pending_messages_mut(&address, move |pending_messages| {
        pending_messages.insert(*message_clone.hash(), message_clone);
    });

    // Broadcast this message to other connected nodes.
    state.broadcast(Packet::Message {
        address,
        message
    });

    true
}
