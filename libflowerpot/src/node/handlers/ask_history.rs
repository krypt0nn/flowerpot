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
use crate::storage::StorageError;
use crate::protocol::network::PacketStream;
use crate::protocol::packets::Packet;
use crate::node::NodeHandler;

/// Handle `AskHistory` packet.
///
/// Return `false` if critical error occured and node connection must be
/// terminated.
pub fn handle(
    stream: &mut PacketStream,
    handler: &NodeHandler,
    address: Address,
    since_block: Hash,
    max_length: u64
) -> bool {
    #[cfg(feature = "tracing")]
    tracing::debug!(
        local_id = base64::encode(stream.local_id()),
        peer_id = base64::encode(stream.peer_id()),
        address = address.to_base64(),
        since_block = since_block.to_base64(),
        ?max_length,
        "handle AskHistory packet"
    );

    // Read known blockchain history.
    let max_length = handler.options.max_history_length
        .min(max_length as usize);

    let history = handler.map_storage(&address, move |storage| {
        let mut history = Vec::with_capacity(max_length);
        let mut curr_block = since_block;

        for _ in 0..max_length {
            let Some(next_block) = storage.next_block(&curr_block)? else {
                break;
            };

            curr_block = next_block;

            let Some(block) = storage.read_block(&curr_block)? else {
                break;
            };

            history.push(block);
        }

        Ok::<_, StorageError>(history)
    });

    let Some(history) = history else {
        #[cfg(feature = "tracing")]
        tracing::debug!(
            local_id = base64::encode(stream.local_id()),
            peer_id = base64::encode(stream.peer_id()),
            address = address.to_base64(),
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
                local_id = base64::encode(stream.local_id()),
                peer_id = base64::encode(stream.peer_id()),
                address = address.to_base64(),
                since_block = since_block.to_base64(),
                ?max_length,
                "failed to read blockchain history from a storage"
            );

            return true;
        }
    };

    // Try to send this history back to the requester.
    if let Err(err) = stream.send(Packet::History {
        address: address.clone(),
        since_block,
        history: history.into_boxed_slice()
    }) {
        #[cfg(feature = "tracing")]
        tracing::error!(
            ?err,
            local_id = base64::encode(stream.local_id()),
            peer_id = base64::encode(stream.peer_id()),
            address = address.to_base64(),
            since_block = since_block.to_base64(),
            ?max_length,
            "failed to send History packet"
        );

        return false;
    }

    true
}
