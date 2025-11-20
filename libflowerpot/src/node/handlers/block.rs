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
use crate::block::Block;
use crate::address::Address;
use crate::protocol::network::PacketStream;
use crate::protocol::packets::Packet;

use super::NodeState;

/// Handle `Block` packet.
///
/// Return `false` if critical error occured and node connection must be
/// terminated.
pub fn handle(
    state: &mut NodeState,
    stream: &mut PacketStream,
    address: Address,
    block: Block
) -> bool {
    #[cfg(feature = "tracing")]
    tracing::debug!(
        local_id = base64::encode(stream.local_id()),
        peer_id = base64::encode(stream.peer_id()),
        ?address,
        block_hash = block.hash().to_base64(),
        "handle Block packet"
    );

    // Verify the block and obtain its hash.
    let (is_valid, block_address) = match block.verify() {
        Ok(result) => result,

        Err(err) => {
            #[cfg(feature = "tracing")]
            tracing::warn!(
                ?err,
                local_id = base64::encode(stream.local_id()),
                peer_id = base64::encode(stream.peer_id()),
                ?address,
                block_hash = block.hash().to_base64(),
                "failed to verify received block"
            );

            return true;
        }
    };

    // Skip the block if it's invalid or has different signer.
    if !is_valid || block_address != address {
        #[cfg(feature = "tracing")]
        tracing::warn!(
            local_id = base64::encode(stream.local_id()),
            peer_id = base64::encode(stream.peer_id()),
            ?address,
            block_hash = block.hash().to_base64(),
            "received invalid block"
        );

        return true;
    }

    #[cfg(feature = "tracing")]
    tracing::info!(
        local_id = base64::encode(stream.local_id()),
        peer_id = base64::encode(stream.peer_id()),
        ?address,
        block_hash = block.hash().to_base64(),
        "received valid block"
    );

    // Try to write this block.
    let should_broadcast = {
        false

        // let local_id = base64::encode(stream.local_id());
        // let peer_id = base64::encode(stream.peer_id());

        // let block = block.clone();

        // state.handler.map_storage(&address, move |storage| {
        //     match storage.write_block(&block) {
        //         Ok(StorageWriteResult::Success) => {
        //             #[cfg(feature = "tracing")]
        //             tracing::info!(
        //                 ?local_id,
        //                 ?peer_id,
        //                 ?address,
        //                 block_hash = block.hash().to_base64(),
        //                 "indexed block in tracker"
        //             );

        //             return true;
        //         }

        //         Ok(StorageWriteResult::BlockAlreadyStored) => {
        //             #[cfg(feature = "tracing")]
        //             tracing::info!(
        //                 ?local_id,
        //                 ?peer_id,
        //                 root_block = root_block.to_base64(),
        //                 block_hash = block.hash().to_base64(),
        //                 verifying_key = verifying_key.to_base64(),
        //                 "block was already stored"
        //             );
        //         }

        //         Ok(result) => {
        //             #[cfg(feature = "tracing")]
        //             tracing::warn!(
        //                 ?local_id,
        //                 ?peer_id,
        //                 root_block = root_block.to_base64(),
        //                 block_hash = block.hash().to_base64(),
        //                 verifying_key = verifying_key.to_base64(),
        //                 ?result,
        //                 "block was not indexed in tracker"
        //             );
        //         }

        //         Err(err) => {
        //             #[cfg(feature = "tracing")]
        //             tracing::warn!(
        //                 ?err,
        //                 ?local_id,
        //                 ?peer_id,
        //                 root_block = root_block.to_base64(),
        //                 block_hash = block.hash().to_base64(),
        //                 verifying_key = verifying_key.to_base64(),
        //                 "failed to write block to the tracker"
        //             );
        //         }
        //     }

        //     false
        // })
    };

    // If we've written the block to the storage then broadcast it further.
    if should_broadcast {
        state.broadcast(Packet::Block {
            address,
            block
        });
    }

    true
}
