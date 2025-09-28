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
use crate::block::{Block, BlockStatus};
use crate::storage::Storage;
use crate::protocol::packets::Packet;

use super::{NodeState, try_write_block};

/// Handle `Block` packet.
///
/// Return `false` is critical error occured and node connection must be
/// terminated.
pub fn handle<S: Storage>(
    state: &mut NodeState<S>,
    mut block: Block
) -> bool {
    #[cfg(feature = "tracing")]
    tracing::debug!(
        local_id = base64::encode(state.stream.local_id()),
        peer_id = base64::encode(state.stream.peer_id()),
        root_block = state.handler.root_block.to_base64(),
        "handle Block packet"
    );

    // Verify the block and obtain its hash.
    let (is_valid, hash, verifying_key) = match block.verify() {
        Ok(result) => result,
        Err(err) => {
            #[cfg(feature = "tracing")]
            tracing::error!(
                ?err,
                local_id = base64::encode(state.stream.local_id()),
                peer_id = base64::encode(state.stream.peer_id()),
                "failed to verify received block"
            );

            return true;
        }
    };

    // Skip the block if it's invalid.
    if !is_valid || !state.handler.validators.read().contains(&verifying_key) {
        #[cfg(feature = "tracing")]
        tracing::warn!(
            local_id = base64::encode(state.stream.local_id()),
            peer_id = base64::encode(state.stream.peer_id()),
            hash = hash.to_base64(),
            verifying_key = verifying_key.to_base64(),
            "received invalid block"
        );

        return true;
    }

    // Check if we already have this block, and if we do - then merge approvals
    // because already stored block can have more than in what we received.
    if let Some(curr_block) = state.handler.pending_blocks.read().get(&hash) {
        for approval in curr_block.approvals() {
            if !block.approvals.contains(approval) {
                block.approvals.push(approval.clone());
            }
        }
    }

    // Check this block using the provided filter.
    if let Some(filter) = &state.handler.options.blocks_filter
        && !filter(&hash, &verifying_key, &block)
    {
        #[cfg(feature = "tracing")]
        tracing::debug!(
            local_id = base64::encode(state.stream.local_id()),
            peer_id = base64::encode(state.stream.peer_id()),
            hash = hash.to_base64(),
            verifying_key = verifying_key.to_base64(),
            "received block which was filtered out"
        );

        return true;
    }

    // Check the block's approval status.
    let status = BlockStatus::validate(
        hash,
        verifying_key,
        block.approvals(),
        state.handler.validators.read().iter()
    );

    match status {
        // Block is valid and approved by enough validators.
        Ok(BlockStatus::Approved {
            hash,
            verifying_key,
            approvals,
            ..
        }) => {
            #[cfg(feature = "tracing")]
            tracing::info!(
                local_id = base64::encode(state.stream.local_id()),
                peer_id = base64::encode(state.stream.peer_id()),
                hash = hash.to_base64(),
                verifying_key = verifying_key.to_base64(),
                "accepted new approved block"
            );

            // Update received block's approvals list to remove any invalid
            // signatures.
            block.approvals = approvals.into_iter()
                .map(|(approval, _)| approval)
                .collect();

            // Try to write this block.
            try_write_block(
                block,
                hash,
                &verifying_key,
                &state.handler
            );
        }

        // Block is valid but not approved by enough validators.
        Ok(BlockStatus::NotApproved {
            hash,
            verifying_key,
            approvals,
            ..
        }) => {
            // Try to read the last block of the blockchain.
            if let Some(last_block) = state.handler.history.read().last() {
                // Update received block's approvals list to remove any invalid
                // signatures.
                block.approvals = approvals.into_iter()
                    .map(|(approval, _)| approval)
                    .collect();

                // If this block is the potential new block for the blockchain
                // then, if options allow it, we should store it in the pending
                // blocks pool.
                if last_block == block.previous() {
                    #[cfg(feature = "tracing")]
                    tracing::info!(
                        local_id = base64::encode(state.stream.local_id()),
                        peer_id = base64::encode(state.stream.peer_id()),
                        hash = hash.to_base64(),
                        verifying_key = verifying_key.to_base64(),
                        "accepted new pending block"
                    );

                    // If we already have block with this hash - we can compare
                    // them, and if the new one is different - we should
                    // broadcast it to other network nodes.
                    if let Some(prev) = state.handler.pending_blocks.read().get(&hash)
                        && prev != &block
                    {
                        state.broadcast(Packet::Block {
                            root_block: state.handler.root_block,
                            block: block.clone()
                        });
                    }

                    state.handler.pending_blocks.write()
                        .insert(hash, block);
                }

                else {
                    #[cfg(feature = "tracing")]
                    tracing::warn!(
                        local_id = base64::encode(state.stream.local_id()),
                        peer_id = base64::encode(state.stream.peer_id()),
                        hash = hash.to_base64(),
                        verifying_key = verifying_key.to_base64(),
                        "new approved block was not accepted due to being out of history"
                    );
                }
            }
        }

        // Block is invalid.
        Ok(BlockStatus::Invalid) => {
            #[cfg(feature = "tracing")]
            tracing::warn!(
                local_id = base64::encode(state.stream.local_id()),
                peer_id = base64::encode(state.stream.peer_id()),
                hash = hash.to_base64(),
                "received invalid block"
            );
        }

        // Failed to check the block.
        Err(err) => {
            #[cfg(feature = "tracing")]
            tracing::error!(
                ?err,
                local_id = base64::encode(state.stream.local_id()),
                peer_id = base64::encode(state.stream.peer_id()),
                hash = hash.to_base64(),
                "failed to validate received block"
            );
        }
    }

    true
}
