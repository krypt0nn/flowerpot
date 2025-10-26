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

use super::NodeState;

/// Handle `Block` packet.
///
/// Return `false` if critical error occured and node connection must be
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
    let (is_valid, verifying_key) = match block.verify() {
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

    // Read current validators list from the tracker.
    let validators = match state.handler.tracker().get_validators() {
        Ok(validators) => validators,
        Err(err) => {
            #[cfg(feature = "tracing")]
            tracing::warn!(
                err = err.to_string(),
                local_id = base64::encode(state.stream.local_id()),
                peer_id = base64::encode(state.stream.peer_id()),
                hash = block.current_hash().to_base64(),
                verifying_key = verifying_key.to_base64(),
                "failed to read current validators list"
            );

            return true;
        }
    };

    // Skip the block if it's invalid.
    if !is_valid || !validators.contains(&verifying_key) {
        #[cfg(feature = "tracing")]
        tracing::warn!(
            local_id = base64::encode(state.stream.local_id()),
            peer_id = base64::encode(state.stream.peer_id()),
            hash = block.current_hash().to_base64(),
            verifying_key = verifying_key.to_base64(),
            "received invalid block"
        );

        return true;
    }

    // Check if we already have this block, and if we do - then merge approvals
    // because already stored block can have more than in what we received.
    if let Some(curr_block) = state.handler.pending_blocks().get(block.current_hash()) {
        for approval in curr_block.approvals() {
            if !block.approvals.contains(approval) {
                block.approvals.push(approval.clone());
            }
        }
    }

    // Check this block using the provided filter.
    if let Some(filter) = &state.handler.options.blocks_filter
        && !filter(block.current_hash(), &verifying_key, &block)
    {
        #[cfg(feature = "tracing")]
        tracing::debug!(
            local_id = base64::encode(state.stream.local_id()),
            peer_id = base64::encode(state.stream.peer_id()),
            hash = block.current_hash().to_base64(),
            verifying_key = verifying_key.to_base64(),
            "received block which was filtered out"
        );

        return true;
    }

    // Check the block's approval status.
    let status = BlockStatus::validate(
        block.current_hash(),
        verifying_key,
        block.approvals(),
        validators
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
            match state.handler.tracker().try_write_block(&block) {
                Ok(true) => {
                    #[cfg(feature = "tracing")]
                    tracing::info!(
                        local_id = base64::encode(state.stream.local_id()),
                        peer_id = base64::encode(state.stream.peer_id()),
                        hash = hash.to_base64(),
                        verifying_key = verifying_key.to_base64(),
                        "block was added to the history"
                    );
                }

                Ok(false) => {
                    #[cfg(feature = "tracing")]
                    tracing::info!(
                        local_id = base64::encode(state.stream.local_id()),
                        peer_id = base64::encode(state.stream.peer_id()),
                        hash = hash.to_base64(),
                        verifying_key = verifying_key.to_base64(),
                        "block was not added to the history"
                    );
                }

                Err(err) => {
                    #[cfg(feature = "tracing")]
                    tracing::warn!(
                        err = err.to_string(),
                        local_id = base64::encode(state.stream.local_id()),
                        peer_id = base64::encode(state.stream.peer_id()),
                        hash = hash.to_base64(),
                        verifying_key = verifying_key.to_base64(),
                        "failed to write block to the tracker"
                    );
                }
            }
        }

        // Block is valid but not approved by enough validators.
        Ok(BlockStatus::NotApproved {
            hash,
            verifying_key,
            approvals,
            ..
        }) => {
            let tail_block = match state.handler.tracker().get_tail_block() {
                Ok(tail_block) => tail_block,
                Err(err) => {
                    #[cfg(feature = "tracing")]
                    tracing::warn!(
                        local_id = base64::encode(state.stream.local_id()),
                        peer_id = base64::encode(state.stream.peer_id()),
                        hash = hash.to_base64(),
                        verifying_key = verifying_key.to_base64(),
                        err = err.to_string(),
                        "failed to get tail block from the tracker"
                    );

                    return true;
                }
            };

            // Update received block's approvals list to remove any invalid
            // signatures.
            block.approvals = approvals.into_iter()
                .map(|(approval, _)| approval)
                .collect();

            // If we don't have tail block (so we don't have root block either),
            // and received block is of root type - then store it.
            if tail_block.is_none() && block.is_root() {
                #[cfg(feature = "tracing")]
                tracing::info!(
                    local_id = base64::encode(state.stream.local_id()),
                    peer_id = base64::encode(state.stream.peer_id()),
                    hash = hash.to_base64(),
                    verifying_key = verifying_key.to_base64(),
                    "accepted new pending block of root type"
                );

                // Broadcast this block if we didn't have it before.
                if state.handler.pending_blocks().get(&hash) != Some(&block) {
                    state.broadcast(Packet::Block {
                        root_block: state.handler.root_block,
                        block: block.clone()
                    });
                }

                // Store this block in the pending queue.
                state.handler.pending_blocks_mut()
                    .insert(hash, block);
            }

            // Otherwise, if received block is continuation of the known
            // blockchain history.
            //
            // TODO: technically we should also accept 1 block deeper than the
            //       tail since tail block is not fixated yet.
            else if tail_block.as_ref() == Some(block.previous_hash()) {
                #[cfg(feature = "tracing")]
                tracing::info!(
                    local_id = base64::encode(state.stream.local_id()),
                    peer_id = base64::encode(state.stream.peer_id()),
                    hash = hash.to_base64(),
                    verifying_key = verifying_key.to_base64(),
                    "accepted new pending block as blockchain history continuation"
                );

                // Broadcast this block if we didn't have it before.
                if state.handler.pending_blocks().get(&hash) != Some(&block) {
                    state.broadcast(Packet::Block {
                        root_block: state.handler.root_block,
                        block: block.clone()
                    });
                }

                // Store this block in the pending queue.
                state.handler.pending_blocks_mut()
                    .insert(hash, block);
            }

            else {
                #[cfg(feature = "tracing")]
                tracing::warn!(
                    local_id = base64::encode(state.stream.local_id()),
                    peer_id = base64::encode(state.stream.peer_id()),
                    hash = hash.to_base64(),
                    verifying_key = verifying_key.to_base64(),
                    "rejected out of history block"
                );
            }
        }

        // Block is invalid.
        Ok(BlockStatus::Invalid) => {
            #[cfg(feature = "tracing")]
            tracing::warn!(
                local_id = base64::encode(state.stream.local_id()),
                peer_id = base64::encode(state.stream.peer_id()),
                hash = block.current_hash().to_base64(),
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
                hash = block.current_hash().to_base64(),
                "failed to validate received block"
            );
        }
    }

    true
}
