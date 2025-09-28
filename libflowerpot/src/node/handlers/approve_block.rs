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
use crate::block::BlockStatus;
use crate::storage::Storage;
use crate::protocol::packets::Packet;

use super::{NodeState, try_write_block};

/// Handle `ApproveBlock` packet.
///
/// Return `false` is critical error occured and node connection must be
/// terminated.
pub fn handle<S: Storage>(
    state: &mut NodeState<S>,
    target_block: Hash,
    approval: Signature
) -> bool {
    #[cfg(feature = "tracing")]
    tracing::debug!(
        local_id = base64::encode(state.stream.local_id()),
        peer_id = base64::encode(state.stream.peer_id()),
        root_block = state.handler.root_block.to_base64(),
        target_block = target_block.to_base64(),
        approval = approval.to_base64(),
        "handle ApproveBlock packet"
    );

    // Verify approval.
    let (is_valid, verifying_key) = match approval.verify(target_block) {
        Ok(result) => result,
        Err(err) => {
            #[cfg(feature = "tracing")]
            tracing::error!(
                ?err,
                local_id = base64::encode(state.stream.local_id()),
                peer_id = base64::encode(state.stream.peer_id()),
                target_block = target_block.to_base64(),
                approval = approval.to_base64(),
                "failed to verify received block approval"
            );

            return true;
        }
    };

    // Skip approval if it's invalid.
    if !is_valid || !state.handler.validators.read().contains(&verifying_key) {
        #[cfg(feature = "tracing")]
        tracing::warn!(
            local_id = base64::encode(state.stream.local_id()),
            peer_id = base64::encode(state.stream.peer_id()),
            target_block = target_block.to_base64(),
            verifying_key = verifying_key.to_base64(),
            "received invalid block approval"
        );

        return true;
    }

    // Add this approval to the block if we have it.
    let mut lock = state.handler.pending_blocks.write();
    let mut broadcast_approval = false;
    let mut write_block = None;

    if let Some(block) = lock.get_mut(&target_block)
        && !block.approvals.contains(&approval)
    {
        #[cfg(feature = "tracing")]
        tracing::info!(
            local_id = base64::encode(state.stream.local_id()),
            peer_id = base64::encode(state.stream.peer_id()),
            target_block = target_block.to_base64(),
            verifying_key = verifying_key.to_base64(),
            "added new approval to the pending block"
        );

        match block.approve(approval.clone()) {
            Ok(true) => broadcast_approval = true,

            Ok(false) => {
                #[cfg(feature = "tracing")]
                tracing::warn!(
                    local_id = base64::encode(state.stream.local_id()),
                    peer_id = base64::encode(state.stream.peer_id()),
                    target_block = target_block.to_base64(),
                    verifying_key = verifying_key.to_base64(),
                    "received invalid block approval"
                );

                return true;
            }

            Err(err) => {
                #[cfg(feature = "tracing")]
                tracing::warn!(
                    ?err,
                    local_id = base64::encode(state.stream.local_id()),
                    peer_id = base64::encode(state.stream.peer_id()),
                    target_block = target_block.to_base64(),
                    verifying_key = verifying_key.to_base64(),
                    "failed to verify received block approval"
                );

                return true;
            }
        }

        // Verify this block (mainly to obtain its public key).
        let (is_valid, hash, verifying_key) = match block.verify() {
            Ok(result) => result,
            Err(err) => {
                #[cfg(feature = "tracing")]
                tracing::error!(
                    ?err,
                    local_id = base64::encode(state.stream.local_id()),
                    peer_id = base64::encode(state.stream.peer_id()),
                    "failed to verify block"
                );

                return true;
            }
        };

        // Skip the block if it's invalid.
        if !is_valid || !state.handler.validators.read().contains(&verifying_key) {
            #[cfg(feature = "tracing")]
            tracing::error!(
                local_id = base64::encode(state.stream.local_id()),
                peer_id = base64::encode(state.stream.peer_id()),
                hash = hash.to_base64(),
                verifying_key = verifying_key.to_base64(),
                "approved a pending block which turned to be invalid (how did it get here?)"
            );

            return true;
        }

        // Validate the block.
        let status = BlockStatus::validate(
            hash,
            verifying_key,
            block.approvals(),
            state.handler.validators.read().as_slice()
        );

        match status {
            Ok(BlockStatus::Approved {
                hash,
                verifying_key,
                approvals,
                ..
            }) => {
                // Update block's approvals list
                // to remove any invalid signatures.
                block.approvals = approvals.into_iter()
                    .map(|(approval, _)| approval)
                    .collect();

                // Order this block to be written.
                write_block = Some((hash, verifying_key));
            }

            Err(err) => {
                #[cfg(feature = "tracing")]
                tracing::warn!(
                    ?err,
                    local_id = base64::encode(state.stream.local_id()),
                    peer_id = base64::encode(state.stream.peer_id()),
                    hash = hash.to_base64(),
                    "failed to validate newly approved block"
                );

                return true;
            }

            _ => ()
        }
    }

    drop(lock);

    // Broadcast approval if it was newly received and valid.
    if broadcast_approval {
        state.broadcast(Packet::ApproveBlock {
            root_block: state.handler.root_block,
            target_block,
            approval
        });
    }

    // If we've approved that this block can now
    // be written to the blockchain storage.
    if let Some((hash, public_key)) = write_block {
        // Try to write this block.
        if let Some(block) = state.handler.pending_blocks.write().remove(&hash) {
            try_write_block(
                block,
                hash,
                &public_key,
                &state.handler
            );
        }
    }

    true
}
