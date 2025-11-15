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

use crate::crypto::hash::Hash;
use crate::crypto::sign::SigningKey;
use crate::block::Block;

use super::NodeHandler;

/// Run new blocks issuing usign provided node handler and signing key.
pub fn run(
    handler: NodeHandler,
    root_block: Hash,
    signing_key: SigningKey
) {
    #[cfg(feature = "tracing")]
    tracing::info!(
        root_block = root_block.to_base64(),
        verifying_key = signing_key.verifying_key().to_base64(),
        "starting blockchain validator thread"
    );

    // Warmup the validator.
    std::thread::sleep(handler.options.validator_warmup_time);

    loop {
        // Wait some time before running the code.
        std::thread::sleep(handler.options.validator_wait_time);

        // Get tail block hash.
        let tail_block = handler.map_tracker(
            root_block,
            |_, tracker| tracker.get_tail_block()
        ).transpose().map(|result| result.flatten());

        let tail_block = match tail_block {
            Ok(Some(tail_block)) => tail_block,

            Ok(None) => {
                #[cfg(feature = "tracing")]
                tracing::error!("tracker doesn't contain tail block hash");

                break;
            }

            Err(err) => {
                #[cfg(feature = "tracing")]
                tracing::error!(
                    ?err,
                    "failed to get tail block from the tracker"
                );

                break;
            }
        };

        // Try to take up to max allowed pending messages.
        let min_num = handler.options.validator_min_messages_num;
        let max_num = handler.options.validator_max_messages_num;

        let messages = handler.map_pending_messages_mut(
            root_block,
            |pending_messages| {
                if pending_messages.len() > min_num {
                    Some(pending_messages.drain()
                        .take(max_num)
                        .collect::<Box<[_]>>())
                } else {
                    None
                }
            }
        ).flatten();

        // If enough messages found then proceed, otherwise run the loop again.
        let Some(messages) = messages else {
            continue;
        };

        #[cfg(feature = "tracing")]
        tracing::debug!(
            root_block = root_block.to_base64(),
            tail_block = tail_block.to_base64(),
            verifying_key = signing_key.verifying_key().to_base64(),
            messages = ?messages.iter()
                .map(|(hash, _)| hash.to_base64())
                .collect::<Vec<_>>(),
            "create new block"
        );

        // Try to create new block.
        let block = Block::create(
            &signing_key,
            tail_block,
            messages.into_iter()
                .map(|(_, message)| message)
                .collect::<Box<[_]>>()
        );

        let block = match block {
            Ok(block) => block,

            Err(err) => {
                #[cfg(feature = "tracing")]
                tracing::error!(
                    ?err,
                    root_block = root_block.to_base64(),
                    tail_block = tail_block.to_base64(),
                    verifying_key = signing_key.verifying_key().to_base64(),
                    "failed to create new block"
                );

                break;
            }
        };

        // Send this block to the network.
        #[cfg(feature = "tracing")]
        tracing::debug!(
            root_block = root_block.to_base64(),
            tail_block = tail_block.to_base64(),
            verifying_key = signing_key.verifying_key().to_base64(),
            block_hash = block.hash().to_base64(),
            "share created block"
        );

        handler.send_block(root_block, block.clone());

        // Write this block to the tracker.
        let result = handler.map_tracker(
            root_block,
            |_, tracker| tracker.try_write_block(&block)
        );

        match result {
            Some(Ok(result)) => {
                #[cfg(feature = "tracing")]
                tracing::info!(
                    ?result,
                    root_block = root_block.to_base64(),
                    tail_block = tail_block.to_base64(),
                    verifying_key = signing_key.verifying_key().to_base64(),
                    block_hash = block.hash().to_base64(),
                    "try to write newly created block to the tracker"
                );
            }

            Some(Err(err)) => {
                #[cfg(feature = "tracing")]
                tracing::warn!(
                    ?err,
                    root_block = root_block.to_base64(),
                    tail_block = tail_block.to_base64(),
                    verifying_key = signing_key.verifying_key().to_base64(),
                    block_hash = block.hash().to_base64(),
                    "failed to write newly created block to the tracker"
                );
            }

            None => ()
        }
    }
}
