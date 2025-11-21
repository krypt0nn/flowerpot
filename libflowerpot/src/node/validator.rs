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

use crate::crypto::sign::SigningKey;
use crate::address::Address;
use crate::block::Block;
use crate::storage::StorageWriteResult;

use super::NodeHandler;

/// Run new blocks issuing usign provided node handler and signing key.
pub fn run(
    handler: NodeHandler,
    address: Address,
    signing_key: SigningKey
) {
    if address.verifying_key() != &signing_key.verifying_key() {
        tracing::error!(
            ?address,
            address_key = address.verifying_key().to_base64(),
            validator_key = signing_key.verifying_key().to_base64(),
            "provided signing key cannot be used to issue new blocks to a blockchain with this address"
        );

        return;
    }

    #[cfg(feature = "tracing")]
    tracing::info!(
        ?address,
        "starting blockchain validator thread"
    );

    loop {
        // Wait some time before running the code.
        std::thread::sleep(handler.options.validator_wait_time);

        // Get tail block hash.
        let tail_block = handler.map_storage(
            &address,
            |storage| storage.tail_block()
        ).transpose().map(|result| result.flatten());

        let tail_block = match tail_block {
            Ok(Some(tail_block)) => tail_block,

            Ok(None) => {
                #[cfg(feature = "tracing")]
                tracing::error!("storage doesn't contain tail block hash");

                break;
            }

            Err(err) => {
                #[cfg(feature = "tracing")]
                tracing::error!(
                    ?err,
                    "failed to get tail block from the storage"
                );

                break;
            }
        };

        // Try to take up to max allowed pending messages.
        let min_num = handler.options.validator_min_messages_num;
        let max_num = handler.options.validator_max_messages_num;

        let messages = handler.map_pending_messages_mut(
            &address,
            |pending_messages| {
                if pending_messages.len() >= min_num {
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
            ?address,
            tail_block = tail_block.to_base64(),
            messages = ?messages.iter()
                .map(|(hash, _)| hash.to_base64())
                .collect::<Vec<_>>(),
            "create new block"
        );

        // Try to create new block.
        let mut block = Block::builder()
            .with_chain_id(address.chain_id())
            .with_prev_hash(tail_block);

        for (hash, message) in messages {
            // Try to read the message's author and check if the message is
            // valid since why not (although at that point it should not be
            // needed at all).
            let verifying_key = match message.verify() {
                Ok((true, verifying_key)) => verifying_key,

                Ok((false, _)) => {
                    #[cfg(feature = "tracing")]
                    tracing::warn!(
                        ?hash,
                        "attempted to create new block with invalid message"
                    );

                    continue;
                }

                Err(err) => {
                    #[cfg(feature = "tracing")]
                    tracing::error!(
                        ?err,
                        "failed to verify pending message"
                    );

                    return;
                }
            };

            // Use special function to decide where to add the message.
            if (handler.options.validator_inline_messages_filter)(&address, &message, &verifying_key) {
                block.add_inline_message(message);
            } else {
                block.add_ref_message(hash);
            }
        }

        let block = match block.sign(&signing_key) {
            Ok(block) => block,

            Err(err) => {
                #[cfg(feature = "tracing")]
                tracing::error!(
                    ?err,
                    ?address,
                    tail_block = tail_block.to_base64(),
                    "failed to create new block"
                );

                break;
            }
        };

        // Write this block to the storage.
        let result = handler.map_storage(
            &address,
            |storage| storage.write_block(&block)
        );

        match result {
            Some(Ok(result)) => {
                #[cfg(feature = "tracing")]
                tracing::info!(
                    ?result,
                    ?address,
                    tail_block = tail_block.to_base64(),
                    block_hash = block.hash().to_base64(),
                    "try to write newly created block to the storage"
                );

                // If the block was successfully written to the storage then
                // send this block to the network.
                if result == StorageWriteResult::Success {
                    #[cfg(feature = "tracing")]
                    tracing::debug!(
                        ?address,
                        tail_block = tail_block.to_base64(),
                        block_hash = block.hash().to_base64(),
                        "share created block"
                    );

                    handler.send_block(address.clone(), block.clone());
                }
            }

            Some(Err(err)) => {
                #[cfg(feature = "tracing")]
                tracing::warn!(
                    ?err,
                    ?address,
                    tail_block = tail_block.to_base64(),
                    block_hash = block.hash().to_base64(),
                    "failed to write newly created block to the tracker"
                );
            }

            None => ()
        }
    }
}
