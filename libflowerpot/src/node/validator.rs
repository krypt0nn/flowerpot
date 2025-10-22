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

use std::collections::HashSet;

use crate::crypto::sign::{Signature, SigningKey};
use crate::block::{Block, BlockContent};
use crate::storage::Storage;

use super::NodeHandler;

pub fn run<S: Storage>(
    handler: NodeHandler<S>,
    signing_keys: Vec<SigningKey>
) {
    #[cfg(feature = "tracing")]
    tracing::info!("starting the validator thread");

    let mut blocks_blacklist = HashSet::new();

    // Warmup the validator.
    std::thread::sleep(handler.options.validator_warmup_time);

    loop {
        // Get current last block hash.
        let current_block = handler.history()
            .last()
            .copied()
            .unwrap_or_default();

        #[cfg(feature = "tracing")]
        tracing::debug!(
            current_block = current_block.to_base64(),
            "new validation round"
        );

        // Keep validator keys which are actual validators of the blockchain and
        // not just randomly generated keys.
        let blockchain_validators = handler.validators();

        let validators = signing_keys.iter()
            .map(|signing_key| (signing_key, signing_key.verifying_key()))
            .filter(|(_, verifying_key)| {
                blockchain_validators.contains(verifying_key)
            })
            .collect::<Box<[_]>>();

        drop(blockchain_validators);

        // Take up to max allowed pending transactions.
        let transactions = handler.pending_transactions()
            .iter()
            .take(handler.options.validator_max_transactions_num)
            .map(|(hash, transaction)| (*hash, transaction.clone()))
            .collect::<Box<[_]>>();

        // If there's enough transactions to form a block - then make one and
        // send it to the network.
        if transactions.len()
            > handler.options.validator_min_transactions_num.max(1)
        {
            #[cfg(feature = "tracing")]
            tracing::debug!(
                transactions = ?transactions.iter()
                    .map(|(hash, _)| hash.to_base64())
                    .collect::<Vec<_>>(),
                "create new block"
            );

            // Iterate over all the available validator keys.
            for (signing_key, verifying_key) in &validators {
                // Create new block from selected transactions and sign it with
                // the current validator key.
                let transactions = transactions.iter()
                    .cloned()
                    .map(|(_, transaction)| transaction);

                let block = Block::new(
                    signing_key,
                    current_block,
                    BlockContent::transactions(transactions)
                );

                let mut block = match block {
                    Ok(block) => block,

                    Err(err) => {
                        #[cfg(feature = "tracing")]
                        tracing::error!(
                            ?err,
                            verifying_key = verifying_key.to_base64(),
                            "failed to create new block"
                        );

                        continue;
                    }
                };

                // If more than one validator is available then also add their
                // approvals to the created block.
                for (_, validator) in &validators {
                    if validator != verifying_key
                        && let Err(err) = block.approve_with(signing_key)
                    {
                        #[cfg(feature = "tracing")]
                        tracing::error!(
                            ?err,
                            author = verifying_key.to_base64(),
                            validator = validator.to_base64(),
                            "failed to add approval to the created block"
                        );
                    }
                }

                #[cfg(feature = "tracing")]
                tracing::debug!(
                    curr_block_hash = ?block.current_hash().to_base64(),
                    prev_block_hash = ?block.previous_hash().to_base64(),
                    author = verifying_key.to_base64(),
                    "share created block"
                );

                // Send this block to the network.
                handler.send_block(block);
            }
        }

        #[cfg(feature = "tracing")]
        tracing::debug!(
            time = handler.options.validator_blocks_await_time.as_secs(),
            "wait for other blocks"
        );

        // Wait for new blocks to appear.
        std::thread::sleep(handler.options.validator_blocks_await_time);

        // Select the best block from the available ones.
        let mut best_block = None;

        let pending_blocks = handler.pending_blocks();

        for (hash, block) in pending_blocks.iter() {
            // Skip blacklisted blocks.
            if blocks_blacklist.contains(hash) {
                continue;
            }

            let author = match block.sign().verify(hash) {
                Ok((true, author)) => author,

                Ok((false, _)) => {
                    #[cfg(feature = "tracing")]
                    tracing::warn!(
                        block_hash = hash.to_base64(),
                        "invalid block is in the pending blocks list"
                    );

                    continue;
                }

                Err(err) => {
                    #[cfg(feature = "tracing")]
                    tracing::error!(
                        ?err,
                        block_hash = hash.to_base64(),
                        sign = block.sign().to_base64(),
                        "failed to derive block author from its signature"
                    );

                    continue;
                }
            };

            // Skip self-signed blocks.
            if validators.iter().any(|(_, verifying_key)| verifying_key == &author) {
                continue;
            }

            // Calculate distance to this block from the previous one.
            let distance = crate::block_validator_distance(
                current_block,
                &author
            );

            // Compare it against the best stored variant.
            match &mut best_block {
                Some((
                    best_block_hash,
                    best_block_author,
                    best_block_dist
                )) => {
                    // Update best block reference if we found closer block or
                    // a block from the same author but with lower hash value.
                    if (best_block_author == &author && *best_block_hash > *hash)
                        || *best_block_dist > distance
                    {
                        *best_block_hash   = *hash;
                        *best_block_author = author;
                        *best_block_dist   = distance;
                    }
                }

                None => best_block = Some((*hash, author, distance))
            }
        }

        // If we've found the new best block.
        if let Some((hash, author, distance)) = &best_block {
            #[cfg(feature = "tracing")]
            tracing::debug!(
                block_hash = hash.to_base64(),
                author = author.to_base64(),
                distance = distance.to_base64(),
                "approving the best found block"
            );

            // Iterate over all the available validators.
            for (signing_key, verifying_key) in &validators {
                // Create and share their approvals of this block.
                match Signature::create(signing_key, hash) {
                    Ok(approval) => {
                        #[cfg(feature = "tracing")]
                        tracing::debug!(
                            block_hash = hash.to_base64(),
                            author = author.to_base64(),
                            distance = distance.to_base64(),
                            approval = approval.to_base64(),
                            "sending approval"
                        );

                        handler.send_block_approval(**hash, approval);
                    }

                    Err(err) => {
                        #[cfg(feature = "tracing")]
                        tracing::error!(
                            ?err,
                            block_hash = hash.to_base64(),
                            validator = verifying_key.to_base64(),
                            "failed to create block approval"
                        );
                    }
                }
            }
        }

        #[cfg(feature = "tracing")]
        tracing::debug!(
            time = handler.options.validator_block_approvals_await_time.as_secs(),
            "wait for other approvals"
        );

        // Wait for other validators to send their approvals.
        std::thread::sleep(handler.options.validator_block_approvals_await_time);

        // Get updated current last block hash.
        let new_current_block = handler.history()
            .last()
            .copied()
            .unwrap_or_default();

        // If none of blocks were approved and added to the blockchain then
        // we blacklist the selected block and start a new approving round.
        if current_block == new_current_block
            && let Some((hash, _, _)) = best_block
        {
            #[cfg(feature = "tracing")]
            tracing::debug!("no block approved, start new round");

            blocks_blacklist.insert(hash);
        }
    }
}
