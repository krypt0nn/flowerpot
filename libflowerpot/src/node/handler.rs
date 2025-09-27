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

use std::collections::{HashMap, HashSet};
use std::sync::mpsc::{Receiver, TryRecvError};
use std::sync::Arc;

use spin::RwLock;

use crate::crypto::base64;
use crate::crypto::hash::Hash;
use crate::crypto::sign::VerifyingKey;
use crate::transaction::Transaction;
use crate::block::{Block, BlockContent, BlockStatus};
use crate::storage::Storage;
use crate::protocol::packets::Packet;
use crate::protocol::network::PacketStream;

use super::NodeOptions;

pub struct NodeState<S: Storage> {
    pub stream: PacketStream,
    pub options: NodeOptions,
    pub receiver: Receiver<Packet>,

    pub root_block: Hash,
    pub storage: Option<S>,

    pub history: Arc<RwLock<Vec<Hash>>>,
    pub current_distance: Arc<RwLock<[u8; 32]>>,
    pub validators: Arc<RwLock<Vec<VerifyingKey>>>,

    pub indexed_transactions: Arc<RwLock<HashSet<Hash>>>,
    pub pending_transactions: Arc<RwLock<HashMap<Hash, Transaction>>>,
    pub pending_blocks: Arc<RwLock<HashMap<Hash, Block>>>
}

/// Try to write provided block to the blockchain. This function
/// does not verify the block and only performs the writing itself.
///
/// Before writing the block it will be compared with the current
/// one to attempt unfixed block replacement.
fn try_write_block<S: Storage>(
    block: Block,
    hash: Hash,
    verifying_key: &VerifyingKey,
    state: &NodeState<S>
) {
    let mut history = state.history.write();
    let mut current_distance = state.current_distance.write();
    let mut validators = state.validators.write();

    let mut indexed_transactions = state.indexed_transactions.write();
    let mut pending_transactions = state.pending_transactions.write();
    let mut pending_blocks = state.pending_blocks.write();

    let n = history.len();

    // Distance between the previous block and the new block's
    // author.
    let new_distance = crate::block_validator_distance(
        &history[n - 2],
        verifying_key
    );

    // If this block is a *replacement* for the last block of the
    // blockchain - then we must compare its xor distance to decide
    // what to do.
    if n > 1 && &history[n - 2] == block.previous() {
        // Reject new block if the current one is closer to the
        // previous one.
        if  *current_distance <= new_distance
            || (*current_distance == new_distance && history[n - 2] <= hash)
        {
            #[cfg(feature = "tracing")]
            tracing::warn!(
                hash = hash.to_base64(),
                "attempted to modify the blockchain history with more distant block"
            );

            return;
        }
    }

    // If this block is a continuation of the blockchain then we
    // simply push it to the end of the history, update the storage
    // and validators list, remove related pending transactions.
    //
    // Otherwise we are not allowed to modify the blockchain history
    // and thus just abort this function.
    else if &history[n - 1] != block.previous() {
        #[cfg(feature = "tracing")]
        tracing::warn!(
            hash = hash.to_base64(),
            "attempted to modify the blockchain history or write out of the known history (out of sync node?)"
        );

        return;
    }

    // Try to write this block to the blockchain storage.
    if let Some(storage) = &state.storage {
        match storage.write_block(&block) {
            Ok(true) => (),

            Ok(false) => {
                #[cfg(feature = "tracing")]
                tracing::warn!(
                    hash = hash.to_base64(),
                    "attempted to write new block to the blockchain storage but history was not modified"
                );

                return;
            }

            Err(err) => {
                #[cfg(feature = "tracing")]
                tracing::error!(
                    ?err,
                    hash = hash.to_base64(),
                    "failed to write new block to the blockchain storage"
                );

                return;
            }
        }
    }

    // Update in-RAM blocks history.
    history.push(hash);

    // Update validators list.
    if let BlockContent::Validators(new_validators) = block.content() {
        *validators = new_validators.to_vec();
    }

    // Update current block's distance.
    *current_distance = new_distance;

    // Remove this block from the pending blocks pool.
    pending_blocks.remove(&hash);

    // Remove related pending transactions.
    if let BlockContent::Transactions(transactions) = block.content() {
        for transaction in transactions {
            let hash = transaction.hash();

            pending_transactions.remove(&hash);
            indexed_transactions.insert(hash);
        }
    }
}

/// Handle connection.
pub fn handle<S: Storage>(mut state: NodeState<S>) {
    // Ask remote node to share pending transactions if we support
    // their storing.
    if state.options.accept_pending_transactions &&
        let Err(err) = state.stream.send(Packet::AskPendingTransactions {
            root_block: state.root_block
        })
    {
        #[cfg(feature = "tracing")]
        tracing::error!(
            ?err,
            local_id = base64::encode(state.stream.local_id()),
            peer_id = base64::encode(state.stream.peer_id()),
            "failed to send packet to the packets stream"
        );

        return;
    }

    // Ask remote node to share pending blocks if we support their
    // storing.
    if state.options.accept_pending_blocks &&
        let Err(err) = state.stream.send(Packet::AskPendingBlocks {
            root_block: state.root_block
        })
    {
        #[cfg(feature = "tracing")]
        tracing::error!(
            ?err,
            local_id = base64::encode(state.stream.local_id()),
            peer_id = base64::encode(state.stream.peer_id()),
            "failed to send packet to the packets stream"
        );

        return;
    }

    // Process incoming packets in a loop.
    loop {
        // Send packets to the remote node.
        loop {
            match state.receiver.try_recv() {
                Ok(packet) => {
                    #[cfg(feature = "tracing")]
                    tracing::debug!(
                        local_id = base64::encode(state.stream.local_id()),
                        peer_id = base64::encode(state.stream.peer_id()),
                        "broadcasting packet"
                    );

                    if let Err(err) = state.stream.send(packet) {
                        #[cfg(feature = "tracing")]
                        tracing::error!(
                            ?err,
                            local_id = base64::encode(state.stream.local_id()),
                            peer_id = base64::encode(state.stream.peer_id()),
                            "failed to send packet to the packets stream"
                        );

                        return;
                    }
                }

                Err(TryRecvError::Disconnected) => {
                    #[cfg(feature = "tracing")]
                    tracing::info!(
                        local_id = base64::encode(state.stream.local_id()),
                        peer_id = base64::encode(state.stream.peer_id()),
                        "local node went offline, terminating connection"
                    );

                    return;
                }

                Err(TryRecvError::Empty) => break
            }
        }

        // Read packet from the remote endpoint.
        // TODO: timeout support
        let packet = state.stream.recv();

        // Process received packet.
        match packet {
            Ok(packet) => {
                match packet {
                    // If we were asked to share the blockchain
                    // history.
                    Packet::AskHistory {
                        root_block: received_root_block,
                        offset,
                        max_length
                    } if received_root_block == state.root_block => {
                        #[cfg(feature = "tracing")]
                        tracing::debug!(
                            local_id = base64::encode(state.stream.local_id()),
                            peer_id = base64::encode(state.stream.peer_id()),
                            root_block = state.root_block.to_base64(),
                            ?offset,
                            ?max_length,
                            "handle AskHistory packet"
                        );

                        // Then read max allowed amount of blocks'
                        // hashes.
                        let history = state.history.read()
                            .iter()
                            .skip(offset as usize)
                            .take(state.options.max_history_length.min(max_length as usize))
                            .copied()
                            .collect();

                        // And try to send them back to the
                        // requester.
                        if let Err(err) = state.stream.send(Packet::History {
                            root_block: state.root_block,
                            offset,
                            history
                        }) {
                            #[cfg(feature = "tracing")]
                            tracing::error!(
                                ?err,
                                local_id = base64::encode(state.stream.local_id()),
                                peer_id = base64::encode(state.stream.peer_id()),
                                "failed to send packet to the packets stream"
                            );

                            break;
                        }
                    }

                    // If we were asked to send the pending
                    // transactions list.
                    Packet::AskPendingTransactions {
                        root_block: received_root_block
                    } if received_root_block == state.root_block => {
                        #[cfg(feature = "tracing")]
                        tracing::debug!(
                            local_id = base64::encode(state.stream.local_id()),
                            peer_id = base64::encode(state.stream.peer_id()),
                            root_block = state.root_block.to_base64(),
                            "handle AskPendingTransactions packet"
                        );

                        // Then collect their hashes.
                        let pending_transactions = state.pending_transactions.read()
                            .keys()
                            .copied()
                            .collect();

                        // And try to send it back to the requester.
                        if let Err(err) = state.stream.send(Packet::PendingTransactions {
                            root_block: state.root_block,
                            pending_transactions
                        }) {
                            #[cfg(feature = "tracing")]
                            tracing::error!(
                                ?err,
                                local_id = base64::encode(state.stream.local_id()),
                                peer_id = base64::encode(state.stream.peer_id()),
                                "failed to send packet to the packets stream"
                            );

                            break;
                        }
                    }

                    // If we were asked to send the pending blocks
                    // list.
                    Packet::AskPendingBlocks {
                        root_block: received_root_block
                    } if received_root_block == state.root_block => {
                        #[cfg(feature = "tracing")]
                        tracing::debug!(
                            local_id = base64::encode(state.stream.local_id()),
                            peer_id = base64::encode(state.stream.peer_id()),
                            root_block = state.root_block.to_base64(),
                            "handle AskPendingBlocks packet"
                        );

                        let pending_blocks = state.pending_blocks.read()
                        // Then collect their hashes and approvals.
                            .iter()
                            .map(|(hash, block)| {
                                let approvals = block.approvals()
                                    .to_vec()
                                    .into_boxed_slice();

                                (*hash, approvals)
                            })
                            .collect();

                        // And try to send it back to the requester.
                        if let Err(err) = state.stream.send(Packet::PendingBlocks {
                            root_block: state.root_block,
                            pending_blocks
                        }) {
                            #[cfg(feature = "tracing")]
                            tracing::error!(
                                ?err,
                                local_id = base64::encode(state.stream.local_id()),
                                peer_id = base64::encode(state.stream.peer_id()),
                                "failed to send packet to the packets stream"
                            );

                            break;
                        }
                    }

                    // If we were asked to send transaction.
                    Packet::AskTransaction {
                        root_block: received_root_block,
                        transaction
                    } if received_root_block == state.root_block => {
                        #[cfg(feature = "tracing")]
                        tracing::debug!(
                            local_id = base64::encode(state.stream.local_id()),
                            peer_id = base64::encode(state.stream.peer_id()),
                            root_block = state.root_block.to_base64(),
                            transaction = transaction.to_base64(),
                            "handle AskTransaction packet"
                        );

                        // If it is a pending transaction.
                        let transaction = state.pending_transactions.read()
                            .get(&transaction)
                            .cloned();

                        #[allow(clippy::collapsible_if)]
                        if let Some(transaction) = transaction {
                            // Then try to send it back.
                            if let Err(err) = state.stream.send(Packet::Transaction {
                                root_block: state.root_block,
                                transaction: transaction.clone()
                            }) {
                                #[cfg(feature = "tracing")]
                                tracing::error!(
                                    ?err,
                                    local_id = base64::encode(state.stream.local_id()),
                                    peer_id = base64::encode(state.stream.peer_id()),
                                    "failed to send packet to the packets stream"
                                );

                                break;
                            }
                        }
                    }

                    // If we received some transaction.
                    Packet::Transaction {
                        root_block: received_root_block,
                        transaction
                    } if received_root_block == state.root_block
                        && state.options.accept_pending_transactions
                    => {
                        #[cfg(feature = "tracing")]
                        tracing::debug!(
                            local_id = base64::encode(state.stream.local_id()),
                            peer_id = base64::encode(state.stream.peer_id()),
                            root_block = state.root_block.to_base64(),
                            "handle Transaction packet"
                        );

                        // TODO: check if this transaction is already
                        // stored in some block!!!!!!!!!

                        // Reject large transactions.
                        if transaction.data().len() > state.options.max_transaction_size {
                            #[cfg(feature = "tracing")]
                            tracing::warn!(
                                local_id = base64::encode(state.stream.local_id()),
                                peer_id = base64::encode(state.stream.peer_id()),
                                "received too large transaction"
                            );

                            continue;
                        }

                        // Verify received transaction.
                        let (is_valid, hash, verifying_key) = match transaction.verify() {
                            Ok(result) => result,
                            Err(err) => {
                                #[cfg(feature = "tracing")]
                                tracing::error!(
                                    ?err,
                                    local_id = base64::encode(state.stream.local_id()),
                                    peer_id = base64::encode(state.stream.peer_id()),
                                    "failed to verify received transaction"
                                );

                                continue;
                            }
                        };

                        // Skip transaction if it's invalid.
                        if !is_valid {
                            #[cfg(feature = "tracing")]
                            tracing::warn!(
                                local_id = base64::encode(state.stream.local_id()),
                                peer_id = base64::encode(state.stream.peer_id()),
                                hash = hash.to_base64(),
                                verifying_key = verifying_key.to_base64(),
                                "received invalid transaction"
                            );

                            continue;
                        }

                        // Reject already indexed transactions.
                        if state.indexed_transactions.read().contains(&hash)
                            || state.pending_transactions.read().contains_key(&hash)
                        {
                            #[cfg(feature = "tracing")]
                            tracing::trace!(
                                local_id = base64::encode(state.stream.local_id()),
                                peer_id = base64::encode(state.stream.peer_id()),
                                hash = hash.to_base64(),
                                verifying_key = verifying_key.to_base64(),
                                "received already indexed transaction"
                            );

                            continue;
                        }

                        // Check this transaction using the provided filter.
                        if let Some(filter) = &state.options.transactions_filter
                            && !filter(&hash, &verifying_key, &transaction)
                        {
                            #[cfg(feature = "tracing")]
                            tracing::debug!(
                                local_id = base64::encode(state.stream.local_id()),
                                peer_id = base64::encode(state.stream.peer_id()),
                                hash = hash.to_base64(),
                                verifying_key = verifying_key.to_base64(),
                                "received transaction which was filtered out"
                            );

                            continue;
                        }

                        state.pending_transactions.write()
                            .insert(hash, transaction);
                    }

                    // If we were asked to send a block of the
                    // blockchain.
                    Packet::AskBlock {
                        root_block: received_root_block,
                        target_block
                    } if received_root_block == state.root_block => {
                        #[cfg(feature = "tracing")]
                        tracing::debug!(
                            local_id = base64::encode(state.stream.local_id()),
                            peer_id = base64::encode(state.stream.peer_id()),
                            root_block = state.root_block.to_base64(),
                            target_block = target_block.to_base64(),
                            "handle AskBlock packet"
                        );

                        // If this block is pending.
                        if let Some(block) = state.pending_blocks.read().get(&target_block) {
                            // Then try to send it back.
                            if let Err(err) = state.stream.send(Packet::Block {
                                root_block: state.root_block,
                                block: block.clone()
                            }) {
                                #[cfg(feature = "tracing")]
                                tracing::error!(
                                    ?err,
                                    local_id = base64::encode(state.stream.local_id()),
                                    peer_id = base64::encode(state.stream.peer_id()),
                                    "failed to send packet to the packets stream"
                                );

                                break;
                            }
                        }

                        // Otherwise, if we have a storage available.
                        else if let Some(storage) = &state.storage {
                            // Then try to read block from that storage.
                            match storage.read_block(&target_block) {
                                // If we've found the block.
                                Ok(Some(block)) => {
                                    // Then try to send it back.
                                    if let Err(err) = state.stream.send(Packet::Block {
                                        root_block: state.root_block,
                                        block
                                    }) {
                                        #[cfg(feature = "tracing")]
                                        tracing::error!(
                                            ?err,
                                            local_id = base64::encode(state.stream.local_id()),
                                            peer_id = base64::encode(state.stream.peer_id()),
                                            "failed to send packet to the packets stream"
                                        );

                                        break;
                                    }
                                }

                                // If block doesn't exist - then do
                                // nothing.
                                Ok(None) => (),

                                // And if we failed - log it.
                                Err(err) => {
                                    #[cfg(feature = "tracing")]
                                    tracing::error!(
                                        ?err,
                                        local_id = base64::encode(state.stream.local_id()),
                                        peer_id = base64::encode(state.stream.peer_id()),
                                        "failed to read block from the storage"
                                    );

                                    break;
                                }
                            }
                        }
                    }

                    // If we received some block.
                    Packet::Block {
                        root_block: received_root_block,
                        mut block
                    } if received_root_block == state.root_block => {
                        #[cfg(feature = "tracing")]
                        tracing::debug!(
                            local_id = base64::encode(state.stream.local_id()),
                            peer_id = base64::encode(state.stream.peer_id()),
                            root_block = state.root_block.to_base64(),
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

                                continue;
                            }
                        };

                        // Skip the block if it's invalid.
                        if !is_valid || !state.validators.read().contains(&verifying_key) {
                            #[cfg(feature = "tracing")]
                            tracing::warn!(
                                local_id = base64::encode(state.stream.local_id()),
                                peer_id = base64::encode(state.stream.peer_id()),
                                hash = hash.to_base64(),
                                verifying_key = verifying_key.to_base64(),
                                "received invalid block"
                            );

                            continue;
                        }

                        // Check if we already have this block, and
                        // if we do - then merge approvals because
                        // already stored block can have more than
                        // in what we received.
                        if let Some(curr_block) = state.pending_blocks.read().get(&hash) {
                            for approval in curr_block.approvals() {
                                if !block.approvals.contains(approval) {
                                    block.approvals.push(approval.clone());
                                }
                            }
                        }

                        // Check this block using the provided filter.
                        if let Some(filter) = &state.options.blocks_filter
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

                            continue;
                        }

                        // Check the block's approval status.
                        let status = BlockStatus::validate(
                            hash,
                            verifying_key,
                            block.approvals(),
                            state.validators.read().iter()
                        );

                        match status {
                            // Block is valid and approved by enough validators.
                            Ok(BlockStatus::Approved {
                                hash,
                                verifying_key,
                                approvals,
                                ..
                            }) => {
                                // Update received block's approvals list
                                // to remove any invalid signatures.
                                block.approvals = approvals.into_iter()
                                    .map(|(approval, _)| approval)
                                    .collect();

                                // Try to write this block.
                                try_write_block(
                                    block,
                                    hash,
                                    &verifying_key,
                                    &state
                                );
                            }

                            // Block is valid but not approved by enough validators.
                            Ok(BlockStatus::NotApproved {
                                approvals,
                                ..
                            }) => {
                                // Try to read the last block of the blockchain.
                                if let Some(last_block) = state.history.read().last() {
                                    // Update received block's approvals list
                                    // to remove any invalid signatures.
                                    block.approvals = approvals.into_iter()
                                        .map(|(approval, _)| approval)
                                        .collect();

                                    // If this block is the potential new block
                                    // for the blockchain then, if options allow
                                    // it, we should store it in the pending
                                    // blocks pool.
                                    if last_block == block.previous()
                                        && state.options.accept_pending_blocks
                                    {
                                        state.pending_blocks.write()
                                            .insert(hash, block);

                                        // TODO: if we didn't have this block
                                        // stored before - then we should send
                                        // it to all the other connected nodes.
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
                    }

                    // If we received block approval.
                    Packet::ApproveBlock {
                        root_block: received_root_block,
                        target_block,
                        approval
                    } if received_root_block == state.root_block => {
                        #[cfg(feature = "tracing")]
                        tracing::debug!(
                            local_id = base64::encode(state.stream.local_id()),
                            peer_id = base64::encode(state.stream.peer_id()),
                            root_block = state.root_block.to_base64(),
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

                                continue;
                            }
                        };

                        // Skip approval if it's invalid.
                        if !is_valid || !state.validators.read().contains(&verifying_key) {
                            #[cfg(feature = "tracing")]
                            tracing::warn!(
                                local_id = base64::encode(state.stream.local_id()),
                                peer_id = base64::encode(state.stream.peer_id()),
                                target_block = target_block.to_base64(),
                                verifying_key = verifying_key.to_base64(),
                                "received invalid block approval"
                            );

                            continue;
                        }

                        // Add this approval to the block if we have it.
                        let mut lock = state.pending_blocks.write();
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

                            block.approvals.push(approval);

                            // Verify this block (mainly to obtain
                            // its public key).
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

                                    continue;
                                }
                            };

                            // Skip the block if it's invalid.
                            if !is_valid || !state.validators.read().contains(&verifying_key) {
                                #[cfg(feature = "tracing")]
                                tracing::error!(
                                    local_id = base64::encode(state.stream.local_id()),
                                    peer_id = base64::encode(state.stream.peer_id()),
                                    hash = hash.to_base64(),
                                    verifying_key = verifying_key.to_base64(),
                                    "approved a pending block which turned to be invalid (how did it get here?)"
                                );

                                continue;
                            }

                            // Validate the block.
                            let status = BlockStatus::validate(
                                hash,
                                verifying_key,
                                block.approvals(),
                                state.validators.read().as_slice()
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

                                    continue;
                                }

                                _ => ()
                            }
                        }

                        drop(lock);

                        // If we've approved that this block can now
                        // be written to the blockchain storage.
                        if let Some((hash, public_key)) = write_block {
                            let mut pending_blocks = state.pending_blocks.write();

                            // Try to write this block.
                            if let Some(block) = pending_blocks.remove(&hash) {
                                try_write_block(
                                    block,
                                    hash,
                                    &public_key,
                                    &state
                                );
                            }
                        }

                        // TODO: resend this approval (or the block itself)
                        // to other connected nodes!!!
                    }

                    _ => ()
                }
            }

            Err(err) => {
                #[cfg(feature = "tracing")]
                tracing::error!(
                    ?err,
                    local_id = base64::encode(state.stream.local_id()),
                    peer_id = base64::encode(state.stream.peer_id()),
                    "failed to read packet from the packets stream"
                );

                break;
            }
        }
    }
}
