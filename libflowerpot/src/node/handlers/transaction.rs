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
use crate::transaction::Transaction;
use crate::storage::Storage;
use crate::protocol::packets::Packet;

use super::NodeState;

/// Handle `Transaction` packet.
///
/// Return `false` is critical error occured and node connection must be
/// terminated.
pub fn handle<S: Storage>(
    state: &mut NodeState<S>,
    transaction: Transaction
) -> bool {
    #[cfg(feature = "tracing")]
    tracing::debug!(
        local_id = base64::encode(state.stream.local_id()),
        peer_id = base64::encode(state.stream.peer_id()),
        root_block = state.handler.root_block.to_base64(),
        "handle Transaction packet"
    );

    // TODO: check if this transaction is already
    // stored in some block!!!!!!!!!

    // Reject large transactions.
    if transaction.data().len() > state.handler.options.max_transaction_size {
        #[cfg(feature = "tracing")]
        tracing::warn!(
            local_id = base64::encode(state.stream.local_id()),
            peer_id = base64::encode(state.stream.peer_id()),
            "received too large transaction"
        );

        return true;
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

            return true;
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

        return true;
    }

    // Reject already indexed transactions.
    if state.handler.indexed_transactions.read().contains(&hash)
        || state.handler.pending_transactions.read().contains_key(&hash)
    {
        #[cfg(feature = "tracing")]
        tracing::trace!(
            local_id = base64::encode(state.stream.local_id()),
            peer_id = base64::encode(state.stream.peer_id()),
            hash = hash.to_base64(),
            verifying_key = verifying_key.to_base64(),
            "received already indexed transaction"
        );

        return true;
    }

    // Check this transaction using the provided filter.
    if let Some(filter) = &state.handler.options.transactions_filter
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

        return true;
    }

    #[cfg(feature = "tracing")]
    tracing::info!(
        local_id = base64::encode(state.stream.local_id()),
        peer_id = base64::encode(state.stream.peer_id()),
        hash = hash.to_base64(),
        verifying_key = verifying_key.to_base64(),
        "accepted new pending transaction"
    );

    // Broadcast this transaction to other connected nodes.
    state.broadcast(Packet::Transaction {
        root_block: state.handler.root_block,
        transaction: transaction.clone()
    });

    // Insert it to the pending transactions pool.
    state.handler.pending_transactions.write()
        .insert(hash, transaction);

    true
}
