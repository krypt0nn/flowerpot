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
use crate::storage::Storage;
use crate::protocol::packets::Packet;

use super::NodeState;

/// Handle `AskTransaction` packet.
///
/// Return `false` if critical error occured and node connection must be
/// terminated.
pub fn handle<S: Storage>(
    state: &mut NodeState<S>,
    transaction: Hash
) -> bool {
    #[cfg(feature = "tracing")]
    tracing::debug!(
        local_id = base64::encode(state.stream.local_id()),
        peer_id = base64::encode(state.stream.peer_id()),
        root_block = state.handler.root_block.to_base64(),
        transaction = transaction.to_base64(),
        "handle AskTransaction packet"
    );

    // If it is a pending transaction.
    let transaction_hash = transaction;

    let transaction = state.handler.pending_transactions.read()
        .get(&transaction_hash)
        .cloned();

    #[allow(clippy::collapsible_if)]
    if let Some(transaction) = transaction {
        // Then try to send it back.
        if let Err(err) = state.stream.send(Packet::Transaction {
            root_block: state.handler.root_block,
            transaction: transaction.clone()
        }) {
            #[cfg(feature = "tracing")]
            tracing::error!(
                ?err,
                local_id = base64::encode(state.stream.local_id()),
                peer_id = base64::encode(state.stream.peer_id()),
                ?transaction_hash,
                "failed to send Transaction packet"
            );

            return false;
        }
    }

    true
}
