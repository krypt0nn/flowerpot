// SPDX-License-Identifier: GPL-3.0-only
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

use crate::crypto::*;
use crate::transaction::Transaction;
use crate::block::Block;

/// Common rules used by shard and validator nodes to reject or accept
/// transactions and blocks.
#[derive(Debug, Clone)]
pub struct SecurityRules {
    /// Maximal allowed size of transaction's body in bytes.
    ///
    /// Transactions with larger body will be rejected.
    ///
    /// Default is `1048576` (1 MB).
    pub max_transaction_body_size: u64,

    /// Optional filter function which will be applied to the pending
    /// transactions before adding them to the pool. If `true` is returned
    /// by such function then transaction is accepted, otherwise it will be
    /// dropped.
    ///
    /// This function is useful for applications with custom transaction
    /// formats and rules to filter out malicious or invalid transactions.
    ///
    /// Default is `None`.
    pub transactions_filter: Option<fn(&Transaction, &Hash, &PublicKey) -> bool>,

    /// Optional filter function which will be applied to the pending blocks
    /// before adding them to the pool. If `true` is returned by such function
    /// then block is accepted, otherwise it will be dropped.
    ///
    /// This function is useful for applications with custom transaction
    /// formats and rules to filter out blocks with malicious or invalid
    /// transactions.
    ///
    /// Default is `None`.
    pub blocks_filter: Option<fn(&Block, &Hash, &PublicKey) -> bool>,
}

impl Default for SecurityRules {
    fn default() -> Self {
        Self {
            max_transaction_body_size: 1024 * 1024,
            transactions_filter: None,
            blocks_filter: None
        }
    }
}
