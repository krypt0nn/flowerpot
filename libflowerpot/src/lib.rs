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

pub mod varint;
pub mod crypto;
pub mod transaction;
pub mod block;
pub mod storage;
pub mod network;
pub mod protocol;
pub mod viewer;
pub mod node;

use crypto::hash::Hash;
use crypto::sign::VerifyingKey;

/// Calculate required amount of block approvals for provided amount of
/// blockchain validators at the current moment.
///
/// The rule is `(n - 1) * 2 / 3` for `n > 0`, otherwise it's `0`.
///
/// - For no validators there's no need in approvals.
/// - For one validator - it's the one who signed the block, so no need in
///   approvals.
/// - For two validators - one of them made the block, the other one's opinion
///   is not important enough.
/// - For three validators - one of them made the block, and at least one
///   approval is required.
/// - and so on...
pub fn calc_required_approvals(validators: usize) -> usize {
    if validators == 0 {
        0
    } else {
        (validators - 1) * 2 / 3
    }
}

/// Calculate distance between a block and a validator's public key.
///
/// This distance is used to determine approved blocks priority.
pub fn block_validator_distance(
    block: &Hash,
    validator: &VerifyingKey
) -> [u8; 32] {
    let mut dist = *blake3::hash(&validator.to_bytes()).as_bytes();

    (0..32).for_each(|i| {
        dist[i] ^= block.0[i];
    });

    dist
}

/// Sort provided validators list in descending priority order using the hash
/// of the previous block.
///
/// The algorithm prioritizes validators which public key's hashes are closer
/// to the previous block in xor distance. If we assume that blocks' hashes
/// are distributed uniformally, then on average all validators should be
/// prioritized equal amount of times.
pub fn rank_validators(
    prev_block_hash: &Hash,
    validators: &mut [VerifyingKey]
) {
    validators.sort_by(|a, b| {
        let a = block_validator_distance(prev_block_hash, a);
        let b = block_validator_distance(prev_block_hash, b);

        a.cmp(&b)
    });
}
