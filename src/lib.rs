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

pub mod crypto;
pub mod transaction;
pub mod block;
pub mod storage;

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "client")]
pub mod viewer;

#[cfg(feature = "client")]
pub mod pool;

#[cfg(any(feature = "shard", feature = "validator"))]
pub mod security;

#[cfg(feature = "shard")]
pub mod shard;

#[cfg(feature = "validator")]
pub mod validator;

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
