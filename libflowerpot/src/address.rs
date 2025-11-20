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

use crate::crypto::sign::VerifyingKey;
use crate::crypto::base64;

/// A struct representing a blockchain address.
///
/// Each blockchain can be uniquely identified using its validator's verifying
/// key and a randomly chosen "chain identifier".
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Address(VerifyingKey, u32);

impl Address {
    pub const SIZE: usize = VerifyingKey::SIZE + 4;

    /// Make new blockchain address.
    #[inline]
    pub fn new(verifying_key: impl Into<VerifyingKey>, chain_id: u32) -> Self {
        Self(verifying_key.into(), chain_id)
    }

    /// Get verifying key of a blockchain validator this address points to.
    #[inline]
    pub const fn verifying_key(&self) -> &VerifyingKey {
        &self.0
    }

    /// Get chain identifier of a blockchain this address points to.
    #[inline]
    pub const fn chain_id(&self) -> u32 {
        self.1
    }

    /// Encode current blockchain address into a binary representation.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0; Self::SIZE];

        buf[..VerifyingKey::SIZE].copy_from_slice(&self.0.to_bytes());
        buf[VerifyingKey::SIZE..].copy_from_slice(&self.1.to_le_bytes());

        buf
    }

    /// Try to decode a blockchain address from a binary representation.
    pub fn from_bytes(address: &[u8; Self::SIZE]) -> Option<Self> {
        let mut verifying_key = [0; VerifyingKey::SIZE];
        let mut seed = [0; 4];

        verifying_key.copy_from_slice(&address[..VerifyingKey::SIZE]);
        seed.copy_from_slice(&address[VerifyingKey::SIZE..]);

        Some(Self(
            VerifyingKey::from_bytes(&verifying_key)?,
            u32::from_le_bytes(seed)
        ))
    }

    /// Encode current blockchain address into a base64 string.
    #[inline]
    pub fn to_base64(&self) -> String {
        base64::encode(self.to_bytes())
    }

    /// Try to decode a blockchain address from a base64 string.
    pub fn from_base64(address: impl AsRef<[u8]>) -> Option<Self> {
        let address = base64::decode(address).ok()?;

        if address.len() != Self::SIZE {
            return None;
        }

        let mut buf = [0; Self::SIZE];

        buf.copy_from_slice(&address);

        Self::from_bytes(&buf)
    }
}

impl AsRef<Address> for Address {
    #[inline(always)]
    fn as_ref(&self) -> &Address {
        self
    }
}

impl std::fmt::Display for Address {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_base64())
    }
}
