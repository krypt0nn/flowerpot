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

use super::base64;

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    /// Byte length of the hash.
    pub const SIZE: usize = 32;

    /// Salt of the hash.
    ///
    /// Value was randomly generated using random.org service.
    pub const SALT: [u8; 32] = [
        55, 104,  74,  99,  32, 143,  65, 212,
        93,  28,  37,  56, 144,  80, 123,  94,
         2,   0, 194, 206,  50,  77, 133, 115,
        40, 168, 154, 253, 246, 174, 123,  68
    ];

    #[inline]
    pub fn hasher() -> Hasher {
        Hasher::new()
    }

    /// Calculate hash of provided bytes slice.
    #[inline]
    pub fn calc(value: impl AsRef<[u8]>) -> Self {
        Self(*blake3::keyed_hash(&Self::SALT, value.as_ref()).as_bytes())
    }

    #[inline(always)]
    pub const fn as_bytes(&self) -> &[u8; Self::SIZE] {
        &self.0
    }

    /// Convert hash value into base64 string.
    #[inline]
    pub fn to_base64(&self) -> String {
        base64::encode(self.0)
    }

    /// Convert base64 string into the hash value.
    pub fn from_base64(hash: impl AsRef<[u8]>) -> Option<Self> {
        match base64::decode(hash) {
            Ok(hash) if hash.len() == 32 => {
                let mut result = Self::default();

                result.0.copy_from_slice(&hash);

                Some(result)
            }

            _ => None
        }
    }
}

impl AsRef<Hash> for Hash {
    #[inline(always)]
    fn as_ref(&self) -> &Hash {
        self
    }
}

impl From<[u8; 32]> for Hash {
    #[inline(always)]
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl From<Hash> for [u8; 32] {
    #[inline(always)]
    fn from(value: Hash) -> Self {
        value.0
    }
}

impl std::ops::Deref for Hash {
    type Target = [u8; 32];

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_base64())
    }
}

#[derive(Debug, Clone)]
pub struct Hasher(blake3::Hasher);

impl Default for Hasher {
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher {
    pub fn new() -> Self {
        Self(blake3::Hasher::new_keyed(&Hash::SALT))
    }

    pub fn update(&mut self, bytes: impl AsRef<[u8]>) -> &mut Self {
        self.0.update(bytes.as_ref());

        self
    }

    pub fn finalize(self) -> Hash {
        Hash(*self.0.finalize().as_bytes())
    }
}

#[test]
fn test() {
    let mut hasher = Hasher::new();

    hasher.update([1, 2, 3]);
    hasher.update([4, 5, 6]);

    assert_eq!(hasher.finalize(), Hash::calc([1, 2, 3, 4, 5, 6]));

    assert_eq!(Hash::calc(b"Hello, World!").to_base64(), "");
}
