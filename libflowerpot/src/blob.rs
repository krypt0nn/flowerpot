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

use crate::crypto::hash::Hash;
use crate::crypto::sign::{SigningKey, VerifyingKey, Signature, SignatureError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BlobDecodeError {
    #[error("encoded blob is too short: got {got} bytes, at least {expected} expected")]
    TooShort {
        got: usize,
        expected: usize
    },

    #[error("unsupported blob format: {0:0X}")]
    UnsupportedFormat(u8),

    #[error("invalid blob signature format")]
    InvalidSignature
}

/// Blob is the smallest, atomic value made by the library users. It contains:
///
/// - A list of binary tags attached to it which could be used to identify
///   different blobs by e.g. being related to different protocols;
/// - A binary data;
/// - A digital signature proving tags and data validity.
///
/// Blobs should be used to share messages, files, or any other form of data
/// with other library users.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blob {
    /// Virtually constructed hash of the blob. Calculated in runtime from tags
    /// and data. Used to identify blobs.
    pub(crate) hash: Hash,

    /// Binary content of the blob. Practically not limited in size, but the
    /// limit can be applied by the node implementation individually.
    pub(crate) data: Box<[u8]>,

    /// Digital signature proving the blob validity and containing its author.
    pub(crate) sign: Signature
}

impl Blob {
    /// Create new blob.
    pub fn create(
        signing_key: impl AsRef<SigningKey>,
        data: impl Into<Box<[u8]>>
    ) -> Result<Self, SignatureError> {
        let data: Box<[u8]> = data.into();

        let hash = Hash::calc(&data);

        let sign = Signature::create(
            signing_key,
            hash
        )?;

        Ok(Self {
            hash,
            data,
            sign
        })
    }

    /// Get current blob hash.
    ///
    /// This value is pre-calculated for performance reasons and is stored in
    /// the struct, so no computations are performed.
    #[inline]
    pub const fn hash(&self) -> &Hash {
        &self.hash
    }

    /// Get current blob data.
    #[inline]
    pub const fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get current blob signature.
    #[inline]
    pub const fn sign(&self) -> &Signature {
        &self.sign
    }

    /// Derive current blob's author and verify that the signature is valid.
    #[inline]
    pub fn verify(&self) -> Result<(bool, VerifyingKey), SignatureError> {
        self.sign.verify(&self.hash)
    }

    /// Encode current blob into a binary representation.
    pub fn to_bytes(&self) -> Box<[u8]> {
        let mut bytes = Vec::new();

        // Blob format version.
        bytes.push(0);

        // Blob signature (fixed size).
        bytes.extend(self.sign.to_bytes());

        // Blob data (rest of the blob so no length needed).
        bytes.extend(&self.data);

        bytes.into_boxed_slice()
    }

    /// Decode blob from a binary representation.
    pub fn from_bytes(
        bytes: impl AsRef<[u8]>
    ) -> Result<Self, BlobDecodeError> {
        let bytes = bytes.as_ref();
        let n = bytes.len();

        // Format byte + signature.
        if n < Signature::SIZE + 1 {
            return Err(BlobDecodeError::TooShort {
                got: n,
                expected: Signature::SIZE + 1
            });
        }

        // Check that the format byte is 0 (there's no different format now).
        if bytes[0] != 0 {
            return Err(BlobDecodeError::UnsupportedFormat(bytes[0]));
        }

        // Read the signature.
        let mut sign = [0; Signature::SIZE];

        sign.copy_from_slice(&bytes[1..Signature::SIZE + 1]);

        let sign = Signature::from_bytes(&sign)
            .ok_or(BlobDecodeError::InvalidSignature)?;

        if n == Signature::SIZE + 1 {
            // Empty message.
            Ok(Self {
                hash: Hash::calc([]),
                data: Box::new([]),
                sign
            })
        }

        else {
            let data = &bytes[Signature::SIZE + 1..];

            Ok(Self {
                hash: Hash::calc(data),
                data: data.to_vec().into_boxed_slice(),
                sign
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_blob() -> Result<(SigningKey, Blob), Box<dyn std::error::Error>> {
        use rand_chacha::rand_core::SeedableRng;

        let mut rand = rand_chacha::ChaCha20Rng::seed_from_u64(123);

        let signing_key = SigningKey::random(&mut rand);

        let blob = Blob::create(
            &signing_key,
            b"hello, world!".to_vec()
        )?;

        Ok((signing_key, blob))
    }

    #[test]
    fn validate() -> Result<(), Box<dyn std::error::Error>> {
        let (signing_key, blob) = get_blob()?;

        let (is_valid, author) = blob.verify()?;

        assert!(is_valid);
        assert_eq!(blob.hash().to_base64(), "vkhPqCNXEhkbIzEYoEuoXKLwdRCjHpk9yGjncZlOQLs=");
        assert_eq!(author, signing_key.verifying_key());
        assert_eq!(blob.data(), b"hello, world!");

        Ok(())
    }

    #[test]
    fn serialize() -> Result<(), Box<dyn std::error::Error>> {
        let (_, blob) = get_blob()?;

        let serialized = blob.to_bytes();

        assert_eq!(Blob::from_bytes(serialized)?, blob);

        Ok(())
    }
}
