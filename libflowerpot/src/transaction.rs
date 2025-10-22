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

#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum TransactionDecodeError {
    #[error("encoded transaction is missing a header")]
    MissingHeader,

    #[error("unsupported transaction format: {0:0X}")]
    UnsupportedFormat(u8),

    #[error("invalid transaction signature format")]
    InvalidSignature
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub(crate) hash: Hash,
    pub(crate) data: Box<[u8]>,
    pub(crate) sign: Signature
}

impl Transaction {
    /// Bytes size of the transaction header.
    ///
    /// Consist of the signature and 1 byte format.
    pub const HEADER_SIZE: usize = Signature::SIZE + 1;

    /// Create new transaction from the given data using provided signing key.
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

    /// Get current transaction's hash.
    ///
    /// This value is pre-calculated for performance reasons and is stored in
    /// the struct, so no computations are performed.
    #[inline(always)]
    pub const fn hash(&self) -> &Hash {
        &self.hash
    }

    /// Get current transaction's data.
    #[inline(always)]
    pub const fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get current transaction's signature.
    #[inline(always)]
    pub const fn sign(&self) -> &Signature {
        &self.sign
    }

    /// Derive transaction's author and verify that the transaction's signature
    /// is valid.
    #[inline]
    pub fn verify(
        &self
    ) -> Result<(bool, VerifyingKey), SignatureError> {
        self.sign.verify(self.hash())
    }

    /// Encode transaction into a binary representation.
    pub fn to_bytes(&self) -> Box<[u8]> {
        let mut bytes = Vec::with_capacity(Self::HEADER_SIZE + self.data.len());

        bytes.push(0); // Format version
        bytes.extend(self.sign.to_bytes()); // Fixed-size sign
        bytes.extend(&self.data); // Transaction data

        bytes.into_boxed_slice()
    }

    /// Decode transaction from a binary representation.
    pub fn from_bytes(
        bytes: impl AsRef<[u8]>
    ) -> Result<Self, TransactionDecodeError> {
        let bytes = bytes.as_ref();
        let n = bytes.len();

        if n < Self::HEADER_SIZE {
            return Err(TransactionDecodeError::MissingHeader);
        }

        if bytes[0] != 0 {
            return Err(TransactionDecodeError::UnsupportedFormat(bytes[0]));
        }

        let mut sign = [0; Signature::SIZE];

        sign.copy_from_slice(&bytes[1..Signature::SIZE + 1]);

        let sign = Signature::from_bytes(&sign)
            .ok_or(TransactionDecodeError::InvalidSignature)?;

        if n <= Self::HEADER_SIZE {
            // Empty transaction.
            Ok(Self {
                hash: Hash::calc([]),
                data: Box::new([]),
                sign
            })
        }

        else {
            let data = &bytes[Self::HEADER_SIZE..];

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

    fn get_transaction() -> Result<(SigningKey, Transaction), Box<dyn std::error::Error>> {
        use rand_chacha::rand_core::SeedableRng;

        let mut rand = rand_chacha::ChaCha20Rng::seed_from_u64(123);

        let signing_key = SigningKey::random(&mut rand);

        let transaction = Transaction::create(
            &signing_key,
            b"hello, world!".to_vec()
        )?;

        Ok((signing_key, transaction))
    }

    #[test]
    fn validate() -> Result<(), Box<dyn std::error::Error>> {
        let (signing_key, transaction) = get_transaction()?;

        let (is_valid, author) = transaction.verify()?;

        assert!(is_valid);
        assert_eq!(transaction.hash().to_base64(), "vkhPqCNXEhkbIzEYoEuoXKLwdRCjHpk9yGjncZlOQLs=");
        assert_eq!(author, signing_key.verifying_key());
        assert_eq!(transaction.data(), b"hello, world!");

        Ok(())
    }

    #[test]
    fn serialize() -> Result<(), Box<dyn std::error::Error>> {
        let (_, transaction) = get_transaction()?;

        let serialized = transaction.to_bytes();

        assert_eq!(Transaction::from_bytes(serialized)?, transaction);

        Ok(())
    }
}
