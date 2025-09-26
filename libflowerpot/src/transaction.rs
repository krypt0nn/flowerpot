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

use crate::crypto::hash::*;
use crate::crypto::sign::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
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
    ) -> Result<Self, k256::ecdsa::Error> {
        let data: Box<[u8]> = data.into();

        let sign = Signature::create(
            signing_key,
            Hash::calc(&data).as_bytes()
        )?;

        Ok(Self {
            data,
            sign
        })
    }

    /// Get transaction's data.
    #[inline(always)]
    pub const fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get transaction's signature.
    #[inline(always)]
    pub const fn sign(&self) -> &Signature {
        &self.sign
    }

    /// Calculate hash of transaction.
    #[inline]
    pub fn hash(&self) -> Hash {
        Hash::calc(&self.data)
    }

    /// Derive transaction's author and verify its content.
    pub fn verify(
        &self
    ) -> Result<(bool, Hash, VerifyingKey), k256::ecdsa::Error> {
        let hash = self.hash();

        self.sign.verify(hash.as_bytes())
            .map(|(is_valid, public_key)| (is_valid, hash, public_key))
    }

    /// Get bytes representation of the current transaction.
    pub fn to_bytes(&self) -> Box<[u8]> {
        let mut bytes = Vec::with_capacity(Self::HEADER_SIZE + self.data.len());

        let sign = self.sign.to_bytes();

        bytes.push(0); // Format version
        bytes.extend(sign); // Fixed-size sign
        bytes.extend_from_slice(&self.data); // Transaction data

        bytes.into_boxed_slice()
    }

    /// Decode transaction from bytes representation.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> std::io::Result<Self> {
        let bytes = bytes.as_ref();
        let n = bytes.len();

        if n < Self::HEADER_SIZE {
            return Err(std::io::Error::other("missing transaction header"));
        }

        if bytes[0] != 0 {
            return Err(std::io::Error::other("unknown transaction format"));
        }

        let mut sign = [0; Signature::SIZE];

        sign.copy_from_slice(&bytes[1..Signature::SIZE + 1]);

        let sign = Signature::from_bytes(&sign)
            .ok_or_else(|| std::io::Error::other("invalid signature"))?;

        if n <= Self::HEADER_SIZE {
            // Empty transaction.
            Ok(Self {
                data: Box::new([]),
                sign
            })
        } else {
            Ok(Self {
                data: bytes[Self::HEADER_SIZE..].to_vec().into_boxed_slice(),
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

        let (is_valid, hash, author) = transaction.verify()?;

        assert!(is_valid);
        assert_eq!(hash.to_base64(), "bpoXoSDXtInY79Eqrdw7lTpUF6-FQH7xs2tH-BP5j5c=");
        assert_eq!(author, signing_key.public_key());
        assert_eq!(transaction.data(), b"hello, world!");

        Ok(())
    }

    #[test]
    fn serialize_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let (_, transaction) = get_transaction()?;

        let deserialized = Transaction::from_bytes(transaction.to_bytes())?;

        assert_eq!(transaction, deserialized);

        Ok(())
    }
}
