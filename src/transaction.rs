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

use std::io::Cursor;

use serde_json::{json, Value as Json};

use crate::crypto::*;

const TRANSACTION_COMPRESSION_LEVEL: i32 = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub(crate) seed: u64,
    pub(crate) data: Box<[u8]>,
    pub(crate) sign: Signature
}

impl Transaction {
    /// Create new transaction from the given data using provided secret key.
    ///
    /// Seed ensures that the hash of this transaction will be different in case
    /// the same data slice exists in some another transaction. **Transactions
    /// with the same hash will be rejected** (only the first one will be
    /// approved) so it's in your interests to choose seed randomly and make it
    /// unique.
    pub fn create(
        secret_key: &SecretKey,
        seed: u64,
        data: impl Into<Box<[u8]>>
    ) -> Result<Self, k256::ecdsa::Error> {
        let data: Box<[u8]> = data.into();

        let mut hasher = blake3::Hasher::new();

        hasher.update(&seed.to_le_bytes());
        hasher.update(&data);

        let sign = Signature::create(secret_key, hasher.finalize())?;

        Ok(Self {
            seed,
            data,
            sign
        })
    }

    /// Calculate hash of transaction.
    #[inline]
    pub fn hash(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();

        hasher.update(&self.seed.to_le_bytes());
        hasher.update(&self.data);

        Hash::from(hasher.finalize())
    }

    /// Get transaction's data.
    #[inline(always)]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get transaction's signature.
    #[inline(always)]
    pub fn sign(&self) -> &Signature {
        &self.sign
    }

    /// Derive transaction's author and verify its content.
    pub fn verify(&self) -> Result<(bool, Hash, PublicKey), k256::ecdsa::Error> {
        let hash = self.hash();

        self.sign.verify(hash)
            .map(|(is_valid, public_key)| (is_valid, hash, public_key))
    }

    /// Get bytes representation of the current transaction.
    pub fn to_bytes(&self) -> std::io::Result<Box<[u8]>> {
        let sign = self.sign.to_bytes();

        let mut bytes = Vec::with_capacity(74 + self.data.len());

        bytes.push(0); // Format version
        // Fixed-size transaction seed
        bytes.extend_from_slice(&self.seed.to_le_bytes());
        bytes.extend(sign);                  // Fixed-size sign
        bytes.extend_from_slice(&self.data); // Transaction data

        let bytes = zstd::encode_all(
            Cursor::new(bytes),
            TRANSACTION_COMPRESSION_LEVEL
        )?;

        Ok(bytes.into_boxed_slice())
    }

    /// Decode transaction from bytes representation.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> std::io::Result<Self> {
        let bytes = zstd::decode_all(bytes.as_ref())?;

        if bytes.len() < 74 {
            return Err(std::io::Error::other("invalid transaction bytes len"));
        }

        if bytes[0] != 0 {
            return Err(std::io::Error::other("unknown transaction format"));
        }

        let mut seed = [0; 8];

        seed.copy_from_slice(&bytes[1..9]);

        let mut sign = [0; 65];

        sign.copy_from_slice(&bytes[9..74]);

        let sign = Signature::from_bytes(sign)
            .ok_or_else(|| std::io::Error::other("invalid signature format"))?;

        Ok(Self {
            seed: u64::from_le_bytes(seed),
            data: bytes[74..].to_vec().into_boxed_slice(),
            sign
        })
    }

    /// Get standard JSON representation of the transaction.
    pub fn to_json(&self) -> std::io::Result<Json> {
        let data = zstd::encode_all(
            Cursor::new(&self.data),
            TRANSACTION_COMPRESSION_LEVEL
        )?;

        Ok(json!({
            "format": 0,
            "seed": format!("{:x}", self.seed),
            "data": base64_encode(data),
            "sign": self.sign.to_base64()
        }))
    }

    /// Decode standard JSON representation of the transaction.
    pub fn from_json(transaction: &Json) -> std::io::Result<Self> {
        if transaction.get("format").and_then(Json::as_u64) != Some(0) {
            return Err(std::io::Error::other("unknown transaction format"));
        }

        let Some(sign) = transaction.get("sign").and_then(Json::as_str) else {
            return Err(std::io::Error::other("missing transaction sign"));
        };

        let sign = Signature::from_base64(sign)
            .ok_or_else(|| std::io::Error::other("invalid signature format"))?;

        let Some(seed) = transaction.get("seed").and_then(Json::as_str) else {
            return Err(std::io::Error::other("missing transaction seed"));
        };

        let seed = u64::from_str_radix(seed, 16)
            .map_err(|_| std::io::Error::other("invalid transaction seed"))?;

        let Some(data) = transaction.get("data").and_then(Json::as_str) else {
            return Err(std::io::Error::other("missing transaction data"));
        };

        let data = base64_decode(data)
            .map_err(std::io::Error::other)?;

        let data = zstd::decode_all(data.as_slice())?;

        Ok(Self {
            seed,
            data: data.into_boxed_slice(),
            sign
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_transaction() -> Result<(SecretKey, Transaction), Box<dyn std::error::Error>> {
        use rand_chacha::rand_core::SeedableRng;

        let mut rand = rand_chacha::ChaCha20Rng::seed_from_u64(123);

        let secret_key = SecretKey::random(&mut rand);

        let transaction = Transaction::create(
            &secret_key,
            123,
            b"hello, world!".to_vec()
        )?;

        Ok((secret_key, transaction))
    }

    #[test]
    fn validate() -> Result<(), Box<dyn std::error::Error>> {
        let (secret_key, transaction) = get_transaction()?;

        let (is_valid, hash, author) = transaction.verify()?;

        assert!(is_valid);
        assert_eq!(hash.to_base64(), "bpoXoSDXtInY79Eqrdw7lTpUF6-FQH7xs2tH-BP5j5c=");
        assert_eq!(author, secret_key.public_key());
        assert_eq!(transaction.data(), b"hello, world!");

        Ok(())
    }

    #[test]
    fn serialize_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let (_, transaction) = get_transaction()?;

        let deserialized = Transaction::from_bytes(transaction.to_bytes()?)?;

        assert_eq!(transaction, deserialized);

        Ok(())
    }

    #[test]
    fn serialize_json() -> Result<(), Box<dyn std::error::Error>> {
        let (_, transaction) = get_transaction()?;

        let deserialized = Transaction::from_json(&transaction.to_json()?)?;

        assert_eq!(transaction, deserialized);

        Ok(())
    }
}
