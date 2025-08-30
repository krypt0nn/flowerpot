use std::io::Cursor;

use serde_json::{json, Value as Json};

use crate::crypto::*;

pub const TRANSACTION_COMPRESSION_LEVEL: i32 = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub(crate) seed: [u8; 32],
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
        seed: [u8; 32],
        data: impl Into<Box<[u8]>>
    ) -> Result<Self, k256::ecdsa::Error> {
        let data: Box<[u8]> = data.into();

        let mut hasher = blake3::Hasher::new();

        hasher.update(&seed);
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

        hasher.update(&self.seed);
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

        let mut bytes = Vec::with_capacity(98 + self.data.len());

        bytes.push(0);                       // Format version
        bytes.extend_from_slice(&self.seed); // Fixed-size transaction seed
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

        if bytes.len() < 98 {
            return Err(std::io::Error::other("invalid transaction bytes len"));
        }

        if bytes[0] != 0 {
            return Err(std::io::Error::other("unknown transaction format"));
        }

        let mut seed = [0; 32];

        seed.copy_from_slice(&bytes[1..33]);

        let mut sign = [0; 65];

        sign.copy_from_slice(&bytes[33..98]);

        let sign = Signature::from_bytes(sign)
            .ok_or_else(|| std::io::Error::other("invalid signature format"))?;

        Ok(Self {
            seed,
            data: bytes[98..].to_vec().into_boxed_slice(),
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
            "seed": base64_encode(self.seed),
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

        let seed_raw = base64_decode(seed)
            .map_err(std::io::Error::other)?;

        if seed_raw.len() != 32 {
            return Err(std::io::Error::other("transaction seed has invalid length"));
        }

        let mut seed = [0; 32];

        seed.copy_from_slice(&seed_raw);

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
            [0; 32],
            b"hello, world!".to_vec()
        )?;

        Ok((secret_key, transaction))
    }

    #[test]
    fn validate() -> Result<(), Box<dyn std::error::Error>> {
        let (secret_key, transaction) = get_transaction()?;

        let (is_valid, hash, author) = transaction.verify()?;

        assert!(is_valid);
        assert_eq!(hash.to_base64(), "GM0sOPU6i7xtqUfl2s2eBWSWWbdCDBy96cG3JDHpYbM=");
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
