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

use time::UtcDateTime;

use crate::varint;
use crate::crypto::hash::{Hash, Hasher};
use crate::crypto::sign::{SigningKey, VerifyingKey, Signature, SignatureError};
use crate::blob::{Blob, BlobDecodeError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BlockDecodeError {
    #[error("block header is too short: {got} bytes got, at least {expected} expected")]
    TooShort {
        got: usize,
        expected: usize
    },

    #[error("unsupported block format: {0:0X}")]
    UnsupportedFormat(u8),

    #[error("invalid block creation timestamp varint format")]
    InvalidTimestamp,

    #[error("invalid block signature format")]
    InvalidSignature,

    #[error("invalid blob length varint format")]
    InvalidBlobLength,

    #[error("failed to decode message from a block: {0}")]
    DecodeBlob(#[from] BlobDecodeError)
}

/// Block is a virtual group containing hashes of different users' blobs,
/// timestamp of when this group was created, reference to the previous group,
/// and a digital signature of a network validator.
///
/// Blobs hashes are enough to reconstruct the block hash and verify the
/// signature. Actual blobs content should be requested from the network. Blocks
/// purpose is to store the *history*, and work as a globally shared *index* of
/// available content, not to share this content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    /// Hash of the previous block.
    pub(crate) prev_hash: Hash,

    /// Hash of the current block. Virtual field, calculated in runtime from
    /// other fields.
    pub(crate) curr_hash: Hash,

    /// Timestamp when the block was said to be created. Defined by the block
    /// author and can in fact be different from an actual creation timestamp.
    pub(crate) timestamp: UtcDateTime,

    /// List of hashes of blobs attached to this block.
    pub(crate) blobs: Box<[Hash]>,

    /// Digital signature proving the block validity and containing its author.
    pub(crate) sign: Signature
}

impl Block {
    /// Create new block.
    pub fn create(
        signing_key: impl AsRef<SigningKey>,
        prev_hash: impl Into<Hash>,
        blobs: impl Into<Box<[Hash]>>
    ) -> Result<Self, SignatureError> {
        let prev_hash: Hash = prev_hash.into();
        let blobs: Box<[Hash]> = blobs.into();

        let timestamp = UtcDateTime::now()
            .replace_nanosecond(0)
            .unwrap_or_else(|_| UtcDateTime::now());

        let mut hasher = Hasher::new();

        hasher.update(prev_hash.as_bytes());
        hasher.update(timestamp.unix_timestamp().to_le_bytes());

        for hash in &blobs {
            hasher.update(hash.as_bytes());
        }

        let curr_hash = hasher.finalize();

        let sign = Signature::create(signing_key, curr_hash)?;

        Ok(Self {
            prev_hash,
            curr_hash,
            timestamp,
            blobs,
            sign
        })
    }

    /// Create new root block from provided signing key.
    #[inline]
    pub fn create_root(
        signing_key: impl AsRef<SigningKey>
    ) -> Result<Self, SignatureError> {
        Self::create(signing_key, Hash::ZERO, [])
    }

    /// Hash of the previous block.
    #[inline]
    pub const fn prev_hash(&self) -> &Hash {
        &self.prev_hash
    }

    /// Hash of the current block.
    ///
    /// This value is pre-calculated for performance reasons and is stored in
    /// the struct, so no computations are performed.
    #[inline]
    pub const fn hash(&self) -> &Hash {
        &self.curr_hash
    }

    /// Current block creation timestamp (up to seconds precision).
    #[inline]
    pub const fn timestamp(&self) -> &UtcDateTime {
        &self.timestamp
    }

    /// List of hashes of blobs attached to the current block.
    #[inline]
    pub const fn blobs(&self) -> &[Hash] {
        &self.blobs
    }

    /// Signature of the current block.
    #[inline]
    pub const fn sign(&self) -> &Signature {
        &self.sign
    }

    /// Return `true` if the current block is root of the blockchain.
    ///
    /// Root block is guatanteed to have `prev_hash = 0`, and its author is
    /// considered the authority of the blockchain.
    #[inline]
    pub fn is_root(&self) -> bool {
        self.prev_hash == Hash::ZERO
    }

    /// Verify signature of the current block and return embedded author's
    /// verifying key.
    #[inline]
    pub fn verify(&self) -> Result<(bool, VerifyingKey), SignatureError> {
        self.sign.verify(&self.curr_hash)
    }

    /// Encode current block into a binary representation.
    pub fn to_bytes(&self) -> Box<[u8]> {
        let timestamp = self.timestamp.unix_timestamp();

        let mut block = Vec::new();

        // Block format version.
        block.push(0);

        // Previous block hash (fixed size).
        block.extend(self.prev_hash.as_bytes());

        // Creation timestamp (varint).
        block.extend(varint::write_u64(timestamp as u64));

        // Block signature (fixed size).
        block.extend(self.sign.to_bytes());

        // List of user blobs hashes (rest of the block with fixed-size hashes).
        for hash in &self.blobs {
            block.extend(hash.as_bytes());
        }

        block.into_boxed_slice()
    }

    /// Decode block from a binary representation.
    pub fn from_bytes(
        block: impl AsRef<[u8]>
    ) -> Result<Self, BlockDecodeError> {
        let block = block.as_ref();
        let n = block.len();

        if n < Hash::SIZE + Signature::SIZE + 3 {
            return Err(BlockDecodeError::TooShort {
                got: n,
                expected: Hash::SIZE + Signature::SIZE + 3
            });
        }

        // Read block format.
        if block[0] != 0 {
            return Err(BlockDecodeError::UnsupportedFormat(block[0]));
        }

        let mut hasher = Hasher::new();

        // Read previous block's hash.
        let mut prev_hash = [0; 32];

        prev_hash.copy_from_slice(&block[1..33]);

        hasher.update(prev_hash);

        // Read block creation timestamp.
        let (Some(timestamp), block) = varint::read_u64(&block[33..]) else {
            return Err(BlockDecodeError::InvalidTimestamp);
        };

        hasher.update((timestamp as i64).to_le_bytes());

        let timestamp = UtcDateTime::from_unix_timestamp(timestamp as i64)
            .map_err(|_| BlockDecodeError::InvalidTimestamp)?;

        // Read the block's signature.
        let mut sign = [0; Signature::SIZE];

        sign.copy_from_slice(&block[..Signature::SIZE]);

        let sign = Signature::from_bytes(&sign)
            .ok_or(BlockDecodeError::InvalidSignature)?;

        // Decode user messages.

        let mut block = &block[Signature::SIZE..];

        hasher.update(block);

        let mut messages = Vec::new();

        while !block.is_empty() {
            let (Some(len), updated_block) = varint::read_u64(block) else {
                return Err(BlockDecodeError::InvalidMessageLength);
            };

            block = updated_block;

            let message = Message::from_bytes(&block[..len as usize])?;

            messages.push(message);

            if block.len() <= len as usize {
                break;
            }

            block = &block[len as usize..];
        }

        Ok(Self {
            prev_hash: Hash::from(prev_hash),
            curr_hash: hasher.finalize(),
            timestamp,
            messages: messages.into_boxed_slice(),
            sign
        })
    }
}

#[test]
fn test() -> Result<(), SignatureError> {
    use rand_chacha::rand_core::SeedableRng;

    let mut rand = rand_chacha::ChaCha20Rng::seed_from_u64(123);

    let signing_key = SigningKey::random(&mut rand);

    let block = Block::create(&signing_key, Hash::ZERO, [
        Message::create(&signing_key, b"Message 1".as_slice())?,
        Message::create(&signing_key, b"Message 2".as_slice())?,
        Message::create(&signing_key, b"Message 3".as_slice())?
    ])?;

    let (is_valid, verifying_key) = block.verify()?;

    assert!(is_valid);
    assert_eq!(verifying_key, signing_key.verifying_key());

    let serialized = block.to_bytes();

    assert_eq!(Block::from_bytes(serialized), Ok(block));

    Ok(())
}
