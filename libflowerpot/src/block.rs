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

use std::collections::HashSet;

use time::UtcDateTime;

use crate::varint;
use crate::crypto::hash::{Hash, Hasher};
use crate::crypto::sign::{SigningKey, Signature, SignatureError};
use crate::blob::{Blob, BlobDecodeError};
use crate::address::Address;

#[derive(Debug, thiserror::Error)]
pub enum BlockCreateError {
    #[error("block can't contain duplicate blobs; duplicate blob hash: {0}")]
    DuplicateBlob(Hash),

    #[error("failed to sign the block: {0}")]
    Signature(#[from] SignatureError)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BlockDecodeError {
    #[error("block header is too short: {got} bytes got, at least {expected} expected")]
    TooShort {
        got: usize,
        expected: usize
    },

    #[error("unsupported block format: {0:0X}")]
    UnsupportedFormat(u8),

    #[error("invalid block signature format")]
    InvalidSignature,

    #[error("invalid block creation timestamp varint format")]
    InvalidTimestamp,

    #[error("invalid blobs amount varint format")]
    InvalidBlobsAmount,

    #[error("invalid inline blobs amount varint format")]
    InvalidInlineBlobsAmount,

    #[error("invalid inline blob length varint format")]
    InvalidInlineBlobLength,

    #[error("failed to decode blob: {0}")]
    DecodeBlob(#[from] BlobDecodeError)
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct BlockBuilder {
    /// Identifier of the chain the current block belongs to. Required to
    /// reconstruct the blockchain address.
    chain_id: u32,

    /// Hash of the previous block.
    prev_hash: Hash,

    /// List of hashes of blobs attached to this block.
    ///
    /// These blobs are stored off-chain and can be requested using the network
    /// protocol.
    ///
    /// If you need to store some blobs directly in the block and force network
    /// clients to download them - then you need to use `inline_blobs` field.
    blobs: Vec<Hash>,

    /// List of blobs attached to this block.
    ///
    /// You have to know these blobs exactly to reconstruct the block's hash,
    /// and thus to verify its signature. It forces network clients to download
    /// these blobs at least once, and to store and share these blobs with other
    /// network clients in order to operate as proper network nodes.
    ///
    /// It is generally recommended to use this field only for administration
    /// purposes or for small enough blobs, because they will be stored in the
    /// blockchain history directly and downloaded every time a history is
    /// verified when a new node is connecting to the network.
    ///
    /// For large blobs you should use the `blobs` field and store blobs hashes
    /// only.
    inline_blobs: Vec<Blob>
}

impl BlockBuilder {
    #[inline]
    pub fn with_chain_id(mut self, chain_id: u32) -> Self {
        self.chain_id = chain_id;

        self
    }

    #[inline]
    pub fn with_prev_hash(mut self, prev_hash: impl Into<Hash>) -> Self {
        self.prev_hash = prev_hash.into();

        self
    }

    #[inline]
    pub fn with_blobs<T: Into<Hash>>(
        mut self,
        blobs: impl IntoIterator<Item = T>
    ) -> Self {
        self.blobs = blobs.into_iter()
            .map(T::into)
            .collect();

        self
    }

    #[inline]
    pub fn with_inline_blobs(
        mut self,
        inline_blobs: impl IntoIterator<Item = Blob>
    ) -> Self {
        self.inline_blobs = inline_blobs.into_iter()
            .collect();

        self
    }

    #[inline]
    pub fn add_blob(&mut self, blob_hash: impl Into<Hash>) -> &mut Self {
        self.blobs.push(blob_hash.into());

        self
    }

    #[inline]
    pub fn add_inline_blob(&mut self, blob: Blob) -> &mut Self {
        self.inline_blobs.push(blob);

        self
    }

    #[inline]
    pub fn sign(
        self,
        signing_key: impl AsRef<SigningKey>
    ) -> Result<Block, BlockCreateError> {
        let Self { chain_id, prev_hash, blobs, inline_blobs } = self;

        let timestamp = UtcDateTime::now()
            .replace_nanosecond(0)
            .unwrap_or_else(|_| UtcDateTime::now());

        let mut stored_blobs = HashSet::new();
        let mut hasher = Hasher::new();

        hasher.update(chain_id.to_le_bytes());
        hasher.update(prev_hash.as_bytes());
        hasher.update(timestamp.unix_timestamp().to_le_bytes());

        for hash in &blobs {
            if !stored_blobs.insert(*hash) {
                return Err(BlockCreateError::DuplicateBlob(*hash));
            }

            hasher.update(hash.as_bytes());
        }

        for blob in &inline_blobs {
            if !stored_blobs.insert(*blob.hash()) {
                return Err(BlockCreateError::DuplicateBlob(*blob.hash()));
            }

            hasher.update(blob.to_bytes());
        }

        let curr_hash = hasher.finalize();

        let sign = Signature::create(signing_key, curr_hash)?;

        Ok(Block {
            chain_id,
            prev_hash,
            curr_hash,
            timestamp,
            blobs: blobs.into_boxed_slice(),
            inline_blobs: inline_blobs.into_boxed_slice(),
            sign
        })
    }
}

// FIXME: it's currently impossible to implement a Storage outside of this lib
//        because it's impossible to construct Block struct outside of it from
//        raw parts.

/// Block is a virtual group containing hashes of different users' blobs or
/// these blobs themselves, randomly chosen chain identifier, timestamp of when
/// this group was created, reference to the previous group, and a digital
/// signature of a network validator.
///
/// Block is the atomic unit of a blockchain history. A history is formed of
/// blocks chained with each other using `prev_hash` values. Some blobs can be
/// stored within these blocks, so stored within the blockchain history and be
/// available for every blockchain users. Other blobs could be referenced by
/// hash value only to be downloaded off-chain using the network protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    /// Identifier of the chain the current block belongs to. Required to
    /// reconstruct the blockchain address.
    pub(crate) chain_id: u32,

    /// Hash of the previous block.
    pub(crate) prev_hash: Hash,

    /// Hash of the current block. Virtual field, calculated in runtime from
    /// other fields.
    pub(crate) curr_hash: Hash,

    /// Timestamp when the block was said to be created. Defined by the block
    /// author and can in fact be different from an actual creation timestamp.
    pub(crate) timestamp: UtcDateTime,

    /// List of hashes of blobs attached to this block.
    ///
    /// These blobs are stored off-chain and can be requested using the network
    /// protocol.
    ///
    /// If you need to store some blobs directly in the block and force network
    /// clients to download them - then you need to use `inline_blobs` field.
    pub(crate) blobs: Box<[Hash]>,

    /// List of blobs attached to this block.
    ///
    /// You have to know these blobs exactly to reconstruct the block's hash,
    /// and thus to verify its signature. It forces network clients to download
    /// these blobs at least once, and to store and share these blobs with other
    /// network clients in order to operate as proper network nodes.
    ///
    /// It is generally recommended to use this field only for administration
    /// purposes or for small enough blobs, because they will be stored in the
    /// blockchain history directly and downloaded every time a history is
    /// verified when a new node is connecting to the network.
    ///
    /// For large blobs you should use the `blobs` field and store blobs hashes
    /// only.
    pub(crate) inline_blobs: Box<[Blob]>,

    /// Digital signature proving the block validity and containing its author.
    pub(crate) sign: Signature
}

impl Block {
    #[inline]
    pub fn builder() -> BlockBuilder {
        BlockBuilder::default()
    }

    /// Identifier of a chain this block belongs to. Required to reconstruct
    /// the blockchain address.
    #[inline]
    pub const fn chain_id(&self) -> u32 {
        self.chain_id
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

    /// List of inline blobs attached to the current block.
    #[inline]
    pub const fn inline_blobs(&self) -> &[Blob] {
        &self.inline_blobs
    }

    /// Signature of the current block.
    #[inline]
    pub const fn sign(&self) -> &Signature {
        &self.sign
    }

    /// Return `true` if the current block is root of the blockchain.
    ///
    /// Root block is guatanteed to have `prev_hash = 0`.
    #[inline]
    pub fn is_root(&self) -> bool {
        self.prev_hash == Hash::ZERO
    }

    /// Try to verify signature of the current block, derive verifying key of
    /// the block's signer and reconstruct the blockchain address this block
    /// belongs to.
    ///
    /// These operations are happening in the same single method because they're
    /// all tied together. You can query current block's verifying key from the
    /// blockchain address returned from this method.
    pub fn verify(&self) -> Result<(bool, Address), SignatureError> {
        let (is_valid, verifying_key) = self.sign.verify(self.curr_hash)?;

        Ok((is_valid, Address::new(verifying_key, self.chain_id)))
    }

    /// Encode current block into a binary representation.
    pub fn to_bytes(&self) -> Box<[u8]> {
        let mut block = Vec::new();

        // Block format version.
        block.push(0);

        // Chain identifier (fixed size).
        block.extend(self.chain_id.to_le_bytes());

        // Previous block hash (fixed size).
        block.extend(self.prev_hash.as_bytes());

        // Block signature (fixed size).
        block.extend(self.sign.to_bytes());

        // Creation timestamp (varint).
        block.extend(varint::write_u64(self.timestamp.unix_timestamp() as u64));

        // List of blobs hashes.
        block.extend(varint::write_u64(self.blobs.len() as u64));

        for hash in &self.blobs {
            // Blob hash (fixed size).
            block.extend(hash.as_bytes());
        }

        // List of inline blobs.
        block.extend(varint::write_u64(self.inline_blobs.len() as u64));

        for blob in &self.inline_blobs {
            let blob = blob.to_bytes();

            // Inline blob size (varint) + blob content.
            block.extend(varint::write_u64(blob.len() as u64));
            block.extend(blob);
        }

        block.into_boxed_slice()
    }

    /// Decode block from a binary representation.
    pub fn from_bytes(
        block: impl AsRef<[u8]>
    ) -> Result<Self, BlockDecodeError> {
        let block = block.as_ref();
        let n = block.len();

        // Format version byte + chain identifier (4 bytes) + prev_hash + sign
        // + timestamp varint (1+ bytes) + list of blobs varint (1+ bytes)
        // + list of inline blobs varint (1+ bytes).
        if n < Hash::SIZE + Signature::SIZE + 8 {
            return Err(BlockDecodeError::TooShort {
                got: n,
                expected: Hash::SIZE + Signature::SIZE + 8
            });
        }

        // Check that the format byte is 0 (there's no different format now).
        if block[0] != 0 {
            return Err(BlockDecodeError::UnsupportedFormat(block[0]));
        }

        let mut hasher = Hasher::new();

        // Read chain identifier.
        let mut chain_id = [0; 4];

        chain_id.copy_from_slice(&block[1..5]);

        hasher.update(chain_id);

        // Read previous block's hash.
        let mut prev_hash = [0; 32];

        prev_hash.copy_from_slice(&block[5..37]);

        hasher.update(prev_hash);

        // Read block signature.
        let mut sign = [0; Signature::SIZE];

        sign.copy_from_slice(&block[37..37 + Signature::SIZE]);

        let sign = Signature::from_bytes(&sign)
            .ok_or(BlockDecodeError::InvalidSignature)?;

        // Read block creation timestamp.
        let (Some(timestamp), block) = varint::read_u64(&block[37 + Signature::SIZE..]) else {
            return Err(BlockDecodeError::InvalidTimestamp);
        };

        hasher.update((timestamp as i64).to_le_bytes());

        let timestamp = UtcDateTime::from_unix_timestamp(timestamp as i64)
            .map_err(|_| BlockDecodeError::InvalidTimestamp)?;

        // Read blobs amount.
        let (Some(mut blobs_amount), mut block) = varint::read_u64(block) else {
            return Err(BlockDecodeError::InvalidBlobsAmount);
        };

        // Read blobs hashes.
        let mut blobs = Vec::with_capacity(blobs_amount as usize);
        let mut blob_hash = [0; Hash::SIZE];

        while blobs_amount > 0 {
            blob_hash.copy_from_slice(&block[..Hash::SIZE]);

            hasher.update(blob_hash);

            blobs.push(Hash::from(blob_hash));

            blobs_amount -= 1;

            block = &block[Hash::SIZE..];
        }

        // Read inline blobs amount.
        let (Some(mut blobs_amount), mut block) = varint::read_u64(block) else {
            return Err(BlockDecodeError::InvalidInlineBlobsAmount);
        };

        // Read inline blobs.
        let mut inline_blobs = Vec::with_capacity(blobs_amount as usize);

        while blobs_amount > 0 {
            let (Some(blob_len), shifted_block) = varint::read_u64(block) else {
                return Err(BlockDecodeError::InvalidInlineBlobLength);
            };

            let inline_blob = &shifted_block[..blob_len as usize];

            hasher.update(inline_blob);

            inline_blobs.push(Blob::from_bytes(inline_blob)?);

            blobs_amount -= 1;

            // Early exit to not to update block ref to not to cause out of
            // bounds.
            if blobs_amount == 0 {
                break;
            }

            block = &shifted_block[blob_len as usize..];
        }

        Ok(Self {
            chain_id: u32::from_le_bytes(chain_id),
            prev_hash: Hash::from(prev_hash),
            curr_hash: hasher.finalize(),
            timestamp,
            blobs: blobs.into_boxed_slice(),
            inline_blobs: inline_blobs.into_boxed_slice(),
            sign
        })
    }
}

#[test]
fn test() -> Result<(), Box<dyn std::error::Error>> {
    use rand_chacha::rand_core::SeedableRng;

    let mut rand = rand_chacha::ChaCha20Rng::seed_from_u64(123);

    let signing_key = SigningKey::random(&mut rand);

    let blob_1 = Blob::create(&signing_key, b"Blob 1".as_slice())?;
    let blob_2 = Blob::create(&signing_key, b"Blob 2".as_slice())?;
    let blob_3 = Blob::create(&signing_key, b"Blob 3".as_slice())?;

    let block = Block::builder()
        .with_blobs([*blob_1.hash()])
        .with_inline_blobs([blob_2, blob_3])
        .sign(&signing_key)?;

    let (is_valid, address) = block.verify()?;

    assert!(is_valid);
    assert_eq!(address.verifying_key(), &signing_key.verifying_key());

    let serialized = block.to_bytes();

    assert_eq!(Block::from_bytes(serialized), Ok(block));

    Ok(())
}
