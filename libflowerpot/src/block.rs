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
use crate::message::{Message, MessageDecodeError};

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

    #[error("invalid message length varint format")]
    InvalidMessageLength,

    #[error("failed to decode message from a block: {0}")]
    DecodeMessage(#[from] MessageDecodeError)
}

#[inline]
fn encode_messages(messages: &[Message]) -> Box<[u8]> {
    let mut buf = Vec::new();

    for message in messages {
        let message = message.to_bytes();
        let len = varint::write_u64(message.len() as u64);

        buf.extend(len);
        buf.extend(message);
    }

    buf.into_boxed_slice()
}

// TODO: make excuse for root blocks that they don't have messages and instead
//       store fixed size random slice of data for hash seeding

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub(crate) prev_hash: Hash,
    pub(crate) curr_hash: Hash,
    pub(crate) timestamp: UtcDateTime,
    pub(crate) messages: Box<[Message]>,
    pub(crate) sign: Signature
}

impl Block {
    /// Create new block from provided previous block's hash and list of user
    /// messages using authority's signing key.
    pub fn create(
        signing_key: impl AsRef<SigningKey>,
        prev_hash: impl Into<Hash>,
        messages: impl Into<Box<[Message]>>
    ) -> Result<Self, SignatureError> {
        let prev_hash: Hash = prev_hash.into();
        let messages: Box<[Message]> = messages.into();

        let timestamp = UtcDateTime::now()
            .replace_nanosecond(0)
            .unwrap_or_else(|_| UtcDateTime::now());

        let mut hasher = Hasher::new();

        hasher.update(prev_hash.as_bytes());
        hasher.update(timestamp.unix_timestamp().to_le_bytes());
        hasher.update(encode_messages(&messages));

        let curr_hash = hasher.finalize();

        let sign = Signature::create(signing_key, curr_hash)?;

        Ok(Self {
            prev_hash,
            curr_hash,
            timestamp,
            messages,
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
    #[inline(always)]
    pub const fn prev_hash(&self) -> &Hash {
        &self.prev_hash
    }

    /// Hash of the current block.
    ///
    /// This value is pre-calculated for performance reasons and is stored in
    /// the struct, so no computations are performed.
    #[inline(always)]
    pub const fn hash(&self) -> &Hash {
        &self.curr_hash
    }

    /// Current block creation timestamp (up to seconds precision).
    #[inline(always)]
    pub const fn timestamp(&self) -> &UtcDateTime {
        &self.timestamp
    }

    /// List of messages stored in the current block.
    #[inline(always)]
    pub const fn messages(&self) -> &[Message] {
        &self.messages
    }

    /// Signature of the current block.
    #[inline(always)]
    pub const fn sign(&self) -> &Signature {
        &self.sign
    }

    /// Return `true` if the current block is root of the blockchain.
    ///
    /// Root block is guatanteed to have `prev_hash = 0`, and its author is
    /// considered the authority of the blockchain.
    #[inline(always)]
    pub fn is_root(&self) -> bool {
        self.prev_hash == Hash::ZERO
    }

    /// Verify signature of the current block and return embedded author's
    /// public key.
    #[inline]
    pub fn verify(&self) -> Result<(bool, VerifyingKey), SignatureError> {
        self.sign.verify(self.curr_hash)
    }

    /// Encode block into a binary representation.
    pub fn to_bytes(&self) -> Box<[u8]> {
        let timestamp = self.timestamp.unix_timestamp();
        let messages = encode_messages(&self.messages);

        let mut block = Vec::with_capacity(
            // format, prev_hash, sign, messages
            1 + Hash::SIZE + Signature::SIZE + messages.len()
        );

        // Format version
        block.push(0);

        // Previous block's hash
        block.extend(self.prev_hash.as_bytes());

        // Creation timestamp
        block.extend(varint::write_u64(timestamp as u64));

        // Sign
        block.extend(self.sign.to_bytes());

        // User messages
        block.extend(messages);

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
