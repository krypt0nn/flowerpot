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
use crate::message::{Message, MessageDecodeError};
use crate::address::Address;

#[derive(Debug, thiserror::Error)]
pub enum BlockCreateError {
    #[error("block can't contain duplicate messages; duplicate message hash: {0}")]
    DuplicateMessage(Hash),

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

    #[error("invalid referenced messages amount varint format")]
    InvalidRefMessagesAmount,

    #[error("invalid inline messages amount varint format")]
    InvalidInlineMessagesAmount,

    #[error("invalid inline message length varint format")]
    InvalidInlineMessageLength,

    #[error("failed to decode blob: {0}")]
    DecodeMessage(#[from] MessageDecodeError)
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct BlockBuilder {
    /// Identifier of the chain the current block belongs to. Required to
    /// reconstruct the blockchain address.
    pub chain_id: u32,

    /// Hash of the previous block.
    pub prev_hash: Hash,

    /// List of hashes of messages attached to this block.
    ///
    /// These messages are stored off-chain and can be requested using the
    /// network protocol.
    ///
    /// If you need to store some messages directly in the block and force
    /// network clients to download them - then you need to use
    /// `inline_messages` field.
    pub ref_messages: Vec<Hash>,

    /// List of messages attached to this block.
    ///
    /// You have to know these messages exactly to reconstruct the block's hash,
    /// and thus to verify its signature. It forces network clients to download
    /// these messages at least once, and to store and share these messages with
    /// other network clients in order to operate as proper network nodes.
    ///
    /// It is generally recommended to use this field only for administration
    /// purposes or for small enough messages, because they will be stored in
    /// the blockchain history directly and downloaded every time a history is
    /// verified when a new node is connecting to the network.
    ///
    /// For large messages you should use the `ref_messages` field and store
    /// messages' hashes only.
    pub inline_messages: Vec<Message>
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
    pub fn with_ref_messages<T: Into<Hash>>(
        mut self,
        messages: impl IntoIterator<Item = T>
    ) -> Self {
        self.ref_messages = messages.into_iter()
            .map(T::into)
            .collect();

        self
    }

    #[inline]
    pub fn with_inline_messages(
        mut self,
        messages: impl IntoIterator<Item = Message>
    ) -> Self {
        self.inline_messages = messages.into_iter()
            .collect();

        self
    }

    #[inline]
    pub fn add_ref_message(&mut self, hash: impl Into<Hash>) -> &mut Self {
        self.ref_messages.push(hash.into());

        self
    }

    #[inline]
    pub fn add_inline_message(&mut self, message: Message) -> &mut Self {
        self.inline_messages.push(message);

        self
    }

    #[inline]
    pub fn sign(
        self,
        signing_key: impl AsRef<SigningKey>
    ) -> Result<Block, BlockCreateError> {
        let Self { chain_id, prev_hash, ref_messages, inline_messages } = self;

        let timestamp = UtcDateTime::now()
            .replace_nanosecond(0)
            .unwrap_or_else(|_| UtcDateTime::now());

        let mut messages = HashSet::new();
        let mut hasher = Hasher::new();

        hasher.update(chain_id.to_le_bytes());
        hasher.update(prev_hash.as_bytes());
        hasher.update(timestamp.unix_timestamp().to_le_bytes());

        for hash in &ref_messages {
            if !messages.insert(*hash) {
                return Err(BlockCreateError::DuplicateMessage(*hash));
            }

            hasher.update(hash.as_bytes());
        }

        for message in &inline_messages {
            if !messages.insert(*message.hash()) {
                return Err(BlockCreateError::DuplicateMessage(*message.hash()));
            }

            hasher.update(message.to_bytes());
        }

        let curr_hash = hasher.finalize();

        let sign = Signature::create(signing_key, curr_hash)?;

        Ok(Block {
            chain_id,
            prev_hash,
            curr_hash,
            timestamp,
            ref_messages: ref_messages.into_boxed_slice(),
            inline_messages: inline_messages.into_boxed_slice(),
            sign
        })
    }
}

// FIXME: it's currently impossible to implement a Storage outside of this lib
//        because it's impossible to construct Block struct outside of it from
//        raw parts.

/// Block is a virtual group containing hashes of different users' messages or
/// these messages themselves, randomly chosen chain identifier, timestamp of
/// when this group was created, reference to the previous group, and a digital
/// signature of a network validator.
///
/// Block is the atomic unit of a blockchain history. A history is formed of
/// blocks chained with each other using `prev_hash` values. Some messages can
/// be stored within these blocks, so stored within the blockchain history and
/// be available for every blockchain users. Other messages could be referenced
/// by hash value only to be downloaded off-chain using the network protocol.
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

    /// List of hashes of messages attached to this block.
    ///
    /// These messages are stored off-chain and can be requested using the
    /// network protocol.
    ///
    /// If you need to store some messages directly in the block and force
    /// network clients to download them - then you need to use
    /// `inline_messages` field.
    pub(crate) ref_messages: Box<[Hash]>,

    /// List of messages attached to this block.
    ///
    /// You have to know these messages exactly to reconstruct the block's hash,
    /// and thus to verify its signature. It forces network clients to download
    /// these messages at least once, and to store and share these messages with
    /// other network clients in order to operate as proper network nodes.
    ///
    /// It is generally recommended to use this field only for administration
    /// purposes or for small enough messages, because they will be stored in
    /// the blockchain history directly and downloaded every time a history is
    /// verified when a new node is connecting to the network.
    ///
    /// For large messages you should use the `ref_messages` field and store
    /// messages' hashes only.
    pub(crate) inline_messages: Box<[Message]>,

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

    /// List of hashes of messages referenced in the current block.
    #[inline]
    pub const fn ref_messages(&self) -> &[Hash] {
        &self.ref_messages
    }

    /// List of inline messages attached to the current block.
    #[inline]
    pub const fn inline_messages(&self) -> &[Message] {
        &self.inline_messages
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

        // List of referenced messages hashes.
        block.extend(varint::write_u64(self.ref_messages.len() as u64));

        for hash in &self.ref_messages {
            // Message hash (fixed size).
            block.extend(hash.as_bytes());
        }

        // List of inline messages.
        block.extend(varint::write_u64(self.inline_messages.len() as u64));

        for message in &self.inline_messages {
            let message = message.to_bytes();

            // Inline message size (varint) + message content.
            block.extend(varint::write_u64(message.len() as u64));
            block.extend(message);
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

        // Read referenced messages amount.
        let (Some(mut ref_messages_amount), mut block) = varint::read_u64(block) else {
            return Err(BlockDecodeError::InvalidRefMessagesAmount);
        };

        // Read messages hashes.
        let mut ref_messages = Vec::with_capacity(ref_messages_amount as usize);
        let mut message_hash = [0; Hash::SIZE];

        while ref_messages_amount > 0 {
            message_hash.copy_from_slice(&block[..Hash::SIZE]);

            hasher.update(message_hash);

            ref_messages.push(Hash::from(message_hash));

            ref_messages_amount -= 1;

            block = &block[Hash::SIZE..];
        }

        // Read inline messages amount.
        let (Some(mut inline_messages_amount), mut block) = varint::read_u64(block) else {
            return Err(BlockDecodeError::InvalidInlineMessagesAmount);
        };

        // Read inline messages.
        let mut inline_messages = Vec::with_capacity(inline_messages_amount as usize);

        while inline_messages_amount > 0 {
            let (Some(message_len), shifted_block) = varint::read_u64(block) else {
                return Err(BlockDecodeError::InvalidInlineMessageLength);
            };

            let inline_message = &shifted_block[..message_len as usize];

            hasher.update(inline_message);

            inline_messages.push(Message::from_bytes(inline_message)?);

            inline_messages_amount -= 1;

            // Early exit to not to update block ref to not to cause out of
            // bounds.
            if inline_messages_amount == 0 {
                break;
            }

            block = &shifted_block[message_len as usize..];
        }

        Ok(Self {
            chain_id: u32::from_le_bytes(chain_id),
            prev_hash: Hash::from(prev_hash),
            curr_hash: hasher.finalize(),
            timestamp,
            ref_messages: ref_messages.into_boxed_slice(),
            inline_messages: inline_messages.into_boxed_slice(),
            sign
        })
    }
}

#[test]
fn test() -> Result<(), Box<dyn std::error::Error>> {
    use rand_chacha::rand_core::SeedableRng;

    let mut rand = rand_chacha::ChaCha20Rng::seed_from_u64(123);

    let signing_key = SigningKey::random(&mut rand);

    let message_1 = Message::create(&signing_key, b"Message 1".as_slice())?;
    let message_2 = Message::create(&signing_key, b"Message 2".as_slice())?;
    let message_3 = Message::create(&signing_key, b"Message 3".as_slice())?;

    let block = Block::builder()
        .with_ref_messages([*message_1.hash()])
        .with_inline_messages([message_2, message_3])
        .sign(&signing_key)?;

    let (is_valid, address) = block.verify()?;

    assert!(is_valid);
    assert_eq!(address.verifying_key(), &signing_key.verifying_key());

    let serialized = block.to_bytes();

    assert_eq!(Block::from_bytes(serialized), Ok(block));

    Ok(())
}
