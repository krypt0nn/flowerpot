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

use std::io::{Read, Cursor};

use time::UtcDateTime;
use varint_rs::{VarintReader, VarintWriter};
use serde_json::{json, Value as Json};
use zstd::zstd_safe::WriteBuf;

use crate::crypto::*;
use crate::transaction::*;

const BLOCK_COMPRESSION_LEVEL: i32 = 20;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to serialize block to bytes: {0}")]
    SerializeBytes(#[source] std::io::Error),

    #[error("failed to calculate hash of the block: {0}")]
    Hash(#[source] std::io::Error),

    #[error("failed to sign new block: {0}")]
    Sign(#[source] k256::ecdsa::Error),

    #[error("failed to verify the block's signature: {0}")]
    Verify(#[source] k256::ecdsa::Error)
}

/// Block validation status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockStatus {
    /// Block is valid and approved by enough amount of validators.
    Approved {
        /// Hash of the block.
        hash: Hash,

        /// Public key of the block's author.
        public_key: PublicKey,

        /// Amount of required approvals.
        required_approvals: usize,

        /// List of valid approvals and their signer's public key.
        approvals: Vec<(Signature, PublicKey)>
    },

    /// Block is valid but not approved by enough amount of validators.
    NotApproved {
        /// Hash of the block.
        hash: Hash,

        /// Public key of the block's author.
        public_key: PublicKey,

        /// Amount of required approvals.
        required_approvals: usize,

        /// List of valid approvals and their signer's public key.
        approvals: Vec<(Signature, PublicKey)>
    },

    /// Block is not valid.
    Invalid
}

impl BlockStatus {
    /// Validate a block with provided params.
    ///
    /// This function will verify the block's approval signatures. It will not
    /// verify the block itself.
    pub fn validate<'a>(
        block_hash: impl Into<Hash>,
        public_key: impl Into<PublicKey>,
        approvals: impl IntoIterator<Item = &'a Signature>,
        validators: impl AsRef<[PublicKey]>
    ) -> Result<Self, Error> {
        let block_hash: Hash = block_hash.into();
        let public_key: PublicKey = public_key.into();
        let validators = validators.as_ref();

        // Immediately reject the block if its signer is not a validator.
        if !validators.is_empty() && !validators.contains(&public_key) {
            return Ok(BlockStatus::Invalid);
        }

        // Iterate over the block's approvals.
        let mut valid_approvals = Vec::new();

        for approval in approvals {
            // Verify that approval is correct.
            let (valid, approval_public_key) = approval.verify(block_hash)
                .map_err(Error::Verify)?;

            // Reject invalid approval, approvals from non-validators and
            // self-approvals from the block's author.
            if !valid
                || (!validators.is_empty() && !validators.contains(&public_key))
                || approval_public_key == public_key
            {
                continue;
            }

            valid_approvals.push((approval.clone(), approval_public_key));
        }

        // Count valid approvals and check that their amount is correct.
        let required_approvals = crate::calc_required_approvals(validators.len());

        if valid_approvals.len() < required_approvals {
            return Ok(Self::NotApproved {
                hash: block_hash,
                public_key,
                required_approvals,
                approvals: valid_approvals
            });
        }

        Ok(Self::Approved {
            hash: block_hash,
            public_key,
            required_approvals,
            approvals: valid_approvals
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub(crate) previous: Hash,
    pub(crate) timestamp: UtcDateTime,
    pub(crate) content: BlockContent,
    pub(crate) sign: Signature,
    pub(crate) approvals: Vec<Signature>
}

impl Block {
    /// Create new block from provided previous block's hash and content using
    /// validator's secret key.
    pub fn new(
        validator: &SecretKey,
        previous: impl Into<Hash>,
        content: impl Into<BlockContent>
    ) -> Result<Self, Error> {
        let previous: Hash = previous.into();
        let content: BlockContent = content.into();

        let timestamp = UtcDateTime::now();

        let mut hasher = blake3::Hasher::new();

        hasher.update(&previous.0);
        hasher.update(&timestamp.unix_timestamp().to_be_bytes());
        hasher.update(&content.to_bytes().map_err(Error::SerializeBytes)?);

        let hash = Hash::from(hasher.finalize());

        let sign = Signature::create(validator, hash)
            .map_err(Error::Sign)?;

        Ok(Self {
            previous,
            timestamp,
            content,
            sign,
            approvals: vec![]
        })
    }

    #[inline(always)]
    pub fn previous(&self) -> &Hash {
        &self.previous
    }

    #[inline(always)]
    pub fn timestamp(&self) -> &UtcDateTime {
        &self.timestamp
    }

    #[inline(always)]
    pub fn content(&self) -> &BlockContent {
        &self.content
    }

    #[inline(always)]
    pub fn sign(&self) -> &Signature {
        &self.sign
    }

    #[inline(always)]
    pub fn approvals(&self) -> &[Signature] {
        &self.approvals
    }

    /// Return `true` if the current block is root of the blockchain.
    #[inline]
    pub fn is_root(&self) -> bool {
        self.previous.0 == [0; 32]
    }

    /// Calculate hash of the current block.
    pub fn hash(&self) -> Result<Hash, Error> {
        let mut hasher = blake3::Hasher::new();

        hasher.update(&self.previous.0);
        hasher.update(&self.timestamp.unix_timestamp().to_be_bytes());
        hasher.update(&self.content.to_bytes().map_err(Error::SerializeBytes)?);

        Ok(Hash::from(hasher.finalize()))
    }

    /// Add approval signature to the block.
    ///
    /// Return `Ok(false)` if signature is not valid.
    pub fn approve(&mut self, approval: Signature) -> Result<bool, Error> {
        if !self.approvals.contains(&approval) {
            let hash = self.hash()?;

            let (is_valid, public_key) = approval.verify(hash)
                .map_err(Error::Verify)?;

            let (_, curr_public_key) = self.sign.verify(hash)
                .map_err(Error::Verify)?;

            if !is_valid || public_key == curr_public_key {
                return Ok(false);
            }

            self.approvals.push(approval);
        }

        Ok(true)
    }

    /// Create approval for the block and add it.
    ///
    /// Return `Ok(false)` if newly created approval is already attached to the
    /// block.
    pub fn approve_with(&mut self, secret_key: &SecretKey) -> Result<bool, Error> {
        let hash = self.hash()?;

        let approval = Signature::create(secret_key, hash)
            .map_err(Error::Sign)?;

        if !self.approvals.contains(&approval) {
            let (is_valid, public_key) = approval.verify(hash)
                .map_err(Error::Verify)?;

            let (_, curr_public_key) = self.sign.verify(hash)
                .map_err(Error::Verify)?;

            if !is_valid || public_key == curr_public_key {
                return Ok(false);
            }

            self.approvals.push(approval);
        }

        Ok(true)
    }

    /// Verify the signature of the current block.
    ///
    /// This method *does not* validate the block's approvals. This must be done
    /// outside of this method using the blockchain's storage.
    pub fn verify(&self) -> Result<(bool, Hash, PublicKey), Error> {
        let hash = self.hash()?;

        self.sign.verify(hash)
            .map(|(valid, public_key)| (valid, hash, public_key))
            .map_err(Error::Verify)
    }

    /// Use provided validators list to verify that the block is approved.
    ///
    /// This method calls `verify` method internally as well so you don't need
    /// to do this twice.
    pub fn validate(
        &self,
        validators: &[PublicKey]
    ) -> Result<BlockStatus, Error> {
        // Verify the block and obtain its hash and signer.
        let (valid, hash, public_key) = self.verify()?;

        // Immediately reject the block if it's not valid or its signer is not
        // a validator.
        if !valid || !validators.contains(&public_key) {
            return Ok(BlockStatus::Invalid);
        }

        BlockStatus::validate(
            hash,
            public_key,
            self.approvals(),
            validators
        )
    }

    /// Encode block into bytes representation.
    pub fn to_bytes(&self) -> std::io::Result<Box<[u8]>> {
        let content = self.content.to_bytes()?;
        let timestamp = self.timestamp.unix_timestamp();

        let mut block = Vec::new();

        block.push(0);                                   // Format version
        block.extend(self.previous.0);                   // Previous block's hash
        block.write_i64_varint(timestamp)?;              // Creation timestamp
        block.extend(self.sign.to_bytes());              // Sign
        block.write_usize_varint(self.approvals.len())?; // Approvals number

        for approval in &self.approvals {
            block.extend(approval.to_bytes()); // Approval signatures
        }

        block.extend(content); // Content

        let block = zstd::encode_all(
            &mut block.as_slice(),
            BLOCK_COMPRESSION_LEVEL
        )?;

        Ok(block.into_boxed_slice())
    }

    /// Decode block from bytes representation.
    pub fn from_bytes(block: impl AsRef<[u8]>) -> std::io::Result<Self> {
        let block = zstd::decode_all(block.as_ref())?;

        if block.is_empty() {
            return Err(std::io::Error::other("invalid block length"));
        }

        if block[0] != 0 {
            return Err(std::io::Error::other("unknown block format"));
        }

        let mut previous = [0; 32];

        previous.copy_from_slice(&block[1..33]);

        let mut block = Cursor::new(block[33..].to_vec());

        let timestamp = block.read_i64_varint()?;

        let timestamp = UtcDateTime::from_unix_timestamp(timestamp)
            .map_err(|_| std::io::Error::other("invalid timestamp format"))?;

        let mut sign = [0; 65];

        block.read_exact(&mut sign)?;

        let sign = Signature::from_bytes(sign)
            .ok_or_else(|| std::io::Error::other("invalid signature format"))?;

        let approvals_num = block.read_usize_varint()?;

        let mut approval = [0; 65];
        let mut approvals = Vec::with_capacity(approvals_num);

        for _ in 0..approvals_num {
            block.read_exact(&mut approval)?;

            let approval = Signature::from_bytes(approval)
                .ok_or_else(|| std::io::Error::other("invalid approval format"))?;

            approvals.push(approval);
        }

        let mut content = Vec::new();

        block.read_to_end(&mut content)?;

        Ok(Self {
            previous: Hash::from(previous),
            timestamp,
            content: BlockContent::from_bytes(content)?,
            sign,
            approvals
        })
    }

    /// Get standard JSON representation of the block.
    pub fn to_json(&self) -> std::io::Result<Json> {
        Ok(json!({
            "format": 0,
            "previous": self.previous.to_base64(),
            "timestamp": self.timestamp.unix_timestamp(),
            "content": self.content.to_json()?,
            "sign": self.sign.to_base64(),
            "approvals": self.approvals.iter()
                .map(|approval| approval.to_base64())
                .collect::<Vec<_>>()
        }))
    }

    /// Decode standard JSON representation of the block.
    pub fn from_json(json: &Json) -> std::io::Result<Self> {
        let Some(format) = json.get("format").and_then(Json::as_u64) else {
            return Err(std::io::Error::other("missing block format"));
        };

        if format != 0 {
            return Err(std::io::Error::other("unknown block format"));
        }

        Ok(Self {
            previous: json.get("previous")
                .and_then(Json::as_str)
                .and_then(Hash::from_base64)
                .ok_or_else(|| std::io::Error::other("missing previous block hash"))?,

            timestamp: json.get("timestamp")
                .and_then(Json::as_i64)
                .map(UtcDateTime::from_unix_timestamp)
                .transpose()
                .map_err(|_| std::io::Error::other("invalid block timestamp"))?
                .ok_or_else(|| std::io::Error::other("missing block timestamp"))?,

            content: json.get("content")
                .map(BlockContent::from_json)
                .ok_or_else(|| std::io::Error::other("missing block's content"))??,

            sign: json.get("sign")
                .and_then(Json::as_str)
                .and_then(Signature::from_base64)
                .ok_or_else(|| std::io::Error::other("missing block signature"))?,

            approvals: json.get("approvals")
                .and_then(Json::as_array)
                .and_then(|approvals| {
                    approvals.iter()
                        .map(Json::as_str)
                        .map(|approval| {
                            approval.and_then(Signature::from_base64)
                        })
                        .collect::<Option<Vec<Signature>>>()
                })
                .ok_or_else(|| std::io::Error::other("invalid block approvals"))?
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockContent {
    /// List of approved validators' public keys.
    Validators(Box<[PublicKey]>),

    /// List of approved transactions.
    Transactions(Box<[Transaction]>),

    /// Arbitrary data.
    Data(Box<[u8]>)
}

impl BlockContent {
    /// Create new validators block.
    pub fn validators<T: Into<PublicKey>>(
        public_keys: impl IntoIterator<Item = T>
    ) -> Self {
        Self::Validators(public_keys.into_iter().map(T::into).collect())
    }

    /// Create new transactions block.
    pub fn transactions<T: Into<Transaction>>(
        transactions: impl IntoIterator<Item = T>
    ) -> Self {
        Self::Transactions(transactions.into_iter().map(T::into).collect())
    }

    /// Create new data block.
    #[inline]
    pub fn data(data: impl Into<Box<[u8]>>) -> Self {
        Self::Data(data.into())
    }

    /// Encode block's content into bytes representation.
    pub fn to_bytes(&self) -> std::io::Result<Box<[u8]>> {
        let mut content = Vec::new();

        match self {
            Self::Validators(validators) => {
                content.push(0); // validators v1 format

                for validator in validators {
                    content.extend(validator.to_bytes());
                }
            }

            Self::Transactions(transactions) => {
                content.push(1); // transactions v1 format

                for transaction in transactions {
                    let transaction = transaction.to_bytes()?;

                    content.write_usize_varint(transaction.len())?;
                    content.extend(transaction);
                }
            }

            Self::Data(data) => {
                content.push(2); // data v1 format
                content.extend_from_slice(data);
            }
        }

        Ok(content.into_boxed_slice())
    }

    /// Decode block's content from bytes representation.
    pub fn from_bytes(content: impl AsRef<[u8]>) -> std::io::Result<Self> {
        let content = content.as_ref();
        let n = content.len();

        if n == 0 {
            return Err(std::io::Error::other("block's content can't be empty"));
        }

        match content[0] {
            // validators v1 format
            0 => {
                if (n - 1) % 33 != 0 {
                    return Err(std::io::Error::other("invalid validators block format"));
                }

                let mut validators = Vec::with_capacity((n - 1) / 33);
                let mut i = 1;

                while i < n {
                    let validator = PublicKey::from_bytes(&content[i..i + 33])
                        .ok_or_else(|| std::io::Error::other("invalid validator's public key format"))?;

                    validators.push(validator);

                    i += 33;
                }

                Ok(Self::Validators(validators.into_boxed_slice()))
            }

            // transactions v1 format
            1 => {
                // empty transactions block
                if n == 1 {
                    return Ok(Self::Transactions(Box::new([])));
                }

                let mut content = Cursor::new(content[1..].to_vec());
                let mut transactions = Vec::new();

                while content.position() < n as u64 {
                    let len = content.read_usize_varint()?;

                    let mut transaction = vec![0; len];

                    content.read_exact(&mut transaction[..len])?;

                    let transaction = Transaction::from_bytes(transaction)?;

                    transactions.push(transaction);
                }

                Ok(Self::Transactions(transactions.into_boxed_slice()))
            }

            // data v1 format
            2 => {
                if n == 1 {
                    Ok(Self::Data(Box::new([])))
                } else {
                    Ok(Self::Data(content[1..].to_vec().into_boxed_slice()))
                }
            }

            _ => Err(std::io::Error::other("unknown block content format"))
        }
    }

    /// Get standard JSON representation of the block's content.
    pub fn to_json(&self) -> std::io::Result<Json> {
        match self {
            Self::Validators(validators) => {
                Ok(json!({
                    "format": 0, // validators v1 format
                    "content": validators.iter()
                        .map(|validator| validator.to_base64())
                        .collect::<Vec<_>>()
                }))
            }

            Self::Transactions(transactions) => {
                Ok(json!({
                    "format": 1, // transactions v1 format
                    "content": transactions.iter()
                        .map(|transactions| transactions.to_json())
                        .collect::<Result<Vec<_>, _>>()?
                }))
            }

            Self::Data(data) => {
                let data = zstd::encode_all(
                    &mut data.as_slice(),
                    BLOCK_COMPRESSION_LEVEL
                )?;

                Ok(json!({
                    "format": 2, // data v1 format
                    "content": base64_encode(data)
                }))
            }
        }
    }

    /// Decode standard JSON representation of the block's content.
    pub fn from_json(json: &Json) -> std::io::Result<Self> {
        let Some(format) = json.get("format").and_then(Json::as_u64) else {
            return Err(std::io::Error::other("missing block's content format"));
        };

        let Some(content) = json.get("content") else {
            return Err(std::io::Error::other("missing block's content data"));
        };

        match format {
            // validators v1 format
            0 => {
                let Some(validators) = content.as_array() else {
                    return Err(std::io::Error::other("invalid validators format"));
                };

                let validators = validators.iter()
                    .flat_map(Json::as_str)
                    .flat_map(PublicKey::from_base64)
                    .collect::<Vec<_>>();

                Ok(Self::Validators(validators.into_boxed_slice()))
            }

            // transactions v1 format
            1 => {
                let Some(transactions) = content.as_array() else {
                    return Err(std::io::Error::other("invalid transactions format"));
                };

                let transactions = transactions.iter()
                    .map(Transaction::from_json)
                    .collect::<Result<Vec<_>, _>>()?;

                Ok(Self::Transactions(transactions.into_boxed_slice()))
            }

            // data v1 format
            2 => {
                let Some(content) = content.as_str() else {
                    return Err(std::io::Error::other("invalid block data format"));
                };

                let content = base64_decode(content)
                    .map_err(std::io::Error::other)?;

                let content = zstd::decode_all(content.as_slice())?;

                Ok(Self::Data(content.into_boxed_slice()))
            }

            _ => Err(std::io::Error::other("unknown block's content format"))
        }
    }
}
