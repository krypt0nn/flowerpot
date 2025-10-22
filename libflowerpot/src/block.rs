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
use crate::transaction::{Transaction, TransactionDecodeError};

#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum BlockDecodeError {
    #[error("block header is too short: {got} bytes got, at least {expected} expected")]
    TooShort {
        got: usize,
        expected: usize
    },

    #[error("unsupported block format: {0:0X}")]
    UnsupportedFormat(u8),

    #[error("invalid block creation timestamp format")]
    InvalidTimestamp,

    #[error("invalid block signature format")]
    InvalidSignature,

    #[error("invalid block approvals number format")]
    InvalidApprovalsNumber,

    #[error("invalid format of a block approval with index {0}")]
    InvalidApproval(usize),

    #[error("failed to decode block' content: {0}")]
    DecodeContent(#[from] BlockContentDecodeError)
}

#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum BlockContentDecodeError {
    #[error("block content is too short: {got} bytes got, at least {expected} expected")]
    TooShort {
        got: usize,
        expected: usize
    },

    #[error("unsupported block content format: {0:0X}")]
    UnsupportedFormat(u8),

    #[error("invalid transaction len format in the transactions block's content")]
    TransactionsInvalidTransactionLen,

    #[error("failed to decode transaction from the transactions block's content: {0}")]
    DecodeTransaction(#[from] TransactionDecodeError),

    #[error("invalid content size of the validators block")]
    ValidatorsInvalidSize,

    #[error("invalid verifying key format in the validators block's content")]
    ValidatorsInvalidVerifyingKey
}

/// Block validation status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockStatus {
    /// Block is valid and approved by enough amount of validators.
    Approved {
        /// Hash of the block.
        hash: Hash,

        /// Verifying key of the block's author.
        verifying_key: VerifyingKey,

        /// Amount of required approvals.
        required_approvals: usize,

        /// List of valid approvals and their signer's verifying key.
        approvals: Vec<(Signature, VerifyingKey)>
    },

    /// Block is valid but not approved by enough amount of validators.
    NotApproved {
        /// Hash of the block.
        hash: Hash,

        /// Verifying key of the block's author.
        verifying_key: VerifyingKey,

        /// Amount of required approvals.
        required_approvals: usize,

        /// List of valid approvals and their signer's verifying key.
        approvals: Vec<(Signature, VerifyingKey)>
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
        verifying_key: impl Into<VerifyingKey>,
        approvals: impl IntoIterator<Item = &'a Signature>,
        validators: impl AsRef<[VerifyingKey]>
    ) -> Result<Self, SignatureError> {
        let block_hash: Hash = block_hash.into();
        let verifying_key: VerifyingKey = verifying_key.into();

        let validators = validators.as_ref();

        // Immediately reject the block if its signer is not a validator.
        if !validators.is_empty() && !validators.contains(&verifying_key) {
            return Ok(BlockStatus::Invalid);
        }

        // Iterate over the block's approvals.
        let mut valid_approvals = Vec::new();

        for approval in approvals {
            // Verify that approval is correct.
            let (valid, approval_public_key) = approval.verify(block_hash)?;

            // Reject invalid approval, approvals from non-validators and
            // self-approvals from the block's author.
            if !valid
                || (!validators.is_empty() && !validators.contains(&verifying_key))
                || approval_public_key == verifying_key
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
                verifying_key,
                required_approvals,
                approvals: valid_approvals
            });
        }

        Ok(Self::Approved {
            hash: block_hash,
            verifying_key,
            required_approvals,
            approvals: valid_approvals
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub(crate) previous_hash: Hash,
    pub(crate) current_hash: Hash,
    pub(crate) timestamp: UtcDateTime,
    pub(crate) content: BlockContent,
    pub(crate) sign: Signature,
    pub(crate) approvals: Vec<Signature>
}

impl Block {
    /// Create new block from provided previous block's hash and content using
    /// validator's signing key.
    pub fn new(
        signing_key: impl AsRef<SigningKey>,
        previous_hash: impl Into<Hash>,
        content: impl Into<BlockContent>
    ) -> Result<Self, SignatureError> {
        let previous_hash: Hash = previous_hash.into();
        let content: BlockContent = content.into();

        let timestamp = UtcDateTime::now()
            .replace_nanosecond(0)
            .unwrap_or_else(|_| UtcDateTime::now());

        let mut hasher = Hasher::new();

        hasher.update(previous_hash.as_bytes());
        hasher.update(timestamp.unix_timestamp().to_le_bytes());
        hasher.update(content.to_bytes());

        let current_hash = hasher.finalize();

        let sign = Signature::create(signing_key, current_hash)?;

        Ok(Self {
            previous_hash,
            current_hash,
            timestamp,
            content,
            sign,
            approvals: vec![]
        })
    }

    /// Hash of the previous block.
    #[inline(always)]
    pub const fn previous_hash(&self) -> &Hash {
        &self.previous_hash
    }

    /// Hash of the current block.
    ///
    /// This value is pre-calculated for performance reasons and is stored in
    /// the struct, so no computations are performed.
    #[inline(always)]
    pub const fn current_hash(&self) -> &Hash {
        &self.current_hash
    }

    /// Current block creation timestamp (up to seconds precision).
    #[inline(always)]
    pub const fn timestamp(&self) -> &UtcDateTime {
        &self.timestamp
    }

    /// Content of the current block.
    #[inline(always)]
    pub const fn content(&self) -> &BlockContent {
        &self.content
    }

    /// Signature of the current block.
    #[inline(always)]
    pub const fn sign(&self) -> &Signature {
        &self.sign
    }

    #[inline(always)]
    pub const fn approvals(&self) -> &Vec<Signature> {
        &self.approvals
    }

    /// Return `true` if the current block is root of the blockchain.
    #[inline]
    pub fn is_root(&self) -> bool {
        self.previous_hash == Hash::default()
    }

    /// Add approval signature to the block.
    ///
    /// Return `Ok(false)` if signature is not valid.
    pub fn approve(&mut self, approval: Signature) -> Result<bool, SignatureError> {
        if !self.approvals.contains(&approval) {
            let (is_valid, verifying_key) = approval.verify(self.current_hash())?;

            let (_, curr_verifying_key) = self.sign.verify(self.current_hash())?;

            if !is_valid || verifying_key == curr_verifying_key {
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
    pub fn approve_with(
        &mut self,
        signing_key: impl AsRef<SigningKey>
    ) -> Result<bool, SignatureError> {
        let approval = Signature::create(
            signing_key.as_ref(),
            self.current_hash()
        )?;

        if !self.approvals.contains(&approval) {
            let (is_valid, verifying_key) = approval.verify(self.current_hash())?;

            let (_, curr_verifying_key) = self.sign.verify(self.current_hash())?;

            if !is_valid || verifying_key == curr_verifying_key {
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
    #[inline]
    pub fn verify(
        &self
    ) -> Result<(bool, VerifyingKey), SignatureError> {
        self.sign.verify(self.current_hash())
    }

    /// Use provided validators list to verify that the block is approved.
    ///
    /// This method calls `verify` method internally as well so you don't need
    /// to do this twice.
    pub fn validate(
        &self,
        validators: &[VerifyingKey]
    ) -> Result<BlockStatus, SignatureError> {
        // Verify the block and obtain its signer.
        let (is_valid, public_key) = self.verify()?;

        // Immediately reject the block if it's not valid or its signer is not
        // a validator.
        if !is_valid || !validators.contains(&public_key) {
            return Ok(BlockStatus::Invalid);
        }

        BlockStatus::validate(
            self.current_hash,
            public_key,
            self.approvals(),
            validators
        )
    }

    /// Encode block into a binary representation.
    pub fn to_bytes(&self) -> Box<[u8]> {
        let content = self.content.to_bytes();
        let timestamp = self.timestamp.unix_timestamp();

        let mut block = Vec::with_capacity(
            1 + Hash::SIZE + Signature::SIZE + content.len()
        );

        // Format version
        block.push(0);

        // Previous block's hash
        block.extend(self.previous_hash.as_bytes());

        // Creation timestamp
        block.extend(varint::write_u64(timestamp as u64));

        // Sign
        block.extend(self.sign.to_bytes());

        // Approvals number
        block.extend(varint::write_u64(self.approvals.len() as u64));

        for approval in &self.approvals {
            // Approval signatures
            block.extend(approval.to_bytes());
        }

        // Block's content
        block.extend(content);

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
        let mut previous_hash = [0; 32];

        previous_hash.copy_from_slice(&block[1..33]);

        hasher.update(previous_hash);

        // Read block creation timestamp.
        let block = &block[33..];

        let (Some(timestamp), block) = varint::read_u64(block) else {
            return Err(BlockDecodeError::InvalidTimestamp);
        };

        hasher.update((timestamp as i64).to_le_bytes());

        let timestamp = UtcDateTime::from_unix_timestamp(timestamp as i64)
            .map_err(|_| BlockDecodeError::InvalidTimestamp)?;

        // Read the block's signature.
        let mut sign = [0; Signature::SIZE];

        sign.copy_from_slice(&block[..Signature::SIZE]);

        let block = &block[Signature::SIZE..];

        let sign = Signature::from_bytes(&sign)
            .ok_or(BlockDecodeError::InvalidSignature)?;

        // Decode block approvals number.

        let (Some(approvals_num), block) = varint::read_u64(block) else {
            return Err(BlockDecodeError::InvalidApprovalsNumber);
        };

        let approvals_num = approvals_num as usize;

        // Check that all these approvals are presented.

        // TODO: some better calculation instead of plain `3` assumption for varints.
        if n < Hash::SIZE + Signature::SIZE + 3 + approvals_num * Signature::SIZE {
            return Err(BlockDecodeError::TooShort {
                got: n,
                expected: Hash::SIZE + Signature::SIZE + 3 + approvals_num * Signature::SIZE
            });
        }

        // Decode block approvals.

        let mut approval = [0; Signature::SIZE];
        let mut approvals = Vec::with_capacity(approvals_num);

        for i in 0..approvals_num {
            approval.copy_from_slice(
                &block[i * Signature::SIZE..(i + 1) * Signature::SIZE]
            );

            let approval = Signature::from_bytes(&approval)
                .ok_or(BlockDecodeError::InvalidApproval(i))?;

            approvals.push(approval);
        }

        // Decode block content.

        let content = &block[approvals_num * Signature::SIZE..];

        hasher.update(content);

        Ok(Self {
            previous_hash: Hash::from(previous_hash),
            current_hash: hasher.finalize(),
            timestamp,
            content: BlockContent::from_bytes(content)?,
            sign,
            approvals
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockContent {
    /// Arbitrary data.
    Data(Box<[u8]>),

    /// List of approved transactions.
    Transactions(Box<[Transaction]>),

    /// List of approved validators' public keys.
    Validators(Box<[VerifyingKey]>)
}

impl BlockContent {
    pub const V1_DATA_BLOCK: u8         = 0;
    pub const V1_TRANSACTIONS_BLOCK: u8 = 1;
    pub const V1_VALIDATORS_BLOCK: u8   = 2;

    /// Create new data block.
    #[inline]
    pub fn data(data: impl Into<Box<[u8]>>) -> Self {
        Self::Data(data.into())
    }

    /// Create new transactions block.
    pub fn transactions<T: Into<Transaction>>(
        transactions: impl IntoIterator<Item = T>
    ) -> Self {
        Self::Transactions(transactions.into_iter().map(T::into).collect())
    }

    /// Create new validators block.
    pub fn validators<T: Into<VerifyingKey>>(
        public_keys: impl IntoIterator<Item = T>
    ) -> Self {
        Self::Validators(public_keys.into_iter().map(T::into).collect())
    }

    /// Encode block's content into bytes representation.
    pub fn to_bytes(&self) -> Box<[u8]> {
        let mut content = Vec::new();

        match self {
            Self::Data(data) => {
                content.push(Self::V1_DATA_BLOCK);
                content.extend_from_slice(data);
            }

            Self::Transactions(transactions) => {
                content.push(Self::V1_TRANSACTIONS_BLOCK);

                for transaction in transactions {
                    let transaction = transaction.to_bytes();

                    content.extend(varint::write_u64(transaction.len() as u64));
                    content.extend(transaction);
                }
            }

            Self::Validators(validators) => {
                content.push(Self::V1_VALIDATORS_BLOCK);

                for validator in validators {
                    content.extend(validator.to_bytes());
                }
            }
        }

        content.into_boxed_slice()
    }

    /// Decode block's content from bytes representation.
    pub fn from_bytes(
        content: impl AsRef<[u8]>
    ) -> Result<Self, BlockContentDecodeError> {
        let content = content.as_ref();
        let n = content.len();

        if n == 0 {
            return Err(BlockContentDecodeError::TooShort {
                got: n,
                expected: 1
            });
        }

        match content[0] {
            Self::V1_DATA_BLOCK => {
                if n == 1 {
                    Ok(Self::Data(Box::new([])))
                } else {
                    Ok(Self::Data(content[1..].to_vec().into_boxed_slice()))
                }
            }

            Self::V1_TRANSACTIONS_BLOCK => {
                // Empty transactions block
                if n == 1 {
                    return Ok(Self::Transactions(Box::new([])));
                }

                let mut content = &content[1..];

                let mut transactions = Vec::new();

                while !content.is_empty() {
                    let (Some(transaction_len), new_content) = varint::read_u64(content) else {
                        return Err(BlockContentDecodeError::TransactionsInvalidTransactionLen);
                    };

                    let transaction_len = transaction_len as usize;

                    content = new_content;

                    if content.len() < transaction_len {
                        return Err(BlockContentDecodeError::TooShort {
                            got: content.len(),
                            expected: transaction_len
                        });
                    }

                    let transaction = Transaction::from_bytes(
                        &content[..transaction_len]
                    )?;

                    content = &content[transaction_len..];

                    transactions.push(transaction);
                }

                Ok(Self::Transactions(transactions.into_boxed_slice()))
            }

            Self::V1_VALIDATORS_BLOCK => {
                if (n - 1) % 33 != 0 {
                    return Err(BlockContentDecodeError::ValidatorsInvalidSize);
                }

                let mut validators = Vec::with_capacity((n - 1) / 33);
                let mut i = 1;

                let mut validator = [0; VerifyingKey::SIZE];

                while i < n {
                    validator.copy_from_slice(&content[i..i + VerifyingKey::SIZE]);

                    let validator = VerifyingKey::from_bytes(&validator)
                        .ok_or(BlockContentDecodeError::ValidatorsInvalidVerifyingKey)?;

                    validators.push(validator);

                    i += VerifyingKey::SIZE;
                }

                Ok(Self::Validators(validators.into_boxed_slice()))
            }

            format => Err(BlockContentDecodeError::UnsupportedFormat(format))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_blocks() -> Result<(SigningKey, Vec<Block>), SignatureError> {
        use rand_chacha::rand_core::SeedableRng;

        let mut rand = rand_chacha::ChaCha20Rng::seed_from_u64(123);

        let signing_key = SigningKey::random(&mut rand);

        let mut blocks = Vec::with_capacity(3);

        // Data block

        let content = BlockContent::data(b"Hello, World!".as_slice());

        blocks.push(Block::new(&signing_key, Hash::default(), content)?);

        // Transactions block

        let content = BlockContent::transactions([
            Transaction::create(&signing_key, b"Transaction 1".as_slice())?,
            Transaction::create(&signing_key, b"Transaction 2".as_slice())?,
            Transaction::create(&signing_key, b"Transaction 3".as_slice())?
        ]);

        blocks.push(Block::new(&signing_key, Hash::default(), content)?);

        // Validators block

        let content = BlockContent::validators([
            signing_key.verifying_key()
        ]);

        blocks.push(Block::new(&signing_key, Hash::default(), content)?);

        Ok((signing_key, blocks))
    }

    #[test]
    fn validate() -> Result<(), SignatureError> {
        let (signing_key, blocks) = get_blocks()?;

        for block in blocks {
            let (is_valid, verifying_key) = block.verify()?;

            assert!(is_valid);
            assert_eq!(verifying_key, signing_key.verifying_key());
        }

        Ok(())
    }

    #[test]
    fn serialize() -> Result<(), Box<dyn std::error::Error>> {
        let (_, blocks) = get_blocks()?;

        for block in blocks {
            let serialized = block.to_bytes();

            assert_eq!(Block::from_bytes(serialized)?, block);
        }

        Ok(())
    }
}
