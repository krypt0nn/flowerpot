use std::io::{Read, Cursor};

use time::UtcDateTime;
use varint_rs::{VarintReader, VarintWriter};

use crate::crypto::*;
use crate::transaction::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    previous: Hash,
    timestamp: UtcDateTime,
    content: BlockContent,
    sign: Signature,
    approvals: Vec<Signature>
}

impl Block {
    /// Create new block from provided previous block's hash and content using
    /// validator's secret key.
    pub fn new(
        validator: &SecretKey,
        previous: impl Into<Hash>,
        content: impl Into<BlockContent>
    ) -> std::io::Result<Self> {
        let previous: Hash = previous.into();
        let content: BlockContent = content.into();

        let timestamp = UtcDateTime::now();

        let mut hasher = blake3::Hasher::new();

        hasher.update(&previous.0);
        hasher.update(&timestamp.unix_timestamp().to_be_bytes());
        hasher.update(&content.to_bytes()?);

        let hash = Hash::from(hasher.finalize());

        let sign = Signature::create(validator, hash)
            .map_err(std::io::Error::other)?;

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

    /// Add approval signature to the block.
    ///
    /// Return `Ok(false)` if signature is not valid.
    pub fn approve(&mut self, sign: Signature) -> std::io::Result<bool> {
        if !self.approvals.contains(&sign) {
            let (valid, _) = sign.verify(self.hash()?)
                .map_err(std::io::Error::other)?;

            if !valid {
                return Ok(false);
            }

            self.approvals.push(sign);
        }

        Ok(true)
    }

    /// Calculate hash of the current block.
    pub fn hash(&self) -> std::io::Result<Hash> {
        let mut hasher = blake3::Hasher::new();

        hasher.update(&self.previous.0);
        hasher.update(&self.timestamp.unix_timestamp().to_be_bytes());
        hasher.update(&self.content.to_bytes()?);

        Ok(Hash::from(hasher.finalize()))
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

        Ok(block.into_boxed_slice())
    }

    /// Decode block from bytes representation.
    pub fn from_bytes(block: impl AsRef<[u8]>) -> std::io::Result<Self> {
        let block = block.as_ref();

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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockContent {
    /// List of approved validators' public keys.
    Validators(Box<[PublicKey]>),

    /// List of approved transactions.
    Transactions(Box<[Transaction]>)
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

            _ => Err(std::io::Error::other("unknown block content format"))
        }
    }
}
