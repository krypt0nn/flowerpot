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

use std::collections::VecDeque;
use std::io::{Read, Cursor};

use varint_rs::*;

use crate::crypto::*;
use crate::block::Block;
use crate::transaction::Transaction;
use crate::network::Stream;

#[derive(Debug, thiserror::Error)]
pub enum PacketError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("unknown packet type: {0}")]
    UnknownPacketType(u8),

    #[error("provided packet bytes slice is too short")]
    PacketTooShort,

    #[error("couldn't deserialize signature from invalid bytes slice")]
    InvalidSignature
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    /// Heartbeat (keep alive) packet.
    Heartbeat,

    /// Ask history of a blockchain.
    AskHistory {
        /// Hash of the blockchain's root block.
        root_block: Hash,

        /// Index of the starting block.
        offset: u64,

        /// Maximal amount of blocks to return.
        max_length: u64
    },

    /// Slice of a blockchain's history.
    History {
        /// Hash of the blockchain's root block.
        root_block: Hash,

        /// Index of the first block in the returned history slice.
        offset: u64,

        /// Slice of the blockchain's history.
        history: Box<[Hash]>
    },

    /// Ask list of blockchain's pending blocks.
    AskPendingBlocks {
        /// Hash of the blockchain's root block.
        root_block: Hash
    },

    /// List of pending blocks of a blockchain.
    PendingBlocks {
        /// Hash of the blockchain's root block.
        root_block: Hash,

        /// List of pending blocks' hashes and their approval signatures.
        pending_blocks: Box<[(Hash, Box<[Signature]>)]>
    },

    /// Ask list of blockchain's pending transactions.
    AskPendingTransactions {
        /// Hash of the blockchain's root block.
        root_block: Hash
    },

    /// List of pending transactions of a blockchain.
    PendingTransactions {
        /// Hash of the blockchain's root block.
        root_block: Hash,

        /// List of pending transactions' hashes.
        pending_transactions: Box<[Hash]>
    },

    /// Ask block of a blockchain.
    AskBlock {
        /// Hash of the blockchain's root block.
        root_block: Hash,

        /// Hash of the block you want to receive.
        target_block: Hash
    },

    /// Block of a blockchain.
    Block {
        /// Hash of the blockchain's root block.
        root_block: Hash,

        /// Block of the blockchain.
        block: Block
    },

    /// Ask transaction from a blockchain.
    AskTransaction {
        /// Hash of the blockchain's root block.
        root_block: Hash,

        /// Hash of the transaction you want to receive.
        transaction: Hash
    },

    /// Transaction of a blockchain.
    Transaction {
        /// Hash of the blockchain's root block.
        root_block: Hash,

        /// Transaction of the blockchain.
        transaction: Transaction
    },

    /// Approve block of a blockchain.
    ApproveBlock {
        /// Hash of the blockchain's root block.
        root_block: Hash,

        /// Hash of the block you want to approve.
        target_block: Hash,

        /// Approval signature.
        approval: Signature
    }
}

impl Packet {
    pub const V1_HEARTBEAT: u8                = 0;
    pub const V1_ASK_HISTORY: u8              = 1;
    pub const V1_HISTORY: u8                  = 2;
    pub const V1_ASK_PENDING_BLOCKS: u8       = 3;
    pub const V1_PENDING_BLOCKS: u8           = 4;
    pub const V1_ASK_PENDING_TRANSACTIONS: u8 = 5;
    pub const V1_PENDING_TRANSACTIONS: u8     = 6;
    pub const V1_ASK_BLOCK: u8                = 7;
    pub const V1_BLOCK: u8                    = 8;
    pub const V1_ASK_TRANSACTION: u8          = 9;
    pub const V1_TRANSACTION: u8              = 10;
    pub const V1_APPROVE_BLOCK: u8            = 11;

    /// Convert current packet to the bytes slice.
    pub fn to_bytes(&self) -> Result<Box<[u8]>, PacketError> {
        match self {
            Self::Heartbeat => Ok(Box::new([Self::V1_HEARTBEAT])),

            Self::AskHistory {
                root_block,
                offset,
                max_length
            } => {
                let mut buf = Vec::new();

                buf.push(Self::V1_ASK_HISTORY);

                buf.extend_from_slice(&root_block.0);
                buf.write_u64_varint(*offset)?;
                buf.write_u64_varint(*max_length)?;

                Ok(buf.into_boxed_slice())
            }

            Self::History {
                root_block,
                offset,
                history
            } => {
                let mut buf = Vec::new();

                buf.push(Self::V1_HISTORY);

                buf.extend_from_slice(&root_block.0);
                buf.write_u64_varint(*offset)?;

                for hash in history {
                    buf.extend_from_slice(&hash.0);
                }

                Ok(buf.into_boxed_slice())
            }

            Self::AskPendingBlocks { root_block } => {
                let mut buf = [0; 33];

                buf[0] = Self::V1_ASK_PENDING_BLOCKS;

                buf[1..].copy_from_slice(&root_block.0);

                Ok(Box::new(buf))
            }

            Self::PendingBlocks { root_block, pending_blocks } => {
                let mut buf = Vec::new();

                buf.push(Self::V1_PENDING_BLOCKS);

                buf.extend_from_slice(&root_block.0);

                for (hash, approvals) in pending_blocks {
                    buf.extend_from_slice(&hash.0);

                    buf.write_usize_varint(approvals.len())?;

                    for approval in approvals {
                        buf.extend_from_slice(&approval.to_bytes());
                    }
                }

                Ok(buf.into_boxed_slice())
            }

            Self::AskPendingTransactions { root_block } => {
                let mut buf = [0; 33];

                buf[0] = Self::V1_ASK_PENDING_TRANSACTIONS;

                buf[1..].copy_from_slice(&root_block.0);

                Ok(Box::new(buf))
            }

            Self::PendingTransactions { root_block, pending_transactions } => {
                let mut buf = Vec::new();

                buf.push(Self::V1_PENDING_TRANSACTIONS);

                buf.extend_from_slice(&root_block.0);

                for hash in pending_transactions {
                    buf.extend_from_slice(&hash.0);
                }

                Ok(buf.into_boxed_slice())
            }

            Self::AskBlock { root_block, target_block } => {
                let mut buf = [0; 65];

                buf[0] = Self::V1_ASK_BLOCK;

                buf[1..33].copy_from_slice(&root_block.0);
                buf[33..65].copy_from_slice(&target_block.0);

                Ok(Box::new(buf))
            }

            Self::Block { root_block, block } => {
                let mut buf = Vec::new();

                buf.push(Self::V1_BLOCK);

                buf.extend_from_slice(&root_block.0);
                buf.extend(block.to_bytes()?);

                Ok(buf.into_boxed_slice())
            }

            Self::AskTransaction { root_block, transaction } => {
                let mut buf = [0; 65];

                buf[0] = Self::V1_ASK_TRANSACTION;

                buf[1..33].copy_from_slice(&root_block.0);
                buf[33..].copy_from_slice(&transaction.0);

                Ok(Box::new(buf))
            }

            Self::Transaction { root_block, transaction } => {
                let mut buf = Vec::new();

                buf.push(Self::V1_TRANSACTION);

                buf.extend_from_slice(&root_block.0);
                buf.extend(transaction.to_bytes()?);

                Ok(buf.into_boxed_slice())
            }

            Self::ApproveBlock {
                root_block,
                target_block,
                approval
            } => {
                let mut buf = [0; 130];

                buf[0] = Self::V1_APPROVE_BLOCK;

                buf[1..33].copy_from_slice(&root_block.0);
                buf[33..65].copy_from_slice(&target_block.0);
                buf[65..].copy_from_slice(&approval.to_bytes());

                Ok(Box::new(buf))
            }
        }
    }

    /// Convert bytes slice to a packet.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, PacketError> {
        let bytes = bytes.as_ref();

        if bytes.is_empty() {
            return Err(PacketError::PacketTooShort);
        }

        match bytes[0] {
            Self::V1_HEARTBEAT => Ok(Self::Heartbeat),

            Self::V1_ASK_HISTORY => {
                if bytes.len() < 35 {
                    return Err(PacketError::PacketTooShort);
                }

                let mut root_block = [0; 32];

                root_block.copy_from_slice(&bytes[1..33]);

                let mut bytes = Cursor::new(bytes[33..].to_vec());

                let offset = bytes.read_u64_varint()?;
                let max_length = bytes.read_u64_varint()?;

                Ok(Self::AskHistory {
                    root_block: Hash::from(root_block),
                    offset,
                    max_length
                })
            }

            Self::V1_HISTORY => {
                if bytes.len() < 33 {
                    return Err(PacketError::PacketTooShort);
                }

                let mut root_block = [0; 32];

                root_block.copy_from_slice(&bytes[1..33]);

                let mut bytes = Cursor::new(bytes[33..].to_vec());

                let offset = bytes.read_u64_varint()?;

                let mut history = Vec::new();
                let mut hash = [0; 32];

                while bytes.read_exact(&mut hash).is_ok() {
                    history.push(Hash::from(hash));
                }

                Ok(Self::History {
                    root_block: Hash::from(root_block),
                    offset,
                    history: history.into_boxed_slice()
                })
            }

            Self::V1_ASK_PENDING_BLOCKS => {
                if bytes.len() < 33 {
                    return Err(PacketError::PacketTooShort);
                }

                let mut root_block = [0; 32];

                root_block.copy_from_slice(&bytes[1..33]);

                Ok(Self::AskPendingBlocks {
                    root_block: Hash::from(root_block)
                })
            },

            Self::V1_PENDING_BLOCKS => {
                if bytes.len() < 33 {
                    return Err(PacketError::PacketTooShort);
                }

                let mut root_block = [0; 32];

                root_block.copy_from_slice(&bytes[1..33]);

                let mut bytes = Cursor::new(bytes[33..].to_vec());

                let mut hash = [0; 32];
                let mut approval = [0; 65];

                let mut blocks = Vec::new();

                while bytes.read_exact(&mut hash).is_ok() {
                    let len = bytes.read_usize_varint()?;

                    let mut approvals = Vec::with_capacity(len);

                    for _ in 0..len {
                        bytes.read_exact(&mut approval)?;

                        let Some(approval) = Signature::from_bytes(approval) else {
                            return Err(PacketError::InvalidSignature);
                        };

                        approvals.push(approval);
                    }

                    blocks.push((
                        Hash::from(hash),
                        approvals.into_boxed_slice()
                    ));
                }

                Ok(Self::PendingBlocks {
                    root_block: Hash::from(root_block),
                    pending_blocks: blocks.into_boxed_slice()
                })
            }

            Self::V1_ASK_PENDING_TRANSACTIONS => {
                if bytes.len() < 33 {
                    return Err(PacketError::PacketTooShort);
                }

                let mut root_block = [0; 32];

                root_block.copy_from_slice(&bytes[1..33]);

                Ok(Self::AskPendingTransactions {
                    root_block: Hash::from(root_block)
                })
            }

            Self::V1_PENDING_TRANSACTIONS => {
                if bytes.len() < 33 {
                    return Err(PacketError::PacketTooShort);
                }

                let mut root_block = [0; 32];

                root_block.copy_from_slice(&bytes[1..33]);

                let mut bytes = Cursor::new(bytes[33..].to_vec());
                let mut hash = [0; 32];

                let mut transactions = Vec::new();

                while bytes.read_exact(&mut hash).is_ok() {
                    transactions.push(Hash::from(hash));
                }

                Ok(Self::PendingTransactions {
                    root_block: Hash::from(root_block),
                    pending_transactions: transactions.into_boxed_slice()
                })
            }

            Self::V1_ASK_BLOCK => {
                if bytes.len() < 65 {
                    return Err(PacketError::PacketTooShort);
                }

                let mut root_block = [0; 32];
                let mut target_block = [0; 32];

                root_block.copy_from_slice(&bytes[1..33]);
                target_block.copy_from_slice(&bytes[33..65]);

                Ok(Self::AskBlock {
                    root_block: Hash::from(root_block),
                    target_block: Hash::from(target_block)
                })
            }

            Self::V1_BLOCK => {
                if bytes.len() < 33 {
                    return Err(PacketError::PacketTooShort);
                }

                let mut root_block = [0; 32];

                root_block.copy_from_slice(&bytes[1..33]);

                Ok(Self::Block {
                    root_block: Hash::from(root_block),
                    block: Block::from_bytes(&bytes[33..])?
                })
            }

            Self::V1_ASK_TRANSACTION => {
                if bytes.len() < 65 {
                    return Err(PacketError::PacketTooShort);
                }

                let mut root_block = [0; 32];
                let mut transaction = [0; 32];

                root_block.copy_from_slice(&bytes[1..33]);
                transaction.copy_from_slice(&bytes[33..65]);

                Ok(Self::AskTransaction {
                    root_block: Hash::from(root_block),
                    transaction: Hash::from(transaction)
                })
            }

            Self::V1_TRANSACTION => {
                if bytes.len() < 33 {
                    return Err(PacketError::PacketTooShort);
                }

                let mut root_block = [0; 32];

                root_block.copy_from_slice(&bytes[1..33]);

                Ok(Self::Transaction {
                    root_block: Hash::from(root_block),
                    transaction: Transaction::from_bytes(&bytes[33..])?
                })
            }

            Self::V1_APPROVE_BLOCK => {
                if bytes.len() < 130 {
                    return Err(PacketError::PacketTooShort);
                }

                let mut root_block = [0; 32];
                let mut target_block = [0; 32];
                let mut approval = [0; 65];

                root_block.copy_from_slice(&bytes[1..33]);
                target_block.copy_from_slice(&bytes[33..65]);
                approval.copy_from_slice(&bytes[65..]);

                let Some(approval) = Signature::from_bytes(approval) else {
                    return Err(PacketError::InvalidSignature);
                };

                Ok(Self::ApproveBlock {
                    root_block: Hash::from(root_block),
                    target_block: Hash::from(target_block),
                    approval
                })
            }

            packet_type => Err(PacketError::UnknownPacketType(packet_type))
        }
    }
}

impl AsRef<Packet> for Packet {
    #[inline(always)]
    fn as_ref(&self) -> &Packet {
        self
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PacketStreamError<S: Stream> {
    #[error(transparent)]
    Stream(S::Error),

    #[error(transparent)]
    Packet(#[from] PacketError),

    #[error("unsupported protocol version: {0}")]
    UnsupportedProtocolVersion(u8),

    #[error("invalid ecdh public key")]
    InvalidPublicKey,

    #[error("failed to build data stream encryptor")]
    EncryptorBuildFailed,

    #[error("remote endpoint sent invalid shared secret image")]
    InvalidSharedSecretImage,

    #[error("packet is too large to be sent over the network")]
    PacketTooLarge
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PacketStreamEncryption {
    ChaCha20,
    ChaCha12,
    ChaCha8
}

use chacha20::cipher::{KeyIvInit, StreamCipher};

pub enum PacketStreamEncryptor {
    ChaCha20(chacha20::ChaCha20),
    ChaCha12(chacha20::ChaCha12),
    ChaCha8(chacha20::ChaCha8)
}

impl PacketStreamEncryptor {
    /// Try to build new stream encryptor with provided algorithm, key and
    /// initialization vector.
    pub fn new(
        algorithm: &PacketStreamEncryption,
        key: &[u8],
        iv: &[u8]
    ) -> Option<Self> {
        match algorithm {
            PacketStreamEncryption::ChaCha20 |
            PacketStreamEncryption::ChaCha12 |
            PacketStreamEncryption::ChaCha8 => {
                let mut key_scaled = [0; 32];
                let mut iv_scaled = [0; 32];

                if key.len() == 32 {
                    key_scaled.copy_from_slice(key);
                } else {
                    key_scaled.copy_from_slice(blake3::hash(key).as_bytes());
                }

                if iv.len() == 32 {
                    iv_scaled.copy_from_slice(iv);
                } else {
                    iv_scaled.copy_from_slice(blake3::hash(iv).as_bytes());
                }

                match algorithm {
                    PacketStreamEncryption::ChaCha20 => {
                        let encryptor = chacha20::ChaCha20::new_from_slices(
                            &key_scaled,
                            &iv_scaled
                        ).ok()?;

                        Some(Self::ChaCha20(encryptor))
                    }

                    PacketStreamEncryption::ChaCha12 => {
                        let encryptor = chacha20::ChaCha12::new_from_slices(
                            &key_scaled,
                            &iv_scaled
                        ).ok()?;

                        Some(Self::ChaCha12(encryptor))
                    }

                    PacketStreamEncryption::ChaCha8 => {
                        let encryptor = chacha20::ChaCha8::new_from_slices(
                            &key_scaled,
                            &iv_scaled
                        ).ok()?;

                        Some(Self::ChaCha8(encryptor))
                    }
                }
            }
        }
    }

    /// Apply stream encryption to the provided buffer.
    pub fn apply(&mut self, buf: &mut [u8]) {
        match self {
            Self::ChaCha20(encryptor) => encryptor.apply_keystream(buf),
            Self::ChaCha12(encryptor) => encryptor.apply_keystream(buf),
            Self::ChaCha8(encryptor)  => encryptor.apply_keystream(buf)
        }
    }
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Hash)]
pub struct PacketStreamOptions {
    /// List of encryption algorithms which can be used by the packet stream.
    ///
    /// The packet stream will choose the best option supported by both parties.
    ///
    /// Set this value as an empty vector if you don't want to encrypt the
    /// transport stream.
    ///
    /// > **Note**: encryption is not needed for blockchain applications since
    /// > blockchain by its nature is open for everybody. This option is mainly
    /// > needed to hide your traffic.
    pub encryption_algorithms: Vec<PacketStreamEncryption>
}

/// Abstraction over a transport protocol data stream which supports packets
/// sending and receiving, endpoint validation and optional stream encryption.
pub struct PacketStream<S: Stream> {
    stream: S,
    endpoint_id: [u8; 32],
    shared_secret: [u8; 32],
    read_encryptor: Option<PacketStreamEncryptor>,
    write_encryptor: Option<PacketStreamEncryptor>,
    peek_queue: VecDeque<Packet>
}

impl<S: Stream> PacketStream<S> {
    pub const V1_HEADER: u8 = 0;

    pub const V1_CHACHA20_ENCRYPTION: u8 = 0b00000001;
    pub const V1_CHACHA12_ENCRYPTION: u8 = 0b00000010;
    pub const V1_CHACHA8_ENCRYPTION: u8  = 0b00000100;

    // Salts were randomly generated using random.org service.

    pub const V1_ENDPOINT_ID_SALT: [u8; 32] = [
        140,  51,  88,  13, 199, 162, 187,  90,
        203, 253, 146, 211,  38, 233,  64,  94,
         22, 149,  33, 125, 120, 238, 151, 247,
        127, 246, 157, 130, 236, 197, 255,  50
    ];

    pub const V1_SHARED_SECRET_SALT1: [u8; 32] = [
         20, 160,  28, 119, 111,  25, 178, 249,
        152, 100, 103,  76, 168, 239, 116, 134,
        137, 241, 219, 175, 196, 216,  61, 227,
        170, 192, 145, 228,  73,   7, 150, 224
    ];

    pub const V1_SHARED_SECRET_SALT2: [u8; 32] = [
        235, 214, 153, 167,  37, 128, 221,  65,
        240, 229, 201,  26,  23, 135,  48, 161,
        107, 251, 212,  57, 252,  55, 131,  60,
        190,   5,  67,  43,  71, 194, 198, 159
    ];

    /// Initialize packet stream connection using the underlying transport
    /// stream.
    ///
    /// This method will exchange some handshake info, read incoming data and
    /// if handshake was successful - provide simple interface to send and
    /// receive packets over the network.
    pub async fn new(
        secret_key: &k256::ecdh::EphemeralSecret,
        options: PacketStreamOptions,
        mut stream: S
    ) -> Result<Self, PacketStreamError<S>> {
        // Prepare public key for key exchange.
        let public_key = secret_key.public_key()
            .to_sec1_bytes();

        let public_key_len = public_key.len();

        assert!(public_key_len <= u8::MAX as usize);

        let public_key_len = public_key_len as u8;

        // Prepare options byte.
        let mut options_byte = 0b00000000;

        for algorithm in &options.encryption_algorithms {
            options_byte |= match algorithm {
                PacketStreamEncryption::ChaCha20 => Self::V1_CHACHA20_ENCRYPTION,
                PacketStreamEncryption::ChaCha12 => Self::V1_CHACHA12_ENCRYPTION,
                PacketStreamEncryption::ChaCha8  => Self::V1_CHACHA8_ENCRYPTION
            };
        }

        // Send header, options and public key length.
        stream.write(&[
            Self::V1_HEADER,
            options_byte,
            public_key_len
        ]).await.map_err(PacketStreamError::Stream)?;

        // Send public key.
        stream.write(&public_key).await
            .map_err(PacketStreamError::Stream)?;

        stream.flush().await
            .map_err(PacketStreamError::Stream)?;

        // Read protocol version from the header byte.
        let mut buf = [0; 1];

        stream.read_exact(&mut buf).await
            .map_err(PacketStreamError::Stream)?;

        if buf[0] != Self::V1_HEADER {
            return Err(PacketStreamError::UnsupportedProtocolVersion(buf[0]));
        }

        // Read options and public key length.
        let mut buf = [0; 2];

        stream.read_exact(&mut buf).await
            .map_err(PacketStreamError::Stream)?;

        // Read public key.
        let mut public_key = vec![0; buf[1] as usize];

        stream.read_exact(&mut public_key).await
            .map_err(PacketStreamError::Stream)?;

        let endpoint_id = blake3::keyed_hash(
            &Self::V1_ENDPOINT_ID_SALT,
            &public_key
        );

        let public_key = k256::PublicKey::from_sec1_bytes(&public_key)
            .map_err(|_| PacketStreamError::InvalidPublicKey)?;

        // Prepare shared secret.
        let shared_secret = secret_key.diffie_hellman(&public_key);

        let shared_secret = blake3::keyed_hash(
            &Self::V1_SHARED_SECRET_SALT1,
            shared_secret.raw_secret_bytes()
        );

        let shared_secret_image = blake3::keyed_hash(
            &Self::V1_SHARED_SECRET_SALT2,
            shared_secret.as_bytes()
        );

        // Decode options.
        let mut supported_encryption = Vec::with_capacity(3);

        if buf[0] & Self::V1_CHACHA20_ENCRYPTION == Self::V1_CHACHA20_ENCRYPTION {
            supported_encryption.push(PacketStreamEncryption::ChaCha20);
        }

        if buf[0] & Self::V1_CHACHA12_ENCRYPTION == Self::V1_CHACHA12_ENCRYPTION {
            supported_encryption.push(PacketStreamEncryption::ChaCha12);
        }

        if buf[0] & Self::V1_CHACHA8_ENCRYPTION == Self::V1_CHACHA8_ENCRYPTION {
            supported_encryption.push(PacketStreamEncryption::ChaCha8);
        }

        // Choose common encryption algorithm.
        let mut encryption_algorithm = None;

        for algorithm in &options.encryption_algorithms {
            if supported_encryption.contains(algorithm) {
                encryption_algorithm = Some(*algorithm);

                break;
            }
        }

        // Prepare read and write encryptors.
        let mut read_encryptor = match &encryption_algorithm {
            Some(algorithm) => {
                Some(PacketStreamEncryptor::new(
                    algorithm,
                    shared_secret.as_bytes(),
                    endpoint_id.as_bytes()
                ).ok_or_else(|| PacketStreamError::EncryptorBuildFailed)?)
            }

            None => None
        };

        let mut write_encryptor = match &encryption_algorithm {
            Some(algorithm) => {
                Some(PacketStreamEncryptor::new(
                    algorithm,
                    shared_secret.as_bytes(),
                    endpoint_id.as_bytes()
                ).ok_or_else(|| PacketStreamError::EncryptorBuildFailed)?)
            }

            None => None
        };

        // Send shared secret image.
        let mut buf: [u8; 32] = *shared_secret_image.as_bytes();

        if let Some(encryptor) = &mut write_encryptor {
            encryptor.apply(&mut buf);
        }

        stream.write(&buf).await
            .map_err(PacketStreamError::Stream)?;

        stream.flush().await
            .map_err(PacketStreamError::Stream)?;

        // Read shared secret image.
        let mut buf = [0; 32];

        stream.read_exact(&mut buf).await
            .map_err(PacketStreamError::Stream)?;

        if let Some(encryptor) = &mut read_encryptor {
            encryptor.apply(&mut buf);
        }

        if &buf != shared_secret_image.as_bytes() {
            return Err(PacketStreamError::InvalidSharedSecretImage);
        }

        Ok(Self {
            stream,
            endpoint_id: endpoint_id.into(),
            shared_secret: shared_secret.into(),
            read_encryptor,
            write_encryptor,
            peek_queue: VecDeque::new()
        })
    }

    /// Get unique identifier of the stream's remote endpoint.
    ///
    /// It is derived from the remote party's public key and can be used to
    /// keep only one connection with the same remote endpoint at once.
    #[inline(always)]
    pub const fn endpoint_id(&self) -> &[u8; 32] {
        &self.endpoint_id
    }

    /// Get shared secret for this stream.
    #[inline(always)]
    pub const fn shared_secret(&self) -> &[u8; 32] {
        &self.shared_secret
    }

    /// Send packet.
    pub async fn send(
        &mut self,
        packet: impl AsRef<Packet>
    ) -> Result<(), PacketStreamError<S>> {
        let mut packet = packet.as_ref()
            .to_bytes()
            .map_err(PacketStreamError::Packet)?;

        let length = packet.len();

        if length > u32::MAX as usize {
            return Err(PacketStreamError::PacketTooLarge);
        }

        let mut length: [u8; 4] = (length as u32).to_le_bytes();

        if let Some(encryptor) = &mut self.write_encryptor {
            encryptor.apply(&mut length);
            encryptor.apply(&mut packet);
        }

        self.stream.write(&length).await
            .map_err(PacketStreamError::Stream)?;

        self.stream.write(&packet).await
            .map_err(PacketStreamError::Stream)?;

        self.stream.flush().await
            .map_err(PacketStreamError::Stream)?;

        Ok(())
    }

    /// Receive packet.
    pub async fn recv(&mut self) -> Result<Packet, PacketStreamError<S>> {
        if let Some(packet) = self.peek_queue.pop_front() {
            return Ok(packet);
        }

        let mut length = [0; 4];

        self.stream.read_exact(&mut length).await
            .map_err(PacketStreamError::Stream)?;

        let mut packet = vec![0; u32::from_le_bytes(length) as usize];

        self.stream.read_exact(&mut packet).await
            .map_err(PacketStreamError::Stream)?;

        if let Some(encryptor) = &mut self.read_encryptor {
            encryptor.apply(&mut length);
            encryptor.apply(&mut packet);
        }

        let packet = Packet::from_bytes(packet)
            .map_err(PacketStreamError::Packet)?;

        Ok(packet)
    }

    /// Receive packets and send them to the provided callback until it returns
    /// `true`. Packet which got `true` from the callback will be returned by
    /// this method. Other packets will be put into a queue of the `recv`
    /// method.
    ///
    /// This method can be used to search for a requested packet.
    pub async fn peek<F: Future<Output = bool>>(
        &mut self,
        mut callback: impl FnMut(&Packet) -> F
    ) -> Result<Packet, PacketStreamError<S>> {
        let mut peek_queue = Vec::new();

        loop {
            let packet = self.recv().await?;

            if callback(&packet).await {
                self.peek_queue.extend(peek_queue);

                return Ok(packet);
            }

            peek_queue.push(packet);
        }
    }
}

#[test]
fn test_serialize() -> Result<(), PacketError> {
    use rand_chacha::ChaCha8Rng;
    use rand_chacha::rand_core::SeedableRng;

    use crate::block::BlockContent;

    let mut rng = ChaCha8Rng::seed_from_u64(123);

    let secret_key = SecretKey::random(&mut rng);

    // ---------------------------------------------------------------

    macro_rules! test_packets {
        ($($packet:expr $(,)*)+) => {
            $(
                let packet = $packet;

                assert_eq!(Packet::from_bytes(packet.to_bytes()?)?, packet);
            )+
        };
    }

    test_packets!(
        Packet::Heartbeat,

        Packet::AskHistory {
            root_block: Hash::from_slice(b"Hello, World!"),
            offset: u16::MAX as u64,
            max_length: u32::MAX as u64
        },

        Packet::History {
            root_block: Hash::from_slice(b"Hello, World!"),
            offset: 376415,
            history: Box::new([
                Hash::from_slice(b"Test 1"),
                Hash::from_slice(b"Test 2"),
                Hash::from_slice(b"Test 3")
            ])
        },

        Packet::AskPendingBlocks {
            root_block: Hash::from_slice(b"Hello, World!")
        },

        Packet::PendingBlocks {
            root_block: Hash::from_slice(b"Hello, World!"),
            pending_blocks: Box::new([
                (Hash::from_slice(b"Block 1"), Box::new([])),
                (Hash::from_slice(b"Block 2"), Box::new([
                    Signature::create(&secret_key, [1; 32]).unwrap(),
                    Signature::create(&secret_key, [2; 32]).unwrap(),
                    Signature::create(&secret_key, [3; 32]).unwrap()
                ])),
                (Hash::from_slice(b"Block 3"), Box::new([
                    Signature::create(&secret_key, [4; 32]).unwrap()
                ]))
            ])
        },

        Packet::AskPendingTransactions {
            root_block: Hash::from_slice(b"Hello, World!")
        },

        Packet::PendingTransactions {
            root_block: Hash::from_slice(b"Hello, World!"),
            pending_transactions: Box::new([
                Hash::from_slice(b"Test 1"),
                Hash::from_slice(b"Test 2"),
                Hash::from_slice(b"Test 3")
            ])
        },

        Packet::AskBlock {
            root_block: Hash::from_slice(b"Hello, World!"),
            target_block: Hash::from_slice(b"Test")
        },

        Packet::Block {
            root_block: Hash::from_slice(b"Hello, World!"),
            block: Block::new(
                &secret_key,
                Hash::default(),
                BlockContent::data([1, 2, 3])
            ).unwrap()
        },

        Packet::AskTransaction {
            root_block: Hash::from_slice(b"Hello, World!"),
            transaction: Hash::from_slice(b"Test")
        },

        Packet::Transaction {
            root_block: Hash::from_slice(b"Hello, World!"),
            transaction: Transaction::create(
                &secret_key,
                283764,
                [1, 2, 3]
            ).unwrap()
        },

        Packet::ApproveBlock {
            root_block: Hash::from_slice(b"Hello, World!"),
            target_block: Hash::from_slice(b"Test"),
            approval: Signature::create(
                &secret_key,
                Hash::from([123; 32])
            ).unwrap()
        }
    );

    Ok(())
}
