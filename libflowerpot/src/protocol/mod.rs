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

use varint_rs::{VarintReader, VarintWriter};

use crate::crypto::hash::Hash;
use crate::crypto::sign::Signature;
use crate::transaction::Transaction;
use crate::block::Block;

mod packet_stream;

pub use packet_stream::*;

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
                let mut buf = [0; Hash::SIZE + 1];

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
                let mut buf = [0; Hash::SIZE + 1];

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
                let mut buf = [0; Hash::SIZE * 2 + 1];

                buf[0] = Self::V1_ASK_BLOCK;

                buf[1..Hash::SIZE + 1].copy_from_slice(&root_block.0);
                buf[Hash::SIZE + 1..65].copy_from_slice(&target_block.0);

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
                let mut buf = [0; Hash::SIZE * 2 + 1];

                buf[0] = Self::V1_ASK_TRANSACTION;

                buf[1..Hash::SIZE + 1].copy_from_slice(&root_block.0);
                buf[Hash::SIZE + 1..].copy_from_slice(&transaction.0);

                Ok(Box::new(buf))
            }

            Self::Transaction { root_block, transaction } => {
                let mut buf = Vec::new();

                buf.push(Self::V1_TRANSACTION);

                buf.extend_from_slice(&root_block.0);
                buf.extend(transaction.to_bytes());

                Ok(buf.into_boxed_slice())
            }

            Self::ApproveBlock {
                root_block,
                target_block,
                approval
            } => {
                let mut buf = [0; Hash::SIZE * 2 + Signature::SIZE + 1];

                buf[0] = Self::V1_APPROVE_BLOCK;

                buf[1..Hash::SIZE + 1].copy_from_slice(&root_block.0);
                buf[Hash::SIZE + 1..Hash::SIZE * 2 + 1].copy_from_slice(&target_block.0);
                buf[Hash::SIZE * 2 + 1..].copy_from_slice(&approval.to_bytes());

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
                if bytes.len() < Hash::SIZE + 3 {
                    return Err(PacketError::PacketTooShort);
                }

                let mut root_block = [0; Hash::SIZE];

                root_block.copy_from_slice(&bytes[1..Hash::SIZE + 1]);

                let mut bytes = Cursor::new(bytes[Hash::SIZE + 1..].to_vec());

                let offset = bytes.read_u64_varint()?;
                let max_length = bytes.read_u64_varint()?;

                Ok(Self::AskHistory {
                    root_block: Hash::from(root_block),
                    offset,
                    max_length
                })
            }

            Self::V1_HISTORY => {
                if bytes.len() < Hash::SIZE + 1 {
                    return Err(PacketError::PacketTooShort);
                }

                let mut root_block = [0; Hash::SIZE];

                root_block.copy_from_slice(&bytes[1..Hash::SIZE + 1]);

                let mut bytes = Cursor::new(bytes[Hash::SIZE + 1..].to_vec());

                let offset = bytes.read_u64_varint()?;

                let mut history = Vec::new();
                let mut hash = [0; Hash::SIZE];

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
                if bytes.len() < Hash::SIZE + 1 {
                    return Err(PacketError::PacketTooShort);
                }

                let mut root_block = [0; Hash::SIZE];

                root_block.copy_from_slice(&bytes[1..Hash::SIZE + 1]);

                Ok(Self::AskPendingBlocks {
                    root_block: Hash::from(root_block)
                })
            },

            Self::V1_PENDING_BLOCKS => {
                if bytes.len() < Hash::SIZE + 1 {
                    return Err(PacketError::PacketTooShort);
                }

                let mut root_block = [0; Hash::SIZE];

                root_block.copy_from_slice(&bytes[1..Hash::SIZE + 1]);

                let mut bytes = Cursor::new(bytes[Hash::SIZE + 1..].to_vec());

                let mut hash = [0; Hash::SIZE];
                let mut approval = [0; Signature::SIZE];

                let mut blocks = Vec::new();

                while bytes.read_exact(&mut hash).is_ok() {
                    let len = bytes.read_usize_varint()?;

                    let mut approvals = Vec::with_capacity(len);

                    for _ in 0..len {
                        bytes.read_exact(&mut approval)?;

                        let Some(approval) = Signature::from_bytes(&approval) else {
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
                if bytes.len() < Hash::SIZE + 1 {
                    return Err(PacketError::PacketTooShort);
                }

                let mut root_block = [0; Hash::SIZE];

                root_block.copy_from_slice(&bytes[1..Hash::SIZE + 1]);

                Ok(Self::AskPendingTransactions {
                    root_block: Hash::from(root_block)
                })
            }

            Self::V1_PENDING_TRANSACTIONS => {
                if bytes.len() < Hash::SIZE + 1 {
                    return Err(PacketError::PacketTooShort);
                }

                let mut root_block = [0; Hash::SIZE];

                root_block.copy_from_slice(&bytes[1..Hash::SIZE + 1]);

                let mut bytes = Cursor::new(bytes[Hash::SIZE + 1..].to_vec());
                let mut hash = [0; Hash::SIZE];

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
                if bytes.len() < Hash::SIZE * 2 + 1 {
                    return Err(PacketError::PacketTooShort);
                }

                let mut root_block = [0; Hash::SIZE];
                let mut target_block = [0; Hash::SIZE];

                root_block.copy_from_slice(&bytes[1..Hash::SIZE + 1]);
                target_block.copy_from_slice(&bytes[Hash::SIZE + 1..]);

                Ok(Self::AskBlock {
                    root_block: Hash::from(root_block),
                    target_block: Hash::from(target_block)
                })
            }

            Self::V1_BLOCK => {
                if bytes.len() < Hash::SIZE + 1 {
                    return Err(PacketError::PacketTooShort);
                }

                let mut root_block = [0; Hash::SIZE];

                root_block.copy_from_slice(&bytes[1..Hash::SIZE + 1]);

                Ok(Self::Block {
                    root_block: Hash::from(root_block),
                    block: Block::from_bytes(&bytes[Hash::SIZE + 1..])?
                })
            }

            Self::V1_ASK_TRANSACTION => {
                if bytes.len() < Hash::SIZE * 2 + 1 {
                    return Err(PacketError::PacketTooShort);
                }

                let mut root_block = [0; Hash::SIZE];
                let mut transaction = [0; Hash::SIZE];

                root_block.copy_from_slice(&bytes[1..Hash::SIZE + 1]);
                transaction.copy_from_slice(&bytes[Hash::SIZE + 1..]);

                Ok(Self::AskTransaction {
                    root_block: Hash::from(root_block),
                    transaction: Hash::from(transaction)
                })
            }

            Self::V1_TRANSACTION => {
                if bytes.len() < Hash::SIZE + 1 {
                    return Err(PacketError::PacketTooShort);
                }

                let mut root_block = [0; Hash::SIZE];

                root_block.copy_from_slice(&bytes[1..Hash::SIZE + 1]);

                Ok(Self::Transaction {
                    root_block: Hash::from(root_block),
                    transaction: Transaction::from_bytes(&bytes[Hash::SIZE + 1..])?
                })
            }

            Self::V1_APPROVE_BLOCK => {
                if bytes.len() < Hash::SIZE * 2 + Signature::SIZE + 1 {
                    return Err(PacketError::PacketTooShort);
                }

                let mut root_block = [0; Hash::SIZE];
                let mut target_block = [0; Hash::SIZE];
                let mut approval = [0; Signature::SIZE];

                root_block.copy_from_slice(&bytes[1..Hash::SIZE + 1]);
                target_block.copy_from_slice(&bytes[Hash::SIZE + 1..Hash::SIZE * 2 + 1]);
                approval.copy_from_slice(&bytes[Hash::SIZE * 2 + 1..]);

                let Some(approval) = Signature::from_bytes(&approval) else {
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

#[test]
fn test_serialize() -> Result<(), PacketError> {
    use rand_chacha::ChaCha8Rng;
    use rand_chacha::rand_core::SeedableRng;

    use crate::crypto::sign::SigningKey;
    use crate::block::BlockContent;

    let mut rng = ChaCha8Rng::seed_from_u64(123);

    let signing_key = SigningKey::random(&mut rng);

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
            root_block: Hash::calc(b"Hello, World!"),
            offset: u16::MAX as u64,
            max_length: u32::MAX as u64
        },

        Packet::History {
            root_block: Hash::calc(b"Hello, World!"),
            offset: 376415,
            history: Box::new([
                Hash::calc(b"Test 1"),
                Hash::calc(b"Test 2"),
                Hash::calc(b"Test 3")
            ])
        },

        Packet::AskPendingBlocks {
            root_block: Hash::calc(b"Hello, World!")
        },

        Packet::PendingBlocks {
            root_block: Hash::calc(b"Hello, World!"),
            pending_blocks: Box::new([
                (Hash::calc(b"Block 1"), Box::new([])),
                (Hash::calc(b"Block 2"), Box::new([
                    Signature::create(&signing_key, [1; 32]).unwrap(),
                    Signature::create(&signing_key, [2; 32]).unwrap(),
                    Signature::create(&signing_key, [3; 32]).unwrap()
                ])),
                (Hash::calc(b"Block 3"), Box::new([
                    Signature::create(&signing_key, [4; 32]).unwrap()
                ]))
            ])
        },

        Packet::AskPendingTransactions {
            root_block: Hash::calc(b"Hello, World!")
        },

        Packet::PendingTransactions {
            root_block: Hash::calc(b"Hello, World!"),
            pending_transactions: Box::new([
                Hash::calc(b"Test 1"),
                Hash::calc(b"Test 2"),
                Hash::calc(b"Test 3")
            ])
        },

        Packet::AskBlock {
            root_block: Hash::calc(b"Hello, World!"),
            target_block: Hash::calc(b"Test")
        },

        Packet::Block {
            root_block: Hash::calc(b"Hello, World!"),
            block: Block::new(
                &signing_key,
                Hash::default(),
                BlockContent::data([1, 2, 3])
            ).unwrap()
        },

        Packet::AskTransaction {
            root_block: Hash::calc(b"Hello, World!"),
            transaction: Hash::calc(b"Test")
        },

        Packet::Transaction {
            root_block: Hash::calc(b"Hello, World!"),
            transaction: Transaction::create(
                &signing_key,
                [1, 2, 3]
            ).unwrap()
        },

        Packet::ApproveBlock {
            root_block: Hash::calc(b"Hello, World!"),
            target_block: Hash::calc(b"Test"),
            approval: Signature::create(
                &signing_key,
                b"test"
            ).unwrap()
        }
    );

    Ok(())
}
