use std::io::{Read, Cursor};

use varint_rs::*;

use crate::crypto::*;
use crate::block::Block;
use crate::transaction::Transaction;

#[derive(Debug, thiserror::Error)]
pub enum Error {
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
    pub fn to_bytes(&self) -> Result<Box<[u8]>, Error> {
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
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, Error> {
        let bytes = bytes.as_ref();

        if bytes.is_empty() {
            return Err(Error::PacketTooShort);
        }

        match bytes[0] {
            Self::V1_HEARTBEAT => Ok(Self::Heartbeat),

            Self::V1_ASK_HISTORY => {
                if bytes.len() < 35 {
                    return Err(Error::PacketTooShort);
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
                    return Err(Error::PacketTooShort);
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
                    return Err(Error::PacketTooShort);
                }

                let mut root_block = [0; 32];

                root_block.copy_from_slice(&bytes[1..33]);

                Ok(Self::AskPendingBlocks {
                    root_block: Hash::from(root_block)
                })
            },

            Self::V1_PENDING_BLOCKS => {
                if bytes.len() < 33 {
                    return Err(Error::PacketTooShort);
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
                            return Err(Error::InvalidSignature);
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
                    return Err(Error::PacketTooShort);
                }

                let mut root_block = [0; 32];

                root_block.copy_from_slice(&bytes[1..33]);

                Ok(Self::AskPendingTransactions {
                    root_block: Hash::from(root_block)
                })
            }

            Self::V1_PENDING_TRANSACTIONS => {
                if bytes.len() < 33 {
                    return Err(Error::PacketTooShort);
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
                    return Err(Error::PacketTooShort);
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
                    return Err(Error::PacketTooShort);
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
                    return Err(Error::PacketTooShort);
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
                    return Err(Error::PacketTooShort);
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
                    return Err(Error::PacketTooShort);
                }

                let mut root_block = [0; 32];
                let mut target_block = [0; 32];
                let mut approval = [0; 65];

                root_block.copy_from_slice(&bytes[1..33]);
                target_block.copy_from_slice(&bytes[33..65]);
                approval.copy_from_slice(&bytes[65..]);

                let Some(approval) = Signature::from_bytes(approval) else {
                    return Err(Error::InvalidSignature);
                };

                Ok(Self::ApproveBlock {
                    root_block: Hash::from(root_block),
                    target_block: Hash::from(target_block),
                    approval
                })
            }

            packet_type => Err(Error::UnknownPacketType(packet_type))
        }
    }
}

#[test]
fn test_serialize() -> Result<(), Error> {
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
