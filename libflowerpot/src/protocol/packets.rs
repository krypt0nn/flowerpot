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

use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};

use crate::varint;
use crate::crypto::hash::Hash;
use crate::blob::{Message, MessageDecodeError};
use crate::block::{Block, BlockDecodeError};

#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum PacketDecodeError {
    #[error("unsupported packet type: {0}")]
    UnsupportedType(u16),

    #[error("provided packet bytes slice is too short: {got} bytes got, at least {expected} bytes expected")]
    TooShort {
        got: usize,
        expected: usize
    },

    #[error("invalid param {param} format in the {packet_type} packet")]
    InvalidParam {
        packet_type: &'static str,
        param: &'static str
    },

    #[error("failed to decode message: {0}")]
    DecodeMessage(#[from] MessageDecodeError),

    #[error("failed to decode block: {0}")]
    DecodeBlock(#[from] BlockDecodeError)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    /// Heartbeat (keep alive) packet.
    Heartbeat {
        /// Randomly chosen number which can be used to calculate ping between
        /// two heartbeat packets.
        id: u32
    },

    /// Ask network nodes addresses.
    AskNodes {
        /// Maximal amount of nodes to send.
        max_nodes: u64
    },

    /// Slice of network nodes addresses.
    Nodes {
        /// List of other network nodes' addresses.
        nodes: Box<[SocketAddr]>
    },

    // /// Ask network node to share what chains it hosts.
    // AskKnownChains {
    //     /// Maximal amount of chains to return.
    //     max_chains: u64
    // },

    // /// List of known chains info.
    // KnownChains {
    //     /// List of `(root_block, verifying_key)` pairs of known chains.
    //     chains: Box<[(Hash, VerifyingKey)]>
    // },

    /// Ask history of a blockchain.
    ///
    /// For chain `A -> B -> C -> D -> E` and packet
    /// `AskHistory { since_block: A, max_length: 2 }` the result packet is
    /// expected to be `History { since_block: A, history: [ B, C ] }`.
    AskHistory {
        /// Hash of the blockchain's root block.
        root_block: Hash,

        /// Hash of the block since which the history should be returned.
        since_block: Hash,

        /// Maximal amount of blocks to return.
        max_length: u64
    },

    /// Slice of a blockchain history.
    History {
        /// Hash of the blockchain's root block.
        root_block: Hash,

        /// Hash of the block since which the history is returned.
        since_block: Hash,

        /// Slice of the blockchain's history.
        history: Box<[Hash]>
    },

    /// Ask list of pending messages.
    AskPendingMessages {
        /// Hash of the blockchain's root block.
        root_block: Hash,

        /// List of messages' hashes which are already stored in the pending
        /// messages pool.
        known_messages: Box<[Hash]>
    },

    /// List of pending messages of a blockchain.
    PendingMessages {
        /// Hash of the blockchain's root block.
        root_block: Hash,

        /// List of pending messages' hashes.
        pending_messages: Box<[Hash]>
    },

    /// Ask for a message stored in a blockchain or in the pending messages
    /// pool.
    AskMessage {
        /// Hash of the blockchain's root block.
        root_block: Hash,

        /// Hash of the message you want to receive.
        message: Hash
    },

    /// Message stored in a blockchain.
    Message {
        /// Hash of the blockchain's root block.
        root_block: Hash,

        /// Message stored in the blockchain or pending messages pool.
        message: Message
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
    }
}

impl Packet {
    pub const V1_HEARTBEAT: u16            = 0;
    pub const V1_ASK_NODES: u16            = 1;
    pub const V1_NODES: u16                = 2;
    pub const V1_ASK_HISTORY: u16          = 3;
    pub const V1_HISTORY: u16              = 4;
    pub const V1_ASK_PENDING_MESSAGES: u16 = 5;
    pub const V1_PENDING_MESSAGES: u16     = 6;
    pub const V1_ASK_MESSAGE: u16          = 7;
    pub const V1_MESSAGE: u16              = 8;
    pub const V1_ASK_BLOCK: u16            = 9;
    pub const V1_BLOCK: u16                = 10;

    /// Encode packet into a binary representation.
    pub fn to_bytes(&self) -> Box<[u8]> {
        match self {
            Self::Heartbeat { id } => {
                let mut buf = [0; 6];

                buf[..2].copy_from_slice(&Self::V1_HEARTBEAT.to_le_bytes());
                buf[2..].copy_from_slice(&id.to_le_bytes());

                Box::new(buf)
            }

            Self::AskNodes { max_nodes } => {
                let mut buf = Vec::new();

                buf.extend(Self::V1_ASK_NODES.to_le_bytes());

                buf.extend(varint::write_u64(*max_nodes));

                buf.into_boxed_slice()
            }

            Self::Nodes { nodes } => {
                let mut buf = Vec::new();

                buf.extend(Self::V1_NODES.to_le_bytes());

                for node in nodes {
                    match node.ip() {
                        IpAddr::V4(ip) => {
                            buf.push(0);
                            buf.extend(node.port().to_le_bytes());
                            buf.extend(ip.octets());
                        }

                        IpAddr::V6(ip) => {
                            buf.push(1);
                            buf.extend(node.port().to_le_bytes());
                            buf.extend(ip.octets());
                        }
                    }
                }

                buf.into_boxed_slice()
            }

            Self::AskHistory {
                root_block,
                since_block,
                max_length
            } => {
                let mut buf = Vec::with_capacity(2 + Hash::SIZE * 2 + 4);

                buf.extend(Self::V1_ASK_HISTORY.to_le_bytes());

                buf.extend(root_block.as_bytes());
                buf.extend(since_block.as_bytes());
                buf.extend(varint::write_u64(*max_length));

                buf.into_boxed_slice()
            }

            Self::History {
                root_block,
                since_block,
                history
            } => {
                let mut buf = Vec::with_capacity(
                    2 + Hash::SIZE * (2 + history.len())
                );

                buf.extend(Self::V1_HISTORY.to_le_bytes());

                buf.extend(root_block.as_bytes());
                buf.extend(since_block.as_bytes());

                for hash in history {
                    buf.extend(hash.as_bytes());
                }

                buf.into_boxed_slice()
            }

            Self::AskPendingMessages { root_block, known_messages } => {
                let mut buf = Vec::with_capacity(
                    2 + Hash::SIZE * (1 + known_messages.len())
                );

                buf.extend(Self::V1_ASK_PENDING_MESSAGES.to_le_bytes());

                buf.extend(root_block.as_bytes());

                for message in known_messages {
                    buf.extend(message.as_bytes());
                }

                buf.into_boxed_slice()
            }

            Self::PendingMessages { root_block, pending_messages } => {
                let mut buf = Vec::new();

                buf.extend(Self::V1_PENDING_MESSAGES.to_le_bytes());

                buf.extend(root_block.as_bytes());

                for hash in pending_messages {
                    buf.extend(hash.as_bytes());
                }

                buf.into_boxed_slice()
            }

            Self::AskMessage { root_block, message } => {
                let mut buf = [0; 2 + Hash::SIZE * 2];

                buf[0..2].copy_from_slice(
                    &Self::V1_ASK_MESSAGE.to_le_bytes()
                );

                buf[2..2 + Hash::SIZE].copy_from_slice(root_block.as_bytes());
                buf[2 + Hash::SIZE..].copy_from_slice(message.as_bytes());

                Box::new(buf)
            }

            Self::Message { root_block, message } => {
                let mut buf = Vec::new();

                buf.extend(Self::V1_MESSAGE.to_le_bytes());

                buf.extend(root_block.as_bytes());
                buf.extend(message.to_bytes());

                buf.into_boxed_slice()
            }

            Self::AskBlock { root_block, target_block } => {
                let mut buf = [0; 2 + Hash::SIZE * 2];

                buf[0..2].copy_from_slice(
                    &Self::V1_ASK_BLOCK.to_le_bytes()
                );

                buf[2..2 + Hash::SIZE].copy_from_slice(root_block.as_bytes());
                buf[2 + Hash::SIZE..66].copy_from_slice(target_block.as_bytes());

                Box::new(buf)
            }

            Self::Block { root_block, block } => {
                let mut buf = Vec::new();

                buf.extend(Self::V1_BLOCK.to_le_bytes());

                buf.extend(root_block.as_bytes());
                buf.extend(block.to_bytes());

                buf.into_boxed_slice()
            }
        }
    }

    /// Decode packet from a binary representation.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, PacketDecodeError> {
        let bytes = bytes.as_ref();

        let n = bytes.len();

        if n < 2 {
            return Err(PacketDecodeError::TooShort {
                got: n,
                expected: 2
            });
        }

        match u16::from_le_bytes([bytes[0], bytes[1]]) {
            Self::V1_HEARTBEAT => {
                if n < 6 {
                    return Err(PacketDecodeError::TooShort {
                        got: n,
                        expected: 6
                    });
                }

                let mut id = [0; 4];

                id.copy_from_slice(&bytes[2..6]);

                Ok(Self::Heartbeat {
                    id: u32::from_le_bytes(id)
                })
            }

            Self::V1_ASK_NODES => {
                if n < 3 {
                    return Err(PacketDecodeError::TooShort {
                        got: n,
                        expected: 3
                    });
                }

                let (Some(max_nodes), _) = varint::read_u64(&bytes[2..]) else {
                    return Err(PacketDecodeError::InvalidParam {
                        packet_type: "AskNodes",
                        param: "max_nodes"
                    });
                };

                Ok(Self::AskNodes {
                    max_nodes
                })
            }

            Self::V1_NODES => {
                let mut i = 2;
                let n = bytes.len();

                let mut nodes = Vec::new();

                while i < n {
                    let port = u16::from_le_bytes([
                        bytes[i + 1],
                        bytes[i + 2]
                    ]);

                    match bytes[i] {
                        0 => {
                            let mut ip = [0; 4];

                            ip.copy_from_slice(&bytes[i + 3..i + 7]);

                            nodes.push(SocketAddr::new(
                                IpAddr::from(Ipv4Addr::from(ip)),
                                port
                            ));

                            i += 7;
                        }

                        1 => {
                            let mut ip = [0; 16];

                            ip.copy_from_slice(&bytes[i + 3..i + 19]);

                            nodes.push(SocketAddr::new(
                                IpAddr::from(Ipv6Addr::from(ip)),
                                port
                            ));

                            i += 19;
                        }

                        _ => return Err(PacketDecodeError::InvalidParam {
                            packet_type: "Nodes",
                            param: "format"
                        })
                    }
                }

                Ok(Self::Nodes {
                    nodes: nodes.into_boxed_slice()
                })
            }

            Self::V1_ASK_HISTORY => {
                if n < 2 + Hash::SIZE * 2 + 1 {
                    return Err(PacketDecodeError::TooShort {
                        got: n,
                        expected: 2 + Hash::SIZE * 2 + 1
                    });
                }

                let mut root_block = [0; Hash::SIZE];
                let mut since_block = [0; Hash::SIZE];

                root_block.copy_from_slice(&bytes[2..2 + Hash::SIZE]);
                since_block.copy_from_slice(&bytes[2 + Hash::SIZE..2 + Hash::SIZE * 2]);

                let (Some(max_length), _) = varint::read_u64(&bytes[2 + Hash::SIZE * 2..]) else {
                    return Err(PacketDecodeError::InvalidParam {
                        packet_type: "AskHistory",
                        param: "max_length"
                    });
                };

                Ok(Self::AskHistory {
                    root_block: Hash::from(root_block),
                    since_block: Hash::from(since_block),
                    max_length
                })
            }

            Self::V1_HISTORY => {
                if n < 2 + Hash::SIZE {
                    return Err(PacketDecodeError::TooShort {
                        got: n,
                        expected: 2 + Hash::SIZE
                    });
                }

                let mut root_block = [0; Hash::SIZE];
                let mut since_block = [0; Hash::SIZE];

                root_block.copy_from_slice(&bytes[2..2 + Hash::SIZE]);
                since_block.copy_from_slice(&bytes[2 + Hash::SIZE..2 + Hash::SIZE * 2]);

                let bytes = &bytes[2 + Hash::SIZE * 2..];

                let mut history = Vec::new();
                let mut hash = [0; Hash::SIZE];

                let n = bytes.len();
                let mut i = 0;

                while i < n {
                    hash.copy_from_slice(&bytes[i..i + Hash::SIZE]);

                    history.push(Hash::from(hash));

                    i += Hash::SIZE;
                }

                Ok(Self::History {
                    root_block: Hash::from(root_block),
                    since_block: Hash::from(since_block),
                    history: history.into_boxed_slice()
                })
            }

            Self::V1_ASK_PENDING_MESSAGES => {
                if n < 2 + Hash::SIZE {
                    return Err(PacketDecodeError::TooShort {
                        got: n,
                        expected: 2 + Hash::SIZE
                    });
                }

                let mut root_block = [0; Hash::SIZE];

                root_block.copy_from_slice(&bytes[2..2 + Hash::SIZE]);

                let bytes = &bytes[2 + Hash::SIZE..];

                let mut messages = Vec::new();
                let mut hash = [0; Hash::SIZE];

                let n = bytes.len();
                let mut i = 0;

                while i < n {
                    hash.copy_from_slice(&bytes[i..i + Hash::SIZE]);

                    messages.push(Hash::from(hash));

                    i += Hash::SIZE;
                }

                Ok(Self::AskPendingMessages {
                    root_block: Hash::from(root_block),
                    known_messages: messages.into_boxed_slice()
                })
            }

            Self::V1_PENDING_MESSAGES => {
                if n < 2 + Hash::SIZE {
                    return Err(PacketDecodeError::TooShort {
                        got: n,
                        expected: 2 + Hash::SIZE
                    });
                }

                let mut root_block = [0; Hash::SIZE];

                root_block.copy_from_slice(&bytes[2..2 + Hash::SIZE]);

                let bytes = &bytes[2 + Hash::SIZE..];

                let mut messages = Vec::new();
                let mut hash = [0; Hash::SIZE];

                let n = bytes.len();
                let mut i = 0;

                while i < n {
                    hash.copy_from_slice(&bytes[i..i + Hash::SIZE]);

                    messages.push(Hash::from(hash));

                    i += Hash::SIZE;
                }

                Ok(Self::PendingMessages {
                    root_block: Hash::from(root_block),
                    pending_messages: messages.into_boxed_slice()
                })
            }

            Self::V1_ASK_MESSAGE => {
                if n < 2 + Hash::SIZE * 2 {
                    return Err(PacketDecodeError::TooShort {
                        got: n,
                        expected: 2 + Hash::SIZE * 2
                    });
                }

                let mut root_block = [0; Hash::SIZE];
                let mut message = [0; Hash::SIZE];

                root_block.copy_from_slice(&bytes[2..2 + Hash::SIZE]);
                message.copy_from_slice(&bytes[2 + Hash::SIZE..]);

                Ok(Self::AskMessage {
                    root_block: Hash::from(root_block),
                    message: Hash::from(message)
                })
            }

            Self::V1_MESSAGE => {
                if n < 2 + Hash::SIZE {
                    return Err(PacketDecodeError::TooShort {
                        got: n,
                        expected: 2 + Hash::SIZE
                    });
                }

                let mut root_block = [0; Hash::SIZE];

                root_block.copy_from_slice(&bytes[2..2 + Hash::SIZE]);

                Ok(Self::Message {
                    root_block: Hash::from(root_block),
                    message: Message::from_bytes(&bytes[2 + Hash::SIZE..])?
                })
            }

            Self::V1_ASK_BLOCK => {
                if n < 2 + Hash::SIZE * 2 {
                    return Err(PacketDecodeError::TooShort {
                        got: n,
                        expected: 2 + Hash::SIZE * 2
                    });
                }

                let mut root_block = [0; Hash::SIZE];
                let mut target_block = [0; Hash::SIZE];

                root_block.copy_from_slice(&bytes[2..2 + Hash::SIZE]);
                target_block.copy_from_slice(&bytes[2 + Hash::SIZE..]);

                Ok(Self::AskBlock {
                    root_block: Hash::from(root_block),
                    target_block: Hash::from(target_block)
                })
            }

            Self::V1_BLOCK => {
                if n < 2 + Hash::SIZE {
                    return Err(PacketDecodeError::TooShort {
                        got: n,
                        expected: 2 + Hash::SIZE
                    });
                }

                let mut root_block = [0; Hash::SIZE];

                root_block.copy_from_slice(&bytes[2..2 + Hash::SIZE]);

                Ok(Self::Block {
                    root_block: Hash::from(root_block),
                    block: Block::from_bytes(&bytes[2 + Hash::SIZE..])?
                })
            }

            packet_type => Err(PacketDecodeError::UnsupportedType(packet_type))
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
fn test_serialize() -> Result<(), PacketDecodeError> {
    use rand_chacha::ChaCha8Rng;
    use rand_chacha::rand_core::SeedableRng;

    use crate::crypto::sign::SigningKey;

    let mut rng = ChaCha8Rng::seed_from_u64(123);

    let signing_key = SigningKey::random(&mut rng);

    // ---------------------------------------------------------------

    macro_rules! test_packets {
        ($($packet:expr $(,)*)+) => {
            $(
                let packet = $packet;

                assert_eq!(Packet::from_bytes(packet.to_bytes())?, packet);
            )+
        };
    }

    test_packets!(
        Packet::Heartbeat {
            id: u32::MAX
        },

        Packet::AskNodes {
            max_nodes: u64::MAX
        },

        Packet::Nodes {
            nodes: Box::new([
                "127.0.0.1:10001".parse::<SocketAddr>().unwrap(),
                "[::]:10002".parse::<SocketAddr>().unwrap(),
                "127.0.0.3:10003".parse::<SocketAddr>().unwrap(),
                "127.0.0.4:10004".parse::<SocketAddr>().unwrap(),
                "[1::5]:10005".parse::<SocketAddr>().unwrap()
            ])
        },

        Packet::AskHistory {
            root_block: Hash::calc(b"Hello, World!"),
            since_block: Hash::ZERO,
            max_length: u32::MAX as u64
        },

        Packet::History {
            root_block: Hash::calc(b"Hello, World!"),
            since_block: Hash::ZERO,
            history: Box::new([
                Hash::calc(b"Test 1"),
                Hash::calc(b"Test 2"),
                Hash::calc(b"Test 3")
            ])
        },

        Packet::AskPendingMessages {
            root_block: Hash::calc(b"Hello, World!"),
            known_messages: Box::new([
                Hash::calc(b"Test 1"),
                Hash::calc(b"Test 2"),
                Hash::calc(b"Test 3")
            ])
        },

        Packet::PendingMessages {
            root_block: Hash::calc(b"Hello, World!"),
            pending_messages: Box::new([
                Hash::calc(b"Test 1"),
                Hash::calc(b"Test 2"),
                Hash::calc(b"Test 3")
            ])
        },

        Packet::AskMessage {
            root_block: Hash::calc(b"Hello, World!"),
            message: Hash::calc(b"Test")
        },

        Packet::Message {
            root_block: Hash::calc(b"Hello, World!"),
            message: Message::create(
                &signing_key,
                [1, 2, 3]
            ).unwrap()
        },

        Packet::AskBlock {
            root_block: Hash::calc(b"Hello, World!"),
            target_block: Hash::calc(b"Test")
        },

        Packet::Block {
            root_block: Hash::calc(b"Hello, World!"),
            block: Block::create(&signing_key, Hash::ZERO, [
                Message::create(&signing_key, b"Message 1".as_slice()).unwrap(),
                Message::create(&signing_key, b"Message 2".as_slice()).unwrap(),
                Message::create(&signing_key, b"Message 3".as_slice()).unwrap()
            ]).unwrap()
        }
    );

    Ok(())
}
