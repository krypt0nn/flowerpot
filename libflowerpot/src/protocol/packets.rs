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
use crate::message::{Message, MessageDecodeError};
use crate::block::{Block, BlockDecodeError};
use crate::address::Address;

#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum PacketDecodeError {
    #[error("unsupported packet type: {0}")]
    UnsupportedType(u16),

    #[error("provided packet bytes slice is too short: got {got} bytes, at least {expected} bytes expected")]
    TooShort {
        got: usize,
        expected: usize
    },

    #[error("invalid param {param} format in the {packet_type} packet")]
    InvalidParam {
        packet_type: &'static str,
        param: &'static str
    },

    #[error("invalid blockchain address value")]
    InvalidAddress,

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

    // TODO: DHT-like packets to share which nodes know which not-inline blobs.

    /// Ask blockchain history.
    ///
    /// For chain `A -> B -> C -> D -> E` and packet
    /// `AskHistory { since_block: A, max_length: 2 }` the result packet is
    /// expected to be `History { since_block: A, history: [ B, C ] }`.
    AskHistory {
        /// Blockchain address.
        address: Address,

        /// Hash of the block since which the history should be returned.
        ///
        /// For `since_block = 0` the head history is expected to be returned
        /// (the first block is the root block of the blockchain).
        since_block: Hash,

        /// Maximal amount of blocks to return.
        max_length: u64
    },

    /// Slice of a blockchain history.
    History {
        /// Blockchain address.
        address: Address,

        /// Hash of the block since which the history is returned.
        since_block: Hash,

        /// Slice of the blockchain history.
        history: Box<[Block]>
    },

    /// Ask list of pending messages.
    AskPendingMessages {
        /// Blockchain address.
        address: Address,

        /// List of messages' hashes which should not be returned.
        except: Box<[Hash]>
    },

    /// List of pending messages of a blockchain.
    PendingMessages {
        /// Blockchain address.
        address: Address,

        /// List of pending messages' hashes.
        messages: Box<[Hash]>
    },

    /// Ask for a message stored in a blockchain or in the pending messages
    /// pool.
    AskMessage {
        /// Blockchain address.
        address: Address,

        /// Hash of requested message.
        hash: Hash
    },

    /// Blockchain message.
    Message {
        /// Blockchain address.
        address: Address,

        /// Blockchain message.
        message: Message
    },

    /// Ask for a blockchain block.
    AskBlock {
        /// Blockchain address.
        address: Address,

        /// Hash of requested block.
        hash: Hash
    },

    /// Blockchain block.
    Block {
        /// Blockchain address.
        address: Address,

        /// Blockchain block.
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

    /// Encode current packet into a binary representation.
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
                address,
                since_block,
                max_length
            } => {
                let mut buf = Vec::new();

                buf.extend(Self::V1_ASK_HISTORY.to_le_bytes());

                buf.extend(address.to_bytes());
                buf.extend(since_block.as_bytes());
                buf.extend(varint::write_u64(*max_length));

                buf.into_boxed_slice()
            }

            Self::History {
                address,
                since_block,
                history
            } => {
                let mut buf = Vec::new();

                buf.extend(Self::V1_HISTORY.to_le_bytes());

                buf.extend(address.to_bytes());
                buf.extend(since_block.as_bytes());

                for block in history {
                    let block = block.to_bytes();

                    buf.extend(varint::write_u64(block.len() as u64));
                    buf.extend(block);
                }

                buf.into_boxed_slice()
            }

            Self::AskPendingMessages { address, except } => {
                let mut buf = Vec::with_capacity(
                    2 + Address::SIZE * (1 + except.len())
                );

                buf.extend(Self::V1_ASK_PENDING_MESSAGES.to_le_bytes());

                buf.extend(address.to_bytes());

                for hash in except {
                    buf.extend(hash.as_bytes());
                }

                buf.into_boxed_slice()
            }

            Self::PendingMessages { address, messages } => {
                let mut buf = Vec::with_capacity(
                    2 + Address::SIZE + Hash::SIZE * messages.len()
                );

                buf.extend(Self::V1_PENDING_MESSAGES.to_le_bytes());

                buf.extend(address.to_bytes());

                for hash in messages {
                    buf.extend(hash.as_bytes());
                }

                buf.into_boxed_slice()
            }

            Self::AskMessage { address, hash } => {
                let mut buf = [0; 2 + Address::SIZE + Hash::SIZE];

                buf[0..2].copy_from_slice(&Self::V1_ASK_MESSAGE.to_le_bytes());

                buf[2..2 + Address::SIZE].copy_from_slice(&address.to_bytes());
                buf[2 + Address::SIZE..].copy_from_slice(hash.as_bytes());

                Box::new(buf)
            }

            Self::Message { address, message } => {
                let mut buf = Vec::new();

                buf.extend(Self::V1_MESSAGE.to_le_bytes());

                buf.extend(address.to_bytes());
                buf.extend(message.to_bytes());

                buf.into_boxed_slice()
            }

            Self::AskBlock { address, hash } => {
                let mut buf = [0; 2 + Address::SIZE + Hash::SIZE];

                buf[0..2].copy_from_slice(&Self::V1_ASK_BLOCK.to_le_bytes());

                buf[2..2 + Address::SIZE].copy_from_slice(&address.to_bytes());
                buf[2 + Address::SIZE..].copy_from_slice(hash.as_bytes());

                Box::new(buf)
            }

            Self::Block { address, block } => {
                let mut buf = Vec::new();

                buf.extend(Self::V1_BLOCK.to_le_bytes());

                buf.extend(address.to_bytes());
                buf.extend(block.to_bytes());

                buf.into_boxed_slice()
            }
        }
    }

    /// Try to decode a packet from a binary representation.
    pub fn from_bytes(packet: impl AsRef<[u8]>) -> Result<Self, PacketDecodeError> {
        let packet = packet.as_ref();

        let n = packet.len();

        if n < 2 {
            return Err(PacketDecodeError::TooShort {
                got: n,
                expected: 2
            });
        }

        match u16::from_le_bytes([packet[0], packet[1]]) {
            Self::V1_HEARTBEAT => {
                if n < 6 {
                    return Err(PacketDecodeError::TooShort {
                        got: n,
                        expected: 6
                    });
                }

                let mut id = [0; 4];

                id.copy_from_slice(&packet[2..6]);

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

                let (Some(max_nodes), _) = varint::read_u64(&packet[2..]) else {
                    return Err(PacketDecodeError::InvalidParam {
                        packet_type: "V1_ASK_NODES",
                        param: "max_nodes"
                    });
                };

                Ok(Self::AskNodes {
                    max_nodes
                })
            }

            Self::V1_NODES => {
                let mut i = 2;
                let mut nodes = Vec::new();

                while i < n {
                    let port = u16::from_le_bytes([
                        packet[i + 1],
                        packet[i + 2]
                    ]);

                    match packet[i] {
                        0 => {
                            let mut ip = [0; 4];

                            ip.copy_from_slice(&packet[i + 3..i + 7]);

                            nodes.push(SocketAddr::new(
                                IpAddr::from(Ipv4Addr::from(ip)),
                                port
                            ));

                            i += 7;
                        }

                        1 => {
                            let mut ip = [0; 16];

                            ip.copy_from_slice(&packet[i + 3..i + 19]);

                            nodes.push(SocketAddr::new(
                                IpAddr::from(Ipv6Addr::from(ip)),
                                port
                            ));

                            i += 19;
                        }

                        _ => return Err(PacketDecodeError::InvalidParam {
                            packet_type: "V1_NODES",
                            param: "format"
                        })
                    }
                }

                Ok(Self::Nodes {
                    nodes: nodes.into_boxed_slice()
                })
            }

            Self::V1_ASK_HISTORY => {
                if n < 2 + Address::SIZE + Hash::SIZE + 1 {
                    return Err(PacketDecodeError::TooShort {
                        got: n,
                        expected: 2 + Address::SIZE + Hash::SIZE + 1
                    });
                }

                let mut address = [0; Address::SIZE];
                let mut since_block = [0; Hash::SIZE];

                address.copy_from_slice(&packet[2..2 + Address::SIZE]);
                since_block.copy_from_slice(&packet[2 + Address::SIZE..2 + Address::SIZE + Hash::SIZE]);

                let address = Address::from_bytes(&address)
                    .ok_or(PacketDecodeError::InvalidAddress)?;

                let (Some(max_length), _) = varint::read_u64(&packet[2 + Address::SIZE + Hash::SIZE..]) else {
                    return Err(PacketDecodeError::InvalidParam {
                        packet_type: "V1_ASK_HISTORY",
                        param: "max_length"
                    });
                };

                Ok(Self::AskHistory {
                    address,
                    since_block: Hash::from(since_block),
                    max_length
                })
            }

            Self::V1_HISTORY => {
                if n < 2 + Address::SIZE + Hash::SIZE {
                    return Err(PacketDecodeError::TooShort {
                        got: n,
                        expected: 2 + Address::SIZE + Hash::SIZE
                    });
                }

                let mut address = [0; Address::SIZE];
                let mut since_block = [0; Hash::SIZE];

                address.copy_from_slice(&packet[2..2 + Address::SIZE]);
                since_block.copy_from_slice(&packet[2 + Address::SIZE..2 + Address::SIZE + Hash::SIZE]);

                let address = Address::from_bytes(&address)
                    .ok_or(PacketDecodeError::InvalidAddress)?;

                let mut packet = &packet[2 + Address::SIZE + Hash::SIZE..];
                let mut history = Vec::new();

                loop {
                    let (Some(block_len), shifted_packet) = varint::read_u64(packet) else {
                        return Err(PacketDecodeError::InvalidParam {
                            packet_type: "V1_HISTORY",
                            param: "block_len"
                        });
                    };

                    let block = Block::from_bytes(
                        &shifted_packet[..block_len as usize]
                    )?;

                    history.push(block);

                    if shifted_packet.len() <= block_len as usize {
                        break;
                    }

                    packet = &shifted_packet[block_len as usize..];
                }

                Ok(Self::History {
                    address,
                    since_block: Hash::from(since_block),
                    history: history.into_boxed_slice()
                })
            }

            Self::V1_ASK_PENDING_MESSAGES => {
                if n < 2 + Address::SIZE {
                    return Err(PacketDecodeError::TooShort {
                        got: n,
                        expected: 2 + Address::SIZE
                    });
                }

                let mut address = [0; Address::SIZE];

                address.copy_from_slice(&packet[2..2 + Address::SIZE]);

                let address = Address::from_bytes(&address)
                    .ok_or(PacketDecodeError::InvalidAddress)?;

                let packet = &packet[2 + Address::SIZE..];

                let mut messages = Vec::with_capacity(packet.len() / Hash::SIZE);
                let mut hash = [0; Hash::SIZE];

                let n = packet.len();
                let mut i = 0;

                while i < n {
                    hash.copy_from_slice(&packet[i..i + Hash::SIZE]);

                    messages.push(Hash::from(hash));

                    i += Hash::SIZE;
                }

                Ok(Self::AskPendingMessages {
                    address,
                    except: messages.into_boxed_slice()
                })
            }

            Self::V1_PENDING_MESSAGES => {
                if n < 2 + Hash::SIZE {
                    return Err(PacketDecodeError::TooShort {
                        got: n,
                        expected: 2 + Address::SIZE
                    });
                }

                let mut address = [0; Address::SIZE];

                address.copy_from_slice(&packet[2..2 + Address::SIZE]);

                let address = Address::from_bytes(&address)
                    .ok_or(PacketDecodeError::InvalidAddress)?;

                let packet = &packet[2 + Address::SIZE..];

                let mut messages = Vec::new();
                let mut hash = [0; Hash::SIZE];

                let n = packet.len();
                let mut i = 0;

                while i < n {
                    hash.copy_from_slice(&packet[i..i + Hash::SIZE]);

                    messages.push(Hash::from(hash));

                    i += Hash::SIZE;
                }

                Ok(Self::PendingMessages {
                    address,
                    messages: messages.into_boxed_slice()
                })
            }

            Self::V1_ASK_MESSAGE => {
                if n < 2 + Address::SIZE + Hash::SIZE {
                    return Err(PacketDecodeError::TooShort {
                        got: n,
                        expected: 2 + Address::SIZE + Hash::SIZE
                    });
                }

                let mut address = [0; Address::SIZE];
                let mut hash = [0; Hash::SIZE];

                address.copy_from_slice(&packet[2..2 + Address::SIZE]);
                hash.copy_from_slice(&packet[2 + Address::SIZE..]);

                Ok(Self::AskMessage {
                    address: Address::from_bytes(&address)
                        .ok_or(PacketDecodeError::InvalidAddress)?,

                    hash: Hash::from(hash)
                })
            }

            Self::V1_MESSAGE => {
                if n < 2 + Hash::SIZE + 1 {
                    return Err(PacketDecodeError::TooShort {
                        got: n,
                        expected: 2 + Address::SIZE + 1
                    });
                }

                let mut address = [0; Address::SIZE];

                address.copy_from_slice(&packet[2..2 + Address::SIZE]);

                Ok(Self::Message {
                    address: Address::from_bytes(&address)
                        .ok_or(PacketDecodeError::InvalidAddress)?,

                    message: Message::from_bytes(&packet[2 + Address::SIZE..])?
                })
            }

            Self::V1_ASK_BLOCK => {
                if n < 2 + Hash::SIZE * 2 {
                    return Err(PacketDecodeError::TooShort {
                        got: n,
                        expected: 2 + Address::SIZE + Hash::SIZE
                    });
                }

                let mut address = [0; Address::SIZE];
                let mut target_block = [0; Hash::SIZE];

                address.copy_from_slice(&packet[2..2 + Address::SIZE]);
                target_block.copy_from_slice(&packet[2 + Address::SIZE..]);

                Ok(Self::AskBlock {
                    address: Address::from_bytes(&address)
                        .ok_or(PacketDecodeError::InvalidAddress)?,

                    hash: Hash::from(target_block)
                })
            }

            Self::V1_BLOCK => {
                if n < 2 + Address::SIZE + 1 {
                    return Err(PacketDecodeError::TooShort {
                        got: n,
                        expected: 2 + Address::SIZE + 1
                    });
                }

                let mut address = [0; Address::SIZE];

                address.copy_from_slice(&packet[2..2 + Address::SIZE]);

                Ok(Self::Block {
                    address: Address::from_bytes(&address)
                        .ok_or(PacketDecodeError::InvalidAddress)?,

                    block: Block::from_bytes(&packet[2 + Address::SIZE..])?
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
fn test_serialize() -> Result<(), Box<dyn std::error::Error>> {
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
            nodes: Box::new([])
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
            address: Address::new(signing_key.verifying_key(), 123),
            since_block: Hash::ZERO,
            max_length: u32::MAX as u64
        },

        Packet::History {
            address: Address::new(signing_key.verifying_key(), 123),
            since_block: Hash::ZERO,
            history: Box::new([])
        },

        Packet::History {
            address: Address::new(signing_key.verifying_key(), 123),
            since_block: Hash::ZERO,
            history: Box::new([
                Block::builder()
                    .sign(&signing_key)?,

                Block::builder()
                    .with_inline_messages([
                        Message::create(&signing_key, b"Message 1".as_slice())?,
                        Message::create(&signing_key, b"Message 2".as_slice())?,
                        Message::create(&signing_key, b"Message 3".as_slice())?
                    ])
                    .sign(&signing_key)?,

                Block::builder()
                    .with_ref_messages([
                        Hash::calc(b"Test 1"),
                        Hash::calc(b"Test 2"),
                        Hash::calc(b"Test 3")
                    ])
                    .sign(&signing_key)?
            ])
        },

        Packet::AskPendingMessages {
            address: Address::new(signing_key.verifying_key(), 123),
            except: Box::new([])
        },

        Packet::AskPendingMessages {
            address: Address::new(signing_key.verifying_key(), 123),
            except: Box::new([
                Hash::calc(b"Test 1"),
                Hash::calc(b"Test 2"),
                Hash::calc(b"Test 3")
            ])
        },

        Packet::PendingMessages {
            address: Address::new(signing_key.verifying_key(), 123),
            messages: Box::new([])
        },

        Packet::PendingMessages {
            address: Address::new(signing_key.verifying_key(), 123),
            messages: Box::new([
                Hash::calc(b"Test 1"),
                Hash::calc(b"Test 2"),
                Hash::calc(b"Test 3")
            ])
        },

        Packet::AskMessage {
            address: Address::new(signing_key.verifying_key(), 123),
            hash: Hash::calc(b"Test")
        },

        Packet::Message {
            address: Address::new(signing_key.verifying_key(), 123),
            message: Message::create(
                &signing_key,
                [1, 2, 3]
            )?
        },

        Packet::AskBlock {
            address: Address::new(signing_key.verifying_key(), 123),
            hash: Hash::calc(b"Test")
        },

        Packet::Block {
            address: Address::new(signing_key.verifying_key(), 123),
            block: Block::builder()
                .with_inline_messages([
                    Message::create(&signing_key, b"Message 1".as_slice())?,
                    Message::create(&signing_key, b"Message 2".as_slice())?,
                    Message::create(&signing_key, b"Message 3".as_slice())?
                ])
                .sign(&signing_key)?
        }
    );

    Ok(())
}
