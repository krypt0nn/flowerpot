// SPDX-License-Identifier: GPL-3.0-or-later
//
// bouquet
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

use std::io::{Read, Write};
use std::net::TcpStream;

use anyhow::Context;
use clap::Subcommand;

use flowerpot::crypto::base64;
use flowerpot::crypto::hash::Hash;
use flowerpot::crypto::sign::SigningKey;
use flowerpot::crypto::key_exchange::SecretKey;
use flowerpot::message::Message;
use flowerpot::block::Block;
use flowerpot::protocol::network::{
    PacketStream, PacketStreamOptions, PacketStreamEncryption
};
use flowerpot::node::{Node, NodeOptions};

#[derive(Subcommand)]
pub enum BlockCommands {
    /// Create new flowerpot block.
    Create {
        /// Seed for random numbers generator.
        #[arg(short = 'r', long, alias = "rand", alias = "random")]
        seed: Option<u64>,

        /// Signing key of the block author. If not specified then randomly
        /// generated key is used.
        #[arg(
            short = 'k',
            long,
            alias = "secret",
            alias = "key",
            alias = "author"
        )]
        signing_key: Option<String>,

        /// Hash of the previous block. If unset, then root block is created.
        #[arg(short = 'p', long, alias = "prev", alias = "parent")]
        previous: Option<String>,

        /// Flowerpot message to add to the block.
        #[arg(short = 'm', long = "message")]
        messages: Vec<String>
    },

    /// Send block to the flowerpot network.
    Send {
        /// Seed for random numbers generator.
        #[arg(short = 'r', long, alias = "rand", alias = "random")]
        seed: Option<u64>,

        /// Hash of the root block of the flowerpot chain.
        #[arg(short = 'b', long, alias = "root")]
        root_block: String,

        /// Address of remote node to connect to.
        #[arg(short = 'n', long = "node", alias = "connect")]
        nodes: Vec<String>,

        /// Flowerpot block. If unset, then stdin value will be read.
        #[arg(short = 'd', long)]
        block: Option<String>,

        /// Disable streams encryption.
        #[arg(long, alias = "disable-encryption")]
        no_encryption: bool
    }
}

impl BlockCommands {
    pub fn run(self) -> anyhow::Result<()> {
        match self {
            Self::Create { seed, signing_key, previous, messages } => {
                let signing_key = match signing_key {
                    Some(signing_key) => {
                        match SigningKey::from_base64(signing_key) {
                            Some(signing_key) => signing_key,
                            None => anyhow::bail!("invalid signing key")
                        }
                    }

                    None => SigningKey::random(&mut super::safe_rng(seed))
                };

                let block = match previous {
                    Some(previous) => {
                        let Some(previous) = Hash::from_base64(previous) else {
                            anyhow::bail!("invalid previous block hash format");
                        };

                        let mut decoded_messages = Vec::with_capacity(messages.len());

                        for message in messages {
                            let message = base64::decode(message)
                                .map_err(|err| {
                                    anyhow::anyhow!(err)
                                        .context("failed to decode message from base64")
                                })?;

                            let message = Message::from_bytes(message)
                                .map_err(|err| {
                                    anyhow::anyhow!(err)
                                        .context("failed to decode message from bytes")
                                })?;

                            decoded_messages.push(message);
                        }

                        Block::create(signing_key, previous, decoded_messages)
                            .context("failed to create block")?
                    }

                    None => Block::create_root(signing_key)
                        .context("failed to create root block")?
                };

                let block = base64::encode(block.to_bytes());

                std::io::stdout().write_all(block.as_bytes())?;
            }

            Self::Send {
                seed,
                root_block,
                nodes,
                block,
                no_encryption
            } => {
                let root_block = Hash::from_base64(root_block)
                    .ok_or_else(|| anyhow::anyhow!("invalid root block"))?;

                let block = match block {
                    Some(block) => {
                        let block = base64::decode(block)
                            .context("failed to decode block")?;

                        Block::from_bytes(&block)
                            .context("invalid block")?
                    }

                    None => {
                        let mut block = Vec::new();

                        std::io::stdin().read_to_end(&mut block)?;

                        let block = base64::decode(block)
                            .context("failed to decode block")?;

                        Block::from_bytes(&block)
                            .context("invalid block")?
                    }
                };

                let secret_key = SecretKey::random(&mut super::safe_rng(seed));

                let options = PacketStreamOptions {
                    encryption_algorithms: if no_encryption {
                        vec![]
                    } else {
                        vec![
                            PacketStreamEncryption::ChaCha20,
                            PacketStreamEncryption::ChaCha12,
                            PacketStreamEncryption::ChaCha8
                        ]
                    }
                };

                let mut node = Node::default();

                for address in nodes {
                    println!("connecting to {address}...");

                    let stream = TcpStream::connect(address)
                        .context("failed to connect to the node")?;

                    let stream = PacketStream::init(&secret_key, &options, stream)
                        .context("failed to initialize packet stream with the node")?;

                    println!(
                        "connected to {} [{}]",
                        stream.peer_addr()?,
                        base64::encode(stream.peer_id())
                    );

                    node.add_stream(stream);
                }

                println!("starting the node...");

                let handler = node.start(NodeOptions {
                    accept_messages: true,
                    accept_blocks: false,
                    ..NodeOptions::default()
                }).map_err(|err| anyhow::anyhow!(err.to_string()))?;

                println!("sending block...");

                handler.send_block(root_block, block);

                // TODO: some sort of .wait() method on the handler.
                std::thread::sleep(std::time::Duration::from_secs(3));
            }
        }

        Ok(())
    }
}
