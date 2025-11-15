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
use flowerpot::protocol::network::{
    PacketStream, PacketStreamOptions, PacketStreamEncryption
};
use flowerpot::node::{Node, NodeOptions};

#[derive(Subcommand)]
pub enum MessageCommands {
    /// Create new flowerpot message.
    Create {
        /// Seed for random numbers generator.
        #[arg(short = 'r', long, alias = "rand", alias = "random")]
        seed: Option<u64>,

        /// Signing key of the message author. If not specified then randomly
        /// generated key is used.
        #[arg(short = 'k', long, alias = "secret", alias = "key")]
        signing_key: Option<String>,

        /// Content of the message. If not specified, then stdin is read.
        #[arg(short = 'd', long, alias = "source", alias = "content")]
        data: Option<String>
    },

    /// Send message to the flowerpot network.
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

        /// Flowerpot message. If unset, then stdin value will be read.
        #[arg(short = 't', long)]
        message: Option<String>,

        /// Disable streams encryption.
        #[arg(long, alias = "disable-encryption")]
        no_encryption: bool
    }
}

impl MessageCommands {
    pub fn run(self) -> anyhow::Result<()> {
        match self {
            Self::Create { seed, signing_key, data } => {
                let signing_key = match signing_key {
                    Some(signing_key) => {
                        match SigningKey::from_base64(signing_key) {
                            Some(signing_key) => signing_key,
                            None => anyhow::bail!("invalid signing key")
                        }
                    }

                    None => SigningKey::random(&mut crate::safe_rng(seed))
                };

                let data = match data {
                    Some(data) => data.as_bytes().to_vec(),
                    None => {
                        let mut buf = Vec::new();

                        std::io::stdin().read_to_end(&mut buf)?;

                        buf
                    }
                };

                let message = Message::create(signing_key, data)
                    .context("failed to create message")?;

                let message = base64::encode(message.to_bytes());

                std::io::stdout().write_all(message.as_bytes())?;
            }

            Self::Send {
                seed,
                root_block,
                nodes,
                message,
                no_encryption
            } => {
                let root_block = Hash::from_base64(root_block)
                    .ok_or_else(|| anyhow::anyhow!("invalid root block"))?;

                let message = match message {
                    Some(message) => {
                        let message = base64::decode(message)
                            .context("failed to decode message")?;

                        Message::from_bytes(&message)
                            .context("invalid message")?
                    }

                    None => {
                        let mut message = Vec::new();

                        std::io::stdin().read_to_end(&mut message)?;

                        let message = base64::decode(message)
                            .context("failed to decode message")?;

                        Message::from_bytes(&message)
                            .context("invalid message")?
                    }
                };

                let secret_key = SecretKey::random(&mut crate::safe_rng(seed));

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

                println!("sending message...");

                handler.send_message(root_block, message);

                // TODO: some sort of .wait() method on the handler.
                std::thread::sleep(std::time::Duration::from_secs(3));
            }
        }

        Ok(())
    }
}
