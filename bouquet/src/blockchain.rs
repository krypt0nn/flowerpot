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

use std::path::PathBuf;
use std::net::{SocketAddr, Ipv6Addr, TcpStream, TcpListener};

use anyhow::Context;
use clap::Subcommand;

use flowerpot::crypto::base64;
use flowerpot::crypto::sign::SigningKey;
use flowerpot::crypto::key_exchange::SecretKey;
use flowerpot::address::Address;
use flowerpot::storage::Storage;
use flowerpot::storage::sqlite_storage::SqliteStorage;
use flowerpot::protocol::network::{
    PacketStream, PacketStreamOptions, PacketStreamEncryption
};
use flowerpot::viewer::BatchedViewer;
use flowerpot::node::{Node, NodeOptions};

#[derive(Subcommand)]
pub enum BlockchainCommands {
    /// Create new flowerpot blockchain.
    Create {
        /// Path to the sqlite storage database.
        #[arg(short = 's', long, alias = "path")]
        storage: PathBuf
    },

    /// Synchronize local flowerpot blockchain storage with remote nodes.
    Sync {
        /// Seed for random numbers generator.
        #[arg(short = 'r', long, alias = "rand", alias = "random")]
        seed: Option<u64>,

        /// Flowerpot blockchain address.
        #[arg(short = 'a', long, alias = "addr")]
        address: String,

        /// Path to the sqlite storage database.
        #[arg(short = 's', long, alias = "path")]
        storage: PathBuf,

        /// Address of remote node to connect to.
        #[arg(short = 'n', long = "node", alias = "connect")]
        nodes: Vec<String>,

        /// Disable streams encryption.
        #[arg(long, alias = "disable-encryption")]
        no_encryption: bool
    },

    /// View blocks of the flowerpot blockchain.
    View {
        /// Seed for random numbers generator.
        #[arg(short = 'r', long, alias = "rand", alias = "random")]
        seed: Option<u64>,

        /// Flowerpot blockchain address.
        #[arg(short = 'a', long, alias = "addr")]
        address: String,

        /// Path to the sqlite storage database.
        #[arg(short = 's', long, alias = "path")]
        storage: Option<PathBuf>,

        /// Address of remote node to connect to.
        #[arg(short = 'n', long = "node", alias = "connect")]
        nodes: Vec<String>,

        /// Disable streams encryption.
        #[arg(long, alias = "disable-encryption")]
        no_encryption: bool,

        /// Disable stream connection status reports.
        #[arg(
            long,
            alias = "disable-stream-connect-report",
            alias = "disable-stream-report",
            alias = "no-stream-report",
            alias = "no-connect-report"
        )]
        no_stream_connect_report: bool
    },

    /// Serve flowerpot blockchain.
    Serve {
        /// Seed for random numbers generator.
        #[arg(short = 'r', long, alias = "rand", alias = "random")]
        seed: Option<u64>,

        /// Signing key of a validator node.
        #[arg(short = 'v', long = "signing-key", alias = "validator")]
        signing_key: String,

        /// Path to the sqlite storage database.
        #[arg(short = 's', long, alias = "path")]
        storage: PathBuf,

        /// Flowerpot blockchain address.
        #[arg(short = 'a', long, alias = "addr")]
        address: String,

        /// Address of remote node to connect to.
        #[arg(short = 'n', long = "node", alias = "connect")]
        nodes: Vec<String>,

        /// Local address to listen to incoming TCP connections.
        #[arg(
            short = 'l',
            long,
            alias = "local",
            alias = "listen",
            alias = "bind",
            default_value_t = SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 13478)
        )]
        local_addr: SocketAddr,

        /// Disable streams encryption.
        #[arg(long, alias = "disable-encryption")]
        no_encryption: bool,

        /// Disable blocks synchronization at startup.
        #[arg(long, alias = "disable-sync")]
        no_sync: bool
    }
}

impl BlockchainCommands {
    pub fn run(self) -> anyhow::Result<()> {
        match self {
            Self::Create { storage } => {
                if storage.exists() {
                    anyhow::bail!("storage database already exists");
                }

                if let Some(parent) = storage.parent() {
                    std::fs::create_dir_all(parent)
                        .context("failed to create parent folder for the storage database")?;
                }

                SqliteStorage::open(storage)
                    .context("failed to create sqlite storage")?;

                println!("Blockchain storage created");
            }

            Self::Sync {
                seed,
                address,
                storage,
                nodes,
                no_encryption
            } => {
                let address = Address::from_base64(address)
                    .ok_or_else(|| anyhow::anyhow!("invalid flowerpot address"))?;

                let storage = SqliteStorage::open(storage)
                    .context("failed to open sqlite storage")?;

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
                    },

                    ..PacketStreamOptions::default()
                };

                let mut node = Node::default()
                    .add_storage(address.clone(), storage.clone());

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

                    node = node.add_stream(stream);
                }

                println!("synchronizing blockchain data...");

                node.sync().map_err(|err| {
                    anyhow::anyhow!(err.to_string())
                        .context("failed to synchronize blockchain data")
                })?;

                let root_block = storage.root_block()
                    .map_err(|err| {
                        anyhow::anyhow!(err.to_string())
                            .context("failed to get root block of the blockchain")
                    })?
                    .map(|block| block.to_base64());

                let tail_block = storage.tail_block()
                    .map_err(|err| {
                        anyhow::anyhow!(err.to_string())
                            .context("failed to get tail block of the blockchain")
                    })?
                    .map(|block| block.to_base64());

                println!();
                println!("Blockchain synchronized!");
                println!("    Root block: {}", root_block.unwrap_or_else(|| String::from("-")));
                println!("    Tail block: {}", tail_block.unwrap_or_else(|| String::from("-")));
            }

            Self::View {
                seed,
                address,
                storage,
                nodes,
                no_encryption,
                no_stream_connect_report
            } => {
                let address = Address::from_base64(address)
                    .ok_or_else(|| anyhow::anyhow!("invalid flowerpot address"))?;

                let storage = match storage {
                    Some(storage) => {
                        let storage = SqliteStorage::open(storage)
                            .context("failed to open sqlite storage")?;

                        Some(storage)
                    }

                    None => None
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
                    },

                    ..PacketStreamOptions::default()
                };

                let mut streams = Vec::with_capacity(nodes.len());

                for address in nodes {
                    if !no_stream_connect_report {
                        println!("connecting to '{address}'...");
                    }

                    let stream = TcpStream::connect(address)
                        .context("failed to connect to the node")?;

                    let stream = PacketStream::init(&secret_key, &options, stream)
                        .context("failed to initialize packet stream with the node")?;

                    if !no_stream_connect_report {
                        println!(
                            "connected to {} [{}]",
                            stream.peer_addr()?,
                            base64::encode(stream.peer_id())
                        );
                    }

                    streams.push(stream);
                }

                let mut viewer = BatchedViewer::new(
                    streams.iter_mut(),
                    address
                );

                loop {
                    let block = match &storage {
                        Some(storage) => viewer.forward_with_storage(storage),
                        None => viewer.forward()
                    };

                    let block = block.map_err(|err| {
                        anyhow::anyhow!(err.to_string())
                            .context("failed to query the next blockchain block")
                    })?;

                    let Some(block) = block else {
                        break;
                    };

                    let ref_messages = block.ref_messages()
                        .iter()
                        .map(|hash| format!("\"{}\"", hash.to_base64()))
                        .collect::<Box<[String]>>();

                    let inline_messages = block.inline_messages()
                        .iter()
                        .map(|message| {
                            format!(
                                "{{ \"hash\": \"{}\", \"size\": {}, \"sign\": \"{}\", \"author\": \"{}\" }}",
                                message.hash().to_base64(),
                                message.data().len(),
                                message.sign().to_base64(),
                                message.verify()
                                    .map(|(_, verifying_key)| verifying_key.to_base64())
                                    .unwrap_or_else(|_| String::from("-"))
                            )
                        })
                        .collect::<Box<[String]>>();

                    println!(
                        "{{ \"hash\": \"{}\", \"timestamp\": {}, \"sign\": \"{}\", \"ref_messages\": [{}], \"inline_messages\": [{}] }}",
                        block.hash().to_base64(),
                        block.timestamp().unix_timestamp(),
                        block.sign().to_base64(),
                        ref_messages.join(", "),
                        inline_messages.join(", ")
                    );
                }
            }

            Self::Serve {
                seed,
                signing_key,
                address,
                storage,
                nodes,
                local_addr,
                no_encryption,
                no_sync
            } => {
                let address = Address::from_base64(address)
                    .ok_or_else(|| anyhow::anyhow!("invalid flowerpot address"))?;

                let storage = SqliteStorage::open(storage)
                    .context("failed to open sqlite storage")?;

                let Some(signing_key) = SigningKey::from_base64(signing_key) else {
                    anyhow::bail!("invalid validator signign key");
                };

                let secret_key = SecretKey::random(&mut super::safe_rng(seed));

                let listener = TcpListener::bind(local_addr)
                    .context("failed to bind TCP listener to the provided local address")?;

                let options = PacketStreamOptions {
                    encryption_algorithms: if no_encryption {
                        vec![]
                    } else {
                        vec![
                            PacketStreamEncryption::ChaCha20,
                            PacketStreamEncryption::ChaCha12,
                            PacketStreamEncryption::ChaCha8
                        ]
                    },

                    ..PacketStreamOptions::default()
                };

                let mut node = Node::default()
                    .add_validator(address.clone(), signing_key.clone())
                    .add_storage(address.clone(), storage);

                for address in nodes {
                    println!("connecting to '{address}'...");

                    let stream = TcpStream::connect(address)
                        .context("failed to connect to the node")?;

                    let stream = PacketStream::init(&secret_key, &options, stream)
                        .context("failed to initialize packet stream with the node")?;

                    println!(
                        "connected to '{}' [{}]",
                        stream.peer_addr()?,
                        base64::encode(stream.peer_id())
                    );

                    node = node.add_stream(stream);
                }

                if !no_sync {
                    println!("synchronizing blockchain data...");

                    node.sync().map_err(|err| {
                        anyhow::anyhow!(err.to_string())
                            .context("failed to synchronize blockchain data")
                    })?;
                }

                println!("starting the node...");

                let handler = node.start(NodeOptions::default())
                    .map_err(|err| {
                        anyhow::anyhow!(err.to_string())
                            .context("failed to start node")
                    })?;

                println!(
                    "node started at '{local_addr}' with address '{}'",
                    address.to_base64()
                );

                loop {
                    match listener.accept() {
                        Ok((stream, address)) => {
                            println!("listener: accept connection from '{address}'");

                            match PacketStream::init(&secret_key, &options, stream) {
                                Ok(stream) => {
                                    println!(
                                        "listener: connected to '{}' [{}]",
                                        stream.peer_addr()?,
                                        base64::encode(stream.peer_id())
                                    );

                                    handler.add_stream(stream);
                                }

                                Err(err) => eprintln!("listener: {err}")
                            }
                        }

                        Err(err) => eprintln!("listener: {err}")
                    }
                }
            }
        }

        Ok(())
    }
}
