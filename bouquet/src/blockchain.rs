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
use flowerpot::crypto::hash::Hash;
use flowerpot::crypto::sign::{SigningKey, VerifyingKey};
use flowerpot::crypto::key_exchange::SecretKey;
use flowerpot::block::Block;
use flowerpot::storage::Storage;
use flowerpot::storage::sqlite_storage::SqliteStorage;
use flowerpot::protocol::network::{
    PacketStream, PacketStreamOptions, PacketStreamEncryption
};
use flowerpot::viewer::BatchedViewer;
use flowerpot::node::{Node, NodeOptions};
use flowerpot::node::tracker::Tracker;

#[derive(Subcommand)]
pub enum BlockchainCommands {
    /// Create new flowerpot blockchain.
    Create {
        /// Seed for random numbers generator.
        #[arg(short = 'r', long, alias = "rand", alias = "random")]
        seed: Option<u64>,

        /// Signing key used to create the chain. If not specified then randomly
        /// generated key is used.
        #[arg(short = 'k', long, alias = "secret", alias = "key")]
        signing_key: Option<String>,

        /// Path to the sqlite storage database.
        #[arg(short = 's', long, alias = "path")]
        storage: PathBuf
    },

    /// Synchronize local flowerpot blockchain storage with remote nodes.
    Sync {
        /// Seed for random numbers generator.
        #[arg(short = 'r', long, alias = "rand", alias = "random")]
        seed: Option<u64>,

        /// Hash of the root block of the flowerpot blockchain. If unset,
        /// root block of the provided storage will be used.
        #[arg(short = 'b', long, alias = "root")]
        root_block: Option<String>,

        /// Verifying key of the flowerpot blockchain. If unset, signing key
        /// of the root block of the provided storage will be used.
        #[arg(short = 'v', long, alias = "validator")]
        verifying_key: Option<String>,

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

        /// Hash of the root block of the flowerpot blockchain. If unset,
        /// root block of the provided storage will be used.
        #[arg(short = 'b', long, alias = "root")]
        root_block: Option<String>,

        /// Verifying key of the flowerpot blockchain. If unset, signing key
        /// of the root block of the provided storage will be used.
        #[arg(short = 'v', long, alias = "validator")]
        verifying_key: Option<String>,

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

        /// Hash of the root block of the flowerpot blockchain. If unset,
        /// root block of the provided storage will be used.
        #[arg(short = 'b', long, alias = "root")]
        root_block: Option<String>,

        /// Signing key of a validator node.
        #[arg(short = 'v', long = "signing-key", alias = "validator")]
        signing_key: String,

        /// Path to the sqlite storage database. If unset, thin client
        /// is started.
        #[arg(short = 's', long, alias = "path")]
        storage: Option<PathBuf>,

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
            Self::Create { seed, signing_key, storage } => {
                if storage.exists() {
                    anyhow::bail!("storage database already exists");
                }

                if let Some(parent) = storage.parent() {
                    std::fs::create_dir_all(parent)
                        .context("failed to create parent folder for the storage database")?;
                }

                let signing_key = match signing_key {
                    Some(signing_key) => {
                        match SigningKey::from_base64(signing_key) {
                            Some(signing_key) => signing_key,
                            None => anyhow::bail!("invalid signing key")
                        }
                    }

                    None => SigningKey::random(&mut super::safe_rng(seed))
                };

                let storage = SqliteStorage::open(storage)
                    .context("failed to create sqlite storage")?;

                let block = Block::create_root(&signing_key)
                    .context("failed to create new block")?;

                storage.write_block(&block)
                    .map_err(|err| {
                        anyhow::anyhow!(err.to_string())
                            .context("failed to write new block to the database storage")
                    })?;

                println!("New blockchain created!");
                println!("     Root block: {}", block.hash().to_base64());
                println!("    Signing key: {}", signing_key.to_base64());
                println!("  Verifying key: {}", signing_key.verifying_key().to_base64());
            }

            Self::Sync {
                seed,
                root_block,
                verifying_key,
                storage,
                nodes,
                no_encryption
            } => {
                let storage = SqliteStorage::open(storage)
                    .context("failed to open sqlite storage")?;

                let root_block = match root_block {
                    Some(root_block) => Hash::from_base64(root_block)
                        .ok_or_else(|| anyhow::anyhow!("invalid root block"))?,

                    None => storage.root_block()
                        .map_err(|err| {
                            anyhow::anyhow!(err.to_string())
                                .context("failed to query root block of the blockchain from the sqlite storage")
                        })?
                        .ok_or_else(|| anyhow::anyhow!("root block is missing in the sqlite storage"))?
                };

                let verifying_key = match verifying_key {
                    Some(verifying_key) => VerifyingKey::from_base64(verifying_key)
                        .ok_or_else(|| anyhow::anyhow!("invalid verifying key"))?,

                    None => {
                        let root_block = storage.read_block(&root_block)
                            .map_err(|err| {
                                anyhow::anyhow!(err.to_string())
                                    .context("failed to query root block of the blockchain from the sqlite storage")
                            })?
                            .ok_or_else(|| anyhow::anyhow!("root block is missing in the sqlite storage"))?;

                        let (is_valid, verifying_key) = root_block.verify()
                            .context("failed to verify root block")?;

                        if !is_valid {
                            anyhow::bail!("root block stored in sqlite storage is invalid");
                        }

                        verifying_key
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

                let tracker = Tracker::from_storage(storage.clone());

                node.add_tracker(tracker, Some(root_block), Some(verifying_key));

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
                root_block,
                verifying_key,
                storage,
                nodes,
                no_encryption,
                no_stream_connect_report
            } => {
                let storage = match storage {
                    Some(storage) => {
                        let storage = SqliteStorage::open(storage)
                            .context("failed to open sqlite storage")?;

                        Some(storage)
                    }

                    None => None
                };

                let root_block = match root_block {
                    Some(root_block) => Hash::from_base64(root_block)
                        .ok_or_else(|| anyhow::anyhow!("invalid root block"))?,

                    None => match &storage {
                        Some(storage) => storage.root_block()
                            .map_err(|err| {
                                anyhow::anyhow!(err.to_string())
                                    .context("failed to query root block of the blockchain from the sqlite storage")
                            })?
                            .ok_or_else(|| anyhow::anyhow!("root block is missing in the sqlite storage"))?,

                        None => anyhow::bail!("either root block hash or storage path must be provided")
                    }
                };

                let verifying_key = match verifying_key {
                    Some(verifying_key) => VerifyingKey::from_base64(verifying_key)
                        .ok_or_else(|| anyhow::anyhow!("invalid verifying key"))?,

                    None => {
                        match &storage {
                            Some(storage) => {
                                let root_block = storage.read_block(&root_block)
                                    .map_err(|err| {
                                        anyhow::anyhow!(err.to_string())
                                            .context("failed to query root block of the blockchain from the sqlite storage")
                                    })?
                                    .ok_or_else(|| anyhow::anyhow!("root block is missing in the sqlite storage"))?;

                                let (is_valid, verifying_key) = root_block.verify()
                                    .context("failed to verify root block")?;

                                if !is_valid {
                                    anyhow::bail!("root block stored in sqlite storage is invalid");
                                }

                                verifying_key
                            }

                            None => anyhow::bail!("can't obtain verifying key without storage")
                        }
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

                let mut streams = Vec::with_capacity(nodes.len());

                for address in nodes {
                    if !no_stream_connect_report {
                        println!("connecting to {address}...");
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

                let viewer = BatchedViewer::open(
                    streams.iter_mut(),
                    root_block,
                    verifying_key
                ).map_err(|err| {
                    anyhow::anyhow!(err.to_string())
                        .context("failed to open batched flowerpot blockchain viewer")
                })?;

                let Some(mut viewer) = viewer else {
                    anyhow::bail!("couldn't build a blockchain viewer");
                };

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

                    let messages = block.block.messages()
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
                        "{{ \"hash\": \"{}\", \"timestamp\": {}, \"sign\": \"{}\", \"messages\": [{}] }}",
                        block.block.hash().to_base64(),
                        block.block.timestamp().unix_timestamp(),
                        block.block.sign().to_base64(),
                        messages.join(", ")
                    );
                }
            }

            Self::Serve {
                seed,
                root_block,
                signing_key,
                storage,
                nodes,
                local_addr,
                no_encryption,
                no_sync
            } => {
                let storage = match storage {
                    Some(storage) => {
                        let storage = SqliteStorage::open(storage)
                            .context("failed to open sqlite storage")?;

                        Some(storage)
                    }

                    None => None
                };

                let root_block = match root_block {
                    Some(root_block) => Hash::from_base64(root_block)
                        .ok_or_else(|| anyhow::anyhow!("invalid root block"))?,

                    None => match &storage {
                        Some(storage) => storage.root_block()
                            .map_err(|err| {
                                anyhow::anyhow!(err.to_string())
                                    .context("failed to query root block of the blockchain from the sqlite storage")
                            })?
                            .ok_or_else(|| anyhow::anyhow!("root block is missing in the sqlite storage"))?,

                        None => anyhow::bail!("either root block hash or storage path must be provided")
                    }
                };

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
                    }
                };

                let mut node = Node::default();

                node.add_validator(root_block, signing_key.clone());

                let tracker = match storage {
                    Some(storage) => Tracker::from_storage(storage),
                    None => Tracker::default()
                };

                node.add_tracker(
                    tracker,
                    Some(root_block),
                    Some(signing_key.verifying_key())
                );

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
                    "node started at {local_addr} with root block {}",
                    root_block.to_base64()
                );

                loop {
                    match listener.accept() {
                        Ok((stream, address)) => {
                            println!("listener: accept connection from {address}");

                            match PacketStream::init(&secret_key, &options, stream) {
                                Ok(stream) => {
                                    println!(
                                        "listener: connected to {} [{}]",
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
