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
use std::time::{Instant, Duration};

use anyhow::Context;
use clap::Subcommand;

use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::{SeedableRng};

use libflowerpot::crypto::base64;
use libflowerpot::crypto::hash::Hash;
use libflowerpot::crypto::sign::SigningKey;
use libflowerpot::crypto::key_exchange::SecretKey;
use libflowerpot::transaction::Transaction;
use libflowerpot::block::{Block, BlockContent};
use libflowerpot::storage::sqlite_storage::SqliteStorage;
use libflowerpot::protocol::network::{
    PacketStream, PacketStreamOptions, PacketStreamEncryption
};
use libflowerpot::node::{Node, NodeOptions};

#[derive(Subcommand)]
pub enum BlockCommands {
    /// Create new flowerpot blockchain block.
    Create {
        /// Seed for random numbers generator. If unset, then system-provided
        /// entropy is used.
        #[arg(short = 'r', long, alias = "rand", alias = "random")]
        seed: Option<u64>,

        /// Signing key of the block's author. If not specified then randomly
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

        /// Transaction to add to the block.
        #[arg(short = 't', long = "transaction")]
        transactions: Vec<String>
    },

    /// Approve flowerpot blockchain block.
    Approve {
        /// Seed for random numbers generator. If unset, then system-provided
        /// entropy is used.
        #[arg(short = 'r', long, alias = "rand", alias = "random")]
        seed: Option<u64>,

        /// Signing key of a validator. If not specified then randomly generated
        /// key is used.
        #[arg(short = 'k', long, alias = "secret", alias = "key")]
        signing_key: Option<String>,

        /// Flowerpot blockchain block. If unset, then stdin value will be read.
        #[arg(short = 'd', long)]
        block: Option<String>
    },

    /// Send block to the flowerpot blockchain network.
    Send {
        /// Seed for random numbers generator. If unset, then system-provided
        /// entropy is used.
        #[arg(short = 'r', long, alias = "rand", alias = "random")]
        seed: Option<u64>,

        /// Hash of the root block of the flowerpot blockchain.
        #[arg(short = 'b', long, alias = "root")]
        root_block: String,

        /// Address of remote node to connect to.
        #[arg(short = 'n', long = "node", alias = "connect")]
        nodes: Vec<String>,

        /// Flowerpot blockchain block. If unset, then stdin value will be read.
        #[arg(short = 'd', long)]
        block: Option<String>,

        /// Disable streams encryption.
        #[arg(long, alias = "disable-encryption")]
        no_encryption: bool,

        /// Amount of seconds to wait for block to appear in the network.
        #[arg(long, alias = "wait", alias = "timeout", default_value_t = 10)]
        wait_timeout: u64
    }
}

impl BlockCommands {
    pub fn run(self) -> anyhow::Result<()> {
        match self {
            Self::Create { seed, signing_key, previous, transactions } => {
                let mut rng = match seed {
                    Some(seed) => ChaCha20Rng::seed_from_u64(seed),
                    None => ChaCha20Rng::from_entropy()
                };

                let signing_key = match signing_key {
                    Some(signing_key) => {
                        match SigningKey::from_base64(signing_key) {
                            Some(signing_key) => signing_key,
                            None => anyhow::bail!("invalid signing key")
                        }
                    }

                    None => SigningKey::random(&mut rng)
                };

                let previous = match previous {
                    Some(previous) => {
                        let Some(previous) = Hash::from_base64(previous) else {
                            anyhow::bail!("invalid previous block hash format");
                        };

                        previous
                    }

                    None => Hash::default()
                };

                let mut decoded_transactions = Vec::with_capacity(transactions.len());

                for transaction in transactions {
                    let transaction = base64::decode(transaction)
                        .map_err(|err| {
                            anyhow::anyhow!(err)
                                .context("failed to decode transaction from base64")
                        })?;

                    let transaction = Transaction::from_bytes(transaction)
                        .map_err(|err| {
                            anyhow::anyhow!(err)
                                .context("failed to decode transaction from bytes")
                        })?;

                    decoded_transactions.push(transaction);
                }

                let content = BlockContent::transactions(decoded_transactions);

                let block = Block::new(signing_key, previous, content)
                    .map_err(|err| {
                        anyhow::anyhow!(err)
                            .context("failed to create block")
                    })?;

                let block = base64::encode(block.to_bytes());

                std::io::stdout().write_all(block.as_bytes())?;
            }

            Self::Approve { seed, signing_key, block } => {
                let mut rng = match seed {
                    Some(seed) => ChaCha20Rng::seed_from_u64(seed),
                    None => ChaCha20Rng::from_entropy()
                };

                let signing_key = match signing_key {
                    Some(signing_key) => {
                        match SigningKey::from_base64(signing_key) {
                            Some(signing_key) => signing_key,
                            None => anyhow::bail!("invalid signing key")
                        }
                    }

                    None => SigningKey::random(&mut rng)
                };

                let mut block = match block {
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

                if let Err(err) = block.approve_with(signing_key) {
                    return Err({
                        anyhow::anyhow!(err)
                            .context("failed to approve block")
                    });
                };

                let block = base64::encode(block.to_bytes());

                std::io::stdout().write_all(block.as_bytes())?;
            }

            Self::Send {
                seed,
                root_block,
                nodes,
                block,
                no_encryption,
                wait_timeout
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

                let mut rng = match seed {
                    Some(seed) => ChaCha20Rng::seed_from_u64(seed),
                    None => ChaCha20Rng::from_entropy()
                };

                let secret_key = SecretKey::random(&mut rng);

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

                let mut node = Node::<SqliteStorage>::new(root_block);

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
                    accept_transactions: true,
                    accept_blocks: false,
                    ..NodeOptions::default()
                })?;

                println!("sending block...");

                let hash = *block.current_hash();

                handler.send_block(block);
                handler.ask_pending_blocks();

                let now = Instant::now();
                let mut last_repeat = Instant::now();
                let mut found = false;

                // Check if the block was added to the pending blocks queue.
                while !handler.pending_blocks().contains_key(&hash)
                    && now.elapsed().as_secs() < wait_timeout
                {
                    if last_repeat.elapsed().as_secs() >= 5 {
                        // The block could have been accepted immediately.
                        if let Ok(Some(tail_block)) = handler.tracker().get_tail_block()
                            && tail_block == hash
                        {
                            found = true;

                            break;
                        }

                        handler.ask_pending_blocks();

                        last_repeat = Instant::now();
                    }

                    std::thread::sleep(Duration::from_secs(1));
                }

                if found || handler.pending_blocks().contains_key(&hash) {
                    println!("block accepted by the network");
                } else {
                    println!("block was not accepted by the network");
                }
            }
        }

        Ok(())
    }
}
