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
use libflowerpot::storage::sqlite_storage::SqliteStorage;
use libflowerpot::protocol::network::{
    PacketStream, PacketStreamOptions, PacketStreamEncryption
};
use libflowerpot::node::{Node, NodeOptions};

#[derive(Subcommand)]
pub enum TransactionCommands {
    /// Create new flowerpot blockchain transaction.
    Create {
        /// Seed for random numbers generator. If unset, then system-provided
        /// entropy is used.
        #[arg(short = 'r', long, alias = "rand", alias = "random")]
        seed: Option<u64>,

        /// Signing key of the transaction's author. If not specified then
        /// randomly generated key is used.
        #[arg(short = 'k', long, alias = "secret", alias = "key")]
        signing_key: Option<String>,

        /// Content of the transaction. If not specified, then stdin is read.
        #[arg(short = 'd', long, alias = "source", alias = "content")]
        data: Option<String>
    },

    /// Send transaction to the flowerpot blockchain network.
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

        /// Flowerpot blockchain transaction. If unset, then stdin value will be
        /// read.
        #[arg(short = 't', long)]
        transaction: Option<String>,

        /// Disable streams encryption.
        #[arg(long, alias = "disable-encryption")]
        no_encryption: bool,

        /// Amount of seconds to wait for transaction to appear in the network.
        #[arg(long, alias = "wait", alias = "timeout", default_value_t = 10)]
        wait_timeout: u64
    }
}

impl TransactionCommands {
    pub fn run(self) -> anyhow::Result<()> {
        match self {
            Self::Create { seed, signing_key, data } => {
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

                let data = match data {
                    Some(data) => data.as_bytes().to_vec(),
                    None => {
                        let mut buf = Vec::new();

                        std::io::stdin().read_to_end(&mut buf)?;

                        buf
                    }
                };

                let trasaction = Transaction::create(signing_key, data)
                    .context("failed to create transaction")?;

                let transaction = base64::encode(trasaction.to_bytes());

                std::io::stdout().write_all(transaction.as_bytes())?;
            }

            Self::Send {
                seed,
                root_block,
                nodes,
                transaction,
                no_encryption,
                wait_timeout
            } => {
                let root_block = Hash::from_base64(root_block)
                    .ok_or_else(|| anyhow::anyhow!("invalid root block"))?;

                let transaction = match transaction {
                    Some(transaction) => {
                        let transaction = base64::decode(transaction)
                            .context("failed to decode transaction")?;

                        Transaction::from_bytes(&transaction)
                            .context("invalid transaction")?
                    }

                    None => {
                        let mut transaction = Vec::new();

                        std::io::stdin().read_to_end(&mut transaction)?;

                        let transaction = base64::decode(transaction)
                            .context("failed to decode transaction")?;

                        Transaction::from_bytes(&transaction)
                            .context("invalid transaction")?
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

                println!("sending transaction...");

                let hash = *transaction.hash();

                handler.send_transaction(transaction);
                handler.ask_pending_transactions();

                let now = Instant::now();
                let mut last_repeat = Instant::now();

                while !handler.pending_transactions().contains_key(&hash)
                    && now.elapsed().as_secs() < wait_timeout
                {
                    if last_repeat.elapsed().as_secs() >= 5 {
                        handler.ask_pending_transactions();

                        last_repeat = Instant::now();
                    }

                    std::thread::sleep(Duration::from_secs(1));
                }

                if handler.pending_transactions().contains_key(&hash) {
                    println!("transaction accepted by the network");
                } else {
                    println!("transaction was not accepted by the network");
                }
            }
        }

        Ok(())
    }
}
