use std::io::{Read, Write};
use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};

use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::{RngCore, SeedableRng};

use libflowerpot::crypto::hash::Hash;
use libflowerpot::crypto::sign::{SigningKey, VerifyingKey, Signature};
use libflowerpot::block::{Block, BlockContent};
use libflowerpot::storage::Storage;
use libflowerpot::storage::sqlite_storage::SqliteStorage;
use libflowerpot::network::{Transport, TcpSocket};
use libflowerpot::protocol::{PacketStream, PacketStreamEncryption};
use libflowerpot::node::Node;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands
}

#[derive(Subcommand)]
enum Commands {
    /// Manage public and secret flowerpot blockchain keys.
    Keypair {
        #[command(subcommand)]
        command: KeypairCommands
    },

    /// Manage flowerpot blockchains.
    Blockchain {
        #[command(subcommand)]
        command: BlockchainCommands
    }
}

#[derive(Subcommand)]
enum KeypairCommands {
    /// Create new flowerpot blockchain secret key.
    Create {
        /// Seed for random numbers generator. If unset, then system-provided
        /// entropy is used.
        #[arg(long)]
        seed: Option<u64>
    },

    /// Export verifying key from the flowerpot's signing key.
    Export {
        /// Signing key of the flowerpot blockchain.
        #[arg(long)]
        signing_key: Option<String>
    }
}

#[derive(Subcommand)]
enum BlockchainCommands {
    /// Create new flowerpot blockchain.
    Create {
        /// Seed for random numbers generator. If unset, then system-provided
        /// entropy is used.
        #[arg(long)]
        seed: Option<u64>,

        /// Secret key used to create the blockchain.
        ///
        /// If not specified then randomly generated key is used.
        #[arg(long, alias = "--secret")]
        secret_key: Option<String>,

        /// Path to the sqlite storage database.
        #[arg(long)]
        storage: PathBuf
    },

    /// Serve flowerpot blockchain.
    Serve {
        /// Hash of the root block of the flowerpot blockchain. If unset,
        /// root block of the provided storage will be used.
        #[arg(long)]
        root_block: Option<String>,

        /// Path to the sqlite storage database. If unset, thin client
        /// is started.
        #[arg(long)]
        storage: Option<PathBuf>,

        /// Address of remote node to connect to.
        #[arg(long = "--node", alias = "--connect")]
        nodes: Vec<String>
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Commands::Keypair { command } => match command {
            KeypairCommands::Create { seed } => {
                let mut rng = match seed {
                    Some(seed) => ChaCha20Rng::seed_from_u64(seed),
                    None => ChaCha20Rng::from_entropy()
                };

                let signing_key = SigningKey::random(&mut rng);

                std::io::stdout().write_all(signing_key.to_base64().as_bytes())?;
            }

            KeypairCommands::Export { signing_key } => {
                let signing_key = match signing_key {
                    Some(signing_key) => {
                        match SigningKey::from_base64(secret_key) {
                            Some(secret_key) => secret_key,
                            None => anyhow::bail!("invalid secret key")
                        }
                    }

                    None => {
                        let mut secret_key = Vec::new();

                        std::io::stdin().read_to_end(&mut secret_key)?;

                        match SigningKey::from_base64(&secret_key) {
                            Some(secret_key) => secret_key,
                            None => SigningKey::from_bytes(secret_key.trim_ascii())
                                .ok_or_else(|| anyhow::anyhow!("invalid secret key"))?
                        }
                    }
                };

                let public_key = secret_key.public_key();

                std::io::stdout().write_all(public_key.to_base64().as_bytes())?;
            }
        }

        Commands::Blockchain { command } => match command {
            BlockchainCommands::Create { seed, secret_key, storage } => {
                if storage.exists() {
                    anyhow::bail!("storage database already exists");
                }

                if let Some(parent) = storage.parent() {
                    std::fs::create_dir_all(parent)
                        .context("failed to create parent folder for the storage database")?;
                }

                let mut rng = match seed {
                    Some(seed) => ChaCha20Rng::seed_from_u64(seed),
                    None => ChaCha20Rng::from_entropy()
                };

                let secret_key = match secret_key {
                    Some(secret_key) => {
                        match SecretKey::from_base64(secret_key) {
                            Some(secret_key) => secret_key,
                            None => anyhow::bail!("invalid secret key")
                        }
                    }

                    None => SecretKey::random(&mut rng)
                };

                let storage = SqliteStorage::open(storage)
                    .context("failed to create sqlite storage")?;

                let mut root_block_seed = [0; 32];

                rng.fill_bytes(&mut root_block_seed);

                let block = Block::new(
                    &secret_key,
                    Hash::default(),
                    BlockContent::data(root_block_seed)
                ).context("failed to create new block")?;

                let hash = block.hash()
                    .context("failed to calculate hash of the new block")?;

                storage.write_block(&block)
                    .context("failed to write new block to the database storage")?;

                println!("New blockchain created!");
                println!("  Root block: {}", hash.to_base64());
                println!("  Secret key: {}", secret_key.to_base64());
                println!("  Public key: {}", secret_key.public_key().to_base64());
            }

            BlockchainCommands::Serve { root_block, storage, nodes } => {
                let storage = match storage {
                    Some(storage) => {
                        if !storage.exists() {
                            anyhow::bail!("storage doesn't exist");
                        }

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
                            .context("failed to query root block of the blockchain from the sqlite storage")?
                            .ok_or_else(|| anyhow::anyhow!("root block is missing in the sqlite storage"))?,

                        None => anyhow::bail!("either root block hash or storage path must be provided")
                    }
                };

                let mut connections = Vec::with_capacity(nodes.len());

                let socket = TcpSocket::default();

                for node in nodes {
                    println!("connecting to {node}...");

                    let connection = socket.connect(node).await
                        .context("failed to connect to the node")?;

                    let stream = PacketStream::init(secret_key, options, stream)

                    connections.push(connection);
                }

                let node = Node::new(root_block);
            }
        }
    }

    Ok(())
}
