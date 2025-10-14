use std::io::{Read, Write};
use std::path::PathBuf;
use std::net::{SocketAddr, Ipv6Addr, TcpStream, TcpListener};
use std::time::{Instant, Duration};

use anyhow::Context;
use clap::{Parser, Subcommand};

use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::{RngCore, SeedableRng};

use libflowerpot::crypto::base64;
use libflowerpot::crypto::hash::Hash;
use libflowerpot::crypto::sign::SigningKey;
use libflowerpot::crypto::key_exchange::SecretKey;
use libflowerpot::transaction::Transaction;
use libflowerpot::block::{Block, BlockContent};
use libflowerpot::storage::Storage;
use libflowerpot::storage::sqlite_storage::SqliteStorage;
use libflowerpot::protocol::network::{
    PacketStream, PacketStreamOptions, PacketStreamEncryption
};
use libflowerpot::node::{Node, NodeOptions};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Optional path to a file where to write debug information.
    #[arg(long, alias = "debug")]
    log: Option<PathBuf>,

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
    },

    /// Manage flowerpot blockchain transactions.
    Transaction {
        #[command(subcommand)]
        command: TransactionCommands
    }
}

#[derive(Subcommand)]
enum KeypairCommands {
    /// Create new flowerpot blockchain signing key.
    Create {
        /// Seed for random numbers generator. If unset, then system-provided
        /// entropy is used.
        #[arg(short = 'r', long, alias = "rand", alias = "random")]
        seed: Option<u64>
    },

    /// Export verifying key from the flowerpot's signing key.
    Export {
        /// Signing key of the flowerpot blockchain.
        #[arg(short = 'k', long, alias = "secret", alias = "key")]
        signing_key: Option<String>
    }
}

#[derive(Subcommand)]
enum BlockchainCommands {
    /// Create new flowerpot blockchain.
    Create {
        /// Seed for random numbers generator. If unset, then system-provided
        /// entropy is used.
        #[arg(short = 'r', long, alias = "rand", alias = "random")]
        seed: Option<u64>,

        /// Signing key used to create the blockchain.
        ///
        /// If not specified then randomly generated key is used.
        #[arg(short = 'k', long, alias = "secret", alias = "key")]
        signing_key: Option<String>,

        /// Path to the sqlite storage database.
        #[arg(short = 's', long, alias = "path")]
        storage: PathBuf
    },

    /// Serve flowerpot blockchain.
    Serve {
        /// Seed for random numbers generator. If unset, then system-provided
        /// entropy is used.
        #[arg(short = 'r', long, alias = "rand", alias = "random")]
        seed: Option<u64>,

        /// Hash of the root block of the flowerpot blockchain. If unset,
        /// root block of the provided storage will be used.
        #[arg(short = 'b', long, alias = "root")]
        root_block: Option<String>,

        /// Path to the sqlite storage database. If unset, thin client
        /// is started.
        #[arg(short = 's', long, alias = "path")]
        storage: Option<PathBuf>,

        /// Address of remote node to connect to.
        #[arg(short = 'n', long = "node", alias = "connect")]
        nodes: Vec<String>,

        /// Signing key of a validator node.
        ///
        /// If specified, the local node will run the blocks validator to create
        /// new blocks and approve blocks made by other validators.
        #[arg(short = 'v', long = "signing-key", alias = "validator")]
        signing_keys: Vec<String>,

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

#[derive(Subcommand)]
enum TransactionCommands {
    /// Create new flowerpot blockchain transaction.
    Create {
        /// Seed for random numbers generator. If unset, then system-provided
        /// entropy is used.
        #[arg(short = 'r', long, alias = "rand", alias = "random")]
        seed: Option<u64>,

        /// Signing key of the transaction's author.
        ///
        /// If not specified then randomly generated key is used.
        #[arg(short = 'k', long, alias = "secret", alias = "key")]
        signing_key: Option<String>,

        /// Content of the transaction.
        ///
        /// If not specified, then stdin is read.
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

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if let Some(log) = cli.log {
        if let Some(parent) = log.parent() {
            std::fs::create_dir_all(parent)
                .context("failed to create log file's parent folder")?;
        }

        let file = std::fs::File::create(log)
            .context("failed to create log file")?;

        tracing_subscriber::fmt()
            .with_writer(file)
            .with_ansi(false)
            .with_max_level(tracing_subscriber::filter::LevelFilter::TRACE)
            .init();
    }

    match cli.command {
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
                        match SigningKey::from_base64(signing_key) {
                            Some(secret_key) => secret_key,
                            None => anyhow::bail!("invalid signing key")
                        }
                    }

                    None => {
                        let mut signing_key = Vec::new();

                        std::io::stdin().read_to_end(&mut signing_key)?;

                        match SigningKey::from_base64(&signing_key) {
                            Some(signing_key) => signing_key,
                            None => {
                                let mut buf = [0; SigningKey::SIZE];

                                buf.copy_from_slice(signing_key.trim_ascii());

                                SigningKey::from_bytes(&buf)
                                    .ok_or_else(|| anyhow::anyhow!("invalid signing key"))?
                            }
                        }
                    }
                };

                let verifying_key = signing_key.verifying_key();

                std::io::stdout().write_all(verifying_key.to_base64().as_bytes())?;
            }
        }

        Commands::Blockchain { command } => match command {
            BlockchainCommands::Create { seed, signing_key, storage } => {
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

                let signing_key = match signing_key {
                    Some(signing_key) => {
                        match SigningKey::from_base64(signing_key) {
                            Some(signing_key) => signing_key,
                            None => anyhow::bail!("invalid signing key")
                        }
                    }

                    None => SigningKey::random(&mut rng)
                };

                let storage = SqliteStorage::open(storage)
                    .context("failed to create sqlite storage")?;

                let mut root_block_seed = [0; 32];

                rng.fill_bytes(&mut root_block_seed);

                let block = Block::new(
                    &signing_key,
                    Hash::default(),
                    BlockContent::data(root_block_seed)
                ).context("failed to create new block")?;

                let hash = block.hash()
                    .context("failed to calculate hash of the new block")?;

                storage.write_block(&block)
                    .context("failed to write new block to the database storage")?;

                println!("New blockchain created!");
                println!("     Root block: {}", hash.to_base64());
                println!("    Signing key: {}", signing_key.to_base64());
                println!("  Verifying key: {}", signing_key.verifying_key().to_base64());
            }

            BlockchainCommands::Serve {
                seed,
                root_block,
                storage,
                nodes,
                signing_keys,
                local_addr,
                no_encryption,
                no_sync
            } => {
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

                let mut rng = match seed {
                    Some(seed) => ChaCha20Rng::seed_from_u64(seed),
                    None => ChaCha20Rng::from_entropy()
                };

                let secret_key = SecretKey::random(&mut rng);

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

                let mut node = Node::new(root_block);

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

                if let Some(storage) = storage {
                    node.attach_storage(storage);
                }

                for signing_key in signing_keys {
                    let Some(signing_key) = SigningKey::from_base64(signing_key) else {
                        anyhow::bail!("invalid validator signign key");
                    };

                    node.add_validator(signing_key);
                }

                if !no_sync {
                    println!("synchronizing blockchain data...");

                    node.sync().context("failed to synchronize blockchain data")?;
                }

                println!("starting the node...");

                let handler = node.start(NodeOptions::default())?;

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

        Commands::Transaction { command } => match command {
            TransactionCommands::Create { seed, signing_key, data } => {
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

            TransactionCommands::Send {
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

                let hash = transaction.hash();

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
    }

    Ok(())
}
