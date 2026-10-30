// SPDX-License-Identifier: GPL-3.0-or-later
//
// bouquet
// Copyright (C) 2025 - 2026  Nikita Podvirnyi <krypt0nn@vk.ru>
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

use anyhow::Context;
use clap::{Parser, Subcommand};

use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;

mod keypair;
mod address;
mod message;
mod block;
mod blockchain;

pub fn safe_rng(seed: Option<u64>) -> ChaCha20Rng {
    match seed {
        Some(seed) => ChaCha20Rng::seed_from_u64(seed),
        None => {
            let mut seed = [0; 32];

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();

            seed[..16].copy_from_slice(&now.to_le_bytes());
            seed[16..].copy_from_slice(&now.to_be_bytes());

            let _ = getrandom::fill(&mut seed);

            ChaCha20Rng::from_seed(seed)
        }
    }
}

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
    /// Manage flowerpot signing keys.
    #[command(subcommand)]
    Keypair(keypair::KeypairCommands),

    /// Manage flowerpot blockchain addresses.
    #[command(subcommand)]
    Address(address::AddressCommands),

    /// Manage flowerpot messages.
    #[command(subcommand)]
    Message(message::MessageCommands),

    /// Manage flowerpot blocks.
    #[command(subcommand)]
    Block(block::BlockCommands),

    /// Manage flowerpot blockchains.
    #[command(subcommand)]
    Blockchain(blockchain::BlockchainCommands)
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
        Commands::Keypair(command) => command.run(),
        Commands::Address(command) => command.run(),
        Commands::Message(command) => command.run(),
        Commands::Block(command) => command.run(),
        Commands::Blockchain(command) => command.run()
    }
}
