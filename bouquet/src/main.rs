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

use anyhow::Context;
use clap::{Parser, Subcommand};

mod keypair;
mod transaction;
mod block;
mod blockchain;

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
    #[command(subcommand)]
    Keypair(keypair::KeypairCommands),

    /// Manage flowerpot blockchain transactions.
    #[command(subcommand)]
    Transaction(transaction::TransactionCommands),

    /// Manage flowerpot blockchain blocks.
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
        Commands::Transaction(command) => command.run(),
        Commands::Block(command) => command.run(),
        Commands::Blockchain(command) => command.run()
    }
}
