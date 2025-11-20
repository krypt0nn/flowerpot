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

use rand_chacha::rand_core::RngCore;
use clap::Subcommand;

use flowerpot::crypto::sign::{SigningKey, VerifyingKey};
use flowerpot::address::Address;

#[derive(Subcommand)]
pub enum AddressCommands {
    /// Create new flowerpot blockchain address.
    Create {
        /// Seed for random numbers generator.
        #[arg(short = 'r', long, alias = "rand", alias = "random")]
        seed: Option<u64>,

        /// Verifying key of a blockchain validator. Randomly generated if
        /// unset.
        #[arg(short = 'v', long, alias = "key")]
        verifying_key: Option<String>,

        /// Blockchain identifier. Randomly generated if unset.
        #[arg(short = 'c', long, alias = "id")]
        chain_id: Option<u32>
    }
}

impl AddressCommands {
    pub fn run(self) -> anyhow::Result<()> {
        match self {
            Self::Create { seed, verifying_key, chain_id } => {
                let mut rng = super::safe_rng(seed);

                let chain_id = chain_id.unwrap_or(rng.next_u32());

                match verifying_key {
                    Some(verifying_key) => {
                        let verifying_key = VerifyingKey::from_base64(verifying_key)
                            .ok_or_else(|| anyhow::anyhow!("invalid verifying key"))?;

                        let address = Address::new(verifying_key.clone(), chain_id);

                        println!("Verifying key: {}", verifying_key.to_base64());
                        println!("     Chain ID: {chain_id}");
                        println!("      Address: {}", address.to_base64());
                    }

                    None => {
                        let signing_key = SigningKey::random(&mut rng);

                        let verifying_key = signing_key.verifying_key();

                        let address = Address::new(verifying_key.clone(), chain_id);

                        println!("  Signing key: {}", signing_key.to_base64());
                        println!("Verifying key: {}", verifying_key.to_base64());
                        println!("     Chain ID: {chain_id}");
                        println!("      Address: {}", address.to_base64());
                    }
                }
            }
        }

        Ok(())
    }
}
