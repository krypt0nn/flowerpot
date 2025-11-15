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

use clap::Subcommand;

use flowerpot::crypto::sign::SigningKey;

#[derive(Subcommand)]
pub enum KeypairCommands {
    /// Create new flowerpot signing key.
    Create {
        /// Seed for random numbers generator.
        #[arg(short = 'r', long, alias = "rand", alias = "random")]
        seed: Option<u64>
    },

    /// Export verifying key from a flowerpot signing key.
    Export {
        /// Flowerpot signing key. If unset, stdin value is read.
        #[arg(short = 'k', long, alias = "secret", alias = "key")]
        signing_key: Option<String>
    }
}

impl KeypairCommands {
    pub fn run(self) -> anyhow::Result<()> {
        match self {
            Self::Create { seed } => {
                let signing_key = SigningKey::random(&mut super::safe_rng(seed));

                std::io::stdout().write_all(signing_key.to_base64().as_bytes())?;
            }

            Self::Export { signing_key } => {
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

        Ok(())
    }
}
