// SPDX-License-Identifier: GPL-3.0-or-later
//
// libflowerpot
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

use std::path::Path;
use std::sync::Arc;

use rusqlite::Connection;
use spin::{Mutex, MutexGuard};
use time::UtcDateTime;

use crate::crypto::*;
use crate::block::{Block, BlockContent};
use crate::transaction::Transaction;

use super::Storage;

fn root_block(
    database: &MutexGuard<'_, Connection>
) -> rusqlite::Result<Option<Hash>> {
    let mut query = database.prepare_cached("
        SELECT current_hash FROM v1_blocks ORDER BY id ASC LIMIT 1
    ")?;

    let hash = query.query_row([], |row| {
        row.get::<_, [u8; 32]>("current_hash")
    });

    match hash {
        Ok(hash) => Ok(Some(Hash::from(hash))),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(err) => Err(err)
    }
}

fn tail_block(
    database: &MutexGuard<'_, Connection>
) -> rusqlite::Result<Option<Hash>> {
    let mut query = database.prepare_cached("
        SELECT current_hash FROM v1_blocks ORDER BY id DESC LIMIT 1
    ")?;

    let hash = query.query_row([], |row| {
        row.get::<_, [u8; 32]>("current_hash")
    });

    match hash {
        Ok(hash) => Ok(Some(Hash::from(hash))),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(err) => Err(err)
    }
}

fn has_block(
    database: &MutexGuard<'_, Connection>,
    hash: &Hash
) -> rusqlite::Result<bool> {
    let mut query = database.prepare_cached("
        SELECT 1 FROM v1_blocks WHERE current_hash = ?1
    ")?;

    match query.query_row([hash.0], |_| Ok(true)) {
        Ok(_) => Ok(true),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
        Err(err) => Err(err)
    }
}

#[derive(Debug, Clone)]
pub struct SqliteStorage(Arc<Mutex<Connection>>);

impl SqliteStorage {
    pub fn open(path: impl AsRef<Path>) -> rusqlite::Result<Self> {
        let mut connection = Connection::open(path)?;

        let transaction = connection.transaction()?;

        transaction.execute_batch(r#"
            CREATE TABLE IF NOT EXISTS v1_blocks (
                id            INTEGER NOT NULL UNIQUE,
                previous_hash BLOB    NOT NULL UNIQUE,
                current_hash  BLOB    NOT NULL UNIQUE,
                timestamp     INTEGER NOT NULL,
                sign          BLOB    NOT NULL,
                type          INTEGER NOT NULL,

                PRIMARY KEY (id)
            );

            CREATE INDEX IF NOT EXISTS v1_blocks_idx ON v1_blocks (
                id,
                previous_hash,
                current_hash
            );

            CREATE TABLE IF NOT EXISTS v1_block_approvals (
                block_id INTEGER NOT NULL,
                approval BLOB    NOT NULL,

                FOREIGN KEY (block_id) REFERENCES v1_blocks (id)
                ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS v1_block_approvals_idx
            ON v1_block_approvals (block_id);

            CREATE TABLE IF NOT EXISTS v1_block_data (
                block_id INTEGER NOT NULL,
                data     BLOB    NOT NULL,

                FOREIGN KEY (block_id) REFERENCES v1_blocks (id)
                ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS v1_block_data_idx
            ON v1_block_data (block_id);

            CREATE TABLE IF NOT EXISTS v1_block_transactions (
                block_id INTEGER NOT NULL,
                hash     BLOB    NOT NULL UNIQUE,
                seed     BLOB    NOT NULL,
                data     BLOB    NOT NULL,
                sign     BLOB    NOT NULL,

                FOREIGN KEY (block_id) REFERENCES v1_blocks (id)
                ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS v1_transactions_idx
            ON v1_block_transactions (block_id, hash);

            CREATE TABLE IF NOT EXISTS v1_block_validators (
                block_id   INTEGER NOT NULL,
                public_key BLOB    NOT NULL,

                FOREIGN KEY (block_id) REFERENCES v1_blocks (id)
                ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS v1_block_validators_idx
            ON v1_block_validators (block_id);
        "#)?;

        transaction.commit()?;

        Ok(Self(Arc::new(Mutex::new(connection))))
    }
}

impl Storage for SqliteStorage {
    type Error = rusqlite::Error;

    #[inline]
    fn root_block(&self) -> Result<Option<Hash>, Self::Error> {
        root_block(&self.0.lock())
    }

    #[inline]
    fn tail_block(&self) -> Result<Option<Hash>, Self::Error> {
        tail_block(&self.0.lock())
    }

    #[inline]
    fn has_block(&self, hash: &Hash) -> Result<bool, Self::Error> {
        has_block(&self.0.lock(), hash)
    }

    fn next_block(&self, hash: &Hash) -> Result<Option<Hash>, Self::Error> {
        let lock = self.0.lock();

        let mut query = lock.prepare_cached("
            SELECT current_hash FROM v1_blocks WHERE previous_hash = ?1
        ")?;

        let hash = query.query_row([hash.0], |row| {
            row.get::<_, [u8; 32]>("current_hash")
        });

        match hash {
            Ok(hash) => Ok(Some(Hash::from(hash))),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(err) => Err(err)
        }
    }

    fn read_block(&self, hash: &Hash) -> Result<Option<Block>, Self::Error> {
        let lock = self.0.lock();

        let mut query = lock.prepare_cached("
            SELECT
                id,
                previous_hash,
                timestamp,
                sign,
                type
            FROM v1_blocks
            WHERE current_hash = ?1
        ")?;

        let result = query.query_row([hash.0], |row| {
            Ok((
                row.get::<_, i64>("id")?,
                row.get::<_, [u8; 32]>("previous_hash")?,
                row.get::<_, i64>("timestamp")?,
                row.get::<_, [u8; 65]>("sign")?,
                row.get::<_, u8>("type")?
            ))
        });

        match result {
            Ok((id, previous_hash, timestamp, sign, block_type)) => {
                let content = match block_type {
                    0 => {
                        let mut query = lock.prepare_cached("
                            SELECT data FROM v1_block_data WHERE block_id = ?1
                        ")?;

                        let data = query.query_row([id], |row| {
                            row.get::<_, Box<[u8]>>("data")
                        })?;

                        BlockContent::data(data)
                    }

                    1 => {
                        let mut query = lock.prepare_cached("
                            SELECT
                                seed,
                                data,
                                sign
                            FROM v1_block_transactions
                            WHERE block_id = ?1
                        ")?;

                        let rows = query.query_map([id], |row| {
                            Ok((
                                row.get::<_, [u8; 8]>("seed")?,
                                row.get::<_, Box<[u8]>>("data")?,
                                row.get::<_, [u8; 65]>("sign")?
                            ))
                        })?;

                        let mut transactions = Vec::new();

                        for row in rows {
                            let (seed, data, sign) = row?;

                            transactions.push(Transaction {
                                seed: u64::from_le_bytes(seed),
                                data,
                                sign: Signature::from_bytes(sign)
                                    .ok_or_else(|| rusqlite::Error::InvalidQuery)?
                            });
                        }

                        BlockContent::transactions(transactions)
                    }

                    2 => {
                        let mut query = lock.prepare_cached("
                            SELECT public_key
                            FROM v1_block_validators
                            WHERE block_id = ?1
                        ")?;

                        let rows = query.query_map([id], |row| {
                            row.get::<_, [u8; 33]>("public_key")
                        })?;

                        let mut validators = Vec::new();

                        for row in rows {
                            let public_key = PublicKey::from_bytes(row?)
                                .ok_or_else(|| rusqlite::Error::InvalidQuery)?;

                            validators.push(public_key);
                        }

                        BlockContent::validators(validators)
                    }

                    _ => return Err(rusqlite::Error::InvalidQuery)
                };

                let mut query = lock.prepare_cached("
                    SELECT approval
                    FROM v1_block_approvals
                    WHERE block_id = ?1
                ")?;

                let rows = query.query_map([id], |row| {
                    row.get::<_, [u8; 65]>("approval")
                })?;

                let mut approvals = Vec::new();

                for row in rows {
                    let approval = Signature::from_bytes(row?)
                        .ok_or_else(|| rusqlite::Error::InvalidQuery)?;

                    approvals.push(approval);
                }

                Ok(Some(Block {
                    previous: Hash::from(previous_hash),
                    timestamp: UtcDateTime::from_unix_timestamp(timestamp)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    content,
                    sign: Signature::from_bytes(sign)
                        .ok_or_else(|| rusqlite::Error::InvalidQuery)?,
                    approvals
                }))
            }

            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(err) => Err(err)
        }
    }

    fn write_block(&self, block: &Block) -> Result<bool, Self::Error> {
        fn insert_block(
            database: &rusqlite::Transaction<'_>,
            hash: &Hash,
            block: &Block
        ) -> rusqlite::Result<()> {
            let mut query = database.prepare_cached("
                INSERT INTO v1_blocks (
                    previous_hash,
                    current_hash,
                    timestamp,
                    sign,
                    type
                ) VALUES (?1, ?2, ?3, ?4, ?5)
            ")?;

            let block_type = match block.content() {
                BlockContent::Data(_)         => 0,
                BlockContent::Transactions(_) => 1,
                BlockContent::Validators(_)   => 2
            };

            let block_id = query.insert((
                block.previous().0,
                hash.0,
                block.timestamp().unix_timestamp(),
                block.sign().to_bytes(),
                block_type
            ))?;

            let mut query = database.prepare_cached("
                INSERT INTO v1_block_approvals (block_id, approval)
                VALUES (?1, ?2)
            ")?;

            for approval in block.approvals() {
                query.execute((block_id, approval.to_bytes()))?;
            }

            match block.content() {
                BlockContent::Data(data) => {
                    let mut query = database.prepare_cached("
                        INSERT INTO v1_block_data (block_id, data) VALUES (?1, ?2)
                    ")?;

                    query.execute((block_id, data))?;
                }

                BlockContent::Transactions(transactions) => {
                    let mut query = database.prepare_cached("
                        INSERT INTO v1_block_transactions (
                            block_id,
                            seed,
                            data,
                            sign
                        ) VALUES (?1, ?2, ?3, ?4)
                    ")?;

                    for transaction in transactions {
                        query.execute((
                            block_id,
                            transaction.seed().to_le_bytes(),
                            transaction.data(),
                            transaction.sign().to_bytes()
                        ))?;
                    }
                }

                BlockContent::Validators(validators) => {
                    let mut query = database.prepare_cached("
                        INSERT INTO v1_block_validators (block_id, public_key)
                        VALUES (?1, ?2)
                    ")?;

                    for validator in validators {
                        query.execute((block_id, validator.to_bytes()))?;
                    }
                }
            }

            Ok(())
        }

        let mut lock = self.0.lock();

        let (is_valid, hash, _) = block.verify()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;

        // Although it's not a part of convention for this method why would
        // we need an invalid block stored here?
        if !is_valid {
            return Ok(false);
        }

        // Ignore block if it's already stored.
        if has_block(&lock, &hash)? {
            return Ok(false);
        }

        // Attempt to store the root block of the blockchain.
        else if root_block(&lock)?.is_none() || block.is_root() {
            // But reject it if it's not of a root type.
            if !block.is_root() {
                return Ok(false);
            }

            let transaction = lock.transaction()?;

            transaction.prepare_cached("DELETE FROM v1_blocks")?
                .execute(())?;

            insert_block(&transaction, &hash, block)?;

            transaction.commit()?;
        }

        // Reject out-of-history blocks.
        else if !has_block(&lock, block.previous())? {
            return Ok(false);
        }

        // At that point we're sure that the block is not stored and its
        // previous block is stored.
        //
        // If the previous block is the last block of the history then we add
        // the new one to the end of the blockchain.
        else if tail_block(&lock)? == Some(block.previous) {
            let transaction = lock.transaction()?;

            insert_block(&transaction, &hash, block)?;

            transaction.commit()?;
        }

        // Otherwise we need to modify the history.
        else {
            let transaction = lock.transaction()?;

            let mut query = transaction.prepare_cached("
                SELECT id FROM v1_blocks WHERE current_hash = ?1
            ")?;

            let id = query.query_one([block.previous().0], |row| {
                row.get::<_, i64>("id")
            })?;

            drop(query);

            transaction.prepare("DELETE FROM v1_blocks WHERE id > ?1")?
                .execute([id])?;

            insert_block(&transaction, &hash, block)?;

            transaction.commit()?;
        }

        Ok(true)
    }
}

#[test]
fn test() -> Result<(), rusqlite::Error> {
    let path = std::env::temp_dir().join("libflowerpot-test.db");

    if path.exists() {
        std::fs::remove_file(&path).unwrap();
    }

    let result = super::test_storage(&SqliteStorage::open(&path)?);

    std::fs::remove_file(path).unwrap();

    result
}
