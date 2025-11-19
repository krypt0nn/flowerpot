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

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use rusqlite::Connection;
use spin::{Mutex, MutexGuard};
use time::UtcDateTime;

use crate::crypto::hash::Hash;
use crate::crypto::sign::Signature;
use crate::blob::Message;
use crate::block::Block;

use super::{Storage, StorageWriteResult, StorageError};

fn root_block(
    database: &MutexGuard<'_, Connection>
) -> rusqlite::Result<Option<Hash>> {
    let mut query = database.prepare_cached("
        SELECT hash FROM v1_blocks ORDER BY id ASC LIMIT 1
    ")?;

    let hash = query.query_row([], |row| {
        row.get::<_, [u8; Hash::SIZE]>("hash")
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
        SELECT hash FROM v1_blocks ORDER BY id DESC LIMIT 1
    ")?;

    let hash = query.query_row([], |row| {
        row.get::<_, [u8; Hash::SIZE]>("hash")
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
        SELECT 1 FROM v1_blocks WHERE hash = ?1 LIMIT 1
    ")?;

    match query.query_row([hash.as_bytes()], |_| Ok(true)) {
        Ok(_) => Ok(true),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
        Err(err) => Err(err)
    }
}

fn has_message(
    database: &MutexGuard<'_, Connection>,
    hash: &Hash
) -> rusqlite::Result<bool> {
    let mut query = database.prepare_cached("
        SELECT 1 FROM v1_messages WHERE hash = ?1 LIMIT 1
    ")?;

    match query.query_row([hash.as_bytes()], |_| Ok(true)) {
        Ok(_) => Ok(true),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
        Err(err) => Err(err)
    }
}

fn find_message(
    database: &MutexGuard<'_, Connection>,
    hash: &Hash
) -> rusqlite::Result<Option<Hash>> {
    let mut query = database.prepare_cached("
        SELECT v1_blocks.hash as block_hash
        FROM v1_blocks INNER JOIN v1_messages
        ON v1_messages.block_id = v1_blocks.id
        WHERE v1_messages.hash = ?1
        LIMIT 1
    ")?;

    let result = query.query_row([hash.as_bytes()], |row| {
        row.get::<_, [u8; Hash::SIZE]>("block_hash")
    });

    match result {
        Ok(hash) => Ok(Some(Hash::from(hash))),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
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
                id        INTEGER NOT NULL UNIQUE,
                hash      BLOB    NOT NULL UNIQUE,
                prev_hash BLOB    NOT NULL UNIQUE,
                timestamp INTEGER NOT NULL,
                sign      BLOB    NOT NULL,

                PRIMARY KEY (id)
            );

            CREATE INDEX IF NOT EXISTS v1_blocks_idx ON v1_blocks (
                id,
                hash,
                prev_hash
            );

            CREATE TABLE IF NOT EXISTS v1_messages (
                block_id INTEGER NOT NULL,
                hash     BLOB    NOT NULL UNIQUE,
                data     BLOB    NOT NULL,
                sign     BLOB    NOT NULL,

                FOREIGN KEY (block_id) REFERENCES v1_blocks (id)
                ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS v1_messages_idx ON v1_messages (
                block_id,
                hash
            );
        "#)?;

        transaction.commit()?;

        Ok(Self(Arc::new(Mutex::new(connection))))
    }
}

impl Storage for SqliteStorage {
    #[inline]
    fn root_block(&self) -> Result<Option<Hash>, StorageError> {
        root_block(&self.0.lock())
            .map_err(|err| Box::new(err) as StorageError)
    }

    #[inline]
    fn tail_block(&self) -> Result<Option<Hash>, StorageError> {
        tail_block(&self.0.lock())
            .map_err(|err| Box::new(err) as StorageError)
    }

    #[inline]
    fn has_block(&self, hash: &Hash) -> Result<bool, StorageError> {
        has_block(&self.0.lock(), hash)
            .map_err(|err| Box::new(err) as StorageError)
    }

    fn next_block(&self, hash: &Hash) -> Result<Option<Hash>, StorageError> {
        let lock = self.0.lock();

        let mut query = lock.prepare_cached("
            SELECT hash FROM v1_blocks WHERE prev_hash = ?1 LIMIT 1
        ")?;

        let hash = query.query_row([hash.as_bytes()], |row| {
            row.get::<_, [u8; Hash::SIZE]>("hash")
        });

        match hash {
            Ok(hash) => Ok(Some(Hash::from(hash))),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(err) => Err(Box::new(err) as StorageError)
        }
    }

    fn prev_block(&self, hash: &Hash) -> Result<Option<Hash>, StorageError> {
        let lock = self.0.lock();

        let mut query = lock.prepare_cached("
            SELECT prev_hash FROM v1_blocks WHERE hash = ?1 LIMIT 1
        ")?;

        let hash = query.query_row([hash.as_bytes()], |row| {
            row.get::<_, [u8; Hash::SIZE]>("prev_hash")
        });

        match hash {
            Ok(hash) => Ok(Some(Hash::from(hash))),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(err) => Err(Box::new(err) as StorageError)
        }
    }

    fn read_block(&self, hash: &Hash) -> Result<Option<Block>, StorageError> {
        let lock = self.0.lock();

        let mut query = lock.prepare_cached("
            SELECT
                id,
                prev_hash,
                timestamp,
                sign
            FROM v1_blocks
            WHERE hash = ?1
        ")?;

        let result = query.query_row([hash.as_bytes()], |row| {
            Ok((
                row.get::<_, i64>("id")?,
                row.get::<_, [u8; Hash::SIZE]>("prev_hash")?,
                row.get::<_, i64>("timestamp")?,
                row.get::<_, [u8; Signature::SIZE]>("sign")?
            ))
        });

        let (id, previous_hash, timestamp, sign) = match result {
            Ok(result) => result,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            Err(err) => return Err(Box::new(err) as StorageError)
        };

        let mut query = lock.prepare_cached("
            SELECT
                hash,
                data,
                sign
            FROM v1_messages
            WHERE block_id = ?1
        ")?;

        let rows = query.query_map([id], |row| {
            Ok((
                row.get::<_, [u8; Hash::SIZE]>("hash")?,
                row.get::<_, Box<[u8]>>("data")?,
                row.get::<_, [u8; Signature::SIZE]>("sign")?
            ))
        })?;

        let mut messages = Vec::new();

        for row in rows {
            let (hash, data, sign) = row?;

            messages.push(Message {
                hash: Hash::from(hash),
                data,
                sign: Signature::from_bytes(&sign)
                    .ok_or_else(|| rusqlite::Error::InvalidQuery)?
            });
        }

        Ok(Some(Block {
            prev_hash: Hash::from(previous_hash),
            curr_hash: *hash,
            timestamp: UtcDateTime::from_unix_timestamp(timestamp)
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
            messages: messages.into_boxed_slice(),
            sign: Signature::from_bytes(&sign)
                .ok_or_else(|| rusqlite::Error::InvalidQuery)?
        }))
    }

    fn write_block(
        &self,
        block: &Block
    ) -> Result<StorageWriteResult, StorageError> {
        fn insert_block(
            database: &rusqlite::Transaction<'_>,
            block: &Block
        ) -> rusqlite::Result<()> {
            let mut query = database.prepare_cached("
                INSERT INTO v1_blocks (
                    hash,
                    prev_hash,
                    timestamp,
                    sign
                ) VALUES (?1, ?2, ?3, ?4)
            ")?;

            let block_id = query.insert((
                block.hash().as_bytes(),
                block.prev_hash().as_bytes(),
                block.timestamp().unix_timestamp(),
                block.sign().to_bytes()
            ))?;

            let mut query = database.prepare_cached("
                INSERT INTO v1_messages (
                    block_id,
                    hash,
                    data,
                    sign
                ) VALUES (?1, ?2, ?3, ?4)
            ")?;

            for message in block.messages() {
                query.execute((
                    block_id,
                    message.hash().as_bytes(),
                    message.data(),
                    message.sign().to_bytes()
                ))?;
            }

            Ok(())
        }

        #[inline]
        fn block_has_duplicate_messages(block: &Block) -> bool {
            let mut messages = HashSet::new();

            for message in block.messages() {
                if !messages.insert(message.hash()) {
                    return true;
                }
            }

            false
        }

        #[inline]
        fn block_has_duplicate_messages_in_history(
            lock: &MutexGuard<'_, Connection>,
            block: &Block
        ) -> rusqlite::Result<bool> {
            let mut messages = HashSet::new();

            for message in block.messages() {
                if !messages.insert(*message.hash()) {
                    return Ok(true);
                }
            }

            let mut query = lock.prepare_cached("
                SELECT v1_messages.hash as message_hash
                FROM v1_blocks INNER JOIN v1_messages
                ON v1_messages.block_id = v1_blocks.id
                WHERE v1_blocks.id <= (SELECT id FROM v1_blocks WHERE hash = ?1)
                ORDER BY v1_blocks.id ASC
            ")?;

            let messages_history = query.query_map(
                [block.prev_hash().as_bytes()],
                |row| row.get::<_, [u8; Hash::SIZE]>("message_hash")
            )?;

            for hash in messages_history {
                let hash = Hash::from(hash?);

                if !messages.insert(hash) {
                    return Ok(true);
                }
            }

            Ok(false)
        }

        let mut lock = self.0.lock();

        let (is_valid, _) = block.verify()
            .map_err(|_| {
                StorageError::from("failed to verify block signature")
            })?;

        // Although it's not a part of convention for this method why would
        // we need an invalid block stored here?
        if !is_valid {
            Ok(StorageWriteResult::BlockInvalid)
        }

        // Ignore block if it's already stored.
        else if has_block(&lock, block.hash())? {
            Ok(StorageWriteResult::BlockAlreadyStored)
        }

        // Ignore block if it has duplicate messages in it.
        else if block_has_duplicate_messages(block) {
            Ok(StorageWriteResult::BlockHasDuplicateMessages)
        }

        // Attempt to store the root block of the blockchain.
        else if root_block(&lock)?.is_none() || block.is_root() {
            // But reject it if it's not of a root type.
            if !block.is_root() {
                return Ok(StorageWriteResult::NotRootBlock);
            }

            let transaction = lock.transaction()?;

            // Messages are deleted automatically by foreign key rule.
            transaction.prepare_cached("DELETE FROM v1_blocks")?
                .execute(())?;

            insert_block(&transaction, block)?;

            transaction.commit()?;

            Ok(StorageWriteResult::Success)
        }

        // Reject out-of-history blocks.
        else if !has_block(&lock, block.prev_hash())? {
            Ok(StorageWriteResult::OutOfHistoryBlock)
        }

        // Reject blocks that contain already stored messages.
        else if block_has_duplicate_messages_in_history(&lock, block)? {
            Ok(StorageWriteResult::BlockHasDuplicateHistoryMessages)
        }

        // At that point we're sure that the block is not stored and its
        // previous block is stored.
        //
        // If the previous block is the last block of the history then we add
        // the new one to the end of the blockchain.
        else if tail_block(&lock)? == Some(*block.prev_hash()) {
            let transaction = lock.transaction()?;

            insert_block(&transaction, block)?;

            transaction.commit()?;

            Ok(StorageWriteResult::Success)
        }

        // Otherwise we need to modify the history.
        else {
            let transaction = lock.transaction()?;

            let mut query = transaction.prepare_cached("
                SELECT id FROM v1_blocks WHERE hash = ?1 LIMIT 1
            ")?;

            let id = query.query_one([block.prev_hash().as_bytes()], |row| {
                row.get::<_, i64>("id")
            })?;

            drop(query);

            transaction.prepare("DELETE FROM v1_blocks WHERE id > ?1")?
                .execute([id])?;

            insert_block(&transaction, block)?;

            transaction.commit()?;

            Ok(StorageWriteResult::Success)
        }
    }

    #[inline]
    fn has_message(&self, hash: &Hash) -> Result<bool, StorageError> {
        has_message(&self.0.lock(), hash)
            .map_err(|err| Box::new(err) as StorageError)
    }

    #[inline]
    fn find_message(
        &self,
        hash: &Hash
    ) -> Result<Option<Hash>, StorageError> {
        find_message(&self.0.lock(), hash)
            .map_err(|err| Box::new(err) as StorageError)
    }

    fn read_message(
        &self,
        hash: &Hash
    ) -> Result<Option<Message>, StorageError> {
        let lock = self.0.lock();

        let mut query = lock.prepare_cached("
            SELECT
                data,
                sign
            FROM v1_messages
            WHERE hash = ?1
        ")?;

        let result = query.query_row([hash.as_bytes()], |row| {
            Ok((
                row.get::<_, Box<[u8]>>("data")?,
                row.get::<_, [u8; Signature::SIZE]>("sign")?
            ))
        });

        match result {
            Ok((data, sign)) => Ok(Some(Message {
                hash: *hash,
                data,
                sign: Signature::from_bytes(&sign)
                    .ok_or_else(|| rusqlite::Error::InvalidQuery)?
            })),

            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(err) => Err(Box::new(err) as StorageError)
        }
    }
}

#[test]
fn test() -> Result<(), StorageError> {
    let path = std::env::temp_dir().join("libflowerpot-test.db");

    if path.exists() {
        std::fs::remove_file(&path).unwrap();
    }

    let result = super::test_storage(&SqliteStorage::open(&path)?);

    std::fs::remove_file(path).unwrap();

    result
}
