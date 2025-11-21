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
use std::sync::{Arc, Mutex, MutexGuard};

use rusqlite::Connection;
use time::UtcDateTime;

use crate::crypto::hash::Hash;
use crate::crypto::sign::Signature;
use crate::message::Message;
use crate::block::Block;

use super::{Storage, StorageWriteResult, StorageError};

#[inline]
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

#[inline]
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

#[inline]
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

#[inline]
fn find_message(
    database: &MutexGuard<'_, Connection>,
    hash: &Hash
) -> rusqlite::Result<Option<Hash>> {
    let mut query = database.prepare_cached("
        SELECT v1_blocks.hash as block_hash
        FROM v1_blocks INNER JOIN v1_block_messages
        ON v1_block_messages.block_id = v1_blocks.id
        WHERE v1_block_messages.message_hash = ?1
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
                chain_id  INTEGER NOT NULL,
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
                hash BLOB NOT NULL UNIQUE,
                data BLOB NOT NULL,
                sign BLOB NOT NULL,

                PRIMARY KEY (hash)
            );

            CREATE INDEX IF NOT EXISTS v1_messages_idx ON v1_messages (hash);

            CREATE TABLE IF NOT EXISTS v1_block_messages (
                block_id     INTEGER NOT NULL,
                message_hash BLOB    NOT NULL,
                is_inline    BOOLEAN NOT NULL,

                UNIQUE (block_id, message_hash),

                FOREIGN KEY (block_id) REFERENCES v1_blocks (id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS v1_block_messages_idx ON v1_block_messages (
                block_id,
                message_hash
            );

            CREATE TRIGGER IF NOT EXISTS v1_delete_orphan_blobs_trg
            AFTER DELETE ON v1_block_messages
            FOR EACH ROW
            BEGIN
                DELETE FROM v1_messages
                WHERE hash = OLD.message_hash AND NOT EXISTS (
                    SELECT 1
                    FROM v1_block_messages b
                    WHERE b.message_hash = OLD.message_hash
                );
            END;
        "#)?;

        transaction.commit()?;

        Ok(Self(Arc::new(Mutex::new(connection))))
    }
}

impl Storage for SqliteStorage {
    #[inline]
    fn root_block(&self) -> Result<Option<Hash>, StorageError> {
        let lock = self.0.lock()
            .map_err(|_| StorageError::from("failed to lock sqlite storage"))?;

        root_block(&lock)
            .map_err(|err| Box::new(err) as StorageError)
    }

    #[inline]
    fn tail_block(&self) -> Result<Option<Hash>, StorageError> {
        let lock = self.0.lock()
            .map_err(|_| StorageError::from("failed to lock sqlite storage"))?;

        tail_block(&lock)
            .map_err(|err| Box::new(err) as StorageError)
    }

    #[inline]
    fn has_block(&self, hash: &Hash) -> Result<bool, StorageError> {
        let lock = self.0.lock()
            .map_err(|_| StorageError::from("failed to lock sqlite storage"))?;

        has_block(&lock, hash)
            .map_err(|err| Box::new(err) as StorageError)
    }

    fn next_block(&self, hash: &Hash) -> Result<Option<Hash>, StorageError> {
        let lock = self.0.lock()
            .map_err(|_| StorageError::from("failed to lock sqlite storage"))?;

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
        let lock = self.0.lock()
            .map_err(|_| StorageError::from("failed to lock sqlite storage"))?;

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
        let lock = self.0.lock()
            .map_err(|_| StorageError::from("failed to lock sqlite storage"))?;

        let mut query = lock.prepare_cached("
            SELECT
                id,
                chain_id,
                prev_hash,
                timestamp,
                sign
            FROM v1_blocks
            WHERE hash = ?1
        ")?;

        let result = query.query_row([hash.as_bytes()], |row| {
            Ok((
                row.get::<_, i64>("id")?,
                row.get::<_, u32>("chain_id")?,
                row.get::<_, [u8; Hash::SIZE]>("prev_hash")?,
                row.get::<_, i64>("timestamp")?,
                row.get::<_, [u8; Signature::SIZE]>("sign")?
            ))
        });

        let (id, chain_id, prev_hash, timestamp, sign) = match result {
            Ok(result) => result,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            Err(err) => return Err(Box::new(err) as StorageError)
        };

        let timestamp = UtcDateTime::from_unix_timestamp(timestamp)
            .map_err(|_| rusqlite::Error::InvalidQuery)?;

        let sign = Signature::from_bytes(&sign)
            .ok_or_else(|| rusqlite::Error::InvalidQuery)?;

        // Read referenced messages.

        let mut query = lock.prepare_cached("
            SELECT message_hash
            FROM v1_block_messages
            WHERE block_id = ?1 AND is_inline = FALSE
        ")?;

        let rows = query.query_map([id], |row| {
            row.get::<_, [u8; Hash::SIZE]>("message_hash")
        })?;

        let mut ref_messages = Vec::new();

        for row in rows {
            ref_messages.push(Hash::from(row?));
        }

        // Read inline messages.

        let mut query = lock.prepare_cached("
            SELECT
                v1_messages.hash as hash,
                v1_messages.data as data,
                v1_messages.sign as sign
            FROM v1_messages INNER JOIN v1_block_messages
            ON v1_block_messages.message_hash = v1_messages.hash
            WHERE
                v1_block_messages.block_id = ?1 AND
                v1_block_messages.is_inline = TRUE
        ")?;

        let rows = query.query_map([id], |row| {
            Ok((
                row.get::<_, [u8; Hash::SIZE]>("hash")?,
                row.get::<_, Box<[u8]>>("data")?,
                row.get::<_, [u8; Signature::SIZE]>("sign")?
            ))
        })?;

        let mut inline_messages = Vec::new();

        for row in rows {
            let (hash, data, sign) = row?;

            inline_messages.push(Message {
                hash: Hash::from(hash),
                data,
                sign: Signature::from_bytes(&sign)
                    .ok_or_else(|| rusqlite::Error::InvalidQuery)?
            });
        }

        Ok(Some(Block {
            chain_id,
            prev_hash: Hash::from(prev_hash),
            curr_hash: *hash,
            timestamp,
            ref_messages: ref_messages.into_boxed_slice(),
            inline_messages: inline_messages.into_boxed_slice(),
            sign
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
            // Block info.

            let mut query = database.prepare_cached("
                INSERT INTO v1_blocks (
                    chain_id,
                    hash,
                    prev_hash,
                    timestamp,
                    sign
                ) VALUES (?1, ?2, ?3, ?4, ?5)
            ")?;

            let block_id = query.insert((
                block.chain_id(),
                block.hash().as_bytes(),
                block.prev_hash().as_bytes(),
                block.timestamp().unix_timestamp(),
                block.sign().to_bytes()
            ))?;

            // Prepare shared query.

            let mut insert_block_messages_query = database.prepare_cached("
                INSERT INTO v1_block_messages (
                    block_id,
                    message_hash,
                    is_inline
                ) VALUES (?1, ?2, ?3)
            ")?;

            // Referenced messages.

            for hash in block.ref_messages() {
                insert_block_messages_query.execute((
                    block_id,
                    hash.as_bytes(),
                    false
                ))?;
            }

            // Inline messages.

            let mut query = database.prepare_cached("
                INSERT INTO v1_messages (
                    hash,
                    data,
                    sign
                ) VALUES (?1, ?2, ?3)
            ")?;

            for message in block.inline_messages() {
                insert_block_messages_query.execute((
                    block_id,
                    message.hash().as_bytes(),
                    true
                ))?;

                query.execute((
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

            for hash in block.ref_messages() {
                if !messages.insert(hash) {
                    return true;
                }
            }

            for message in block.inline_messages() {
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

            for hash in block.ref_messages() {
                if !messages.insert(*hash) {
                    return Ok(true);
                }
            }

            for message in block.inline_messages() {
                if !messages.insert(*message.hash()) {
                    return Ok(true);
                }
            }

            let mut query = lock.prepare_cached("
                SELECT v1_block_messages.message_hash as message_hash
                FROM v1_blocks INNER JOIN v1_block_messages
                ON v1_block_messages.block_id = v1_blocks.id
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

        let mut lock = self.0.lock()
            .map_err(|_| StorageError::from("failed to lock sqlite storage"))?;

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
            // Check if the new block is older than the old one.
            let mut query = lock.prepare_cached("
                SELECT timestamp FROM v1_blocks WHERE prev_hash = ?1 LIMIT 1
            ")?;

            let timestamp = query.query_row([block.prev_hash().as_bytes()], |row| {
                row.get::<_, i64>("timestamp")
            })?;

            let timestamp = UtcDateTime::from_unix_timestamp(timestamp)
                .map_err(|_| rusqlite::Error::InvalidQuery)?;

            if &timestamp >= block.timestamp() {
                return Ok(StorageWriteResult::NewerBlockStored);
            }

            drop(query);

            // Update the history.
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

    fn is_message_referenced(&self, hash: &Hash) -> Result<bool, StorageError> {
        let lock = self.0.lock()
            .map_err(|_| StorageError::from("failed to lock sqlite storage"))?;

        let mut query = lock.prepare_cached("
            SELECT 1
            FROM v1_block_messages
            WHERE message_hash = ?1 AND is_inline = FALSE
            LIMIT 1
        ")?;

        match query.query_row([hash.as_bytes()], |_| Ok(true)) {
            Ok(_) => Ok(true),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
            Err(err) => Err(Box::new(err) as StorageError)
        }
    }

    fn is_message_stored(&self, hash: &Hash) -> Result<bool, StorageError> {
        let lock = self.0.lock()
            .map_err(|_| StorageError::from("failed to lock sqlite storage"))?;

        let mut query = lock.prepare_cached("
            SELECT 1
            FROM v1_block_messages
            WHERE message_hash = ?1 AND is_inline = TRUE
            LIMIT 1
        ")?;

        match query.query_row([hash.as_bytes()], |_| Ok(true)) {
            Ok(_) => Ok(true),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
            Err(err) => Err(Box::new(err) as StorageError)
        }
    }

    fn has_message(&self, hash: &Hash) -> Result<bool, StorageError> {
        let lock = self.0.lock()
            .map_err(|_| StorageError::from("failed to lock sqlite storage"))?;

        let mut query = lock.prepare_cached("
            SELECT 1
            FROM v1_block_messages
            WHERE message_hash = ?1
            LIMIT 1
        ")?;

        match query.query_row([hash.as_bytes()], |_| Ok(true)) {
            Ok(_) => Ok(true),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
            Err(err) => Err(Box::new(err) as StorageError)
        }
    }

    #[inline]
    fn find_message(
        &self,
        hash: &Hash
    ) -> Result<Option<Hash>, StorageError> {
        let lock = self.0.lock()
            .map_err(|_| StorageError::from("failed to lock sqlite storage"))?;

        find_message(&lock, hash)
            .map_err(|err| Box::new(err) as StorageError)
    }

    fn read_message(
        &self,
        hash: &Hash
    ) -> Result<Option<Message>, StorageError> {
        let lock = self.0.lock()
            .map_err(|_| StorageError::from("failed to lock sqlite storage"))?;

        let mut query = lock.prepare_cached("
            SELECT data, sign
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

    fn write_message(&self, message: &Message) -> Result<bool, StorageError> {
        let lock = self.0.lock()
            .map_err(|_| StorageError::from("failed to lock sqlite storage"))?;

        let mut query = lock.prepare_cached("
            INSERT INTO v1_messages (hash, data, sign)
            VALUES (?1, ?2, ?3)
        ")?;

        query.execute((
            message.hash().as_bytes(),
            message.data(),
            message.sign().to_bytes()
        ))?;

        Ok(true)
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
