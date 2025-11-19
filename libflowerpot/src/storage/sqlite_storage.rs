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
use crate::blob::Blob;
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

fn has_blob(
    database: &MutexGuard<'_, Connection>,
    hash: &Hash
) -> rusqlite::Result<bool> {
    let mut query = database.prepare_cached("
        SELECT 1 FROM v1_blobs WHERE hash = ?1 LIMIT 1
    ")?;

    match query.query_row([hash.as_bytes()], |_| Ok(true)) {
        Ok(_) => Ok(true),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
        Err(err) => Err(err)
    }
}

fn find_blob(
    database: &MutexGuard<'_, Connection>,
    hash: &Hash
) -> rusqlite::Result<Option<Hash>> {
    let mut query = database.prepare_cached("
        SELECT v1_blocks.hash as block_hash
        FROM v1_blocks INNER JOIN v1_block_blobs
        ON v1_block_blobs.block_id = v1_blocks.id
        WHERE v1_block_blobs.blob_hash = ?1
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

            CREATE TABLE IF NOT EXISTS v1_blobs (
                hash BLOB NOT NULL UNIQUE,
                data BLOB NOT NULL,
                sign BLOB NOT NULL,

                PRIMARY KEY (hash)
            );

            CREATE INDEX IF NOT EXISTS v1_blobs_idx ON v1_blobs (hash);

            CREATE TABLE IF NOT EXISTS v1_block_blobs (
                block_id  INTEGER NOT NULL,
                blob_hash BLOB    NOT NULL,
                is_inline BOOLEAN NOT NULL,

                UNIQUE (block_id, blob_hash),

                FOREIGN KEY (block_id) REFERENCES v1_blocks (id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS v1_block_blobs_idx ON v1_block_blobs (
                block_id,
                blob_hash
            );

            CREATE TRIGGER IF NOT EXISTS v1_delete_orphan_blobs_trg
            AFTER DELETE ON v1_block_blobs
            FOR EACH ROW
            BEGIN
                DELETE FROM v1_blobs
                WHERE hash = OLD.blob_hash AND NOT EXISTS (
                    SELECT 1
                    FROM v1_block_blobs b
                    WHERE b.blob_hash = OLD.blob_hash
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

        // Read blobs.

        let mut query = lock.prepare_cached("
            SELECT blob_hash
            FROM v1_block_blobs
            WHERE block_id = ?1 AND is_inline = FALSE
        ")?;

        let rows = query.query_map([id], |row| {
            row.get::<_, [u8; Hash::SIZE]>("blob_hash")
        })?;

        let mut blobs = Vec::new();

        for row in rows {
            blobs.push(Hash::from(row?));
        }

        // Read inline blobs.

        let mut query = lock.prepare_cached("
            SELECT
                v1_blobs.hash as hash,
                v1_blobs.data as data,
                v1_blobs.sign as sign
            FROM v1_blobs INNER JOIN v1_block_blobs
            ON v1_block_blobs.blob_hash = v1_blobs.hash
            WHERE
                v1_block_blobs.block_id = ?1 AND
                v1_block_blobs.is_inline = TRUE
        ")?;

        let rows = query.query_map([id], |row| {
            Ok((
                row.get::<_, [u8; Hash::SIZE]>("hash")?,
                row.get::<_, Box<[u8]>>("data")?,
                row.get::<_, [u8; Signature::SIZE]>("sign")?
            ))
        })?;

        let mut inline_blobs = Vec::new();

        for row in rows {
            let (hash, data, sign) = row?;

            inline_blobs.push(Blob {
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
            blobs: blobs.into_boxed_slice(),
            inline_blobs: inline_blobs.into_boxed_slice(),
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

            let mut insert_block_blobs_query = database.prepare_cached("
                INSERT INTO v1_block_blobs (
                    block_id,
                    blob_hash,
                    is_inline
                ) VALUES (?1, ?2, ?3)
            ")?;

            // Blobs.

            for hash in block.blobs() {
                query.execute((
                    block_id,
                    hash.as_bytes(),
                    false
                ))?;
            }

            // Inline blobs.

            let mut query = database.prepare_cached("
                INSERT INTO v1_blobs (
                    hash,
                    data,
                    sign
                ) VALUES (?1, ?2, ?3)
            ")?;

            for blob in block.inline_blobs() {
                insert_block_blobs_query.execute((
                    block_id,
                    blob.hash().as_bytes(),
                    true
                ))?;

                query.execute((
                    blob.hash().as_bytes(),
                    blob.data(),
                    blob.sign().to_bytes()
                ))?;
            }

            Ok(())
        }

        #[inline]
        fn block_has_duplicate_blobs(block: &Block) -> bool {
            let mut blobs = HashSet::new();

            for hash in block.blobs() {
                if !blobs.insert(hash) {
                    return true;
                }
            }

            for blob in block.inline_blobs() {
                if !blobs.insert(blob.hash()) {
                    return true;
                }
            }

            false
        }

        #[inline]
        fn block_has_duplicate_blobs_in_history(
            lock: &MutexGuard<'_, Connection>,
            block: &Block
        ) -> rusqlite::Result<bool> {
            let mut blobs = HashSet::new();

            for hash in block.blobs() {
                if !blobs.insert(*hash) {
                    return Ok(true);
                }
            }

            for blob in block.inline_blobs() {
                if !blobs.insert(*blob.hash()) {
                    return Ok(true);
                }
            }

            let mut query = lock.prepare_cached("
                SELECT v1_block_blobs.blob_hash as blob_hash
                FROM v1_blocks INNER JOIN v1_block_blobs
                ON v1_block_blobs.block_id = v1_blocks.id
                WHERE v1_blocks.id <= (SELECT id FROM v1_blocks WHERE hash = ?1)
                ORDER BY v1_blocks.id ASC
            ")?;

            let blobs_history = query.query_map(
                [block.prev_hash().as_bytes()],
                |row| row.get::<_, [u8; Hash::SIZE]>("blob_hash")
            )?;

            for hash in blobs_history {
                let hash = Hash::from(hash?);

                if !blobs.insert(hash) {
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

        // Ignore block if it has duplicate blobs in it.
        else if block_has_duplicate_blobs(block) {
            Ok(StorageWriteResult::BlockHasDuplicateBlobs)
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

        // Reject blocks that contain already stored blobs.
        else if block_has_duplicate_blobs_in_history(&lock, block)? {
            Ok(StorageWriteResult::BlockHasDuplicateHistoryBlobs)
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
    fn has_blob(&self, hash: &Hash) -> Result<bool, StorageError> {
        has_blob(&self.0.lock(), hash)
            .map_err(|err| Box::new(err) as StorageError)
    }

    #[inline]
    fn find_blob(
        &self,
        hash: &Hash
    ) -> Result<Option<Hash>, StorageError> {
        find_blob(&self.0.lock(), hash)
            .map_err(|err| Box::new(err) as StorageError)
    }

    fn read_blob(
        &self,
        hash: &Hash
    ) -> Result<Option<Blob>, StorageError> {
        let lock = self.0.lock();

        let mut query = lock.prepare_cached("
            SELECT data, sign
            FROM v1_blobs
            WHERE hash = ?1
        ")?;

        let result = query.query_row([hash.as_bytes()], |row| {
            Ok((
                row.get::<_, Box<[u8]>>("data")?,
                row.get::<_, [u8; Signature::SIZE]>("sign")?
            ))
        });

        match result {
            Ok((data, sign)) => Ok(Some(Blob {
                hash: *hash,
                data,
                sign: Signature::from_bytes(&sign)
                    .ok_or_else(|| rusqlite::Error::InvalidQuery)?
            })),

            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(err) => Err(Box::new(err) as StorageError)
        }
    }

    fn write_blob(&self, blob: &Blob) -> Result<bool, StorageError> {
        let lock = self.0.lock();

        let mut query = lock.prepare_cached("
            INSERT INTO v1_blobs (hash, data, sign)
            VALUES (?1, ?2, ?3)
        ")?;

        query.execute((
            blob.hash().as_bytes(),
            blob.data(),
            blob.sign().to_bytes()
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
