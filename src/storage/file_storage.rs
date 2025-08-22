use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::fs::File;

use super::*;

/// Very inefficient, quickly crafted filesystem-based storage for blockchain.
pub struct FileStorage(PathBuf);

impl FileStorage {
    pub fn open(path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path: PathBuf = path.into();

        if !path.join("transactions").is_dir() {
            std::fs::create_dir_all(path.join("transactions"))?;
        }

        if !path.join("blocks").is_dir() {
            std::fs::create_dir_all(path.join("blocks"))?;
        }

        if !path.join("index").is_file() {
            std::fs::write(path.join("index"), b"")?;
        }

        Ok(Self(path))
    }

    fn get_transaction_path(&self, hash: &Hash) -> PathBuf {
        self.0.join("transactions")
            .join(format!("{:0x}", hash.0[0]))
            .join(format!("{:0x}", hash.0[1]))
            .join(hash.to_base64())
    }

    fn get_block_path(&self, hash: &Hash) -> PathBuf {
        self.0.join("blocks")
            .join(format!("{:0x}", hash.0[0]))
            .join(format!("{:0x}", hash.0[1]))
            .join(hash.to_base64())
    }

    fn read_block_from_index(&self, mut index: u64) -> std::io::Result<Option<Hash>> {
        let mut db = File::open(self.0.join("index"))?;

        index *= 32;

        if index > db.metadata()?.len() {
            return Ok(None);
        }

        let mut hash = [0; 32];

        db.seek(SeekFrom::Start(index))?;
        db.read_exact(&mut hash)?;

        Ok(Some(Hash::from(hash)))
    }

    fn read_last_block_hash(&self) -> std::io::Result<Option<Hash>> {
        let mut db = File::open(self.0.join("index"))?;

        if db.metadata()?.len() < 32 {
            return Ok(None);
        }

        let mut hash = [0; 32];

        db.seek(SeekFrom::End(-32))?;
        db.read_exact(&mut hash)?;

        Ok(Some(Hash::from(hash)))
    }

    fn append_block_to_index(&self, hash: &Hash) -> std::io::Result<()> {
        let mut db = File::options()
            .append(true)
            .open(self.0.join("index"))?;

        db.write_all(&hash.0)?;
        db.flush()?;

        Ok(())
    }
}

impl Storage for FileStorage {
    type Error = std::io::Error;

    fn read_transaction(&self, hash: &Hash) -> Result<Option<Transaction>, Self::Error> {
        let path = self.get_transaction_path(hash);

        if !path.is_file() {
            return Ok(None);
        }

        let transaction = std::fs::read(path)?;
        let transaction = Transaction::from_bytes(transaction)?;

        Ok(Some(transaction))
    }

    fn read_block(&self, hash: &Hash) -> Result<Option<Block>, Self::Error> {
        let path = self.get_block_path(hash);

        if !path.is_file() {
            return Ok(None);
        }

        let block = std::fs::read(path)?;
        let block = Block::from_bytes(block)?;

        Ok(Some(block))
    }

    fn read_last_block(&self) -> Result<Option<Block>, Self::Error> {
        match self.read_last_block_hash()? {
            Some(hash) => self.read_block(&hash),
            None => Ok(None)
        }
    }

    fn index_block(&self, index: u64) -> Result<Option<Block>, Self::Error> {
        match self.read_block_from_index(index)? {
            Some(hash) => self.read_block(&hash),
            None => Ok(None)
        }
    }

    fn write_block(&self, block: Block) -> Result<(), Self::Error> {
        let hash = block.hash()?;
        let path = self.get_block_path(&hash);

        // TODO: obviously very inefficient, this is just a hack

        std::fs::write(path, block.to_bytes()?)?;

        if let BlockContent::Transactions(transactions) = block.content() {
            for transaction in transactions {
                let path = self.get_transaction_path(&transaction.hash());

                std::fs::write(path, transaction.to_bytes()?)?;
            }
        }

        self.append_block_to_index(&hash)?;

        Ok(())
    }

    fn get_current_validators(&self) -> Result<Vec<PublicKey>, Self::Error> {
        match self.read_last_block_hash()? {
            Some(hash) => self.get_validators_for_block(&hash),
            None => Ok(vec![])
        }
    }

    fn get_validators_for_block(&self, hash: &Hash) -> Result<Vec<PublicKey>, Self::Error> {
        let mut block = self.read_block(hash)?;

        while let Some(value) = block {
            if let BlockContent::Validators(validators) = value.content() {
                return Ok(validators.to_vec());
            }

            block = self.read_block(value.previous())?;
        }

        Ok(vec![])
    }
}
