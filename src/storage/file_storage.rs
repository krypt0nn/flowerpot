use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::fs::File;

use super::*;

/// Very inefficient, quickly crafted filesystem-based storage for blockchain.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FileStorage(PathBuf);

impl FileStorage {
    pub fn open(path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path: PathBuf = path.into();

        if !path.is_dir() {
            std::fs::create_dir_all(&path)?;
        }

        if !path.join("index").is_file() {
            std::fs::write(path.join("index"), b"")?;
        }

        Ok(Self(path))
    }

    fn get_block_path(&self, hash: &Hash) -> PathBuf {
        self.0
            .join(format!("{:0x}", hash.0[0]))
            .join(format!("{:0x}", hash.0[1]))
            .join(hash.to_base64())
    }

    fn index_size(&self) -> std::io::Result<u64> {
        Ok(self.0.join("index").metadata()?.len() / 32)
    }

    fn index_read_block_hash(
        &self,
        index: u64
    ) -> std::io::Result<Option<Hash>> {
        if self.index_size()? <= index {
            return Ok(None);
        }

        let mut file = File::options()
            .create(true)
            .truncate(false)
            .read(true)
            .open(self.0.join("index"))?;

        let mut hash = [0; 32];

        file.seek(SeekFrom::Start(index * 32))?;
        file.read_exact(&mut hash)?;

        Ok(Some(Hash::from(hash)))
    }

    fn index_write_block_hash(
        &self,
        index: u64,
        hash: &Hash
    ) -> std::io::Result<()> {
        let mut file = File::options()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.0.join("index"))?;

        file.set_len(index * 32)?;
        file.seek(SeekFrom::Start(index * 32))?;
        file.write_all(&hash.0)?;
        file.flush()?;

        Ok(())
    }

    fn index_find_block_hash(
        &self,
        hash: &Hash
    ) -> std::io::Result<Option<u64>> {
        let mut file = File::options()
            .create(true)
            .truncate(false)
            .read(true)
            .open(self.0.join("index"))?;

        let mut current_hash = [0; 32];
        let mut i = 0;

        while file.read_exact(&mut current_hash).is_ok() {
            if current_hash == hash.0 {
                return Ok(Some(i));
            }

            i += 1;
        }

        Ok(None)
    }
}

impl Storage for FileStorage {
    type Error = std::io::Error;

    fn read_block(&self, hash: &Hash) -> Result<Option<Block>, Self::Error> {
        let path = self.get_block_path(hash);

        if !path.is_file() {
            return Ok(None);
        }

        let block = std::fs::read(path)?;
        let block = Block::from_bytes(block)?;

        Ok(Some(block))
    }

    fn read_next_block(
        &self,
        hash: &Hash
    ) -> Result<Option<Block>, Self::Error> {
        match self.index_find_block_hash(hash)? {
            Some(index) => {
                match self.index_read_block_hash(index + 1)? {
                    Some(hash) => self.read_block(&hash),
                    None => Ok(None)
                }
            }

            None => Ok(None)
        }
    }

    fn read_first_block(&self) -> Result<Option<Block>, Self::Error> {
        match self.index_read_block_hash(0)? {
            Some(hash) => self.read_block(&hash),
            None => Ok(None)
        }
    }

    fn read_last_block(&self) -> Result<Option<Block>, Self::Error> {
        let size = self.index_size()?;

        if size == 0 {
            return Ok(None);
        }

        match self.index_read_block_hash(size - 1)? {
            Some(hash) => self.read_block(&hash),
            None => Ok(None)
        }
    }

    fn write_block(&self, block: &Block) -> Result<(), Self::Error> {
        let hash = block.hash()?;
        let path = self.get_block_path(&hash);

        if let Some(parent) = path.parent() && !parent.is_dir() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(path, block.to_bytes()?)?;

        if !block.is_root() {
            let Some(index) = self.index_find_block_hash(block.previous())? else {
                return Err(std::io::Error::other("can't write block if parent block is not written yet"));
            };

            self.index_write_block_hash(index + 1, &hash)?;
        } else {
            self.index_write_block_hash(0, &hash)?;
        }

        Ok(())
    }

    fn get_validators_before_block(&self, hash: &Hash) -> Result<Vec<PublicKey>, Self::Error> {
        let mut block = self.read_block(hash)?;

        while let Some(value) = block {
            block = self.read_block(value.previous())?;

            if let BlockContent::Validators(validators) = value.content() {
                return Ok(validators.to_vec());
            }
        }

        Ok(vec![])
    }

    fn get_validators_after_block(&self, hash: &Hash) -> Result<Vec<PublicKey>, Self::Error> {
        let mut block = self.read_block(hash)?;

        while let Some(value) = block {
            if let BlockContent::Validators(validators) = value.content() {
                return Ok(validators.to_vec());
            }

            block = self.read_block(value.previous())?;
        }

        Ok(vec![])
    }

    fn get_current_validators(&self) -> Result<Vec<PublicKey>, Self::Error> {
        match self.read_last_block()? {
            Some(block) => self.get_validators_after_block(&block.hash()?),
            None => Ok(vec![])
        }
    }
}
