use crate::crypto::*;
use crate::transaction::*;
use crate::block::*;

pub mod file_storage;

pub trait Storage {
    type Error;

    /// Read transaction from its hash.
    fn read_transaction(&self, hash: &Hash) -> Result<Option<Transaction>, Self::Error>;

    /// Read block from its hash.
    fn read_block(&self, hash: &Hash) -> Result<Option<Block>, Self::Error>;

    /// Read last block.
    fn read_last_block(&self) -> Result<Option<Block>, Self::Error>;

    /// Read block from its index in the chain.
    fn index_block(&self, index: u64) -> Result<Option<Block>, Self::Error>;

    /// Write block to the chain.
    ///
    /// This method must automatically prune excess blocks if this one modifies
    /// the history, and write all the transactions from the block's content if
    /// there's any. History modifications, block and stored transactions must
    /// be verified outside of this trait so this method must work without extra
    /// verifications, even if the block is not valid.
    fn write_block(&self, block: Block) -> Result<(), Self::Error>;

    /// Get list of current blockchain validators.
    fn get_current_validators(&self) -> Result<Vec<PublicKey>, Self::Error>;

    /// Get list of blockchain validators at the point in time when the block
    /// with provided hash existed. This is needed because validators can change
    /// over time and we want to know which validators existed at any point in
    /// time.
    ///
    /// Result of this method must be equal to the `get_current_validators` for
    /// the last block in blockchain.
    fn get_validators_for_block(&self, hash: &Hash) -> Result<Vec<PublicKey>, Self::Error>;
}
