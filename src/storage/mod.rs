use crate::crypto::*;
use crate::block::*;

pub mod file_storage;

pub trait Storage {
    type Error;

    /// Read block from its hash. Return `Ok(None)` if there's no such block.
    fn read_block(&self, hash: &Hash) -> Result<Option<Block>, Self::Error>;

    /// Read block next to the one with provided hash. Return `Ok(None)` if
    /// there's no block next to the requested one.
    ///
    /// ```text,no_run
    /// [curr_block] <--- [next_block]
    ///                   ^^^^^^^^^^^^ returned value
    /// ```
    fn read_next_block(
        &self,
        hash: &Hash
    ) -> Result<Option<Block>, Self::Error>;

    /// Read the first block. Return `Ok(None)` if blockchain is empty.
    fn read_first_block(&self) -> Result<Option<Block>, Self::Error>;

    /// Read the last block. Return `Ok(None)` if blockchain is empty.
    fn read_last_block(&self) -> Result<Option<Block>, Self::Error>;

    /// Write block to the blockchain.
    ///
    /// This method must automatically prune excess blocks if this one modifies
    /// the history, and write all the transactions from the block's content if
    /// there's any. History modifications, block and stored transactions must
    /// be verified outside of this trait so this method must work without extra
    /// verifications, even if the block is not valid.
    fn write_block(&self, block: Block) -> Result<(), Self::Error>;

    /// Get list of blockchain validators at the point in time when the block
    /// with provided hash didn't exist yet. This is needed because validators
    /// can change over time and we want to know which validators existed at any
    /// point in time.
    ///
    /// The "didn't exist" rule means that if the block with provided hash
    /// changes validators list then this method should return *previous
    /// validators* list - so validators who can approve creation of the block
    /// with provided hash.
    fn get_validators_for_block(
        &self,
        hash: &Hash
    ) -> Result<Vec<PublicKey>, Self::Error>;

    /// Get list of current blockchain validators.
    fn get_current_validators(&self) -> Result<Vec<PublicKey>, Self::Error>;
}
