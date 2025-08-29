use crate::crypto::*;
use crate::transaction::Transaction;
use crate::block::Block;

/// Common rules used by shard and validator nodes to reject or accept
/// transactions and blocks.
#[derive(Debug, Clone)]
pub struct SecurityRules {
    /// Maximal allowed size of transaction's body in bytes.
    ///
    /// Transactions with larger body will be rejected.
    ///
    /// Default is `1048576` (1 MB).
    pub max_transaction_body_size: u64,

    /// Optional filter function which will be applied to the pending
    /// transactions before adding them to the pool. If `true` is returned
    /// by such function then transaction is accepted, otherwise it will be
    /// dropped.
    ///
    /// This function is useful for applications with custom transaction
    /// formats and rules to filter out malicious or invalid transactions.
    ///
    /// Default is `None`.
    pub transactions_filter: Option<fn(&Transaction, &Hash, &PublicKey) -> bool>,

    /// Optional filter function which will be applied to the pending blocks
    /// before adding them to the pool. If `true` is returned by such function
    /// then block is accepted, otherwise it will be dropped.
    ///
    /// This function is useful for applications with custom transaction
    /// formats and rules to filter out blocks with malicious or invalid
    /// transactions.
    ///
    /// Default is `None`.
    pub blocks_filter: Option<fn(&Block, &Hash, &PublicKey) -> bool>,
}

impl Default for SecurityRules {
    fn default() -> Self {
        Self {
            max_transaction_body_size: 1024 * 1024,
            transactions_filter: None,
            blocks_filter: None
        }
    }
}
