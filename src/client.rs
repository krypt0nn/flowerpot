use std::collections::HashSet;
use std::time::Duration;

use reqwest::Client as Http;
use serde_json::Value as Json;

use crate::crypto::*;
use crate::transaction::*;
use crate::block::{Block, Error as BlockError};

pub const DEFAULT_CLIENT_TIMEOUT: Duration = Duration::from_secs(7);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("shard request error: {0}")]
    ShardRequest(#[source] reqwest::Error),

    #[error("failed to deserialize shard response: {0}")]
    ShardResponseDeserialize(#[source] serde_json::Error),

    #[error("shard returned a response with invalid format: {0}")]
    ShardInvalidResponseFormat(String),

    #[error("failed to serialize transaction: {0}")]
    ClientTransactionSerialize(#[source] std::io::Error),

    #[error("failed to deserialize transaction received from a shard: {0}")]
    ShardTransactionDeserialize(#[source] std::io::Error),

    #[error("shard returned invalid pending block format: {0}")]
    ShardInvalidPendingBlock(&'static str),

    #[error("failed to serialize block: {0}")]
    ClientBlockSerialize(#[source] std::io::Error),

    #[error("failed to deserialize block received from a shard: {0}")]
    ShardBlockDeserialize(#[source] std::io::Error),

    #[error("failed to verify block: {0}")]
    ClientBlockVerify(#[source] BlockError),

    #[error("failed to calculate hash of a block: {0}")]
    ClientBlockHash(#[source] BlockError),

    #[error("failed to verify signature: {0}")]
    ClientSignatureVerify(#[source] k256::ecdsa::Error),

    #[error("failed to perform json (de)serialization: {0}")]
    JsonSerialize(#[source] serde_json::Error)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingBlock {
    pub current_hash: Hash,
    pub previous_hash: Hash,
    pub sign: Signature,
    pub approvals: Vec<Signature>
}

impl PendingBlock {
    pub fn from_json(json: &Json) -> Result<Self, Error> {
        let block = json.get("block")
            .ok_or_else(|| {
                Error::ShardInvalidPendingBlock("field 'block' is invalid")
            })?;

        Ok(Self {
            current_hash: block.get("current")
                .and_then(Json::as_str)
                .and_then(Hash::from_base64)
                .ok_or_else(|| {
                    Error::ShardInvalidPendingBlock("field 'block.current' is invalid")
                })?,

            previous_hash: block.get("previous")
                .and_then(Json::as_str)
                .and_then(Hash::from_base64)
                .ok_or_else(|| {
                    Error::ShardInvalidPendingBlock("field 'block.previous' is invalid")
                })?,

            sign: json.get("sign")
                .and_then(Json::as_str)
                .and_then(Signature::from_base64)
                .ok_or_else(|| {
                    Error::ShardInvalidPendingBlock("field 'sign' is invalid")
                })?,

            approvals: json.get("approvals")
                .and_then(Json::as_array)
                .and_then(|approvals| {
                    approvals.iter()
                        .map(Json::as_str)
                        .map(|approval| {
                            approval.and_then(Signature::from_base64)
                        })
                        .collect::<Option<Vec<Signature>>>()
                })
                .ok_or_else(|| {
                    Error::ShardInvalidPendingBlock("field 'approvals' is invalid")
                })?
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncResult {
    /// Internal shard error with HTTP error code.
    ShardError(u16),

    /// `after_block` is not a part of the known blockchain or there's no root
    /// block.
    BlockNotFound,

    /// Returned blocks chain is not ordered properly (previous hash is wrong).
    ChainNotOrdered,

    /// Chain contains a block with invalid signature.
    InvalidBlock {
        hash: Hash,
        public_key: PublicKey,
        sign: Signature
    },

    /// Properly ordered and verified chain of blocks.
    Blocks(Vec<Block>)
}

/// Client is a network node which doesn't expose any data and just uses remote,
/// publicly available shards and their HTTP API to work with the blockchain.
#[derive(Debug, Clone)]
pub struct Client(pub Http);

impl Default for Client {
    fn default() -> Self {
        let http = Http::builder()
            .connect_timeout(DEFAULT_CLIENT_TIMEOUT)
            .build()
            .unwrap_or_default();

        Self(http)
    }
}

impl Client {
    /// Wrap HTTP client to perform shard API requests.
    ///
    /// It is highly recommended to use a client with configured timeouts.
    #[inline]
    pub fn new(http: Http) -> Self {
        Self(http)
    }

    /// Check online status of the given shard.
    ///
    /// Perform `GET /api/v1/heartbeat` request.
    pub async fn get_heartbeat(
        &self,
        shard_address: impl AsRef<str>
    ) -> bool {
        #[cfg(feature = "tracing")]
        tracing::trace!("GET /api/v1/heartbeat");

        let request = self.0.get(format!(
            "{}/api/v1/heartbeat",
            shard_address.as_ref()
        ));

        match request.send().await {
            Ok(response) => response.status().as_u16() == 200,
            Err(_) => false
        }
    }

    /// Fetch list of pending (not yet verified by validators) transactions.
    ///
    /// Perform `GET /api/v1/transactions` request.
    pub async fn get_transactions(
        &self,
        shard_address: impl AsRef<str>
    ) -> Result<HashSet<Hash>, Error> {
        #[cfg(feature = "tracing")]
        tracing::trace!("GET /api/v1/transactions");

        let mut transactions = HashSet::new();

        let response = self.0.get(format!("{}/api/v1/transactions", shard_address.as_ref()))
            .send().await
            .map_err(Error::ShardRequest)?;

        if !response.status().is_success() {
            return Ok(transactions);
        }

        let response = response.bytes().await
            .map_err(Error::ShardRequest)?;

        let response = serde_json::from_slice::<HashSet<String>>(&response)
            .map_err(Error::ShardResponseDeserialize)?;

        for hash in response {
            let Some(hash) = Hash::from_base64(&hash) else {
                return Err(Error::ShardInvalidResponseFormat(format!("invalid hash format: {hash}")));
            };

            transactions.insert(hash);
        }

        Ok(transactions)
    }

    /// Announce transaction to all the given shards. This method accepts list
    /// of addresses to handle transaction serialization efficiently.
    ///
    /// Perform `PUT /api/v1/transactions` request.
    pub async fn put_transaction<T: AsRef<str>>(
        &self,
        shards_addresses: impl IntoIterator<Item = T>,
        transaction: &Transaction
    ) -> Result<(), Error> {
        #[cfg(feature = "tracing")]
        tracing::trace!("PUT /api/v1/transactions");

        let transaction = transaction.to_json()
            .map_err(Error::ClientTransactionSerialize)?;

        let transaction = serde_json::to_vec(&transaction)
            .map_err(Error::JsonSerialize)?;

        let mut responses = Vec::new();

        for address in shards_addresses {
            let request = self.0.put(format!("{}/api/v1/transactions", address.as_ref()))
                .header("Content-Type", "application/json")
                .body(transaction.clone());

            responses.push(request.send());
        }

        // join_all so that all the requests finish first, and only then we
        // handle errors and throw them from the function. This will send
        // transaction to all the working shards first, and only then we will
        // report broken shards to the user.
        for response in futures::future::join_all(responses).await {
            if let Err(err) = response {
                return Err(Error::ShardRequest(err));
            }
        }

        Ok(())
    }

    /// Read transaction with the given hash.
    ///
    /// Perform `GET /api/v1/transactions/<hash>` request.
    pub async fn read_transaction(
        &self,
        shard_address: impl AsRef<str>,
        hash: &Hash
    ) -> Result<Option<Transaction>, Error> {
        let hash = hash.to_base64();

        #[cfg(feature = "tracing")]
        tracing::trace!(?hash, "GET /api/v1/transactions/<hash>");

        let request = self.0.get(format!(
            "{}/api/v1/transactions/{hash}",
            shard_address.as_ref()
        ));

        let response = request.send().await
            .map_err(Error::ShardRequest)?;

        if !response.status().is_success() {
            return Ok(None);
        }

        let response = response.bytes().await
            .map_err(Error::ShardRequest)?;

        let response = serde_json::from_slice::<Json>(&response)
            .map_err(Error::ShardResponseDeserialize)?;

        let transaction = Transaction::from_json(&response)
            .map_err(Error::ShardTransactionDeserialize)?;

        Ok(Some(transaction))
    }

    /// Fetch list of pending (not yet verified by validators) blocks.
    ///
    /// Perform `GET /api/v1/blocks` request.
    pub async fn get_blocks(
        &self,
        shard_address: impl AsRef<str>
    ) -> Result<Vec<PendingBlock>, Error> {
        #[cfg(feature = "tracing")]
        tracing::trace!("GET /api/v1/blocks");

        let mut blocks = Vec::new();

        let response = self.0.get(format!("{}/api/v1/blocks", shard_address.as_ref()))
            .send().await
            .map_err(Error::ShardRequest)?;

        if !response.status().is_success() {
            return Ok(blocks);
        }

        let response = response.bytes().await
            .map_err(Error::ShardRequest)?;

        let response = serde_json::from_slice::<Vec<Json>>(&response)
            .map_err(Error::ShardResponseDeserialize)?;

        for pending_block in response {
            let pending_block = PendingBlock::from_json(&pending_block)?;

            blocks.push(pending_block);
        }

        Ok(blocks)
    }

    /// Announce block to all the given shards. This method accepts list
    /// of addresses to handle block serialization efficiently.
    ///
    /// Perform `PUT /api/v1/blocks` request.
    pub async fn put_block<T: AsRef<str>>(
        &self,
        shards_addresses: impl IntoIterator<Item = T>,
        block: &Block
    ) -> Result<(), Error> {
        #[cfg(feature = "tracing")]
        tracing::trace!("PUT /api/v1/blocks");

        let block = block.to_json()
            .map_err(Error::ClientBlockSerialize)?;

        let block = serde_json::to_vec(&block)
            .map_err(Error::JsonSerialize)?;

        let mut responses = Vec::new();

        for address in shards_addresses {
            let request = self.0.put(format!("{}/api/v1/blocks", address.as_ref()))
                .header("Content-Type", "application/json")
                .body(block.clone());

            responses.push(request.send());
        }

        // join_all so that all the requests finish first, and only then we
        // handle errors and throw them from the function. This will send
        // block to all the working shards first, and only then we will
        // report broken shards to the user.
        for response in futures::future::join_all(responses).await {
            if let Err(err) = response {
                return Err(Error::ShardRequest(err));
            }
        }

        Ok(())
    }

    /// Read block with the given hash.
    ///
    /// Perform `GET /api/v1/blocks/<hash>` request.
    pub async fn read_block(
        &self,
        shard_address: impl AsRef<str>,
        hash: &Hash
    ) -> Result<Option<Block>, Error> {
        let hash = hash.to_base64();

        #[cfg(feature = "tracing")]
        tracing::trace!(?hash, "GET /api/v1/blocks/<hash>");

        let request = self.0.get(format!(
            "{}/api/v1/blocks/{hash}",
            shard_address.as_ref()
        ));

        let response = request.send().await
            .map_err(Error::ShardRequest)?;

        if !response.status().is_success() {
            return Ok(None);
        }

        let response = response.bytes().await
            .map_err(Error::ShardRequest)?;

        let response = serde_json::from_slice::<Json>(&response)
            .map_err(Error::ShardResponseDeserialize)?;

        let block = Block::from_json(&response)
            .map_err(Error::ShardBlockDeserialize)?;

        Ok(Some(block))
    }

    /// Announce approval of a pending block to all the given shards.
    ///
    /// Perform `PUT /api/v1/blocks/<hash>` request.
    pub async fn approve_block<T: AsRef<str>>(
        &self,
        shards_addresses: impl IntoIterator<Item = T>,
        hash: &Hash,
        approval: &Signature
    ) -> Result<(), Error> {
        let hash = hash.to_base64();
        let approval = approval.to_base64();

        #[cfg(feature = "tracing")]
        tracing::trace!(?hash, ?approval, "PUT /api/v1/blocks/<hash>");

        let mut responses = Vec::new();

        for address in shards_addresses {
            let request = self.0.put(format!(
                "{}/api/v1/blocks/{hash}",
                address.as_ref()
            ));

            let response = request.body(approval.clone())
                .send();

            responses.push(response);
        }

        // join_all so that all the requests finish first, and only then we
        // handle errors and throw them from the function. This will send
        // approval to all the working shards first, and only then we will
        // report broken shards to the user.
        for response in futures::future::join_all(responses).await {
            if let Err(err) = response {
                return Err(Error::ShardRequest(err));
            }
        }

        Ok(())
    }

    /// Read some blocks from the shard's blockchain.
    ///
    /// This method verifies that:
    ///
    /// 1. All the returned blocks are ordered properly, with next block's
    ///    previous hash equal to the previous block's hash.
    /// 2. If `after_block` is specified then the first returned block's
    ///    previous hash is equal to it. If `after_block` is not specified then
    ///    the first returned block is the root block of the blockchain.
    /// 3. All the blocks' signatures are valid.
    ///
    /// This method **does not verify blocks' approvals** because it doesn't
    /// iterate over the whole blockchian and just requests a part of it.
    ///
    /// Note that this method can return more blocks than `max_blocks`.
    ///
    /// Perform `GET /api/v1/sync` request.
    pub async fn get_blockchain(
        &self,
        shard_address: impl AsRef<str>,
        after_block: Option<Hash>,
        max_blocks: Option<usize>
    ) -> Result<SyncResult, Error> {
        #[cfg(feature = "tracing")]
        tracing::trace!("GET /api/v1/sync");

        let mut request = self.0.get(format!(
            "{}/api/v1/sync",
            shard_address.as_ref()
        ));

        if let Some(after_block) = after_block {
            request = request.query(&[("after", after_block.to_base64())]);
        }

        if let Some(max_blocks) = max_blocks {
            request = request.query(&[("max_blocks", max_blocks)]);
        }

        let response = request.send().await
            .map_err(Error::ShardRequest)?;

        if !response.status().is_success() {
            let code = response.status().as_u16();

            if code == 404 {
                return Ok(SyncResult::BlockNotFound);
            } else {
                return Ok(SyncResult::ShardError(code));
            }
        }

        let response = response.bytes().await
            .map_err(Error::ShardRequest)?;

        let response = serde_json::from_slice::<Vec<Json>>(&response)
            .map_err(Error::ShardResponseDeserialize)?;

        let mut blocks = Vec::with_capacity(response.len());

        let mut prev_block = after_block.unwrap_or_default();

        for block in response {
            let block = Block::from_json(&block)
                .map_err(Error::ShardBlockDeserialize)?;

            if block.previous() != &prev_block {
                return Ok(SyncResult::ChainNotOrdered);
            }

            let (valid, hash, public_key) = block.verify()
                .map_err(Error::ClientBlockVerify)?;

            if !valid {
                return Ok(SyncResult::InvalidBlock {
                    hash,
                    public_key,
                    sign: block.sign
                });
            }

            blocks.push(block);

            prev_block = hash;
        }

        Ok(SyncResult::Blocks(blocks))
    }
}

impl From<Http> for Client {
    #[inline(always)]
    fn from(value: Http) -> Self {
        Self(value)
    }
}

impl From<Client> for Http {
    #[inline(always)]
    fn from(value: Client) -> Self {
        value.0
    }
}
