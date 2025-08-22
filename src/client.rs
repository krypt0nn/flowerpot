use std::collections::{HashSet, HashMap};

use reqwest::Client as Http;
use serde_json::{json, Value as Json};

use crate::crypto::*;
use crate::transaction::*;
use crate::block::*;
use crate::storage::Storage;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("[{method}]: invalid json field value: {field}")]
    InvalidField {
        method: &'static str,
        field: &'static str
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingBlock {
    pub block: Hash,
    pub sign: Signature,
    pub approvals: Vec<Signature>
}

impl PendingBlock {
    pub fn from_json(json: &Json) -> Result<Self, Error> {
        Ok(Self {
            block: json.get("block")
                .and_then(Json::as_str)
                .and_then(Hash::from_base64)
                .ok_or_else(|| Error::InvalidField {
                    method: "/api/v1/blocks",
                    field: "blocks"
                })?,

            sign: json.get("sign")
                .and_then(Json::as_str)
                .and_then(Signature::from_base64)
                .ok_or_else(|| Error::InvalidField {
                    method: "/api/v1/blocks",
                    field: "sign"
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
                .ok_or_else(|| Error::InvalidField {
                    method: "/api/v1/blocks",
                    field: "approvals"
                })?
        })
    }
}

#[derive(Debug, Clone)]
pub struct Client {
    secret_key: SecretKey,
    http: Http,
    shards: HashSet<String>
}

impl Client {
    #[inline]
    pub fn new<T: ToString>(
        secret_key: SecretKey,
        shards: impl IntoIterator<Item = T>
    ) -> Self {
        Self::new_with_http(secret_key, Http::new(), shards)
    }

    pub fn new_with_http<T: ToString>(
        secret_key: SecretKey,
        http: Http,
        shards: impl IntoIterator<Item = T>
    ) -> Self {
        Self {
            secret_key,
            http,
            shards: shards.into_iter()
                .map(|shard| shard.to_string())
                .collect()
        }
    }

    #[inline(always)]
    pub fn shards(&self) -> &HashSet<String> {
        &self.shards
    }

    #[inline]
    pub fn add_shard(&mut self, address: impl ToString) {
        self.shards.insert(address.to_string());
    }

    #[inline]
    pub fn remove_shard(&mut self, address: impl AsRef<str>) {
        self.shards.remove(address.as_ref());
    }

    #[inline(always)]
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    /// Announce transaction to all the connected shards.
    ///
    /// Perform `PUT /api/v1/transactions` request.
    pub async fn announce_transaction(&self, transaction: &Transaction) -> Result<(), Error> {
        let transaction = serde_json::to_vec(&transaction.to_json()?)?;

        let mut responses = Vec::with_capacity(self.shards.len());

        for address in &self.shards {
            let request = self.http.put(format!("{address}/api/v1/transactions"))
                .body(transaction.clone());

            responses.push(request.send());
        }

        futures::future::try_join_all(responses).await?;

        Ok(())
    }

    /// Fetch list of pending (not yet verified by validators) transactions.
    ///
    /// Perform `GET /api/v1/transactions` request.
    pub async fn list_pending_transactions(&self) -> Result<HashSet<Hash>, Error> {
        let mut responses = Vec::with_capacity(self.shards.len());
        let mut transactions = HashSet::new();

        for address in &self.shards {
            let request = self.http.get(format!("{address}/api/v1/transactions"));

            responses.push(request.send());
        }

        for response in futures::future::try_join_all(responses).await? {
            let response = response.bytes().await?;
            let response = serde_json::from_slice::<HashSet<String>>(&response)?;

            for hash in response {
                if let Some(hash) = Hash::from_base64(hash) {
                    transactions.insert(hash);
                }
            }
        }

        Ok(transactions)
    }

    /// Read transaction with the given hash.
    ///
    /// Perform `GET /api/v1/transactions/<hash>` request.
    pub async fn read_transaction(&self, hash: &Hash) -> Result<Option<Transaction>, Error> {
        let hash = hash.to_base64();

        for address in &self.shards {
            let response = self.http.get(format!("{address}/api/v1/transactions/{hash}"))
                .send().await?;

            if response.status().is_success() {
                let response = response.bytes().await?;
                let response = serde_json::from_slice::<Json>(&response)?;

                return Ok(Some(Transaction::from_json(&response)?));
            }
        }

        Ok(None)
    }

    /// Announce block to all the connected shards.
    ///
    /// Perform `PUT /api/v1/blocks` request.
    pub async fn announce_block(&self, block: &Block) -> Result<(), Error> {
        let block = serde_json::to_vec(&block.to_json()?)?;

        let mut responses = Vec::with_capacity(self.shards.len());

        for address in &self.shards {
            let request = self.http.put(format!("{address}/api/v1/blocks"))
                .body(block.clone());

            responses.push(request.send());
        }

        futures::future::try_join_all(responses).await?;

        Ok(())
    }

    /// Fetch list of pending (not yet verified by validators) blocks.
    ///
    /// Perform `GET /api/v1/blocks` request.
    pub async fn list_pending_blocks(&self) -> Result<Vec<PendingBlock>, Error> {
        let mut responses = Vec::with_capacity(self.shards.len());
        let mut blocks = HashMap::new();

        for address in &self.shards {
            let request = self.http.get(format!("{address}/api/v1/blocks"));

            responses.push(request.send());
        }

        for response in futures::future::try_join_all(responses).await? {
            let response = response.bytes().await?;
            let response = serde_json::from_slice::<Vec<Json>>(&response)?;

            for block in response {
                let block = PendingBlock::from_json(&block)?;

                let approvals = block.approvals.clone();

                let entry = blocks.entry(block.block)
                    .or_insert(block);

                for approval in approvals {
                    if !entry.approvals.contains(&approval) {
                        entry.approvals.push(approval);
                    }
                }
            }
        }

        Ok(blocks.values().cloned().collect())
    }

    /// Read block with the given hash.
    ///
    /// Perform `GET /api/v1/blocks/<hash>` request.
    pub async fn read_block(&self, hash: &Hash) -> Result<Option<Block>, Error> {
        let hash = hash.to_base64();

        for address in &self.shards {
            let response = self.http.get(format!("{address}/api/v1/blocks/{hash}"))
                .send().await?;

            if response.status().is_success() {
                let response = response.bytes().await?;
                let response = serde_json::from_slice::<Json>(&response)?;

                return Ok(Some(Block::from_json(&response)?));
            }
        }

        Ok(None)
    }

    /// Announce approval of a pending block to all the connected shards.
    ///
    /// Perform `PUT /api/v1/blocks/<hash>` request.
    pub async fn approve_block(
        &self,
        hash: &Hash,
        approval: &Signature
    ) -> Result<(), Error> {
        let hash = hash.to_base64();
        let approval = approval.to_base64();

        let mut responses = Vec::with_capacity(self.shards.len());

        for address in &self.shards {
            let request = self.http.put(format!("{address}/api/v1/blocks/{hash}"))
                .body(approval.clone());

            responses.push(request.send());
        }

        futures::future::try_join_all(responses).await?;

        Ok(())
    }
}
