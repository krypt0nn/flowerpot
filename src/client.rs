use std::collections::{HashSet, HashMap};

use futures::FutureExt;
use reqwest::Client as Http;
use serde_json::Value as Json;

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

    #[error(transparent)]
    Signature(#[from] k256::ecdsa::Error),

    #[error("[{method}]: invalid json field value: {field}")]
    InvalidField {
        method: &'static str,
        field: &'static str
    },

    #[error("storage error: {0}")]
    Storage(String),

    #[error("storage is empty although it was populated by a root block previously")]
    StorageIsEmpty
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
    shards: HashSet<String>,
    target_root: Option<Hash>
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
                .collect(),
            target_root: None
        }
    }

    #[inline(always)]
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    #[inline(always)]
    pub fn http(&self) -> &Http {
        &self.http
    }

    #[inline(always)]
    pub fn shards(&self) -> &HashSet<String> {
        &self.shards
    }

    /// This function will verify that the added shards' root blocks are equal
    /// to the target root block of the current client by performing
    /// `GET /api/v1/blocks/<hash>` requests.
    pub async fn with_shards<T: ToString>(
        &mut self,
        shards: impl IntoIterator<Item = T>
    ) -> Result<(), Error> {
        self.shards = shards.into_iter()
            .map(|shard| shard.to_string())
            .collect();

        self.filter_shards().await
    }

    /// This function will verify that the added shards' root blocks are equal
    /// to the target root block of the current client by performing
    /// `GET /api/v1/blocks/<hash>` requests.
    pub async fn add_shards<T: ToString>(
        &mut self,
        shards: impl IntoIterator<Item = T>
    ) -> Result<(), Error> {
        for address in shards {
            self.shards.insert(address.to_string());
        }

        self.filter_shards().await
    }

    #[inline]
    pub fn remove_shard(&mut self, address: impl AsRef<str>) {
        self.shards.remove(address.as_ref());
    }

    /// Specify target root block hash. If one is specified then only shards
    /// with the asked root block will be used, and all the other shards will
    /// be silently ignored.
    ///
    /// This function will iterate over the known shards and filter out those
    /// with different target block.
    #[inline]
    pub async fn with_target_root(&mut self, hash: impl Into<Hash>) -> Result<(), Error> {
        self.target_root = Some(hash.into());

        self.filter_shards().await
    }

    /// Iterate over connected shards and remove those which root block is
    /// different from the target one, if it is specified.
    async fn filter_shards(&mut self) -> Result<(), Error> {
        let Some(root_hash) = self.target_root else {
            return Ok(());
        };

        let mut responses = Vec::with_capacity(self.shards.len());
        let mut bodies = Vec::with_capacity(responses.len());

        let root_hash = root_hash.to_base64();

        for address in &self.shards {
            let request = self.http.get(format!("{address}/api/v1/blocks/{root_hash}"));

            responses.push(request.send().map(|response| {
                response.map(|response| (address.clone(), response))
            }));
        }

        for (address, response) in futures::future::try_join_all(responses).await? {
            if response.status().is_success() {
                bodies.push(response.bytes().map(|body| {
                    body.map(|body| (address, body))
                }));
            } else {
                self.shards.remove(&address);
            }
        }

        for (address, body) in futures::future::try_join_all(bodies).await? {
            let body = serde_json::from_slice::<Json>(&body)?;

            let block = Block::from_json(&body)?;

            if !block.is_root() {
                self.shards.remove(&address);
            }
        }

        Ok(())
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
        let mut bodies = Vec::with_capacity(self.shards.len());
        let mut transactions = HashSet::new();

        for address in &self.shards {
            let request = self.http.get(format!("{address}/api/v1/transactions"));

            responses.push(request.send());
        }

        for response in futures::future::try_join_all(responses).await? {
            if response.status().is_success() {
                bodies.push(response.bytes());
            }
        }

        for body in futures::future::try_join_all(bodies).await? {
            let response = serde_json::from_slice::<HashSet<String>>(&body)?;

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
        let mut bodies = Vec::with_capacity(self.shards.len());
        let mut blocks = HashMap::new();

        for address in &self.shards {
            let request = self.http.get(format!("{address}/api/v1/blocks"));

            responses.push(request.send());
        }

        for response in futures::future::try_join_all(responses).await? {
            if response.status().is_success() {
                bodies.push(response.bytes());
            }
        }

        for body in futures::future::try_join_all(bodies).await? {
            let body = serde_json::from_slice::<Vec<Json>>(&body)?;

            for block in body {
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

    /// Synchronize local blockchain storage with all the connected shards.
    ///
    /// Perform `GET /api/v1/sync` requests for each shard first, then
    /// perform `PUT /api/v1/sync` requests for each shard with different
    /// blockchain history.
    ///
    /// This is a heavy operation and should be performed in background.
    pub async fn sync(&self, storage: &impl Storage) -> Result<(), Error> {
        // List of shards with invalid blockchains (blocklist).
        let mut invalid_shards = HashSet::with_capacity(self.shards.len());

        // For each connected shard request their known blockchain history and
        // update our local storage.
        for address in &self.shards {
            // Request initial history of the blockchain known to the shard.
            let response = self.http.get(format!("{address}/api/v1/sync"))
                .send().await?;

            // Skip shard if it didn't return anything useful.
            if !response.status().is_success() {
                continue;
            }

            // Read the response body (json list of next blocks).
            let response = response.bytes().await?;
            let response = serde_json::from_slice::<Vec<Json>>(&response)?;

            // Deserialize the blocks.
            let mut history = response.iter()
                .take(1)
                .map(Block::from_json)
                .collect::<Result<Vec<_>, _>>()?;

            // Save up some RAM.
            drop(response);

            // Take the root block of the shard's known blockchain.
            let Some(shard_root_block) = history.pop() else {
                continue;
            };

            // Read the root block of the local blockchain.
            let block = storage.read_first_block()
                .map_err(|err| Error::Storage(err.to_string()))?;

            // Compare it with the root block of the shard.
            match block {
                // If we have root block - compare it.
                Some(block) => {
                    // Skip shard if its root block is different from ours
                    // and block it.
                    if block.hash()? != shard_root_block.hash()? {
                        invalid_shards.insert(address.clone());

                        continue;
                    }
                }

                // If we don't have a root block - insert one form the shard.
                None => {
                    storage.write_block(&shard_root_block)
                        .map_err(|err| Error::Storage(err.to_string()))?;
                }
            }

            // At this point we're sure that:
            //
            // a) we have the root block,
            // b) this root block is the same as the one in the shard, and
            // c) this block is valid.
            //
            // Now let's request history of blocks after our last known block
            // in the local blockchain and see what we can do with it.

            // Read current last block of the local blockchain.
            let block = storage.read_last_block()
                .map_err(|err| Error::Storage(err.to_string()))?;

            let Some(block) = block else {
                // It cannot be empty because we literally just populated the
                // storage with at least one block.
                return Err(Error::StorageIsEmpty);
            };

            #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
            enum Status {
                AlreadySynced,
                Success,
                InvalidShard
            }

            /// Try to synchronize blocks from the shard.
            async fn try_sync_from_shard(
                target_block: &Block,
                storage: &impl Storage,
                shard_address: &str,
                http: &Http
            ) -> Result<Status, Error> {
                // Calculate hash of the target block.
                let target_block_hash = target_block.hash()?;

                // Read local blockchain validators.
                let mut validators = storage.get_validators_after_block(&target_block_hash)
                    .map_err(|err| Error::Storage(err.to_string()))?;

                // Then request history known to the shard after our last block.
                let response = http.get(format!("{shard_address}/api/v1/sync"))
                    .query(&[("after", target_block_hash.to_base64())])
                    .send().await?;

                // If shard knows our block and it's a valid part of the
                // blockchain - then we must receive next blocks of the
                // blockchain.
                if response.status().is_success() {
                    // Read the response body (json list of next blocks).
                    let response = response.bytes().await?;
                    let response = serde_json::from_slice::<Vec<Json>>(&response)?;

                    // Deserialize the blocks.
                    let mut history = response.iter()
                        .map(Block::from_json)
                        .collect::<Result<Vec<_>, _>>()?;

                    // Skip history processing if it's empty (our local blockchain
                    // is already synced).
                    if history.is_empty() {
                        return Ok(Status::AlreadySynced);
                    }

                    // Save up some RAM.
                    drop(response);

                    // Verify the blocks of received history.
                    let mut history_valid = true;
                    let mut prev_hash = target_block_hash;

                    for block in &history {
                        // Skip history synchronization if blocks in the
                        // provided history are not ordered properly.
                        if block.previous() != &prev_hash {
                            history_valid = false;

                            break;
                        }

                        let (valid, hash, author) = block.verify()?;

                        prev_hash = hash;

                        // Skip history synchronization if one of blocks
                        // is not valid or its signer is not in the
                        // validators pool.
                        if !valid || !validators.contains(&author) {
                            history_valid = false;

                            break;
                        }

                        // Verify block approvals.
                        let required_approvals = validators.len() * 2 / 3;
                        let mut accepted_approvals = HashSet::new();

                        for approval in block.approvals() {
                            // Verify the approval itself.
                            let (valid, validator) = approval.verify(hash)?;

                            // Skip history synchronization if one of the
                            // approvals is not valid or its signer is not
                            // in the validators pool.
                            if !valid || !validators.contains(&validator) {
                                history_valid = false;

                                break;
                            }

                            // If approval is made by someone else but the
                            // author then we accept it.
                            if validator != author {
                                accepted_approvals.insert(validator.to_bytes());
                            }
                        }

                        // Skip history synchronization if there's not
                        // enough approvals for the block.
                        if accepted_approvals.len() < required_approvals {
                            history_valid = false;

                            break;
                        }

                        // Update validators if such block received.
                        if let BlockContent::Validators(new_validators) = block.content() {
                            validators = new_validators.to_vec();
                        }
                    }

                    // Skip current shard if his returned history is invalid
                    // and block it.
                    if !history_valid {
                        return Ok(Status::InvalidShard);
                    }

                    // At this point received history is:
                    //
                    // a) ordered properly and has proper offset,
                    // b) signed by a real validators,
                    // c) approved by enough other validators,
                    // d) and all these signs are valid.
                    //
                    // Now we can compare received history with our locally
                    // stored one and merge them together.

                    // Try to read next local block from the target one.
                    let next_block = storage.read_next_block(&target_block_hash)
                        .map_err(|err| Error::Storage(err.to_string()))?;

                    // If there's any - it means that received history is
                    // attempting to replace our local one. Before doing so
                    // we must verify that it's actually prevalent to our own.
                    if let Some(next_block) = next_block {
                        let new_next_block = &history[0];

                        /// Count amount of validators for a block with given hash.
                        fn count_validators(block: &Block, hash: Hash) -> Result<usize, Error> {
                            let mut validators = HashSet::new();

                            let (valid, validator) = block.sign().verify(hash)?;

                            if valid {
                                validators.insert(validator.to_bytes());
                            }

                            for approval in block.approvals() {
                                let (valid, validator) = approval.verify(hash)?;

                                if valid {
                                    validators.insert(validator.to_bytes());
                                }
                            }

                            Ok(validators.len())
                        }

                        let next_block_hash = next_block.hash()?;
                        let new_next_block_hash = new_next_block.hash()?;

                        let curr_validators = count_validators(&next_block, next_block_hash)?;
                        let new_validators = count_validators(new_next_block, new_next_block_hash)?;

                        // If we have more approves than received history's block
                        // then we just skip it and keep our own copy.
                        if curr_validators > new_validators {
                            return Ok(Status::InvalidShard);
                        }

                        // If we have equal amount of approves but our block's
                        // hash is lower or equal to the received block's hash
                        // then we just keep our own and that's it.
                        if curr_validators == new_validators && next_block_hash <= new_next_block_hash {
                            return Ok(Status::InvalidShard);
                        }
                    }

                    // Merge the history into our local blockchain after all the
                    // verifications were passed successfully.
                    for block in history.drain(..) {
                        storage.write_block(&block)
                            .map_err(|err| Error::Storage(err.to_string()))?;
                    }

                    Ok(Status::Success)
                }

                // Otherwise our last block is not a part of the blockchain
                // and we must try to find the divergence point.
                //
                // TODO: binary search would be really nice here.
                else {
                    let target_block = storage.read_block(target_block.previous())
                        .map_err(|err| Error::Storage(err.to_string()))?;

                    // If there's no previous block - then we've reached the
                    // root block, but at that point shard must have accepted
                    // it for synchronization, which means it's invalid.
                    let Some(target_block) = target_block else {
                        return Ok(Status::InvalidShard);
                    };

                    Box::pin(try_sync_from_shard(
                        &target_block,
                        storage,
                        shard_address,
                        http
                    )).await
                }
            }

            // Sync blockchain with the shard.
            loop {
                let status = try_sync_from_shard(
                    &block,
                    storage,
                    address,
                    &self.http
                ).await?;

                match status {
                    Status::AlreadySynced => break,
                    Status::Success => continue,

                    Status::InvalidShard => {
                        invalid_shards.insert(address.clone());

                        break;
                    }
                }
            }
        }

        // TODO: reverse sync with PUT requests.

        Ok(())
    }

    /// Fetch list of other shards known to shards we are connected to.
    ///
    /// Perform `GET /api/v1/shards` request.
    pub async fn list_shards(&self) -> Result<HashSet<String>, Error> {
        let mut responses = Vec::with_capacity(self.shards.len());
        let mut bodies = Vec::with_capacity(self.shards.len());
        let mut addresses = HashSet::new();

        for address in &self.shards {
            let request = self.http.get(format!("{address}/api/v1/shards"));

            responses.push(request.send());
        }

        for response in futures::future::try_join_all(responses).await? {
            if response.status().is_success() {
                bodies.push(response.bytes());
            }
        }

        for body in futures::future::try_join_all(bodies).await? {
            let response = serde_json::from_slice::<HashSet<String>>(&body)?;

            for address in response {
                if !self.shards.contains(&address) {
                    addresses.insert(address);
                }
            }
        }

        Ok(addresses)
    }

    /// Announce shards to all the shards we are connected to.
    ///
    /// This method will merge lists of all the shards we are connected to
    /// with the provided `extra_shards` list and send it to all the shards
    /// we are connected to.
    ///
    /// Perform `PUT /api/v1/shards` request.
    pub async fn announce_shards<T: ToString>(
        &self,
        extra_shards: impl IntoIterator<Item = T>
    ) -> Result<(), Error> {
        let mut responses = Vec::with_capacity(self.shards.len());
        let mut addresses = self.shards.clone();

        for address in extra_shards {
            addresses.insert(address.to_string());
        }

        let addresses = serde_json::to_vec(&addresses)?;

        for address in &self.shards {
            let request = self.http.put(format!("{address}/api/v1/shards"))
                .body(addresses.clone());

            responses.push(request.send());
        }

        futures::future::try_join_all(responses).await?;

        Ok(())
    }
}
