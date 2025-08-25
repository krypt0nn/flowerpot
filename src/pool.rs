use std::collections::VecDeque;

use futures::FutureExt;

use crate::client::Client;

// TODO: batch processing

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardsPool {
    active_shards: VecDeque<String>,
    inactive_shards: VecDeque<String>,
    max_active: usize,
    max_inactive: usize
}

impl Default for ShardsPool {
    fn default() -> Self {
        Self {
            active_shards: VecDeque::with_capacity(16),
            inactive_shards: VecDeque::with_capacity(1024),
            max_active: 16,
            max_inactive: 1024
        }
    }
}

impl ShardsPool {
    #[inline]
    pub fn active(&self) -> impl Iterator<Item = &'_ String> {
        self.active_shards.iter()
    }

    #[inline]
    pub fn inactive(&self) -> impl Iterator<Item = &'_ String> {
        self.inactive_shards.iter()
    }

    /// Iterate over the shards within the pool, verify their online status,
    /// use active shards to bootstrap the pool and keep its size at max
    /// capacity.
    pub async fn update(&mut self, client: &Client) {
        // Send heartbeat requests to the active shards.
        let mut responses = Vec::with_capacity(self.active_shards.len());

        for address in self.active_shards.drain(..) {
            responses.push(client.get_heartbeat(address.clone()).map(|response| {
                (address, response)
            }));
        }

        for (address, is_active) in futures::future::join_all(responses).await {
            // If requested shard is active and we can fit it to the active pool
            // then put it there.
            if is_active && self.active_shards.len() < self.max_active {
                self.active_shards.push_front(address);
            }

            // Otherwise put it to the top of the inactive shards pool.
            else {
                self.inactive_shards.push_front(address);
            }
        }

        // Send heartbeat requests to the inactive shards only if active shards
        // pool is not full. Otherwise we don't need to bother.
        if self.active_shards.len() >= self.max_active {
            let mut responses = Vec::with_capacity(self.inactive_shards.len());

            for address in self.inactive_shards.drain(..) {
                responses.push(client.get_heartbeat(address.clone()).map(|response| {
                    (address, response)
                }));
            }

            for (address, is_active) in futures::future::join_all(responses).await {
                // If requested shard is active then it has priority over other
                // shards and we must process it individually.
                if is_active {
                    // If possible - we should put the active shard to the active
                    // shards pool.
                    if self.active_shards.len() < self.max_active {
                        self.active_shards.push_front(address);
                    }

                    // Otherwise we put it to the top of the inactive shards pool.
                    else {
                        self.inactive_shards.push_front(address);
                    }
                }

                // If requested shard is inactive and inactive shards pool is not
                // full yet then we put it to the bottom of this pool.
                else if self.inactive_shards.len() < self.max_inactive {
                    self.inactive_shards.push_back(address);
                }
            }
        }

        // If inactive shards pool is larger than allowed (it has a bunch of
        // active shards) then we truncate the end of the pool where all the
        // inactive shards are collected.
        if self.inactive_shards.len() > self.max_inactive {
            self.inactive_shards.resize(self.max_inactive, String::new());
        }

        // Otherwise we don't have enough shards, so we need to bootstrap their
        // amount using active shards pool if there's any of them.
        else if !self.active_shards.is_empty() {
            // TODO: bootstrap both pools using GET /api/v1/shards
        }
    }
}
