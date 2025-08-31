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
    pub fn new<T: ToString>(shards: impl IntoIterator<Item = T>) -> Self {
        let mut pool = Self::default();

        pool.add_shards(shards);

        pool
    }

    pub fn with_max_active(&mut self, max_active: usize) -> &mut Self {
        self.max_active = max_active;

        // Push excess active shards to the top of the inactive shards pool.
        while self.active_shards.len() > max_active {
            let Some(address) = self.active_shards.pop_back() else {
                break;
            };

            self.inactive_shards.push_front(address);
        }

        // Truncate inactive shards pool to its max allowed capacity.
        if self.inactive_shards.len() > self.max_inactive {
            self.inactive_shards.resize(self.max_inactive, String::new());
        }

        self
    }

    pub fn with_max_inactive(&mut self, max_inactive: usize) -> &mut Self {
        self.max_inactive = max_inactive;

        // Truncate inactive shards pool to its max allowed capacity.
        if self.inactive_shards.len() > max_inactive {
            self.inactive_shards.resize(max_inactive, String::new());
        }

        self
    }

    pub fn add_shards<T: ToString>(&mut self, shards: impl IntoIterator<Item = T>) {
        let shards = shards.into_iter()
            .map(|address| address.to_string());

        // Ensure that there are no duplicates.
        for address in shards {
            if self.inactive_shards.contains(&address) {
                self.inactive_shards.push_front(address);
            }
        }

        // Truncate inactive shards pool to its max allowed capacity.
        if self.inactive_shards.len() > self.max_inactive {
            self.inactive_shards.resize(self.max_inactive, String::new());
        }
    }

    #[inline]
    pub fn active(&self) -> impl Iterator<Item = &'_ String> {
        self.active_shards.iter()
    }

    #[inline]
    pub fn inactive(&self) -> impl Iterator<Item = &'_ String> {
        self.inactive_shards.iter()
    }

    #[inline(always)]
    pub fn max_active(&self) -> usize {
        self.max_active
    }

    #[inline(always)]
    pub fn max_inactive(&self) -> usize {
        self.max_inactive
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
