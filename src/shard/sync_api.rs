// SPDX-License-Identifier: GPL-3.0-only
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

use serde_json::{json, Value as Json};

use axum::Json as AxumJson;
use axum::http::StatusCode;
use axum::extract::{State, Query};

use crate::storage::Storage;

use super::*;

const MAX_SYNC_BLOCKS: usize = 10;

/// `GET /api/v1/sync` request params.
#[derive(serde::Deserialize)]
pub struct GetSyncParams {
    pub after: Option<String>,
    pub max_blocks: Option<usize>,
}

pub async fn get_sync<S: Storage>(
    State(state): State<ShardState<S>>,
    Query(params): Query<GetSyncParams>
) -> (StatusCode, AxumJson<Json>) {
    #[cfg(feature = "tracing")]
    tracing::trace!("GET /api/v1/sync");

    let guard = state.storage.lock().await;

    let block = match params.after {
        Some(hash) => {
            let Some(hash) = Hash::from_base64(&hash) else {
                #[cfg(feature = "tracing")]
                tracing::warn!(?hash, "GET /api/v1/sync: failed to decode hash");

                return (StatusCode::NOT_ACCEPTABLE, AxumJson(Json::Null));
            };

            if let Ok(None) = guard.read_block(&hash) {
                return (StatusCode::NOT_FOUND, AxumJson(Json::Null));
            }

            match guard.next_block(&hash) {
                Ok(Some(next_block)) => guard.read_block(&next_block),
                Ok(None) => Ok(None),
                Err(err) => {
                    #[cfg(feature = "tracing")]
                    tracing::error!(
                        ?hash,
                        ?err,
                        "GET /api/v1/sync: failed to read block next to the requested one"
                    );

                    return (StatusCode::INTERNAL_SERVER_ERROR, AxumJson(Json::Null));
                }
            }
        }

        None => match guard.root_block() {
            Ok(Some(root_block)) => guard.read_block(&root_block),

            // No root block => blockchain is empty => nothing to sync.
            Ok(None) => return (StatusCode::OK, AxumJson(json!([]))),

            Err(err) => {
                #[cfg(feature = "tracing")]
                tracing::error!(?err, "GET /api/v1/sync: failed to get root block hash");

                return (StatusCode::INTERNAL_SERVER_ERROR, AxumJson(Json::Null));
            }
        }
    };

    let mut block = match block {
        Ok(Some(block)) => block,

        Ok(None) => return (StatusCode::OK, AxumJson(json!([]))),

        Err(err) => {
            #[cfg(feature = "tracing")]
            tracing::error!(?err, "GET /api/v1/sync: failed to read block from the local storage");

            return (StatusCode::INTERNAL_SERVER_ERROR, AxumJson(Json::Null));
        }
    };

    let return_blocks = match params.max_blocks {
        Some(max_blocks) => MAX_SYNC_BLOCKS.min(max_blocks),
        None => MAX_SYNC_BLOCKS
    };

    let mut sync_blocks = Vec::with_capacity(return_blocks);

    for _ in 0..return_blocks {
        let hash = match block.hash() {
            Ok(hash) => hash,
            Err(err) => {
                #[cfg(feature = "tracing")]
                tracing::error!(?err, "GET /api/v1/sync: failed to calculate hash of a block");

                return (StatusCode::INTERNAL_SERVER_ERROR, AxumJson(Json::Null));
            }
        };

        match block.to_json() {
            Ok(block) => sync_blocks.push(block),
            Err(err) => {
                #[cfg(feature = "tracing")]
                tracing::error!(
                    hash = hash.to_base64(),
                    ?err,
                    "GET /api/v1/sync: failed to serialize block to json"
                );
            }
        }

        let next_block = match guard.next_block(&hash) {
            Ok(Some(next_block)) => next_block,
            Ok(None) => break,
            Err(err) => {
                #[cfg(feature = "tracing")]
                tracing::error!(
                    ?hash,
                    ?err,
                    "GET /api/v1/sync: failed to read next block from the local storage"
                );

                return (StatusCode::INTERNAL_SERVER_ERROR, AxumJson(Json::Null));
            }
        };

        match guard.read_block(&next_block) {
            Ok(Some(next_block)) => block = next_block,
            Ok(None) => break,
            Err(err) => {
                #[cfg(feature = "tracing")]
                tracing::error!(
                    hash = hash.to_base64(),
                    next_block = next_block.to_base64(),
                    ?err,
                    "GET /api/v1/sync: failed to read next block from the storage"
                );

                return (StatusCode::INTERNAL_SERVER_ERROR, AxumJson(Json::Null));
            }
        }
    }

    (StatusCode::OK, AxumJson(json!(sync_blocks)))
}
