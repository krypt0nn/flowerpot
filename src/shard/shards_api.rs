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

use std::collections::HashSet;

use serde_json::{json, Value as Json};

use axum::Json as AxumJson;
use axum::http::StatusCode;
use axum::extract::State;

use crate::storage::Storage;

use super::*;

pub async fn get_shards<S: Storage>(
    State(state): State<ShardState<S>>
) -> (StatusCode, AxumJson<Json>) {
    #[cfg(feature = "tracing")]
    tracing::trace!("GET /api/v1/shards");

    let guard = state.shards.read().await;

    let shards = guard.active()
        .chain(guard.inactive())
        .cloned()
        .collect::<Vec<_>>();

    (StatusCode::OK, AxumJson(json!(shards)))
}

pub async fn put_shards<S: Storage>(
    State(state): State<ShardState<S>>,
    AxumJson(shards): AxumJson<Json>
) -> (StatusCode, AxumJson<Json>) {
    #[cfg(feature = "tracing")]
    tracing::trace!("PUT /api/v1/shards");

    // Skip processing if this method is disabled by security rules.
    if !state.shard_settings.accept_shards {
        return (StatusCode::OK, AxumJson(Json::Null));
    }

    match serde_json::from_value::<HashSet<String>>(shards) {
        Ok(shards) => {
            state.shards.write().await
                .add_shards(shards);

            (StatusCode::OK, AxumJson(Json::Null))
        }

        Err(err) => {
            #[cfg(feature = "tracing")]
            tracing::warn!(?err, "PUT /api/v1/shards: failed to deserialize shards");

            (StatusCode::NOT_ACCEPTABLE, AxumJson(Json::Null))
        }
    }
}
