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
