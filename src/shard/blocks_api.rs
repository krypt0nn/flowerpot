use serde_json::{json, Value as Json};

use axum::Json as AxumJson;
use axum::http::StatusCode;
use axum::body::Body;
use axum::extract::{State, Request, Path};

use crate::block::*;
use crate::storage::Storage;

use super::*;

pub async fn get_blocks<S: Storage>(
    State(state): State<ShardState<S>>
) -> (StatusCode, AxumJson<Json>) {
    #[cfg(feature = "tracing")]
    tracing::trace!("GET /api/v1/blocks");

    let blocks = state.pending_blocks.read().await
        .iter()
        .map(|(hash, block)| json!({
            "block": {
                "current": Hash::from(*hash).to_base64(),
                "previous": block.previous().to_base64()
            },
            "sign": block.sign().to_base64(),
            "approvals": block.approvals()
                .iter()
                .map(|approval| approval.to_base64())
                .collect::<Vec<String>>()
        }))
        .collect::<Vec<Json>>();

    (StatusCode::OK, AxumJson(json!(blocks)))
}

pub async fn put_blocks<S: Storage>(
    State(state): State<ShardState<S>>,
    AxumJson(block): AxumJson<Json>
) -> (StatusCode, AxumJson<Json>) {
    #[cfg(feature = "tracing")]
    tracing::trace!("PUT /api/v1/blocks");

    match Block::from_json(&block) {
        Ok(block) => {
            if state.events_sender.send(ShardEvent::TryPutBlock(block)).is_err() {
                #[cfg(feature = "tracing")]
                tracing::error!("PUT /api/v1/blocks: events handler is down");

                return (StatusCode::INTERNAL_SERVER_ERROR, AxumJson(Json::Null));
            }

            (StatusCode::OK, AxumJson(Json::Null))
        }

        Err(err) => {
            #[cfg(feature = "tracing")]
            tracing::warn!(?err, "PUT /api/v1/blocks: failed to deserialize block");

            (StatusCode::NOT_ACCEPTABLE, AxumJson(Json::Null))
        }
    }
}

pub async fn get_blocks_hash<S: Storage>(
    State(state): State<ShardState<S>>,
    Path(hash): Path<String>
) -> (StatusCode, AxumJson<Json>) {
    #[cfg(feature = "tracing")]
    tracing::trace!(?hash, "GET /api/v1/blocks/<hash>");

    let Some(hash) = Hash::from_base64(&hash) else {
        #[cfg(feature = "tracing")]
        tracing::warn!(?hash, "GET /api/v1/blocks/<hash>: failed to decode hash");

        return (StatusCode::NOT_ACCEPTABLE, AxumJson(Json::Null));
    };

    let mut block = state.pending_blocks.read().await
        .get(&hash.0)
        .cloned();

    if block.is_none() {
        match state.storage.lock().await.read_block(&hash) {
            Ok(result) => block = result,
            Err(err) => {
                #[cfg(feature = "tracing")]
                tracing::error!(
                    hash = hash.to_base64(),
                    ?err,
                    "GET /api/v1/blocks/<hash>: failed to read block from the storage"
                );

                return (StatusCode::INTERNAL_SERVER_ERROR, AxumJson(Json::Null));
            }
        }
    }

    let Some(block) = block else {
        return (StatusCode::NOT_FOUND, AxumJson(Json::Null));
    };

    match block.to_json() {
        Ok(block) => (StatusCode::OK, AxumJson(block)),
        Err(err) => {
            #[cfg(feature = "tracing")]
            tracing::error!(?err, "GET /api/v1/blocks/<hash>: failed to serialize block");

            (StatusCode::INTERNAL_SERVER_ERROR, AxumJson(Json::Null))
        }
    }
}

pub async fn put_blocks_hash<S: Storage>(
    State(state): State<ShardState<S>>,
    Path(hash): Path<String>,
    body: Request<Body>
) -> (StatusCode, AxumJson<Json>) {
    #[cfg(feature = "tracing")]
    tracing::trace!(?hash, "PUT /api/v1/blocks/<hash>");

    let Some(hash) = Hash::from_base64(&hash) else {
        #[cfg(feature = "tracing")]
        tracing::warn!(?hash, "PUT /api/v1/blocks/<hash>: failed to decode hash");

        return (StatusCode::NOT_ACCEPTABLE, AxumJson(Json::Null));
    };

    match axum::body::to_bytes(body.into_body(), 128).await {
        Ok(body) => {
            let body = String::from_utf8_lossy(&body);

            let Some(approval) = Signature::from_base64(body.trim_end()) else {
                #[cfg(feature = "tracing")]
                tracing::warn!(?hash, "PUT /api/v1/blocks/<hash>: failed to decode signature");

                return (StatusCode::NOT_ACCEPTABLE, AxumJson(Json::Null));
            };

            if state.events_sender.send(ShardEvent::TryApproveBlock(hash, approval)).is_err() {
                #[cfg(feature = "tracing")]
                tracing::error!("PUT /api/v1/blocks/<hash>: events handler is down");

                return (StatusCode::INTERNAL_SERVER_ERROR, AxumJson(Json::Null));
            }

            (StatusCode::OK, AxumJson(Json::Null))
        }

        Err(err) => {
            #[cfg(feature = "tracing")]
            tracing::error!(?err, "PUT /api/v1/blocks/<hash>: failed to read request body");

            (StatusCode::INTERNAL_SERVER_ERROR, AxumJson(Json::Null))
        }
    }
}
