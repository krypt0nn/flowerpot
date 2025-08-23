use serde_json::{json, Value as Json};

use axum::Json as AxumJson;
use axum::http::StatusCode;
use axum::body::Body;
use axum::extract::{State, Request, Path};

use crate::block::Block;
use crate::storage::Storage;

use super::*;

pub async fn get_blocks<S: Storage>(
    State(state): State<ShardState<S>>
) -> (StatusCode, AxumJson<Json>) {
    #[cfg(feature = "tracing")]
    tracing::trace!("GET /api/v1/blocks");

    let blocks = state.pending_blocks.read().await
        .keys()
        .map(|hash| Hash::from(*hash).to_base64())
        .collect::<Vec<String>>();

    (StatusCode::OK, AxumJson(json!(blocks)))
}

pub async fn put_blocks<S: Storage>(
    State(state): State<ShardState<S>>,
    AxumJson(block): AxumJson<Json>
) -> (StatusCode, AxumJson<Json>) {
    #[cfg(feature = "tracing")]
    tracing::trace!("PUT /api/v1/blocks");

    match Block::from_json(&block) {
        Ok(mut block) => {
            match block.verify() {
                Ok((true, hash, public_key)) => {
                    let validators = state.storage.lock().await
                        .get_current_validators();

                    // TODO: do not accept pending blocks if current last block
                    //       is not the previous block of this pending block?

                    match validators {
                        Ok(validators) => {
                            if !validators.contains(&public_key) {
                                #[cfg(feature = "tracing")]
                                tracing::error!("PUT /api/v1/blocks: attempted to put a block with invalid signer");

                                return (StatusCode::NOT_ACCEPTABLE, AxumJson(Json::Null));
                            }

                            // Keep only valid approvals before storing a pending block.
                            let mut valid_approvals = Vec::with_capacity(block.approvals.len());

                            for approval in block.approvals.drain(..) {
                                match approval.verify(hash) {
                                    Ok((true, verifier)) => {
                                        if !validators.contains(&verifier) {
                                            #[cfg(feature = "tracing")]
                                            tracing::error!("PUT /api/v1/blocks: sent block contains approval signature from invalid validator");
                                        } else {
                                            valid_approvals.push(approval);
                                        }
                                    }

                                    Ok((false, _)) => {
                                        #[cfg(feature = "tracing")]
                                        tracing::warn!("PUT /api/v1/blocks: sent block contains invalid approval signature");
                                    }

                                    Err(err) => {
                                        #[cfg(feature = "tracing")]
                                        tracing::error!(?err, "PUT /api/v1/blocks: failed to verify approval signature");

                                        return (StatusCode::INTERNAL_SERVER_ERROR, AxumJson(Json::Null));
                                    }
                                }
                            }

                            block.approvals = valid_approvals;

                            // Store the pending block.

                            #[cfg(feature = "tracing")]
                            tracing::debug!(
                                public_key = public_key.to_base64(),
                                sign = block.sign().to_base64(),
                                hash = hash.to_base64(),
                                "PUT /api/v1/blocks: add pending block"
                            );

                            let mut guard = state.pending_blocks.write().await;

                            // Share this block with other shards if it is newly added
                            // and security rules allow it.
                            if guard.insert(hash.0, block).is_none() &&
                                state.security_rules.spread_pending_blocks
                            {
                                let _ = state.events_sender.send(ShardEvent::SharePendingBlock(hash));
                            }

                            (StatusCode::OK, AxumJson(Json::Null))
                        }

                        Err(err) => {
                            #[cfg(feature = "tracing")]
                            tracing::error!(?err, "PUT /api/v1/blocks: failed to read current validators");

                            (StatusCode::INTERNAL_SERVER_ERROR, AxumJson(Json::Null))
                        }
                    }
                }

                Ok((false, hash, public_key)) => {
                    #[cfg(feature = "tracing")]
                    tracing::warn!(
                        public_key = public_key.to_base64(),
                        sign = block.sign().to_base64(),
                        hash = hash.to_base64(),
                        "PUT /api/v1/blocks: attempted to put invalid block"
                    );

                    (StatusCode::NOT_ACCEPTABLE, AxumJson(Json::Null))
                }

                Err(err) => {
                    #[cfg(feature = "tracing")]
                    tracing::error!(?err, "PUT /api/v1/blocks: failed to verify block");

                    (StatusCode::INTERNAL_SERVER_ERROR, AxumJson(Json::Null))
                }
            }
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

    match block {
        Some(block) => {
            match block.to_json() {
                Ok(block) => (StatusCode::OK, AxumJson(block)),
                Err(err) => {
                    #[cfg(feature = "tracing")]
                    tracing::error!(?err, "GET /api/v1/blocks/<hash>: failed to serialize block");

                    (StatusCode::INTERNAL_SERVER_ERROR, AxumJson(Json::Null))
                }
            }
        }

        None => (StatusCode::NOT_FOUND, AxumJson(Json::Null))
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

            let Some(sign) = Signature::from_base64(body.trim_end()) else {
                #[cfg(feature = "tracing")]
                tracing::warn!(?hash, "PUT /api/v1/blocks/<hash>: failed to decode signature");

                return (StatusCode::NOT_ACCEPTABLE, AxumJson(Json::Null));
            };

            match sign.verify(hash) {
                Ok((true, public_key)) => {
                    let validators = state.storage.lock().await
                        .get_current_validators();

                    match validators {
                        Ok(validators) => {
                            if !validators.contains(&public_key) {
                                #[cfg(feature = "tracing")]
                                tracing::error!("PUT /api/v1/blocks/<hash>: attempted to put approval signature with invalid signer");

                                return (StatusCode::NOT_ACCEPTABLE, AxumJson(Json::Null));
                            }

                            let mut guard = state.pending_blocks.write().await;

                            match guard.get_mut(&hash.0) {
                                Some(block) => {
                                    match block.verify() {
                                        Ok((valid, hash, block_author)) => {
                                            if !valid {
                                                #[cfg(feature = "tracing")]
                                                tracing::warn!("PUT /api/v1/blocks/<hash>: asked block is invalid");

                                                guard.remove(&hash.0);
                                            }

                                            else if !block.approvals.contains(&sign) && public_key != block_author {
                                                block.approvals.push(sign.clone());

                                                // Share this approval with other shards if it is
                                                // newly added and security rules allow it.
                                                if state.security_rules.spread_pending_blocks_approvals {
                                                    let _ = state.events_sender.send(ShardEvent::SharePendingBlockApproval(hash, sign));
                                                }
                                            }

                                            (StatusCode::OK, AxumJson(Json::Null))
                                        }

                                        Err(err) => {
                                            #[cfg(feature = "tracing")]
                                            tracing::error!(?err, "PUT /api/v1/blocks/<hash>: failed to read the block's signer");

                                            (StatusCode::INTERNAL_SERVER_ERROR, AxumJson(Json::Null))
                                        }
                                    }
                                }

                                None => {
                                    #[cfg(feature = "tracing")]
                                    tracing::debug!(
                                        hash = hash.to_base64(),
                                        "PUT /api/v1/blocks/<hash>: block with that hash is not pending"
                                    );

                                    (StatusCode::NOT_FOUND, AxumJson(Json::Null))
                                }
                            }
                        }

                        Err(err) => {
                            #[cfg(feature = "tracing")]
                            tracing::error!(?err, "PUT /api/v1/blocks/<hash>: failed to read current validators");

                            (StatusCode::INTERNAL_SERVER_ERROR, AxumJson(Json::Null))
                        }
                    }
                }

                Ok((false, _)) => {
                    #[cfg(feature = "tracing")]
                    tracing::error!("PUT /api/v1/blocks/<hash>: attempted to put invalid approval signature");

                    (StatusCode::NOT_ACCEPTABLE, AxumJson(Json::Null))
                }

                Err(err) => {
                    #[cfg(feature = "tracing")]
                    tracing::error!(?err, "PUT /api/v1/blocks/<hash>: failed to verify approval signature");

                    (StatusCode::INTERNAL_SERVER_ERROR, AxumJson(Json::Null))
                }
            }
        }

        Err(err) => {
            #[cfg(feature = "tracing")]
            tracing::error!(?err, "PUT /api/v1/blocks/<hash>: failed to read request body");

            (StatusCode::INTERNAL_SERVER_ERROR, AxumJson(Json::Null))
        }
    }
}
