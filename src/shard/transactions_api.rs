use serde_json::{json, Value as Json};

use axum::Json as AxumJson;
use axum::http::StatusCode;
use axum::extract::{State, Path};

use crate::transaction::Transaction;
use crate::storage::Storage;

use super::*;

pub async fn get_transactions<S: Storage>(
    State(state): State<ShardState<S>>
) -> (StatusCode, AxumJson<Json>) {
    #[cfg(feature = "tracing")]
    tracing::trace!("GET /api/v1/transactions");

    let transactions = state.pending_transactions.read().await
        .keys()
        .map(|hash| Hash::from(*hash).to_base64())
        .collect::<Vec<String>>();

    (StatusCode::OK, AxumJson(json!(transactions)))
}

pub async fn put_transactions<S: Storage>(
    State(state): State<ShardState<S>>,
    AxumJson(transaction): AxumJson<Json>
) -> (StatusCode, AxumJson<Json>) {
    #[cfg(feature = "tracing")]
    tracing::trace!("PUT /api/v1/transactions");

    match Transaction::from_json(&transaction) {
        Ok(transaction) => {
            if transaction.data.len() as u64 > state.security_rules.max_transaction_body_size {
                #[cfg(feature = "tracing")]
                tracing::debug!(
                    sign = transaction.sign().to_base64(),
                    hash = transaction.hash().to_base64(),
                    size = transaction.data.len(),
                    "PUT /api/v1/transactions: rejecting transaction because it's too large"
                );

                return (StatusCode::PAYLOAD_TOO_LARGE, AxumJson(Json::Null));
            }

            match transaction.verify() {
                Ok((true, public_key)) => {
                    #[cfg(feature = "tracing")]
                    tracing::debug!(
                        public_key = public_key.to_base64(),
                        sign = transaction.sign().to_base64(),
                        hash = transaction.hash().to_base64(),
                        "PUT /api/v1/transactions: add pending transaction"
                    );

                    let mut guard = state.pending_transactions.write().await;

                    // Share this transaction with other shards if it is newly added
                    // and security rules allow it.
                    let hash = transaction.hash();

                    if guard.insert(hash.0, transaction).is_none() &&
                        state.security_rules.spread_pending_transactions
                    {
                        let _ = state.events_sender.send(ShardEvent::SharePendingTransaction(hash));
                    }

                    (StatusCode::OK, AxumJson(Json::Null))
                }

                Ok((false, public_key)) => {
                    #[cfg(feature = "tracing")]
                    tracing::warn!(
                        public_key = public_key.to_base64(),
                        sign = transaction.sign().to_base64(),
                        hash = transaction.hash().to_base64(),
                        "PUT /api/v1/transactions: attempted to put invalid transaction"
                    );

                    (StatusCode::NOT_ACCEPTABLE, AxumJson(Json::Null))
                }

                Err(err) => {
                    #[cfg(feature = "tracing")]
                    tracing::error!(?err, "PUT /api/v1/transactions: failed to verify transaction");

                    (StatusCode::INTERNAL_SERVER_ERROR, AxumJson(Json::Null))
                }
            }
        }

        Err(err) => {
            #[cfg(feature = "tracing")]
            tracing::warn!(?err, "PUT /api/v1/transactions: failed to deserialize transaction");

            (StatusCode::NOT_ACCEPTABLE, AxumJson(Json::Null))
        }
    }
}

pub async fn get_transactions_hash<S: Storage>(
    State(state): State<ShardState<S>>,
    Path(hash): Path<String>
) -> (StatusCode, AxumJson<Json>) {
    #[cfg(feature = "tracing")]
    tracing::trace!(?hash, "GET /api/v1/transactions/<hash>");

    let Some(hash) = Hash::from_base64(&hash) else {
        #[cfg(feature = "tracing")]
        tracing::warn!(?hash, "GET /api/v1/transactions/<hash>: failed to decode hash");

        return (StatusCode::NOT_ACCEPTABLE, AxumJson(Json::Null));
    };

    // TODO: support reading transactions from blockchain?

    let guard = state.pending_transactions.read().await;

    match guard.get(&hash.0) {
        Some(transaction) => {
            match transaction.to_json() {
                Ok(transaction) => (StatusCode::OK, AxumJson(transaction)),
                Err(err) => {
                    #[cfg(feature = "tracing")]
                    tracing::error!(?err, "GET /api/v1/transactions/<hash>: failed to serialize transaction");

                    (StatusCode::INTERNAL_SERVER_ERROR, AxumJson(Json::Null))
                }
            }
        }

        None => (StatusCode::NOT_FOUND, AxumJson(Json::Null))
    }
}
