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
                tracing::warn!(
                    hash = transaction.hash().to_base64(),
                    sign = transaction.sign().to_base64(),
                    size = transaction.data.len(),
                    "PUT /api/v1/transactions: rejecting transaction because it's too large"
                );

                return (StatusCode::NOT_ACCEPTABLE, AxumJson(Json::Null));
            }

            if state.events_sender.send(ShardEvent::TryPutTransaction(transaction)).is_err() {
                #[cfg(feature = "tracing")]
                tracing::error!("PUT /api/v1/transactions: events handler is down");

                return (StatusCode::INTERNAL_SERVER_ERROR, AxumJson(Json::Null));
            }

            (StatusCode::OK, AxumJson(Json::Null))
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
