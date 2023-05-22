use crate::state::AppState;
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use bls::{PublicKey, Signature};
use std::sync::Arc;
use ssz_derive::{Decode, Encode};

#[derive(Serialize, Deserialize, Debug)]
pub struct PriceValueEntry {
    pub validator_public_key: String,
    pub value: i64,
    pub slot_number: i64,
}

#[derive(Clone, Debug, Encode, Decode, Serialize, Deserialize)]
pub struct Price {
    pub value: u64, // TODO: Check if we need to add further info here such as timestamp
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OracleMessage {
    pub value_message: SignedPriceValueMessage,
    pub interval_inclusion_messages: Vec<SignedIntervalInclusionMessage>,
    pub validator_public_key: PublicKey,
}

#[derive(Debug, Decode, Encode, Serialize, Deserialize)]
pub struct PriceValueMessage {
    pub price: Price,
    pub slot_number: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignedPriceValueMessage {
    pub message: PriceValueMessage,
    pub signature: Signature,
}

#[derive(Debug, Decode, Encode, Serialize, Deserialize)]
pub struct IntervalInclusionMessage {
    pub value: u64,
    pub interval_size: u64,
    pub slot_number: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignedIntervalInclusionMessage {
    pub message: IntervalInclusionMessage,
    pub signature: Signature,
}

pub async fn get_price_value_attestations(State(state): State<Arc<AppState>>) -> Json<Vec<PriceValueEntry>> {
    let db_pool = &state.db_pool;
    let contracts: Vec<PriceValueEntry> = sqlx::query!(
        "
        SELECT
            validator_public_key,
            value,
            slot_number
        FROM
            price_value_attestations;
        "
    )
    .fetch_all(db_pool)
    .await
    .unwrap()
    .into_iter()
    .map(|row| PriceValueEntry {
        validator_public_key: row.validator_public_key,
        value: row.value,
        slot_number: row.slot_number
    })
    .collect();
    Json(contracts)
}

pub async fn post_oracle_message(State(state): State<Arc<AppState>>, Json(message): Json<OracleMessage>) {
    tracing::info!("Received oracle message: {:?}", message);
}
