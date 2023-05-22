use crate::state::AppState;
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Serialize, Deserialize, Debug)]
pub struct PriceValueEntry {
    pub validator_public_key: String,
    pub value: i64,
    pub slot_number: i64,
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
