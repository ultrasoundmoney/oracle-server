use crate::state::AppState;
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use bls::{Hash256, PublicKey, Signature};
use std::sync::Arc;
use ssz_derive::{Decode, Encode};
use sha3::{Digest, Sha3_256};
use sqlx::SqlitePool;

#[derive(Serialize, Deserialize, Debug)]
pub struct PriceValueEntry {
    pub validator_public_key: String,
    pub value: i64,
    pub slot_number: i64,
    pub signature: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PriceIntervalEntry {
    pub validator_public_key: String,
    pub value: i64,
    pub slot_number: i64,
    pub signature: String,
    pub interval_size: i64,
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
    let entries: Vec<PriceValueEntry> = sqlx::query!(
        "
        SELECT
            validator_public_key,
            value,
            slot_number,
            signature
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
        slot_number: row.slot_number,
        signature: row.signature,
    })
    .collect();
    Json(entries)
}

pub async fn get_price_interval_attestations(State(state): State<Arc<AppState>>) -> Json<Vec<PriceIntervalEntry>> {
    let db_pool = &state.db_pool;
    let entries: Vec<PriceIntervalEntry> = sqlx::query!(
        "
        SELECT
            validator_public_key,
            value,
            slot_number,
            signature,
            interval_size
        FROM
            price_interval_attestations;
        "
    )
    .fetch_all(db_pool)
    .await
    .unwrap()
    .into_iter()
    .map(|row| PriceIntervalEntry {
        validator_public_key: row.validator_public_key,
        value: row.value,
        slot_number: row.slot_number,
        signature: row.signature,
        interval_size: row.interval_size,
    })
    .collect();
    Json(entries)
}


pub async fn post_oracle_message(State(state): State<Arc<AppState>>, Json(message): Json<OracleMessage>) -> Result<(), axum::http::StatusCode> {
    tracing::info!("Received oracle message: {:?}", message);
    let db_pool = &state.db_pool;
    let validator_public_key = message.validator_public_key;
    save_price_value_attestation(db_pool, &message.value_message, &validator_public_key).await.map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;
    save_price_interval_attestations(db_pool, &message.interval_inclusion_messages, &validator_public_key).await.map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;
    Ok(())
}

async fn save_price_value_attestation(db_pool: &SqlitePool, message: &SignedPriceValueMessage, validator_public_key: &PublicKey) -> eyre::Result<()>{
    if !validate_message(validator_public_key, &message.message, &message.signature) {
        return Err(eyre::eyre!("Invalid signature"));
    }
    let value = message.message.price.value.to_string();
    let slot_number = message.message.slot_number.to_string();
    let signature = message.signature.to_string();
    let pk_string = validator_public_key.to_string();

    // Save price_value_message in DB
    sqlx::query!(
        "
        INSERT INTO price_value_attestations(
            validator_public_key,
            value,
            slot_number,
            signature
        )
        VALUES (
            ?1,
            ?2,
            ?3,
            ?4
        );
        ",
        pk_string,
        value,
        slot_number,
        signature,
    ).execute(db_pool).await?;
    Ok(())
}

async fn save_price_interval_attestations(db_pool: &SqlitePool, messages: &Vec<SignedIntervalInclusionMessage>, validator_public_key: &PublicKey) -> eyre::Result<()>{
    for message in messages {
        save_price_interval_attestation(db_pool, message, validator_public_key).await?;
    }
    Ok(())
}

async fn save_price_interval_attestation(db_pool: &SqlitePool, message: &SignedIntervalInclusionMessage, validator_public_key: &PublicKey) -> eyre::Result<()> {
    if !validate_message(validator_public_key, &message.message, &message.signature) {
        return Err(eyre::eyre!("Invalid signature"));
    }
    let value = message.message.value.to_string();
    let interval_size = message.message.interval_size.to_string();
    let slot_number = message.message.slot_number.to_string();
    let signature = message.signature.to_string();
    let pk_string = validator_public_key.to_string();

    // Save price_value_message in DB
    sqlx::query!(
        "
        INSERT INTO price_interval_attestations(
            validator_public_key,
            value,
            interval_size,
            slot_number,
            signature
        )
        VALUES (
            ?1,
            ?2,
            ?3,
            ?4,
            ?5
        );
        ",
        pk_string,
        value,
        interval_size,
        slot_number,
        signature,
    ).execute(db_pool).await?;
    Ok(())
}

fn validate_message<T: ssz::Encode>(public_key: &PublicKey, message: &T, signature: &Signature)  -> bool {
    let message_digest = get_message_digest(&message);
    signature.verify(public_key, message_digest)
}

pub fn get_message_digest<T: ssz::Encode>(message: &T) -> Hash256 {
    let message_ssz = message.as_ssz_bytes();
    Hash256::from_slice(&Sha3_256::digest(message_ssz ))
}



