use crate::db::DbPool;
use crate::state::AppState;
use axum::{
    extract::{Query, State},
    Json,
};
use bls::{AggregatePublicKey, AggregateSignature, Hash256, PublicKey, Signature};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use ssz_derive::{Decode, Encode};
use std::sync::Arc;

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

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct AggregatePriceIntervalEntry {
    pub value: i64,
    pub slot_number: i64,
    pub aggregate_signature: String,
    pub aggregate_public_key: String,
    pub interval_size: i64,
    pub num_validators: i64,
}

#[derive(Clone, Debug, Encode, Decode, Serialize, Deserialize)]
pub struct Price {
    pub value: u64, // TODO: Check if we need to add further info here such as timestamp
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OracleMessage {
    pub value_message: SignedPriceValueMessage,
    pub interval_inclusion_messages: Vec<SignedIntervalInclusionMessage>,
    pub validator_public_key: PublicKey,
}

#[derive(Clone, Debug, Decode, Encode, Serialize, Deserialize)]
pub struct PriceValueMessage {
    pub price: Price,
    pub slot_number: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedPriceValueMessage {
    pub message: PriceValueMessage,
    pub signature: Signature,
}

#[derive(Clone, Debug, Decode, Encode, Serialize, Deserialize)]
pub struct IntervalInclusionMessage {
    pub value: u64,
    pub interval_size: u64,
    pub slot_number: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedIntervalInclusionMessage {
    pub message: IntervalInclusionMessage,
    pub signature: Signature,
}

pub async fn get_price_value_attestations(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<PriceValueEntry>> {
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
        validator_public_key: row.validator_public_key.into(),
        value: row.value.into(),
        slot_number: row.slot_number.into(),
        signature: row.signature.into(),
    })
    .collect();
    Json(entries)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PriceAggregateQueryParams {
    slot_number: Option<i64>,
    interval_size: Option<i64>,
}

pub async fn get_price_aggregate(
    Query(query): Query<PriceAggregateQueryParams>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<AggregatePriceIntervalEntry>, axum::http::StatusCode> {
    let db_pool = &state.db_pool;
    tracing::debug!("Query: {:?}", query);
    // TODO: Improve error / none handling - remove unwrap
    let slot_number = query.slot_number.unwrap_or(
        get_slot_number(db_pool)
            .await
            .map_err(|e| {
                tracing::error!("Error getting slot number: {:?}", e);
                axum::http::StatusCode::INTERNAL_SERVER_ERROR
            })?
            .unwrap(),
    );

    let interval_size = query.interval_size.unwrap_or(
        get_most_common_interval_size(db_pool, slot_number)
            .await
            .map_err(|e| {
                tracing::error!("Error getting most common interval size: {:?}", e);
                axum::http::StatusCode::INTERNAL_SERVER_ERROR
            })?
            .unwrap(),
    );

    let aggregate_price = get_price_aggregate_for_params(db_pool, slot_number, interval_size)
        .await
        .map_err(|e| {
            tracing::error!("Error getting aggregate price: {:?}", e);
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(aggregate_price))
}

async fn get_most_common_interval_size(
    db_pool: &DbPool,
    slot_number: i64,
) -> eyre::Result<Option<i64>> {
    #[cfg(not(postgres))]
    let slot_number = slot_number.to_string();
    #[cfg(postgres)]
    let slot_number = slot_number as i64;
    let interval_size = sqlx::query!(
        "
        SELECT
            interval_size
        FROM
            aggregate_interval_attestations
        WHERE
            slot_number = $1
        GROUP BY
            interval_size
        ORDER BY
            COUNT(*) DESC
        LIMIT 1;
        ",
        slot_number
    )
    .fetch_one(db_pool)
    .await?
    .interval_size;
    #[cfg(postgres)]
    {
        Ok(Some(interval_size))
    }
    #[cfg(not(postgres))]
    {
        Ok(interval_size)
    }
}

async fn get_slot_number(db_pool: &DbPool) -> eyre::Result<Option<i64>> {
    let slot_number = sqlx::query!(
        "
        SELECT
            slot_number
        FROM
            price_value_attestations
        ORDER BY
            slot_number DESC
        LIMIT 1;
        "
    )
    .fetch_one(db_pool)
    .await?
    .slot_number;
    #[cfg(postgres)]
    {
        Ok(Some(slot_number.into()))
    }
    #[cfg(not(postgres))]
    {
        Ok(slot_number)
    }
}

async fn get_price_aggregate_for_params(
    db_pool: &DbPool,
    slot_number: i64,
    interval_size: i64,
) -> eyre::Result<AggregatePriceIntervalEntry> {
    #[cfg(not(postgres))]
    let (slot_number, interval_size) = (slot_number.to_string(), interval_size.to_string());
    #[cfg(postgres)]
    let (slot_number, interval_size) = (slot_number as i64, interval_size as i64);
    let entries: Vec<AggregatePriceIntervalEntry> = sqlx::query!(
        "
        SELECT
            value,
            slot_number,
            aggregate_signature,
            aggregate_public_key,
            interval_size,
            num_validators
        FROM
            aggregate_interval_attestations 
        WHERE
            slot_number = $1
        AND
            interval_size = $2
        ",
        slot_number,
        interval_size
    )
    .fetch_all(db_pool)
    .await
    .unwrap()
    .into_iter()
    .map(|row| AggregatePriceIntervalEntry {
        value: row.value.into(),
        slot_number: row.slot_number.into(),
        aggregate_signature: row.aggregate_signature.into(),
        aggregate_public_key: row.aggregate_public_key.into(),
        interval_size: row.interval_size.into(),
        num_validators: row.num_validators.into(),
    })
    .collect();
    let max_num_validators = entries
        .iter()
        .map(|entry| entry.num_validators)
        .max()
        .ok_or(eyre::eyre!("No entries found"))?;
    let entries_with_max_num_validators_ordered_by_value: Vec<AggregatePriceIntervalEntry> =
        entries
            .into_iter()
            .filter(|entry| entry.num_validators == max_num_validators)
            .sorted_by(|a, b| Ord::cmp(&a.value, &b.value))
            .collect();

    let median_index = entries_with_max_num_validators_ordered_by_value.len() / 2;
    let median_entry = entries_with_max_num_validators_ordered_by_value[median_index].clone();
    Ok(median_entry)
}

pub async fn get_aggregate_price_interval_attestations(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<AggregatePriceIntervalEntry>> {
    let db_pool = &state.db_pool;
    let entries: Vec<AggregatePriceIntervalEntry> = sqlx::query!(
        "
        SELECT
            value,
            slot_number,
            aggregate_signature,
            aggregate_public_key,
            interval_size,
            num_validators
        FROM
            aggregate_interval_attestations 
        "
    )
    .fetch_all(db_pool)
    .await
    .unwrap()
    .into_iter()
    .map(|row| AggregatePriceIntervalEntry {
        value: row.value.into(),
        slot_number: row.slot_number.into(),
        aggregate_signature: row.aggregate_signature.into(),
        aggregate_public_key: row.aggregate_public_key.into(),
        interval_size: row.interval_size.into(),
        num_validators: row.num_validators.into(),
    })
    .collect();
    Json(entries)
}

pub async fn get_price_interval_attestations(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<PriceIntervalEntry>> {
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
        validator_public_key: row.validator_public_key.into(),
        value: row.value.into(),
        slot_number: row.slot_number.into(),
        signature: row.signature.into(),
        interval_size: row.interval_size.into(),
    })
    .collect();
    Json(entries)
}

pub async fn post_oracle_message(
    State(state): State<Arc<AppState>>,
    Json(message): Json<OracleMessage>,
) -> Result<(), axum::http::StatusCode> {
    tracing::info!("Received oracle message: {:?}", message);
    let db_pool = &state.db_pool;
    let validator_public_key = message.validator_public_key;
    // TODO: Improve error handling instead of returning "BAD REQUEST" for any kind of error
    save_price_value_attestation(db_pool, &message.value_message, &validator_public_key)
        .await
        .map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;
    save_price_interval_attestations(
        db_pool,
        &message.interval_inclusion_messages,
        &validator_public_key,
    )
    .await
    .map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;
    Ok(())
}

async fn save_price_value_attestation(
    db_pool: &DbPool,
    message: &SignedPriceValueMessage,
    validator_public_key: &PublicKey,
) -> eyre::Result<()> {
    if !validate_message(validator_public_key, &message.message, &message.signature) {
        return Err(eyre::eyre!("Invalid signature"));
    }
    let value = message.message.price.value;
    let slot_number = message.message.slot_number;
    let signature = &message.signature.to_string();
    let pk_string = validator_public_key.to_string();

    #[cfg(not(postgres))]
    let (value, slot_number) = (value.to_string(), slot_number.to_string());
    #[cfg(postgres)]
    let (value, slot_number) = (value as i64, slot_number as i64);

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
            $1,
            $2,
            $3,
            $4
        );
        ",
        pk_string,
        value,
        slot_number,
        signature,
    )
    .execute(db_pool)
    .await?;
    Ok(())
}

async fn save_price_interval_attestations(
    db_pool: &DbPool,
    messages: &Vec<SignedIntervalInclusionMessage>,
    validator_public_key: &PublicKey,
) -> eyre::Result<()> {
    for message in messages {
        save_price_interval_attestation(db_pool, message, validator_public_key).await?;
    }
    Ok(())
}

async fn save_price_interval_attestation(
    db_pool: &DbPool,
    message: &SignedIntervalInclusionMessage,
    validator_public_key: &PublicKey,
) -> eyre::Result<()> {
    if !validate_message(validator_public_key, &message.message, &message.signature) {
        return Err(eyre::eyre!("Invalid signature"));
    }
    let value = message.message.value;
    let interval_size = message.message.interval_size;
    let slot_number = message.message.slot_number;
    let signature = &message.signature.to_string();
    let pk_string = validator_public_key.to_string();
    #[cfg(not(postgres))]
    let (value, interval_size, slot_number) = (
        value.to_string(),
        interval_size.to_string(),
        slot_number.to_string(),
    );
    #[cfg(postgres)]
    let (value, interval_size, slot_number) =
        (value as i64, interval_size as i64, slot_number as i64);

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
            $1,
            $2,
            $3,
            $4,
            $5
        );
        ",
        pk_string,
        value,
        interval_size,
        slot_number,
        signature,
    )
    .execute(db_pool)
    .await?;

    // TODO: Review if we really want to aggregate every time we receive a new message
    extend_or_create_aggregate_interval_attestation(db_pool, message, validator_public_key).await?;
    Ok(())
}

async fn extend_or_create_aggregate_interval_attestation(
    db_pool: &DbPool,
    message: &SignedIntervalInclusionMessage,
    validator_public_key: &PublicKey,
) -> eyre::Result<()> {
    let interval_size = message.message.interval_size;
    let slot_number = message.message.slot_number;
    let value = message.message.value;
    #[cfg(not(postgres))]
    let (interval_size, slot_number, value) = (
        interval_size.to_string(),
        slot_number.to_string(),
        value.to_string(),
    );
    #[cfg(postgres)]
    let (interval_size, slot_number, value) =
        (interval_size as i64, slot_number as i64, value as i64);
    let (new_num_validators, mut aggregate_signature, aggregate_public_key) = if let Some(entry) =
        sqlx::query!(
            "
        SELECT
            num_validators,
            aggregate_signature,
            aggregate_public_key
        FROM
            aggregate_interval_attestations
        WHERE
            interval_size = $1
        AND
            slot_number = $2
        AND
            value = $3;
        ",
            interval_size,
            slot_number,
            value,
        )
        .fetch_optional(db_pool)
        .await?
    {
        (
            entry.num_validators + 1,
            AggregateSignature::deserialize(&hex::decode(entry.aggregate_signature)?)
                .map_err(|_| eyre::eyre!("Invalid aggregate signature in DB"))?,
            AggregatePublicKey::aggregate(&[
                PublicKey::deserialize(&hex::decode(entry.aggregate_public_key)?)
                    .map_err(|_| eyre::eyre!("Invalid aggregate public key in DB"))?,
                validator_public_key.clone(),
            ])
            .map_err(|_| eyre::eyre!("Invalid aggregate public key in DB"))?,
        )
    } else {
        (
            1,
            AggregateSignature::infinity(),
            AggregatePublicKey::aggregate(&[validator_public_key.clone()])
                .map_err(|_| eyre::eyre!("Invalid aggregate public key"))?,
        )
    };

    aggregate_signature.add_assign(&message.signature);
    let new_aggregate_signature = hex::encode(aggregate_signature.serialize());
    let new_aggregate_public_key = hex::encode(aggregate_public_key.to_public_key().serialize());

    if new_num_validators == 1 {
        // Create new db entry
        sqlx::query!(
            "
            INSERT INTO aggregate_interval_attestations(
                value,
                interval_size,
                slot_number,
                num_validators,
                aggregate_signature,
                aggregate_public_key
            )
            VALUES (
                $1,
                $2,
                $3,
                $4,
                $5,
                $6
            );
            ",
            value,
            interval_size,
            slot_number,
            new_num_validators,
            new_aggregate_signature,
            new_aggregate_public_key,
        )
        .execute(db_pool)
        .await?;
    } else {
        // Update existing db entry
        sqlx::query!(
            "
            UPDATE aggregate_interval_attestations
            SET
                num_validators = $1,
                aggregate_signature = $2
            WHERE
                interval_size = $3
            AND
                slot_number = $4
            AND
                value = $5;
            ",
            new_num_validators,
            new_aggregate_signature,
            interval_size,
            slot_number,
            value,
        )
        .execute(db_pool)
        .await?;
    }

    Ok(())
}

fn validate_message<T: ssz::Encode>(
    public_key: &PublicKey,
    message: &T,
    signature: &Signature,
) -> bool {
    let message_digest = get_message_digest(&message);
    signature.verify(public_key, message_digest)
}

pub fn get_message_digest<T: ssz::Encode>(message: &T) -> Hash256 {
    let message_ssz = message.as_ssz_bytes();
    Hash256::from_slice(&Sha3_256::digest(message_ssz))
}
