use crate::attestations::{
    get_aggregate_price_interval_attestations, get_price_interval_attestations,
    get_price_value_attestations, post_oracle_message,
    get_price_aggregate,
};
use crate::db::get_db_pool;
use crate::state::AppState;
use axum::{
    routing::{get, post},
    Router,
};
use sqlx::SqlitePool;
use std::sync::Arc;

pub async fn get_app() -> Router {
    let db_pool = get_db_pool().await;
    get_app_with_db_pool(db_pool)
}

fn get_app_with_db_pool(db_pool: SqlitePool) -> Router {
    let shared_state = Arc::new(AppState { db_pool });
    Router::new()
        .route(
            "/aggregate_price_interval_attestations",
            get(get_aggregate_price_interval_attestations),
        )
        .route(
            "/price_value_attestations",
            get(get_price_value_attestations),
        )
        .route(
            "/price_interval_attestations",
            get(get_price_interval_attestations),
        )
        .route("/post_oracle_message", post(post_oracle_message))
        .route(
            "/price_aggregate",
            get(get_price_aggregate),
        )
        .with_state(shared_state)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::attestations::get_message_digest;
    use crate::attestations::{
        AggregatePriceIntervalEntry, OracleMessage, PriceIntervalEntry, PriceValueEntry,
    };
    use axum::{body::Body, http::Request};
    use bls::{AggregateSignature, SecretKey, Signature};
    use tower::ServiceExt;

    async fn get_db_pool() -> SqlitePool {
        let test_db_url = "sqlite::memory:";
        let pool = SqlitePool::connect(test_db_url).await.unwrap();
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("Failed to migrate database");
        pool
    }

    fn get_test_message() -> OracleMessage {
        let test_data_file = std::fs::File::open("./test_data/input/17292025.json").unwrap();
        serde_json::from_reader(test_data_file).unwrap()
    }

    fn sign_oracle_message_with_new_key(
        mut message: OracleMessage,
        private_key: &SecretKey,
    ) -> OracleMessage {
        message.validator_public_key = private_key.public_key();
        message.value_message.signature =
            sign_message(&message.value_message.message, &private_key);
        for interval_message in message.interval_inclusion_messages.iter_mut() {
            interval_message.signature = sign_message(&interval_message.message, &private_key);
        }
        message
    }

    #[tokio::test]
    async fn can_aggregate_multiple_messages() {
        let num_validators = 3;
        let private_keys: Vec<SecretKey> =
            (0..num_validators).map(|_| SecretKey::random()).collect();
        let test_message = get_test_message();
        let messages: Vec<OracleMessage> = private_keys
            .iter()
            .map(|private_key| sign_oracle_message_with_new_key(test_message.clone(), &private_key))
            .collect();

        let pool = get_db_pool().await;
        for message in messages.iter() {
            let post_response = get_app_with_db_pool(pool.clone())
                .oneshot(
                    Request::builder()
                        .uri("/post_oracle_message")
                        .method("POST")
                        .header("Content-Type", "application/json")
                        .body(Body::from(serde_json::to_string(&message).unwrap()))
                        .unwrap(),
                )
                .await
                .expect("Request Failed");
            assert_eq!(post_response.status(), 200);
        }

        let response = get_app_with_db_pool(pool)
            .oneshot(
                Request::builder()
                    .uri("/aggregate_price_interval_attestations")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("Request Failed");
        assert_eq!(response.status(), 200);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let entries: Vec<AggregatePriceIntervalEntry> = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            entries.len(),
            test_message.interval_inclusion_messages.len()
        );

        for (i, entry) in entries.iter().enumerate() {
            assert_eq!(
                entry.slot_number,
                test_message.interval_inclusion_messages[i]
                    .message
                    .slot_number as i64
            );
            let mut aggregate_signature = AggregateSignature::infinity();
            messages.iter().for_each(|message| {
                aggregate_signature.add_assign(&message.interval_inclusion_messages[i].signature)
            });
            assert_eq!(
                entry.aggregate_signature,
                hex::encode(aggregate_signature.serialize())
            );
            assert_eq!(entry.num_validators, num_validators);

            // TODO: Find out how to verify the aggregate signature with aggregate public key
            // let signature = Signature::deserialize(&hex::decode(entry.aggregate_signature.clone()).unwrap())
            //     .expect("Failed to deserialize signature");
            // let public_key = bls::PublicKey::deserialize(&hex::decode(entry.aggregate_public_key.clone()).unwrap())
            //     .expect("Failed to deserialize public key");
            // assert!(
            //     signature.verify(
            //         &public_key,
            //         get_message_digest(&test_message.interval_inclusion_messages[i].message),
            //     )
            // );
        }
    }

    #[tokio::test]
    async fn can_save_first_submitted_message() {
        let pool = get_db_pool().await;
        let test_message = get_test_message();

        let post_response = get_app_with_db_pool(pool.clone())
            .oneshot(
                Request::builder()
                    .uri("/post_oracle_message")
                    .method("POST")
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_string(&test_message).unwrap()))
                    .unwrap(),
            )
            .await
            .expect("Request Failed");
        assert_eq!(post_response.status(), 200);

        let value_response = get_app_with_db_pool(pool.clone())
            .oneshot(
                Request::builder()
                    .uri("/price_value_attestations")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("Request Failed");
        assert_eq!(value_response.status(), 200);
        let body = hyper::body::to_bytes(value_response.into_body())
            .await
            .unwrap();
        let entries: Vec<PriceValueEntry> = serde_json::from_slice(&body).unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].value,
            test_message.value_message.message.price.value as i64
        );
        assert_eq!(
            entries[0].slot_number,
            test_message.value_message.message.slot_number as i64
        );
        assert_eq!(
            entries[0].validator_public_key,
            test_message.validator_public_key.to_string()
        );

        let interval_response = get_app_with_db_pool(pool.clone())
            .oneshot(
                Request::builder()
                    .uri("/price_interval_attestations")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("Request Failed");
        assert_eq!(interval_response.status(), 200);
        let body = hyper::body::to_bytes(interval_response.into_body())
            .await
            .unwrap();
        let entries: Vec<PriceIntervalEntry> = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            entries.len(),
            test_message.interval_inclusion_messages.len()
        );

        for (i, entry) in entries.iter().enumerate() {
            assert_eq!(
                entry.slot_number,
                test_message.interval_inclusion_messages[i]
                    .message
                    .slot_number as i64
            );
            assert_eq!(
                entry.validator_public_key,
                test_message.validator_public_key.to_string()
            );
        }

        let response = get_app_with_db_pool(pool.clone())
            .oneshot(
                Request::builder()
                    .uri("/aggregate_price_interval_attestations")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("Request Failed");
        assert_eq!(response.status(), 200);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let entries: Vec<AggregatePriceIntervalEntry> = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            entries.len(),
            test_message.interval_inclusion_messages.len()
        );

        for (i, entry) in entries.iter().enumerate() {
            assert_eq!(
                entry.slot_number,
                test_message.interval_inclusion_messages[i]
                    .message
                    .slot_number as i64
            );
            assert_eq!(
                entry.aggregate_signature,
                hex::encode(
                    test_message.interval_inclusion_messages[i]
                        .signature
                        .serialize()
                )
            );
            assert_eq!(entry.num_validators, 1);
        }

        let response = get_app_with_db_pool(pool.clone())
            .oneshot(
                Request::builder()
                    .uri("/price_aggregate")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("Request Failed");
        assert_eq!(response.status(), 200);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let data: AggregatePriceIntervalEntry = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            data.slot_number,
            test_message.interval_inclusion_messages[0]
                .message
                .slot_number as i64
        );

        let response = get_app_with_db_pool(pool.clone())
            .oneshot(
                Request::builder()
                    .uri(format!("/price_aggregate?slot_number={}&interval_size={}", test_message.value_message.message.slot_number, test_message.interval_inclusion_messages[0].message.interval_size))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("Request Failed");
        assert_eq!(response.status(), 200);

        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let data: AggregatePriceIntervalEntry = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            data.slot_number,
            test_message.interval_inclusion_messages[0]
                .message
                .slot_number as i64
        );

        let response = get_app_with_db_pool(pool.clone())
            .oneshot(
                Request::builder()
                    .uri(format!("/price_aggregate?slot_number={}", 1))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("Request Failed");
        assert_eq!(response.status(), 500);

        let response = get_app_with_db_pool(pool.clone())
            .oneshot(
                Request::builder()
                    .uri(format!("/price_aggregate?interval_size={}", 1))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("Request Failed");
        assert_eq!(response.status(), 500);

    }

    #[tokio::test]
    async fn rejects_invalid_signature_on_value_message() {
        let pool = get_db_pool().await;
        let mut test_message = get_test_message();

        test_message.value_message.signature =
            signature_from_random_signer(&test_message.value_message.message);

        let post_response = get_app_with_db_pool(pool.clone())
            .oneshot(
                Request::builder()
                    .uri("/post_oracle_message")
                    .method("POST")
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_string(&test_message).unwrap()))
                    .unwrap(),
            )
            .await
            .expect("Request Failed");
        assert_eq!(post_response.status(), 400);

        let value_response = get_app_with_db_pool(pool.clone())
            .oneshot(
                Request::builder()
                    .uri("/price_value_attestations")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("Request Failed");
        assert_eq!(value_response.status(), 200);
        let body = hyper::body::to_bytes(value_response.into_body())
            .await
            .unwrap();
        let entries: Vec<PriceValueEntry> = serde_json::from_slice(&body).unwrap();
        assert_eq!(entries.len(), 0);

        let interval_response = get_app_with_db_pool(pool)
            .oneshot(
                Request::builder()
                    .uri("/price_interval_attestations")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("Request Failed");
        assert_eq!(interval_response.status(), 200);
        let body = hyper::body::to_bytes(interval_response.into_body())
            .await
            .unwrap();
        let entries: Vec<PriceIntervalEntry> = serde_json::from_slice(&body).unwrap();
        // Will not save any interval messages even though they are valid
        // TODO: Review if this is intended behaviour
        assert_eq!(entries.len(), 0);
    }

    #[tokio::test]
    async fn rejects_invalid_signature_on_interval_message() {
        let pool = get_db_pool().await;
        let mut test_message = get_test_message();

        let message_index_to_alter = 42;
        test_message.interval_inclusion_messages[message_index_to_alter].signature =
            signature_from_random_signer(&test_message.value_message.message);

        let post_response = get_app_with_db_pool(pool.clone())
            .oneshot(
                Request::builder()
                    .uri("/post_oracle_message")
                    .method("POST")
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_string(&test_message).unwrap()))
                    .unwrap(),
            )
            .await
            .expect("Request Failed");
        assert_eq!(post_response.status(), 400);

        let value_response = get_app_with_db_pool(pool.clone())
            .oneshot(
                Request::builder()
                    .uri("/price_value_attestations")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("Request Failed");
        assert_eq!(value_response.status(), 200);
        let body = hyper::body::to_bytes(value_response.into_body())
            .await
            .unwrap();
        let entries: Vec<PriceValueEntry> = serde_json::from_slice(&body).unwrap();
        // Note that it will still save the the value message, but not the interval message
        // TODO: Review if this is intended behaviour
        assert_eq!(entries.len(), 1);

        let interval_response = get_app_with_db_pool(pool)
            .oneshot(
                Request::builder()
                    .uri("/price_interval_attestations")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("Request Failed");
        assert_eq!(interval_response.status(), 200);
        let body = hyper::body::to_bytes(interval_response.into_body())
            .await
            .unwrap();
        let entries: Vec<PriceIntervalEntry> = serde_json::from_slice(&body).unwrap();
        // Saves all messages up to the invalid one
        // TODO: Review if this is intended behaviour
        assert_eq!(entries.len(), 42);
    }

    fn signature_from_random_signer<T: ssz::Encode>(message: &T) -> Signature {
        let private_key = SecretKey::random();
        sign_message(message, &private_key)
    }

    fn sign_message<T: ssz::Encode>(message: &T, private_key: &SecretKey) -> Signature {
        let message_digest = get_message_digest(message);
        private_key.sign(message_digest)
    }
}
