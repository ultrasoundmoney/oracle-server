use crate::attestations::{
    get_aggregate_price_interval_attestations, get_price_interval_attestations,
    get_price_value_attestations, post_oracle_message,
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
    use bls::{SecretKey, Signature};
    use tower::ServiceExt;

    #[tokio::test]
    async fn can_save_first_submitted_message() {
        let test_db_url = "sqlite::memory:";
        let pool = SqlitePool::connect(test_db_url).await.unwrap();
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("Failed to migrate database");

        let test_data_file = std::fs::File::open("./test_data/input/17292025.json").unwrap();
        let test_message: OracleMessage = serde_json::from_reader(test_data_file).unwrap();

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
    }

    #[tokio::test]
    async fn rejects_invalid_signature_on_value_message() {
        let test_db_url = "sqlite::memory:";
        let pool = SqlitePool::connect(test_db_url).await.unwrap();
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("Failed to migrate database");

        let test_data_file = std::fs::File::open("./test_data/input/17292025.json").unwrap();
        let mut test_message: OracleMessage = serde_json::from_reader(test_data_file).unwrap();

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
        let test_db_url = "sqlite::memory:";
        let pool = SqlitePool::connect(test_db_url).await.unwrap();
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("Failed to migrate database");

        let test_data_file = std::fs::File::open("./test_data/input/17292025.json").unwrap();
        let mut test_message: OracleMessage = serde_json::from_reader(test_data_file).unwrap();

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
        let message_digest = get_message_digest(message);
        private_key.sign(message_digest)
    }
}
