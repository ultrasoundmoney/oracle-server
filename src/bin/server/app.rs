use crate::attestations::{
    get_aggregate_price_interval_attestations, get_price_aggregate,
    get_price_interval_attestations, get_price_value_attestations, post_oracle_message,
};
use crate::db::{get_db_pool, DbPool};
use crate::state::AppState;
use axum::{
    routing::{get, post},
    Router,
};
use std::sync::Arc;

pub async fn get_app() -> Router {
    let db_pool = get_db_pool().await;
    get_app_with_db_pool(db_pool)
}

fn get_app_with_db_pool(db_pool: DbPool) -> Router {
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
        .route("/price_aggregate", get(get_price_aggregate))
        .with_state(shared_state)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::attestations::get_message_digest;
    use crate::attestations::{
        AggregatePriceIntervalEntry, OracleMessage, PriceIntervalEntry, PriceValueEntry,
    };
    use crate::db::get_db_url;
    use axum::{body::Body, http::Request};
    use bls::{AggregateSignature, SecretKey, Signature};
    use bytes::Bytes;
    use itertools::Itertools;
    use tower::ServiceExt;

    async fn get_db_pool() -> DbPool {
        let test_db_url = get_db_url();
        let pool = DbPool::connect(&test_db_url).await.unwrap();
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("Failed to migrate database");
        pool
    }

    enum TestRequest {
        Get(),
        Post(Body),
    }
    struct TestApp {
        db_pool: DbPool,
    }

    impl TestApp {
        pub async fn new(db_pool: DbPool) -> Self {
            TestApp { db_pool }
        }

        pub async fn get(&self, uri: &str, expected_code: u16) -> Bytes {
            self.send_request(TestRequest::Get(), uri, expected_code)
                .await
        }

        pub async fn post(&self, uri: &str, body: Body, expected_code: u16) -> Bytes {
            self.send_request(TestRequest::Post(body), uri, expected_code)
                .await
        }

        async fn send_request(&self, request: TestRequest, uri: &str, expected_code: u16) -> Bytes {
            let app = get_app_with_db_pool(self.db_pool.clone());
            let req = match request {
                TestRequest::Get() => Request::builder()
                    .uri(uri)
                    .method("GET")
                    .body(Body::empty())
                    .unwrap(),
                TestRequest::Post(body) => Request::builder()
                    .uri(uri)
                    .method("POST")
                    .header("Content-Type", "application/json")
                    .body(body)
                    .unwrap(),
            };

            let response = app.oneshot(req).await.unwrap();
            assert_eq!(response.status().as_u16(), expected_code);
            let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
            body
        }
    }

    fn get_test_message() -> OracleMessage {
        let test_data_file = std::fs::File::open("./test_data/input/6556020.json").unwrap();
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

    #[sqlx::test]
    async fn can_aggregate_multiple_messages(db_pool: DbPool) {
        let num_validators = 1;
        let private_keys: Vec<SecretKey> =
            (0..num_validators).map(|_| SecretKey::random()).collect();
        let test_message = get_test_message();
        let messages: Vec<OracleMessage> = private_keys
            .iter()
            .map(|private_key| sign_oracle_message_with_new_key(test_message.clone(), &private_key))
            .collect();

        let test_app = TestApp::new(db_pool).await;
        for message in messages.iter() {
            test_app
                .post(
                    "/post_oracle_message",
                    Body::from(serde_json::to_string(&message).unwrap()),
                    200,
                )
                .await;
        }

        let response = test_app
            .get("/aggregate_price_interval_attestations", 200)
            .await;
        let entries: Vec<AggregatePriceIntervalEntry> = serde_json::from_slice(&response).unwrap();
        assert_eq!(
            entries.len(),
            test_message.interval_inclusion_messages.len()
        );

        for (i, entry) in entries
            .iter()
            .sorted_by(|a, b| a.value.cmp(&b.value))
            .enumerate()
        {
            assert_eq!(
                entry.value,
                test_message.interval_inclusion_messages[i].message.value as i64
            );
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

    #[sqlx::test]
    async fn can_save_first_submitted_message(db_pool: DbPool) {
        let test_message = get_test_message();
        let test_app = TestApp::new(db_pool).await;

        let response = test_app.get("/price_interval_attestations", 200).await;
        let entries: Vec<PriceIntervalEntry> = serde_json::from_slice(&response).unwrap();
        assert_eq!(entries.len(), 0);

        let body = Body::from(serde_json::to_string(&test_message).unwrap());
        test_app.post("/post_oracle_message", body, 200).await;

        let response = test_app.get("/price_value_attestations", 200).await;
        let entries: Vec<PriceValueEntry> = serde_json::from_slice(&response).unwrap();

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

        let response = test_app.get("/price_interval_attestations", 200).await;
        let entries: Vec<PriceIntervalEntry> = serde_json::from_slice(&response).unwrap();
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

        let response = test_app
            .get("/aggregate_price_interval_attestations", 200)
            .await;
        let entries: Vec<AggregatePriceIntervalEntry> = serde_json::from_slice(&response).unwrap();
        assert_eq!(
            entries.len(),
            test_message.interval_inclusion_messages.len()
        );

        for (i, entry) in entries
            .iter()
            .sorted_by(|a, b| a.value.cmp(&b.value))
            .enumerate()
        {
            assert_eq!(
                entry.value,
                test_message.interval_inclusion_messages[i].message.value as i64
            );
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

        let response = test_app.get("/price_aggregate", 200).await;
        let data: AggregatePriceIntervalEntry = serde_json::from_slice(&response).unwrap();
        assert_eq!(
            data.slot_number,
            test_message.interval_inclusion_messages[0]
                .message
                .slot_number as i64
        );

        let response = test_app
            .get(
                &format!(
                    "/price_aggregate?slot_number={}&interval_size={}",
                    test_message.value_message.message.slot_number,
                    test_message.interval_inclusion_messages[0]
                        .message
                        .interval_size
                ),
                200,
            )
            .await;

        let data: AggregatePriceIntervalEntry = serde_json::from_slice(&response).unwrap();
        assert_eq!(
            data.slot_number,
            test_message.interval_inclusion_messages[0]
                .message
                .slot_number as i64
        );

        assert_eq!(
            data.value,
            test_message.value_message.message.price.value as i64 / 10000
        );

        test_app
            .get(&format!("/price_aggregate?slot_number={}", 1), 500)
            .await;
        test_app
            .get(&format!("/price_aggregate?interval_size={}", 1), 500)
            .await;
    }

    #[sqlx::test]
    async fn rejects_invalid_signature_on_value_message(db_pool: DbPool) {
        let mut test_message = get_test_message();
        let test_app = TestApp::new(db_pool).await;

        test_message.value_message.signature =
            signature_from_random_signer(&test_message.value_message.message);

        let body = Body::from(serde_json::to_string(&test_message).unwrap());
        test_app.post("/post_oracle_message", body, 400).await;

        let body = test_app.get("/price_value_attestations", 200).await;
        let entries: Vec<PriceValueEntry> = serde_json::from_slice(&body).unwrap();
        assert_eq!(entries.len(), 0);

        let body = test_app.get("/price_interval_attestations", 200).await;
        let entries: Vec<PriceIntervalEntry> = serde_json::from_slice(&body).unwrap();
        // Will not save any interval messages even though they are valid
        // TODO: Review if this is intended behaviour
        assert_eq!(entries.len(), 0);
    }

    #[sqlx::test]
    async fn rejects_invalid_signature_on_interval_message(db_pool: DbPool) {
        let mut test_message = get_test_message();
        let test_app = TestApp::new(db_pool).await;

        let message_index_to_alter = 42;
        test_message.interval_inclusion_messages[message_index_to_alter].signature =
            signature_from_random_signer(&test_message.value_message.message);

        let body = Body::from(serde_json::to_string(&test_message).unwrap());
        test_app.post("/post_oracle_message", body, 400).await;

        let value_response = test_app.get("/price_value_attestations", 200).await;
        let entries: Vec<PriceValueEntry> = serde_json::from_slice(&value_response).unwrap();
        // Note that it will still save the the value message, but not the interval message
        // TODO: Review if this is intended behaviour
        assert_eq!(entries.len(), 1);

        let interval_response = test_app.get("/price_interval_attestations", 200).await;
        let entries: Vec<PriceIntervalEntry> = serde_json::from_slice(&interval_response).unwrap();
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
