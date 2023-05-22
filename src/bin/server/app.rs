use crate::attestations::{get_price_interval_attestations, get_price_value_attestations, post_oracle_message};
use crate::db::get_db_pool;
use crate::state::AppState;
use axum::{routing::{get, post}, Router};
use sqlx::SqlitePool;
use std::sync::Arc;

pub async fn get_app() -> Router {
    let db_pool = get_db_pool().await;
    get_app_with_db_pool(db_pool)
}

fn get_app_with_db_pool(db_pool: SqlitePool) -> Router {
    let shared_state = Arc::new(AppState { db_pool });
    Router::new()
        .route("/price_value_attestations", get(get_price_value_attestations))
        .route("/price_interval_attestations", get(get_price_interval_attestations))
        .route("/post_oracle_message", post(post_oracle_message))
        .with_state(shared_state)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::attestations::PriceValueEntry;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_get_contracts_against_dev_db() {
        let app = get_app().await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/price_value_attestations")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("Request Failed");
        assert_eq!(response.status(), 200);
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let contracts: Vec<PriceValueEntry> = serde_json::from_slice(&body).unwrap();
        assert_eq!(contracts.len(), 100);

        for contract in contracts {
            assert!(contract.validator_public_key.len() > 0);
            assert!(contract.value > 0);
        }
    }
}
