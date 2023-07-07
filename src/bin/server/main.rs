use std::net::SocketAddr;

mod app;
mod attestations;
mod db;
mod env;
mod state;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let db_pool = db::get_db_pool().await;
    sqlx::migrate!().run(&db_pool).await.unwrap();
    let app = app::get_router_with_db_pool(db_pool);
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    tracing::info!("Listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
