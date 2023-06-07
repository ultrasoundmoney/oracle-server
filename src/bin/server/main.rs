use std::net::SocketAddr;
mod app;
mod attestations;
mod db;
mod env;
mod state;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let app = app::get_router().await;
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    tracing::info!("Listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
