use sqlx::SqlitePool;

pub struct AppState {
    pub db_pool: SqlitePool,
}
