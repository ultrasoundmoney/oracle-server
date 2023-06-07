use crate::db::DbPool;

pub struct AppState {
    pub db_pool: DbPool,
}
