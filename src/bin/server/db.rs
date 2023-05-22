use crate::env;
use sqlx::SqlitePool;

fn get_db_url() -> String {
    env::get_env_var_unsafe("DATABASE_URL")
}

pub async fn get_db_pool() -> SqlitePool {
    let db_url = get_db_url();
    SqlitePool::connect(&db_url)
        .await
        .expect("expect DB to be available to connect")
}
