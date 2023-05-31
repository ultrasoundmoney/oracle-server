use crate::env;

pub fn get_db_url() -> String {
    env::get_env_var_unsafe("DATABASE_URL")
}

pub type DbPool = sqlx::PgPool;

pub async fn get_db_pool() -> DbPool {
    let db_url = get_db_url();
        sqlx::PgPool::connect(&db_url)
            .await
            .expect("expect Postgres DB to be available to connect")
}
