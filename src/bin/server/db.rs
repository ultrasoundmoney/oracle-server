use crate::env;

fn get_db_url() -> String {
    env::get_env_var_unsafe("DATABASE_URL")
}

#[cfg(not(postgres))]
pub type DbPool = sqlx::SqlitePool;
#[cfg(postgres)]
pub type DbPool = sqlx::PgPool;

pub async fn get_db_pool() -> DbPool {
    let db_url = get_db_url();
    #[cfg(not(postgres))]
    {
        sqlx::SqlitePool::connect(&db_url)
            .await
            .expect("expect Sqlite DB to be available to connect")
    }
    #[cfg(postgres)]
    {
        sqlx::PgPool::connect(&db_url)
            .await
            .expect("expect Postgres DB to be available to connect")
    }
}
