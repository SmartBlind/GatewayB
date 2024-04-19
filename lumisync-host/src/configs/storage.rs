use std::sync::Arc;

use sqlx::{Error, SqlitePool};

use crate::configs::settings::Settings;

#[derive(Clone)]
pub struct Storage {
    pool: SqlitePool,
}

impl Storage {
    pub async fn new(settings: &Arc<Settings>) -> Result<Self, Error> {
        let pool = SqlitePool::connect(&settings.database.url).await?;

        Ok(Self { pool })
    }

    pub fn get_pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub async fn create_tables(&self) -> Result<(), Error> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE);

            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER UNIQUE NOT NULL,
                temp REAL NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE);

            CREATE TABLE IF NOT EXISTS sensors (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE);

            CREATE TABLE IF NOT EXISTS sensor_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sensor_id TEXT NOT NULL,
                temp REAL NOT NULL,
                time TIMESTAMP NOT NULL,
                FOREIGN KEY (sensor_id) REFERENCES sensors (id) ON DELETE CASCADE);
            "#
        )
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}
