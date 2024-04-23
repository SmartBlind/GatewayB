use std::sync::Arc;

use sqlx::{Error, SqlitePool};
use sqlx::sqlite::SqlitePoolOptions;

use crate::configs::settings::Settings;

#[derive(Clone)]
pub struct Storage {
    pool: SqlitePool,
}

impl Storage {
    pub async fn new(settings: &Arc<Settings>) -> Result<Self, Error> {
        let pool = SqlitePoolOptions::new()
            .min_connections(1) // in memory db might drop connection when 0
            .max_connections(10)
            .connect(&settings.database.url)
            .await?;

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

            CREATE TABLE IF NOT EXISTS windows (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                sensor_id TEXT UNIQUE,
                name TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE);

            CREATE TABLE IF NOT EXISTS sensor_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                window_id TEXT NOT NULL,
                temp REAL NOT NULL,
                time TIMESTAMP NOT NULL,
                FOREIGN KEY (window_id) REFERENCES windows (sensor_id) ON DELETE CASCADE);
            "#
        )
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}
