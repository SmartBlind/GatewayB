use std::error::Error;
use std::sync::Arc;

use sqlx::SqlitePool;

use crate::configs::settings::Settings;

pub struct Storage {
    pool: SqlitePool,
}

impl Storage {
    pub async fn new(settings: &Arc<Settings>) -> Result<Self, Box<dyn Error>> {
        let pool = SqlitePool::connect(&settings.database.url).await?;

        Ok(Self { pool })
    }

    pub fn get_pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub async fn create_sensor_data_table(&self) -> Result<(), Box<dyn Error>> {
        sqlx::query("CREATE TABLE IF NOT EXISTS sensor_data (id INTEGER PRIMARY KEY, payload TEXT NOT NULL, time TIMESTAMP NOT NULL)")
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}