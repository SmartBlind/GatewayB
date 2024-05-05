use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::models::Table;

#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub struct SensorData {
    pub id: i32,
    pub light: i32,
    pub temperature: f32,
    pub time: DateTime<Utc>,
}

pub struct SensorDataTable;

impl Table for SensorDataTable {
    fn create(&self) -> String {
        String::from(
            r#"
            CREATE TABLE IF NOT EXISTS sensor_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sensor_id INTEGER NOT NULL,
                light INTEGER NOT NULL,
                temperature REAL NOT NULL,
                time DATETIME NOT NULL,
                FOREIGN KEY (sensor_id) REFERENCES sensors (id) ON DELETE CASCADE
            );
            "#
        )
    }

    fn dispose(&self) -> String {
        String::from("DROP TABLE IF EXISTS sensor_data;")
    }
}
