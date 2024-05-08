use serde::{Deserialize, Serialize};

use crate::models::Table;

#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub struct WindowSensor {
    pub id: i32,
    pub window_id: i32,
    pub sensor_id: i32,
}

pub struct WindowSensorTable;

impl Table for WindowSensorTable {
    fn create(&self) -> String {
        String::from(
            r#"
            CREATE TABLE IF NOT EXISTS windows_sensors_link (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                window_id INTEGER NOT NULL,
                sensor_id INTEGER NOT NULL,
                FOREIGN KEY (sensor_id) REFERENCES sensors (id) ON DELETE CASCADE,
                FOREIGN KEY (window_id) REFERENCES windows (id) ON DELETE CASCADE
            );
            "#
        )
    }

    fn dispose(&self) -> String {
        String::from("DROP TABLE IF EXISTS windows_sensors_link;")
    }
}
