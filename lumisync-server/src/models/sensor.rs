use serde::{Deserialize, Serialize};

use crate::models::Table;

#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub struct Sensor {
    pub id: i32,
    pub group_id: i32,
    pub name: String,
}

pub struct SensorTable;

impl Table for SensorTable {
    fn create(&self) -> String {
        String::from(
            r#"
            CREATE TABLE IF NOT EXISTS sensors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id INTEGER NOT NULL,
                name TEXT,
                FOREIGN KEY (group_id) REFERENCES groups (id) ON DELETE CASCADE
            );
            "#
        )
    }

    fn dispose(&self) -> String {
        String::from("DROP TABLE IF EXISTS sensors;")
    }
}
