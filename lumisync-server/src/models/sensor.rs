use serde::{Deserialize, Serialize};

use crate::models::Table;

#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub struct Sensor {
    pub id: i32,
    pub region_id: i32,
    pub name: String,
}

#[derive(Clone)]
pub struct SensorTable;

impl Table for SensorTable {
    fn name(&self) -> &'static str {
        "sensors"
    }

    fn create(&self) -> String {
        String::from(
            r#"
            CREATE TABLE IF NOT EXISTS sensors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                region_id INTEGER NOT NULL,
                name TEXT NOT NULL UNIQUE,
                FOREIGN KEY (region_id) REFERENCES regions (id) ON DELETE CASCADE
            );
            "#
        )
    }

    fn dispose(&self) -> String {
        String::from("DROP TABLE IF EXISTS sensors;")
    }

    fn dependencies(&self) -> Vec<&'static str> {
        vec!["regions"]
    }
}
