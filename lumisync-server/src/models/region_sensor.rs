use serde::{Deserialize, Serialize};

use crate::models::Table;

#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub struct RegionSensor {
    pub id: i32,
    pub region_id: i32,
    pub sensor_id: i32,
}

pub struct RegionSensorTable;

impl Table for RegionSensorTable {
    fn create(&self) -> String {
        String::from(
            r#"
            CREATE TABLE IF NOT EXISTS regions_sensors_link (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                region_id INTEGER NOT NULL,
                sensor_id INTEGER NOT NULL,
                FOREIGN KEY (region_id) REFERENCES regions (id) ON DELETE CASCADE,
                FOREIGN KEY (sensor_id) REFERENCES sensors (id) ON DELETE CASCADE
            );
            "#
        )
    }

    fn dispose(&self) -> String {
        String::from("DROP TABLE IF EXISTS regions_sensors_link;")
    }
}
