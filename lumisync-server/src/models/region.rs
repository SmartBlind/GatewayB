use serde::{Deserialize, Serialize};

use crate::models::Table;

#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub struct Region {
    pub id: i32,
    pub group_id: i32,
    pub name: String,
    // Light is the global lumen in room, average of sensors in region.
    pub light: i32,
    pub temperature: f32,
}

#[derive(Clone)]
pub struct RegionTable;

impl Table for RegionTable {
    fn name(&self) -> &'static str {
        "regions"
    }

    fn create(&self) -> String {
        String::from(
            r#"
            CREATE TABLE IF NOT EXISTS regions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id INTEGER NOT NULL,
                name TEXT NOT NULL UNIQUE,
                light INTEGER NOT NULL,
                temperature REAL NOT NULL,
                FOREIGN KEY (group_id) REFERENCES groups (id) ON DELETE CASCADE
            );
            "#
        )
    }

    fn dispose(&self) -> String {
        String::from("DROP TABLE IF EXISTS regions;")
    }

    fn dependencies(&self) -> Vec<&'static str> {
        vec!["groups"]
    }
}
