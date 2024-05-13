use serde::{Deserialize, Serialize};

use crate::models::Table;

#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub struct Window {
    pub id: i32,
    pub region_id: i32,
    pub name: String,
    /// State in a range of [-1, 1].
    /// when 0 means off;
    /// when -1 means rotate anti-clockwise to end;
    /// when 1 means clockwise to end;
    pub state: f32,
}

pub struct WindowTable;

impl Table for WindowTable {
    fn create(&self) -> String {
        String::from(
            r#"
            CREATE TABLE IF NOT EXISTS windows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                region_id INTEGER NOT NULL,
                name TEXT NOT NULL UNIQUE,
                state REAL NOT NULL,
                FOREIGN KEY (region_id) REFERENCES regions (id) ON DELETE CASCADE
            );
            "#
        )
    }

    fn dispose(&self) -> String {
        String::from("DROP TABLE IF EXISTS windows;")
    }
}
