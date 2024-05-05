use serde::{Deserialize, Serialize};

use crate::models::Table;

#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub struct Setting {
    pub id: i32,
    pub user_id: i32,
    pub light: i32,
    pub temperature: f32,
}

pub struct SettingTable;

impl Table for SettingTable {
    fn create(&self) -> String {
        String::from(
            r#"
            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                light INTEGER NOT NULL,
                temperature REAL NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            );
            "#
        )
    }

    fn dispose(&self) -> String {
        String::from("DROP TABLE IF EXISTS settings;")
    }
}
