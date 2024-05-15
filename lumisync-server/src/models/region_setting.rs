use serde::{Deserialize, Serialize};

use crate::models::Table;

#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub struct RegionSetting {
    pub id: i32,
    pub region_id: i32,
    pub setting_id: i32,
}

#[derive(Clone)]
pub struct RegionSettingTable;

impl Table for RegionSettingTable {
    fn name(&self) -> &'static str {
        "regions_settings"
    }

    fn create(&self) -> String {
        String::from(
            r#"
            CREATE TABLE IF NOT EXISTS regions_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                region_id INTEGER NOT NULL,
                setting_id INTEGER NOT NULL,
                FOREIGN KEY (region_id) REFERENCES regions (id) ON DELETE CASCADE,
                FOREIGN KEY (setting_id) REFERENCES settings (id) ON DELETE CASCADE
            );
            "#
        )
    }

    fn dispose(&self) -> String {
        String::from("DROP TABLE IF EXISTS regions_settings;")
    }

    fn dependencies(&self) -> Vec<&'static str> {
        vec!["regions", "settings"]
    }
}