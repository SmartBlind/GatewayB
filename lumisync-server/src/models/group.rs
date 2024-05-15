use serde::{Deserialize, Serialize};

use crate::models::Table;

#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub struct Group {
    pub id: i32,
    pub name: String,
}

#[derive(Clone)]
pub struct GroupTable;

impl Table for GroupTable {
    fn name(&self) -> &'static str {
        "groups"
    }

    fn create(&self) -> String {
        String::from(
            r#"
            CREATE TABLE IF NOT EXISTS groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE
            );
            "#
        )
    }

    fn dispose(&self) -> String {
        String::from("DROP TABLE IF EXISTS groups;")
    }

    fn dependencies(&self) -> Vec<&'static str> {
        vec![]
    }
}
