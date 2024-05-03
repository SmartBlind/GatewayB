use serde::{Deserialize, Serialize};

use crate::models::Table;

#[derive(Serialize, Deserialize, Clone, sqlx::FromRow)]
pub struct User {
    pub id: i32,
    pub group_id: i32,
    pub email: String,
    pub password: String,
}

pub struct UserTable;

impl Table for UserTable {
    fn create(&self) -> String {
        String::from(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id INTEGER NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                FOREIGN KEY (group_id) REFERENCES groups (id)
            );
            "#
        )
    }

    fn dispose(&self) -> String {
        String::from("DROP TABLE users;")
    }
}
