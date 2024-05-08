use std::fmt::{Display, Formatter, Result};

use serde::{Deserialize, Serialize};

use crate::models::Table;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Role {
    Admin,
    User,
}

impl From<String> for Role {
    fn from(value: String) -> Self {
        match value.as_str() {
            "admin" => Role::Admin,
            _  => Role::User,
        }
    }
}

impl Display for Role {
    fn fmt(&self, f: &mut Formatter) -> Result {
        match self {
            Role::Admin => write!(f, "admin"),
            Role::User => write!(f, "user"),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, sqlx::FromRow)]
pub struct User {
    pub id: i32,
    pub group_id: i32,
    pub email: String,
    pub password: String,
    pub role: String,
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
                role TEXT NOT NULL,
                FOREIGN KEY (group_id) REFERENCES groups (id) ON DELETE CASCADE
            );
            "#
        )
    }

    fn dispose(&self) -> String {
        String::from("DROP TABLE IF EXISTS users;")
    }
}
