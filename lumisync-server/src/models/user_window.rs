use serde::{Deserialize, Serialize};
use crate::models::Table;

#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub struct UserWindow {
    pub id: i32,
    pub user_id: i32,
    pub window_id: i32,
}

pub struct UserWindowTable;

impl Table for UserWindowTable {
    fn create(&self) -> String {
        String::from(
            r#"
            CREATE TABLE IF NOT EXISTS users_windows_link (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                window_id INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (window_id) REFERENCES windows (id) ON DELETE CASCADE
            );
            "#
        )
    }

    fn dispose(&self) -> String {
        String::from("DROP TABLE IF EXISTS users_windows_link;")
    }
}
