use std::sync::Arc;

use sqlx::{Error, SqlitePool};
use sqlx::sqlite::SqlitePoolOptions;

use crate::configs::settings::Database;
use crate::models::group::GroupTable;
use crate::models::sensor::SensorTable;
use crate::models::sensor_data::SensorDataTable;
use crate::models::setting::SettingTable;
use crate::models::Table;
use crate::models::user::UserTable;
use crate::models::user_window::UserWindowTable;
use crate::models::window::WindowTable;
use crate::models::window_sensor::WindowSensorTable;

#[derive(Clone)]
pub struct Storage {
    pool: SqlitePool,
    database: Arc<Database>,
}

impl Storage {
    pub async fn new(database: Database) -> Result<Self, Error> {
        let pool = SqlitePoolOptions::new()
            .min_connections(1) // in memory db might drop connection when 0
            .max_connections(10)
            .connect(&database.url)
            .await?;

        Ok(Self {
            pool,
            database: Arc::new(database),
        })
    }

    pub fn get_pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub async fn create_tables(&self) -> Result<(), Error> {
        let mut statements: Vec<String> = Vec::new();
        let tables: Vec<Box<dyn Table>> = vec![
            Box::new(GroupTable),
            Box::new(UserTable),
            Box::new(SettingTable),
            Box::new(WindowTable),
            Box::new(SensorTable),
            Box::new(SensorDataTable),
            // Reference
            Box::new(UserWindowTable),
            Box::new(WindowSensorTable),
        ];

        if self.database.clean {
            for table in tables.iter().rev() {
                statements.push(table.dispose());
            }
        }

        for table in tables {
            statements.push(table.create());
        }

        if let Some(migrate) = self.database.migrate.clone() {
            statements.push(migrate);
        }

        sqlx::query(&statements.join("\n"))
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}
