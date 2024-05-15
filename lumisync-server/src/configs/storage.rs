use std::path::Path;

use sqlx::{Error, SqlitePool};
use sqlx::migrate::Migrator;
use sqlx::sqlite::SqlitePoolOptions;

use crate::configs::schema::SchemaManager;
use crate::configs::settings::Database;

#[derive(Clone)]
pub struct Storage {
    pool: SqlitePool,
}

impl Storage {
    pub async fn new(database: Database, schema_manager: SchemaManager) -> Result<Self, Error> {
        let pool = SqlitePoolOptions::new()
            .min_connections(1) // in memory db might drop connection when 0
            .max_connections(10)
            .connect(&database.url)
            .await?;

        Self::create_schema(&pool, &schema_manager, &database).await?;

        Ok(Self { pool })
    }

    pub fn get_pool(&self) -> &SqlitePool {
        &self.pool
    }

    async fn create_schema(pool: &SqlitePool, schema: &SchemaManager, database: &Database) -> Result<(), Error> {
        if database.clean_start {
            let dispose_statements = schema.dispose_schema();
            let create_statements = schema.create_schema();
            let statements = [&dispose_statements[..], &create_statements[..]].concat();

            // Clean migration history
            sqlx::query("DROP TABLE IF EXISTS _sqlx_migrations")
                .execute(pool)
                .await?;

            // Recreate all schema
            sqlx::query(&statements.join("\n"))
                .execute(pool)
                .await?;

            tracing::warn!("perform a clean boot: clean and recreate schema");
        }

        if let Some(migration_path) = database.migration_path.clone() {
            let mut pool_connection = pool.acquire().await?;
            let migrator = Migrator::new(Path::new(&migration_path)).await?;
            migrator.run(&mut pool_connection).await?;

            tracing::info!("database migration success");
        }

        Ok(())
    }
}
