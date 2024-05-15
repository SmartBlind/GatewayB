use std::sync::Arc;

use lumisync_server::configs::schema::SchemaManager;
use lumisync_server::configs::settings::{Auth, Database};
use lumisync_server::configs::storage::Storage;
use lumisync_server::models::group::Group;
use lumisync_server::models::region::Region;
use lumisync_server::models::sensor::Sensor;
use lumisync_server::models::user::User;
use lumisync_server::models::window::Window;
use lumisync_server::services::auth_service::AuthService;
use lumisync_server::services::token_service::TokenService;

pub struct MockApp {
    pub storage: Arc<Storage>,
    pub auth_service: Arc<AuthService>,
    pub token_service: Arc<TokenService>,
}

impl MockApp {
    pub async fn new() -> Self {
        let storage = Arc::new(Storage::new(Database {
            migration_path: None,
            clean_start: true,
            url: String::from("sqlite::memory:"),
        }, SchemaManager::default()).await.unwrap());

        let auth_service = Arc::new(AuthService::new());
        let token_service = Arc::new(TokenService::new(Auth {
            secret: String::from("test"),
            expiration: 1000,
        }));

        Self {
            storage,
            auth_service,
            token_service
        }
    }

    pub async fn create_test_group(&self) -> Group {
        sqlx::query_as::<_, Group>("INSERT INTO groups (name) VALUES ('sample') RETURNING *;")
            .fetch_one(self.storage.get_pool())
            .await
            .unwrap()
    }

    pub async fn create_test_user(&self) -> User {
        sqlx::query_as::<_, User>(
            r#"
            INSERT INTO users (group_id, email, password, role)
                VALUES (
                    1,
                    'test@test.com',
                    '$argon2id$v=19$m=19456,t=2,p=1$zk5JmuovvG7B6vyGGmLxDQ$qoqCpKkqrgoVjeTGa5ewrqFpuPUisTCDnEiPz6Dh/oc',
                    'admin'
                )
                RETURNING *;
            "#
        )
            .fetch_one(self.storage.get_pool())
            .await
            .unwrap()
    }

    pub async fn create_test_region(&self) -> Region {
        let region = sqlx::query_as::<_, Region>(
            r#"
            INSERT INTO regions (group_id, name, light, temperature)
                VALUES (1, 'Test Room', 6, 22.5)
                RETURNING *;
            "#
        )
            .fetch_one(self.storage.get_pool())
            .await
            .unwrap();

        sqlx::query("INSERT INTO users_regions_link (user_id, region_id) VALUES (1, 1);")
            .execute(self.storage.get_pool())
            .await
            .unwrap();

        region
    }

    pub async fn create_test_window(&self) -> Window {
        sqlx::query_as::<_, Window>(
            r#"
            INSERT INTO windows (region_id, name, state)
                VALUES (1, 'Test Window', 0)
                RETURNING *;
            "#
        )
            .fetch_one(self.storage.get_pool())
            .await
            .unwrap()
    }

    pub async fn create_test_sensor(&self) -> Sensor {
        let sensor = sqlx::query_as::<_, Sensor>(
            r#"
            INSERT INTO sensors (region_id, name)
                VALUES (1, 'SENSOR-MOCK')
                RETURNING *;
            "#
        )
            .fetch_one(self.storage.get_pool())
            .await
            .unwrap();

        sqlx::query("INSERT INTO regions_sensors_link (region_id, sensor_id) VALUES (1, 1);")
            .execute(self.storage.get_pool())
            .await
            .unwrap();

        sensor
    }
}