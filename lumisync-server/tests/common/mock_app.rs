use std::sync::Arc;

use lumisync_server::configs::settings::{Auth, Database};
use lumisync_server::configs::storage::Storage;
use lumisync_server::models::group::Group;
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
            migrate: None,
            clean: false,
            url: String::from("sqlite::memory:"),
        }).await.unwrap());
        storage.create_tables().await.unwrap();

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
        sqlx::query_as::<_, Group>("INSERT INTO groups (name) VALUES ('sample') RETURNING *")
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

    pub async fn create_test_window(&self) -> Window {
        let window = sqlx::query_as::<_, Window>(
            r#"
            INSERT INTO windows (group_id, name, state)
                VALUES (1, 'Test Room', 0)
                RETURNING *;
            "#
        )
            .fetch_one(self.storage.get_pool())
            .await
            .unwrap();

        sqlx::query("INSERT INTO users_windows_link (user_id, window_id) VALUES (1, 1)")
            .execute(self.storage.get_pool())
            .await
            .unwrap();

        window
    }

    pub async fn create_test_sensor(&self) -> Sensor {
        let sensor = sqlx::query_as::<_, Sensor>(
            r#"
            INSERT INTO sensors (group_id, name)
                VALUES (1, 'SENSOR-MOCK')
                RETURNING *;
            "#
        )
            .fetch_one(self.storage.get_pool())
            .await
            .unwrap();

        sqlx::query("INSERT INTO windows_sensors_link (window_id, sensor_id) VALUES (1, 1);")
            .execute(self.storage.get_pool())
            .await
            .unwrap();

        sensor
    }
}