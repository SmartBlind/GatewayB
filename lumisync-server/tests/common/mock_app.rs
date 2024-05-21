use std::sync::Arc;

use axum::{Extension, middleware, Router};
use axum::routing::{get, post, put};

use lumisync_server::configs::schema::SchemaManager;
use lumisync_server::configs::settings::{Auth, Database};
use lumisync_server::configs::storage::Storage;
use lumisync_server::handles::region_handle::{create_region, get_regions, RegionState};
use lumisync_server::handles::sensor_handle::{create_sensor, get_sensors, get_sensors_by_region, SensorState};
use lumisync_server::handles::setting_handle::{create_setting, get_settings, get_settings_by_region, SettingState};
use lumisync_server::handles::user_handle::{authenticate_user, authorize_user, create_user, UserState};
use lumisync_server::handles::window_handle::{create_window, delete_window, get_windows, get_windows_by_region, update_window, WindowState};
use lumisync_server::middlewares::auth_middleware::{auth, TokenState};
use lumisync_server::models::group::Group;
use lumisync_server::models::region::Region;
use lumisync_server::models::sensor::Sensor;
use lumisync_server::models::setting::Setting;
use lumisync_server::models::user::User;
use lumisync_server::models::window::Window;
use lumisync_server::services::auth_service::AuthService;
use lumisync_server::services::token_service::{TokenClaims, TokenService};

pub struct MockApp {
    pub router: Router,
    pub admin: User,
    pub token: String,
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

        let user = User {
            id: 1,
            group_id: 1,
            email: String::from("test@test.com"),
            password: String::from("test"),
            role: String::from("admin"),
        };

        let token_data = token_service.generate_token(user.to_owned()).unwrap();

        Self {
            router: Default::default(),
            admin: user,
            token: token_data.token,
            storage,
            auth_service,
            token_service
        }
    }

    pub async fn with_auth_middleware(mut self) -> Self {
        self.router = self.router
            .merge(
                Router::new()
                    .route("/check", get(
                        |Extension(token_data): Extension<TokenClaims>| async move {
                            format!("{:?}", token_data)
                        }),
                    )
                    .route_layer(middleware::from_fn_with_state(TokenState {
                        token_service: self.token_service.clone(),
                        storage: self.storage.clone(),
                    }, auth))
            );

        self
    }

    pub async fn with_user_handle(mut self) -> Self {
        self.router = self.router
            .merge(
                Router::new()
                    .route("/register", post(create_user))
                    .route("/authenticate", post(authenticate_user))
                    .route(
                        "/authorize",
                        get(authorize_user)
                            .route_layer(middleware::from_fn_with_state(TokenState {
                                token_service: self.token_service.clone(),
                                storage: self.storage.clone(),
                            }, auth))
                    )
                    .with_state(UserState {
                        auth_service: self.auth_service.clone(),
                        token_service: self.token_service.clone(),
                        storage: self.storage.clone(),
                    })
            );

        self
    }

    pub async fn with_region_handle(mut self) -> Self {
        self.router = self.router
            .merge(
                Router::new()
                    .route("/region", get(get_regions).post(create_region))
                    .route_layer(middleware::from_fn_with_state(TokenState {
                        token_service: self.token_service.clone(),
                        storage: self.storage.clone(),
                    }, auth))
                    .with_state(RegionState {
                        storage: self.storage.clone(),
                    })
            );

        self
    }

    pub async fn with_window_handle(mut self) -> Self {
        self.router = self.router
            .merge(
                Router::new()
                    .route("/window", get(get_windows).post(create_window))
                    .route("/window/:window_id", put(update_window).delete(delete_window))
                    .route("/window/region/:region_id", get(get_windows_by_region))
                    .route_layer(middleware::from_fn_with_state(TokenState {
                        token_service: self.token_service.clone(),
                        storage: self.storage.clone(),
                    }, auth))
                    .with_state(WindowState {
                        actuator_service: None,
                        storage: self.storage.clone(),
                    })
            );

        self
    }

    pub async fn with_sensor_handle(mut self) -> Self {
        self.router = self.router
            .merge(
                Router::new()
                    .route("/sensor", get(get_sensors).post(create_sensor))
                    .route("/sensor/region/:region_id", get(get_sensors_by_region))
                    .route_layer(middleware::from_fn_with_state(TokenState {
                        token_service: self.token_service.clone(),
                        storage: self.storage.clone(),
                    }, auth))
                    .with_state(SensorState {
                        storage: self.storage.clone(),
                    })
            );

        self
    }

    pub async fn with_setting_handle(mut self) -> Self {
        self.router = self.router
            .merge(
                Router::new()
                    .route("/setting", get(get_settings).post(create_setting))
                    .route("/setting/region/:region_id", get(get_settings_by_region))
                    .route_layer(middleware::from_fn_with_state(TokenState {
                        token_service: self.token_service.clone(),
                        storage: self.storage.clone(),
                    }, auth))
                    .with_state(SettingState {
                        storage: self.storage.clone(),
                    })
            );

        self
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

        sensor
    }

    pub async fn create_test_setting(&self) -> Setting {
        let setting = sqlx::query_as::<_, Setting>(
            r#"
            INSERT INTO settings (user_id, light, temperature, start, end, interval)
                VALUES (1, 100, 22.5, DATETIME('now'), DATETIME('now', '+03:30'), 0)
                RETURNING *;
            "#
        )
            .fetch_one(self.storage.get_pool())
            .await
            .unwrap();

        sqlx::query("INSERT INTO regions_settings_link (region_id, setting_id) VALUES (1, 1);")
            .execute(self.storage.get_pool())
            .await
            .unwrap();

        setting
    }
}
