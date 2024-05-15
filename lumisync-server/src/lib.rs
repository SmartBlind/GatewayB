use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::{middleware, Router};
use axum::routing::{get, post};
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;

use crate::configs::settings::Settings;
use crate::configs::storage::Storage;
use crate::handles::control_handle::{ControlState, execute_command};
use crate::handles::sensor_handle::{get_sensor_data, get_sensor_data_in_range, get_sensors, SensorState};
use crate::handles::setting_handle::{save_setting, SettingState};
use crate::handles::user_handle::{authenticate_user, authorize_user, create_user, UserState};
use crate::handles::window_handle::{create_window, delete_window, get_window_owners, get_windows, update_window, WindowState};
use crate::middlewares::auth_middleware::{auth, TokenState};
use crate::services::actuator_service::ActuatorService;
use crate::services::auth_service::AuthService;
use crate::services::sensor_service::SensorService;
use crate::services::token_service::TokenService;

pub mod configs;
pub mod handles;
pub mod middlewares;
pub mod models;
pub mod services;

pub async fn run(settings: &Arc<Settings>) {
    let app = create_app(settings).await;

    let ip_addr = settings.server.host.parse::<IpAddr>().unwrap();

    let address = SocketAddr::from((ip_addr, settings.server.port));

    let listener = TcpListener::bind(&address).await.unwrap();

    tracing::info!("listening on {:?}", address);

    axum::serve(listener, app).await.unwrap();
}

async fn create_app(settings: &Arc<Settings>) -> Router {
    let storage = Arc::new(Storage::new(settings.database.clone()).await.unwrap());
    storage.create_tables().await.unwrap();

    let sensor_service = Arc::new(SensorService::new(settings.gateway.clone(), &storage).await.unwrap());
    sensor_service.subscribe_all_groups().await.unwrap();

    let actuator_service = ActuatorService::new(settings.embedded.clone()).map(Arc::new).ok();
    let auth_service = Arc::new(AuthService::new());
    let token_service = Arc::new(TokenService::new(settings.auth.clone()));

    let auth_middleware = middleware::from_fn_with_state(
        TokenState {
            token_service: token_service.clone(),
            storage: storage.clone(),
        },
        auth
    );

    let user = Router::new()
        .route("/register", post(create_user))
        .route("/authorize", get(authorize_user).route_layer(auth_middleware))
        .route("/authenticate", post(authenticate_user))
        .with_state(UserState {
            auth_service: auth_service.clone(),
            token_service: token_service.clone(),
            storage: storage.clone(),
        });

    let settings = Router::new()
        .route("/", post(save_setting))
        .with_state(SettingState {
            storage: storage.clone(),
        });

    let windows = Router::new()
        .route("/", get(get_windows).post(create_window))
        .route("/:window_id", get(get_window_owners).put(update_window).delete(delete_window))
        .with_state(WindowState {
            actuator_service: actuator_service.clone(),
            storage: storage.clone(),
        });

    let sensors = Router::new()
        .route("/", get(get_sensors))
        .route("/data/:sensor_id", get(get_sensor_data_in_range))
        .route("/data/sse/:sensor_id", get(get_sensor_data))
        .with_state(SensorState {
            storage: storage.clone(),
        });

    // for debug
    let control = Router::new()
        .route("/:command", get(execute_command))
        .with_state(ControlState {
            actuator_service: actuator_service.clone(),
        });

    Router::new()
        .nest("/control", control)
        .nest("/users", user)
        .nest("/settings", settings)
        .nest("/windows", windows)
        .nest("/sensors", sensors)
        .layer(CorsLayer::permissive())
}
