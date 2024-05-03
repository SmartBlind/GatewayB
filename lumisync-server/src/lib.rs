use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;

use crate::configs::settings::Settings;
use crate::configs::storage::Storage;
use crate::handles::control_handle::{ControlState, execute_command};
use crate::handles::sensor_handle::{get_sensor_data, get_sensor_data_in_range, get_sensors_by_group, SensorState};
use crate::handles::setting_handle::{save_setting, SettingState};
use crate::handles::user_handle::{create_user, UserState, authenticate_user};
use crate::handles::window_handle::{create_window, delete_window, get_windows_by_user, get_window, update_window, WindowState};
use crate::services::actuator_service::ActuatorService;
use crate::services::auth_service::AuthService;
use crate::services::sensor_service::SensorService;
use crate::services::token_service::TokenService;

pub mod configs;
mod handles;
mod middlewares;
mod models;
mod services;

pub async fn run(settings: &Arc<Settings>) {
    let app = create_app(settings).await;

    let ip_addr = settings.server.host.parse::<IpAddr>().unwrap();

    let address = SocketAddr::from((ip_addr, settings.server.port));

    let listener = TcpListener::bind(&address).await.unwrap();

    tracing::info!("listening on {}", address);

    axum::serve(listener, app).await.unwrap();
}

async fn create_app(settings: &Arc<Settings>) -> Router {
    let storage = Arc::new(Storage::new(settings).await.expect("Fail to create database."));
    storage.create_tables().await.expect("Fail to create tables.");

    let sensor_service = Arc::new(SensorService::new(settings, &storage).await
        .expect("Fail to load remote gateway."));
    sensor_service.subscribe_all_groups().await
        .expect("Fail to subscribe topic");

    let actuator_service = ActuatorService::new(settings).map(Arc::new).ok();
    let auth_service = Arc::new(AuthService::new());
    let token_service = Arc::new(TokenService::new(settings));

    let user = Router::new()
        .route("/register", post(create_user))
        .route("/auth", post(authenticate_user))
        .with_state(UserState {
            auth_service: auth_service.clone(),
            token_service: token_service.clone(),
            database: storage.clone(),
        });

    let settings = Router::new()
        .route("/", post(save_setting))
        .with_state(SettingState {
            database: storage.clone(),
        });

    let windows = Router::new()
        .route("/", post(create_window))
        .route("/:window_id", get(get_window).put(update_window).delete(delete_window))
        .route("/user/:user_id", get(get_windows_by_user))
        .with_state(WindowState {
            sensor_service: sensor_service.clone(),
            actuator_service: actuator_service.clone(),
            storage: storage.clone(),
        });

    let sensors = Router::new()
        .route("/:group_id", get(get_sensors_by_group))
        .route("/data/:sensor_id", get(get_sensor_data_in_range))
        .route("/data/sse/:sensor_id", get(get_sensor_data))
        .with_state(SensorState {
            database: storage.clone(),
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
