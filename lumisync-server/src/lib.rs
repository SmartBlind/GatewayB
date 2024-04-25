use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::configs::settings::Settings;
use crate::configs::storage::Storage;
use crate::handles::control_handle::{ControlState, execute_command};
use crate::handles::sensor_handle::{get_sensor_data, get_sensor_data_in_range, SensorState};
use crate::handles::setting_handle::{save_setting, SettingState};
use crate::handles::user_handle::{create_user, get_user, UserState};
use crate::handles::window_handle::{create_window, delete_window, get_windows_by_user, get_window, update_window, WindowState};
use crate::services::actuator_service::ActuatorService;
use crate::services::sensor_service::SensorService;

pub mod configs;
mod handles;
mod services;

pub async fn run() {
    let settings = Arc::new(Settings::new().expect("Failed to load settings."));

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            let app_name = env!("CARGO_PKG_NAME").replace('-', "_");
            let level = settings.logger.level.as_str();

            format!("{app_name}={level},tower_http={level}").into()
        }))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let app = create_app(&settings).await;

    let ip_addr = settings.server.host.parse::<IpAddr>().unwrap();

    let address = SocketAddr::from((ip_addr, settings.server.port));

    let listener = TcpListener::bind(&address).await.unwrap();

    tracing::debug!("listening on {}", address);

    axum::serve(listener, app).await.unwrap();
}

async fn create_app(settings: &Arc<Settings>) -> Router {
    let storage = Arc::new(Storage::new(settings).await.expect("Fail to create database."));
    storage.create_tables().await.expect("Fail to create tables.");

    let sensor_service = Arc::new(SensorService::new(settings, &storage).await
        .expect("Fail to load remote gateway."));

    let actuator_service = ActuatorService::new(settings)
        .map(|service| Arc::new(service))
        .ok();

    let user = Router::new()
        .route("/", post(create_user))
        .route("/:user_id", get(get_user))
        .with_state(UserState {
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
            database: storage.clone(),
        });

    let sensors = Router::new()
        .route("/:sensor_id", get(get_sensor_data))
        .route("/range/:sensor_id", get(get_sensor_data_in_range))
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
