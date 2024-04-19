use std::env;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::configs::settings::Settings;
use crate::configs::storage::Storage;
use crate::handles::sensor_handle::{get_sensor_data, register_sensor, RemoteState};
use crate::handles::user_handle::{create_user, get_user, UserState};
use crate::services::remote_service::RemoteService;

pub mod configs;
mod handles;
mod services;

pub async fn run() {
    let settings = Arc::new(Settings::new().expect("Failed to load settings."));

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            let app_name = env::var("CARGO_PKG_NAME").unwrap();
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

    let remote = Arc::new(RemoteService::new(settings, &storage)
        .await.expect("Fail to create remote gateway."));

    let user = Router::new()
        .route("/", post(create_user))
        .route("/:user_id", get(get_user))
        .with_state(UserState {
            database: Arc::clone(&storage),
        });

    let sensors = Router::new()
        .route("/", post(register_sensor))
        .route("/:sensor_id", get(get_sensor_data))
        .with_state(RemoteState {
            remote: Arc::clone(&remote),
            database: Arc::clone(&storage),
        });

    Router::new()
        .nest("/users", user)
        .nest("/sensors", sensors)
        .layer(CorsLayer::permissive())
}
