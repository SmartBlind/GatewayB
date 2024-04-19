use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};
use tower_http::cors::CorsLayer;

use crate::configs::settings::Settings;
use crate::configs::storage::Storage;
use crate::handles::sensor_handle::{get_sensor_data, register_sensor, RemoteState};
use crate::handles::user_handle::{create_user, get_user, UserState};
use crate::services::remote_service::RemoteService;

pub async fn create_app(settings: &Arc<Settings>) -> Router {
    let storage = Arc::new(Storage::new(settings).await.expect("Fail to create database."));
    storage.create_user_table().await.expect("Fail to create user table.");
    storage.create_setting_table().await.expect("Fail to create setting table.");
    storage.create_sensor_table().await.expect("Fail to create sensor table.");
    storage.create_sensor_data_table().await.expect("Fail to create sensor data table.");

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
