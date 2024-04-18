use std::sync::Arc;

use axum::Router;
use axum::routing::get;
use tower_http::cors::CorsLayer;

use crate::configs::settings::Settings;
use crate::configs::storage::Storage;
use crate::handles::statistics::{get_timeline, RemoteState};
use crate::services::remote_service::RemoteService;

pub async fn create_app(settings: &Arc<Settings>) -> Router {
    let storage = Arc::new(Storage::new(settings).await.expect("Fail to create database."));
    storage.create_sensor_data_table().await.expect("Fail to create sensor data table.");

    let topic = settings.gateway.topic.clone();

    let remote = Arc::new(RemoteService::new(settings, &storage).await.expect("Fail to create remote gateway."));
    remote.connect_and_subscribe(format!("{}/{}/{}/#", topic.prefix_env, topic.prefix_country, topic.customer_id))
        .await.expect("Fail to subscribe.");

    let remote = Router::new()
        .route("/timeline", get(get_timeline))
        .with_state(RemoteState {
            remote: Arc::clone(&remote),
            database: Arc::clone(&storage),
        });

    Router::new()
        .nest("/remote", remote)
        .layer(CorsLayer::permissive())
}
