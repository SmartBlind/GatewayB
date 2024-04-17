use std::sync::Arc;

use axum::{Json, Router};
use axum::extract::{Query, State};
use axum::routing::get;
use serde::Deserialize;
use tower_http::cors::CorsLayer;

use crate::cache::{Database, RemoteGateway, SensorData};
use crate::settings::Settings;

#[derive(Clone)]
struct RemoteState {
    remote: Arc<RemoteGateway>,
    database: Arc<Database>,
}

#[derive(Deserialize)]
struct GetSensor {
    id: i32,
}

async fn get_timeline(
    Query(params): Query<GetSensor>,
    State(state): State<RemoteState>,
) -> Json<Vec<SensorData>> {
    let messages: Vec<SensorData> = sqlx::query_as("SELECT id, payload, time FROM sensor_data where id = ?")
        .bind(params.id)
        .fetch_all(state.database.get_pool())
        .await
        .unwrap();

    Json(messages)
}

pub async fn create_app(settings: &Arc<Settings>) -> Router {
    let database = Arc::new(Database::new(settings).await.expect("Fail to create database."));
    database.create_sensor_data_table().await.expect("Fail to create sensor data table.");

    let remote = Arc::new(RemoteGateway::new(settings, &database).await.expect("Fail to create remote gateway."));
    if let Some(topic) = settings.gateway.topic.clone() {
        let target = format!("{}/{}/{}/#", topic.prefix_env, topic.prefix_country, topic.customer_id);

        remote.connect_and_subscribe(target).await.expect("Fail to subscribe.");
    }

    let remote = Router::new()
        .route("/timeline", get(get_timeline))
        .with_state(RemoteState {
            remote: Arc::clone(&remote),
            database: Arc::clone(&database),
        });

    Router::new()
        .nest("/remote", remote)
        .layer(CorsLayer::permissive())
}
