use std::sync::Arc;

use axum::{Json, Router};
use axum::extract::{Query, State};
use axum::routing::get;
use serde::Deserialize;
use sqlx::SqlitePool;
use tower_http::cors::CorsLayer;

use crate::cache::{RemoteGatway, SensorData};
use crate::settings::Settings;

#[derive(Clone)]
struct RemoteState {
    remote: Arc<RemoteGatway>,
    pool: Arc<SqlitePool>,
}

#[derive(Deserialize)]
struct GetSensor {
    id: i32,
}

async fn get_timeline(
    Query(params): Query<GetSensor>,
    State(state): State<RemoteState>,
) -> Json<Vec<SensorData>> {
    let messages = sqlx::query_as!(SensorData, "SELECT id, payload, time FROM sensor_data", params.id)
        .fetch_all(&state.pool).await.unwrap();

    Json(messages)
}

pub async fn create_app(settings: &Arc<Settings>) -> Router {
    let pool = Arc::new(SqlitePool::connect(&settings.database.url).await
        .expect("Fail to load database"));

    let mut remote = RemoteGatway::new(settings.gateway.clone(), &pool).await;
    remote.connect_and_subscribe("cloudext/json/pr/fi/office/#".to_string());

    let remote = Router::new()
        .route("/timeline", get(get_timeline))
        .with_state(RemoteState { pool, remote: Arc::new(remote) });

    Router::new()
        .nest("/remote", remote)
        .layer(CorsLayer::permissive())
}
