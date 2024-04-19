use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use crate::configs::storage::Storage;
use crate::services::remote_service::RemoteService;

#[derive(Serialize, Deserialize, Clone)]
pub struct SensorBody {
    id: String,
    user_id: i32,
}

#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub struct SensorData {
    id: i32,
    temp: f32,
    time: i32,
}

#[derive(Clone)]
pub struct RemoteState {
    pub remote: Arc<RemoteService>,
    pub database: Arc<Storage>,
}

pub async fn register_sensor(
    State(state): State<RemoteState>,
    Json(body): Json<SensorBody>,
) -> Result<impl IntoResponse, StatusCode> {
    sqlx::query("INSERT OR IGNORE INTO sensors (id, user_id) VALUES (?, ?)")
        .bind(&body.id)
        .bind(body.user_id)
        .execute(state.database.get_pool())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    state.remote.subscribe(&body.id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(format!("Subscribe from sensor {}", body.id))
}

pub async fn get_sensor_data(
    Path(sensor_id): Path<String>,
    State(state): State<RemoteState>,
) -> Result<impl IntoResponse, StatusCode> {
    let key_point: Vec<SensorData> = sqlx::query_as("SELECT * FROM sensor_data where sensor_id = ?")
        .bind(sensor_id)
        .fetch_all(state.database.get_pool())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(key_point))
}