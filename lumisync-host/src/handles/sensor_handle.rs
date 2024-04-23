use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use crate::configs::storage::Storage;

#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub struct SensorData {
    id: i32,
    temp: f32,
    time: i32,
}

#[derive(Clone)]
pub struct SensorState {
    pub database: Arc<Storage>,
}

pub async fn get_sensor_data(
    Path(sensor_id): Path<String>,
    State(state): State<SensorState>,
) -> Result<impl IntoResponse, StatusCode> {
    let key_point: Vec<SensorData> = sqlx::query_as("SELECT * FROM sensor_data where sensor_id = ?")
        .bind(sensor_id)
        .fetch_all(state.database.get_pool())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(key_point))
}