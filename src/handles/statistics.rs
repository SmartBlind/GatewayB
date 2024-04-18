use std::sync::Arc;

use axum::extract::{Query, State};
use axum::Json;
use serde::Deserialize;

use crate::configs::storage::Storage;
use crate::services::remote_service::{RemoteService, SensorData};

#[derive(Clone)]
pub struct RemoteState {
    pub(crate) remote: Arc<RemoteService>,
    pub(crate) database: Arc<Storage>,
}

#[derive(Deserialize)]
pub struct GetSensor {
    id: i32,
}

pub async fn get_timeline(
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