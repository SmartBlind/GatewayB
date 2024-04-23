use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, State};
use axum::response::Sse;
use axum::response::sse::Event;
use serde::{Deserialize, Serialize};
use tokio::time::interval;
use tokio_stream::{Stream, StreamExt};
use tokio_stream::wrappers::IntervalStream;

use crate::configs::storage::Storage;

#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub struct SensorData {
    id: i32,
    light: i32,
    temperature: f32,
    time: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone)]
pub struct SensorState {
    pub database: Arc<Storage>,
}

pub async fn get_sensor_data(
    Path(sensor_id): Path<String>,
    State(state): State<SensorState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let stream = IntervalStream::new(interval(Duration::from_secs(3)))
        .then(move |_| {
            let window_id = sensor_id.clone();
            let database = Arc::clone(&state.database);
            async move {
                let key_point = sqlx::query_as::<_, SensorData>("SELECT * FROM sensor_data where window_id = ?")
                    .bind(&window_id)
                    .fetch_all(database.get_pool())
                    .await
                    .unwrap_or_else(|_| vec![]);
                //.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                let event_data = serde_json::to_string(&key_point).unwrap();
                Ok(Event::default().data(event_data))
            }
        });

    Sse::new(stream)
}