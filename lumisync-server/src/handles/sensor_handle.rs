use std::convert::Infallible;
use std::sync::Arc;
use std::time;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use axum::response::{IntoResponse, Sse};
use axum::response::sse::Event;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio::time::interval;
use tokio_stream::{Stream, StreamExt, wrappers};

use crate::configs::storage::Storage;
use crate::models::sensor::Sensor;
use crate::models::sensor_data::SensorData;

#[derive(Serialize, Deserialize, Clone)]
pub struct TimeRangeQuery {
    start: Option<DateTime<Utc>>,
    end: Option<DateTime<Utc>>,
}

#[derive(Clone)]
pub struct SensorState {
    pub database: Arc<Storage>,
}

pub async fn get_sensors_by_group(
    Path(group_id): Path<i32>,
    State(state): State<SensorState>,
) -> Result<impl IntoResponse, StatusCode> {
    let sensors = sqlx::query_as::<_, Sensor>("SELECT * FROM sensors WHERE group_id = ?")
        .bind(group_id.to_string())
        .fetch_all(state.database.get_pool())
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    Ok(Json(sensors))
}

pub async fn get_sensor_data(
    Path(sensor_id): Path<String>,
    Query(range): Query<TimeRangeQuery>,
    State(state): State<SensorState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let initial_timestamp = range.start.unwrap_or(Utc::now() - Duration::days(1));
    let last_timestamp = Arc::new(Mutex::new(initial_timestamp));

    let stream = wrappers::IntervalStream::new(interval(time::Duration::from_secs(3)))
        .then(move |_| {
            let id = sensor_id.clone();
            let database = Arc::clone(&state.database);
            let last_timestamp = Arc::clone(&last_timestamp);
            async move {
                let last_time = *last_timestamp.lock().await;
                let result = sqlx::query_as::<_, SensorData>("SELECT * FROM sensor_data where sensor_id = ? AND time > DATETIME(?) ORDER BY time")
                    .bind(&id)
                    .bind(last_time)
                    .fetch_all(database.get_pool())
                    .await;

                match result {
                    Ok(key_point) if !key_point.is_empty() => {
                        let latest_time = key_point.last().unwrap().time;
                        *last_timestamp.lock().await = latest_time;
                        let event_data = serde_json::to_string(&key_point).unwrap();
                        Ok(Event::default().data(event_data))
                    },
                    _ => Ok(Event::default()),
                }
            }
        });

    Sse::new(stream)
}

pub async fn get_sensor_data_in_range(
    Path(sensor_id): Path<String>,
    Query(range): Query<TimeRangeQuery>,
    State(state): State<SensorState>
) -> Result<impl IntoResponse, StatusCode> {
    let mut conditions = vec!["sensor_id = ?"];

    if range.start.is_some() { conditions.push("time >= ?"); }
    if range.end.is_some() { conditions.push("time <= ?"); }

    let where_clause = conditions.join(" AND ");

    let key_point = sqlx::query_as::<_, SensorData>(&format!("SELECT * FROM sensor_data WHERE {where_clause} ORDER BY time", ))
        .bind(&sensor_id)
        .bind(range.start)
        .bind(range.end)
        .fetch_all(state.database.get_pool())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(key_point))
}