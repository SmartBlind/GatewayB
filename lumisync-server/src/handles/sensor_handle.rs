use std::convert::Infallible;
use std::sync::Arc;
use std::time;

use axum::{Extension, Json};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Sse};
use axum::response::sse::Event;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::QueryBuilder;
use tokio::sync::Mutex;
use tokio::time::interval;
use tokio_stream::{Stream, StreamExt, wrappers};

use crate::configs::storage::Storage;
use crate::models::sensor::Sensor;
use crate::models::sensor_data::SensorData;
use crate::models::user::Role;
use crate::services::token_service::TokenClaims;

#[derive(Clone, Serialize, Deserialize)]
pub struct SensorBody {
    pub region_id: i32,
    pub name: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TimeRangeQuery {
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
}

#[derive(Clone)]
pub struct SensorState {
    pub storage: Arc<Storage>,
}

pub async fn create_sensor(
    Extension(token_data): Extension<TokenClaims>,
    State(state): State<SensorState>,
    Json(body): Json<SensorBody>,
) -> Result<impl IntoResponse, StatusCode> {
    match Role::from(token_data.role.to_owned()) {
        Role::Admin => {
            let sensor: Sensor = sqlx::query_as(
                r#"
                INSERT INTO sensors (region_id, name)
                    VALUES ($1, $2)
                    RETURNING *;
                "#
            )
                .bind(&body.region_id)
                .bind(&body.name)
                .fetch_one(state.storage.get_pool())
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            Ok(Json(sensor))
        },
        _ => Err(StatusCode::FORBIDDEN)?,
    }
}

pub async fn get_sensors(
    Extension(token_data): Extension<TokenClaims>,
    State(state): State<SensorState>,
) -> Result<impl IntoResponse, StatusCode> {
    match Role::from(token_data.role.to_owned()) {
        Role::Admin => {
            let sensors: Vec<Sensor> = sqlx::query_as(
                r#"
                    SELECT sensors.* FROM groups
                        JOIN regions ON groups.id = regions.group_id
                        JOIN sensors ON regions.id = sensors.region_id
                        WHERE groups.id = ?;
                "#
            )
                .bind(&token_data.group_id)
                .fetch_all(state.storage.get_pool())
                .await
                .map_err(|_| StatusCode::NOT_FOUND)?;

            Ok(Json(sensors))
        },
        Role::User => {
            let sensors = sqlx::query_as::<_, Sensor>(
                r#"
                    SELECT s.* FROM users u
                        JOIN users_regions_link ur ON u.id = ur.user_id
                        JOIN regions r ON ur.region_id = r.id
                        JOIN sensors s ON r.id = s.region_id
                        WHERE u.id = ?;
                "#
            )
                .bind(&token_data.sub)
                .fetch_all(state.storage.get_pool())
                .await
                .map_err(|_| StatusCode::NOT_FOUND)?;

            Ok(Json(sensors))
        },
    }
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
            let id = sensor_id.to_owned();
            let database = state.storage.to_owned();
            let last_timestamp = last_timestamp.to_owned();
            async move {
                let last_time = *last_timestamp.lock().await;
                let result = sqlx::query_as::<_, SensorData>(
                    r#"
                    SELECT * FROM sensor_data
                        WHERE sensor_id = $1 AND time > DATETIME($2)
                        ORDER BY time;
                    "#
                )
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
    let mut query = QueryBuilder::new("SELECT * FROM sensor_data WHERE sensor_id = $1");
    query.push_bind(&sensor_id);

    let mut index = 2;

    if let Some(start) = range.start {
        query.push(format!(" AND time >= ${}", index));
        query.push_bind(start);
        index += 1;
    }

    if let Some(end) = range.end {
        query.push(format!(" AND time <= ${}", index));
        query.push_bind(end);
    }

    query.push(" ORDER BY time");

    let key_point: Vec<SensorData> = query
        .build_query_as()
        .fetch_all(state.storage.get_pool())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(key_point))
}
