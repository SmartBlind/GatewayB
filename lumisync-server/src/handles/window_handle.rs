use std::borrow::Cow::Borrowed;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use sqlx::Error::Database;

use crate::configs::storage::Storage;
use crate::services::actuator_service::ActuatorService;
use crate::services::sensor_service::SensorService;

#[derive(Serialize, Deserialize, Clone)]
pub struct WindowBody {
    user_id: i32,
    sensor_id: String,
    name: String,
    state: f32,
}

#[derive(Serialize, Deserialize, sqlx::FromRow)]
struct Window {
    id: i32,
    user_id: i32,
    sensor_id: String,
    name: String,
    /// State in a range of [-1, 1].
    /// when 0 means off;
    /// when -1 means rotate anti-clockwise to end;
    /// when 1 means clockwise to end;
    state: f32,
}

#[derive(Clone)]
pub struct WindowState {
    pub sensor_service: Arc<SensorService>,
    pub actuator_service: Option<Arc<ActuatorService>>,
    pub database: Arc<Storage>,
}

pub async fn create_window(
    State(state): State<WindowState>,
    Json(body): Json<WindowBody>,
) -> Result<impl IntoResponse, StatusCode> {
    let result = sqlx::query("INSERT INTO windows (user_id, sensor_id, name, state) VALUES (?, ?, ?, ?)")
        .bind(body.user_id)
        .bind(&body.sensor_id)
        .bind(&body.name)
        .bind(body.state)
        .execute(state.database.get_pool())
        .await;

    match result {
        Ok(_) => {
            let window: Window = sqlx::query_as("SELECT * FROM windows WHERE sensor_id = ?")
                .bind(&body.sensor_id)
                .fetch_one(state.database.get_pool())
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            // state.sensor_service.subscribe(&body.sensor_id)
            //     .await
            //     .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            Ok(Json(window))
        },
        Err(Database(err)) if err.code() == Some(Borrowed("23000")) => Err(StatusCode::CONFLICT),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

pub async fn get_windows_by_user(
    Path(user_id): Path<i32>,
    State(state): State<WindowState>
) -> Result<impl IntoResponse, StatusCode> {
    let window = sqlx::query_as::<_, Window>("SELECT * FROM windows WHERE user_id = ?")
        .bind(user_id.to_string())
        .fetch_all(state.database.get_pool())
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    Ok(Json(window))
}

pub async fn get_window(
    Path(window_id): Path<i32>,
    State(state): State<WindowState>
) -> Result<impl IntoResponse, StatusCode> {
    let window: Window = sqlx::query_as("SELECT * FROM windows WHERE id = ?")
        .bind(window_id.to_string())
        .fetch_one(state.database.get_pool())
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    Ok(Json(window))
}

pub async fn update_window(
    Path(window_id): Path<i32>,
    State(state): State<WindowState>,
    Json(body): Json<WindowBody>,
) -> Result<impl IntoResponse, StatusCode> {
    sqlx::query("UPDATE windows SET user_id = ?, sensor_id = ?, name = ?, state = ? WHERE id = ?")
        .bind(body.user_id)
        .bind(&body.sensor_id)
        .bind(&body.name)
        .bind(&body.state)
        .bind(window_id)
        .execute(state.database.get_pool())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let updated: Window = sqlx::query_as("SELECT * FROM windows WHERE id = ?")
        .bind(window_id)
        .fetch_one(state.database.get_pool())
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    Ok(Json(updated))
}

pub async fn delete_window(
    Path(window_id): Path<i32>,
    State(state): State<WindowState>,
) -> Result<impl IntoResponse, StatusCode> {
    sqlx::query("DELETE FROM windows WHERE id = ?")
        .bind(window_id)
        .execute(state.database.get_pool())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::NO_CONTENT)
}