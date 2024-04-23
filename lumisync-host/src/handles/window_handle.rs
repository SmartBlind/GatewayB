use std::borrow::Cow::Borrowed;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use sqlx::Error::Database;

use crate::configs::storage::Storage;
use crate::services::remote_service::RemoteService;

#[derive(Serialize, Deserialize, Clone)]
pub struct WindowBody {
    user_id: i32,
    sensor_id: String,
    name: String,
}

#[derive(Serialize, Deserialize, sqlx::FromRow)]
struct Window {
    id: i32,
    user_id: i32,
    sensor_id: String,
    name: String,
}

#[derive(Clone)]
pub struct WindowState {
    pub remote: Arc<RemoteService>,
    pub database: Arc<Storage>,
}

pub async fn create_window(
    State(state): State<WindowState>,
    Json(body): Json<WindowBody>,
) -> Result<impl IntoResponse, StatusCode> {
    let result = sqlx::query("INSERT INTO windows (user_id, sensor_id, name) VALUES (?, ?, ?)")
        .bind(body.user_id)
        .bind(&body.sensor_id)
        .bind(&body.name)
        .execute(state.database.get_pool())
        .await;

    match result {
        Ok(_) => {
            let window: Window = sqlx::query_as("SELECT * FROM windows WHERE sensor_id = ?")
                .bind(&body.sensor_id)
                .fetch_one(state.database.get_pool())
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            state.remote.subscribe(&body.sensor_id)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            Ok(Json(window))
        },
        Err(Database(err)) if err.code() == Some(Borrowed("23000")) => Err(StatusCode::CONFLICT),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR)
    }
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
    sqlx::query("UPDATE windows SET user_id = ?, sensor_id = ?, name = ? WHERE id = ?")
        .bind(body.user_id)
        .bind(&body.sensor_id)
        .bind(&body.name)
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