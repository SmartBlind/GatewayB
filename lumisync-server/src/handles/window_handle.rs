use std::sync::Arc;

use axum::{Extension, Json};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use jsonwebtoken::TokenData;
use serde::{Deserialize, Serialize};

use crate::configs::storage::Storage;
use crate::models::window::Window;
use crate::services::actuator_service::ActuatorService;
use crate::services::sensor_service::SensorService;
use crate::services::token_service::TokenClaims;

#[derive(Serialize, Deserialize, Clone)]
pub struct WindowBody {
    user_id: i32,
    sensor_id: String,
    name: String,
    state: f32,
}

#[derive(Clone)]
pub struct WindowState {
    pub sensor_service: Arc<SensorService>,
    pub actuator_service: Option<Arc<ActuatorService>>,
    pub storage: Arc<Storage>,
}

pub async fn create_window(
    Extension(token_data): Extension<TokenData<TokenClaims>>,
    State(state): State<WindowState>,
    Json(body): Json<WindowBody>,
) -> Result<impl IntoResponse, StatusCode> {
    let window = sqlx::query_as::<_, Window>(
        r#"
        INSERT INTO windows (group_id, name, state)
            VALUES ($1, $2, $3)
            RETURNING *;
        "#
    )
        .bind(&token_data.claims.group_id)
        .bind(&body.name)
        .bind(body.state)
        .fetch_one(state.storage.get_pool())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(window))
}

pub async fn get_windows(
    Extension(token_data): Extension<TokenData<TokenClaims>>,
    State(state): State<WindowState>
) -> Result<impl IntoResponse, StatusCode> {
    let windows = sqlx::query_as::<_, Window>(
        r#"
            SELECT w.* FROM users u
                JOIN users_windows_link uw ON u.id = uw.user_id
                JOIN windows w ON uv.window_id = w.id
                WHERE u.id = ?;
        "#
    )
        .bind(&token_data.claims.sub)
        .fetch_all(state.storage.get_pool())
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    Ok(Json(windows))
}

pub async fn get_window(
    Path(window_id): Path<i32>,
    State(state): State<WindowState>
) -> Result<impl IntoResponse, StatusCode> {
    let window: Window = sqlx::query_as("SELECT * FROM windows WHERE id = ?")
        .bind(window_id.to_string())
        .fetch_one(state.storage.get_pool())
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
        .execute(state.storage.get_pool())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let updated: Window = sqlx::query_as("SELECT * FROM windows WHERE id = ?")
        .bind(window_id)
        .fetch_one(state.storage.get_pool())
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
        .execute(state.storage.get_pool())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::NO_CONTENT)
}