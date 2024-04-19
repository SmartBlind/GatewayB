use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use crate::configs::storage::Storage;

#[derive(Serialize, Deserialize, Clone)]
pub struct UserBody {
    email: String,
}

#[derive(Serialize, Deserialize, sqlx::FromRow)]
struct User {
    id: i32,
    email: String,
}

#[derive(Clone)]
pub struct UserState {
    pub database: Arc<Storage>,
}

pub async fn create_user(
    State(state): State<UserState>,
    Json(body): Json<UserBody>,
) -> Result<impl IntoResponse, StatusCode> {
    sqlx::query("INSERT INTO users (email) VALUES (?)")
        .bind(&body.email)
        .execute(state.database.get_pool())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let user: User = sqlx::query_as("SELECT * FROM users WHERE email = ?")
        .bind(&body.email)
        .fetch_one(state.database.get_pool())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(user))
}

pub async fn get_user(
    Path(user_id): Path<i32>,
    State(state): State<UserState>
) -> Result<impl IntoResponse, StatusCode> {
    let user: User = sqlx::query_as("SELECT * FROM users WHERE id = ?")
        .bind(user_id.to_string())
        .fetch_one(state.database.get_pool())
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    Ok(Json(user))
}
