use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use crate::configs::storage::Storage;
use crate::models::user::User;
use crate::services::auth_service::AuthService;
use crate::services::token_service::TokenService;

#[derive(Serialize, Deserialize, Clone)]
pub struct UserRegisterBody {
    group_id: i32,
    email: String,
    password: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct UserAuthBody {
    email: String,
    password: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct UserData {
    group_id: i32,
    email: String,
    token: String,
}

#[derive(Clone)]
pub struct UserState {
    pub auth_service: Arc<AuthService>,
    pub token_service: Arc<TokenService>,
    pub database: Arc<Storage>,
}

pub async fn create_user(
    State(state): State<UserState>,
    Json(body): Json<UserRegisterBody>,
) -> Result<impl IntoResponse, StatusCode> {
    let hash_password = state.auth_service.hash(&body.password)
        .map_err(|_| StatusCode::FORBIDDEN)?;

    sqlx::query("INSERT INTO users (group_id, email, password) VALUES (?, ?, ?)")
        .bind(body.group_id.to_string())
        .bind(&body.email)
        .bind(&hash_password)
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

pub async fn authenticate_user(
    State(state): State<UserState>,
    Json(body): Json<UserAuthBody>,
) -> Result<impl IntoResponse, StatusCode> {
    let user: User = sqlx::query_as("SELECT * FROM users WHERE email = ?")
        .bind(&body.email)
        .fetch_one(state.database.get_pool())
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    let result = state.auth_service.verify(&user, &body.password)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    if result {
        let token_data = state.token_service.generate_token(&user)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        Ok(Json(UserData {
            group_id: user.group_id,
            email: user.email,
            token: token_data.token,
        }))
    } else {
        Err(StatusCode::BAD_REQUEST)
    }
}
