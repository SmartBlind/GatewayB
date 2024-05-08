use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use crate::configs::storage::Storage;
use crate::models::user::{Role, User};
use crate::services::auth_service::AuthService;
use crate::services::token_service::TokenService;

#[derive(Serialize, Deserialize, Clone)]
pub struct UserRegisterBody {
    group: String,
    email: String,
    password: String,
    role: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct UserAuthBody {
    email: String,
    password: String,
}

#[derive(Clone)]
pub struct UserState {
    pub auth_service: Arc<AuthService>,
    pub token_service: Arc<TokenService>,
    pub storage: Arc<Storage>,
}

pub async fn create_user(
    State(state): State<UserState>,
    Json(body): Json<UserRegisterBody>,
) -> Result<impl IntoResponse, StatusCode> {
    let hash_password = state.auth_service.hash(&body.password)
        .map_err(|_| StatusCode::FORBIDDEN)?;

    sqlx::query(
        r#"INSERT INTO users (group_id, email, password, role) VALUES (
            (SELECT id FROM groups WHERE name = ?), ?, ?, ?
        )
        "#
    )
        .bind(&body.group)
        .bind(&body.email)
        .bind(&hash_password)
        .bind(Role::User.to_string())
        .execute(state.storage.get_pool())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let user: User = sqlx::query_as("SELECT * FROM users WHERE email = ?")
        .bind(&body.email)
        .fetch_one(state.storage.get_pool())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let token_data = state.token_service.generate_token(&user)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(token_data.token)
}

pub async fn authenticate_user(
    State(state): State<UserState>,
    Json(body): Json<UserAuthBody>,
) -> Result<impl IntoResponse, StatusCode> {
    let user: User = sqlx::query_as("SELECT * FROM users WHERE email = ?")
        .bind(&body.email)
        .fetch_one(state.storage.get_pool())
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    let result = state.auth_service.verify(&user, &body.password)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    if result {
        let token_data = state.token_service.generate_token(&user)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        Ok(token_data.token)
    } else {
        Err(StatusCode::BAD_REQUEST)
    }
}
