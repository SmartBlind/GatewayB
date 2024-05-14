use std::sync::Arc;

use axum::{Extension, Json};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use crate::configs::storage::Storage;
use crate::models::user::User;
use crate::services::auth_service::AuthService;
use crate::services::token_service::{TokenClaims, TokenService};

#[derive(Clone, Serialize, Deserialize)]
pub struct UserRegisterBody {
    pub group: String,
    pub email: String,
    pub password: String,
    pub role: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct UserLoginBody {
    pub email: String,
    pub password: String,
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

    let user: User = sqlx::query_as(
        r#"
        INSERT INTO users (group_id, email, password, role)
            VALUES ((SELECT id FROM groups WHERE name = $1), $2, $3, $4)
            RETURNING *;
        "#
    )
        .bind(&body.group)
        .bind(&body.email)
        .bind(&hash_password)
        .bind(&body.role)
        .fetch_one(state.storage.get_pool())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let token = state.token_service.generate_token(user.to_owned())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .token;

    Ok(token)
}

pub async fn authorize_user(
    Extension(token_data): Extension<TokenClaims>,
    State(state): State<UserState>,
) -> Result<impl IntoResponse, StatusCode> {
    let token = state.token_service
        .generate_token(token_data)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .token;

    Ok(token)
}

pub async fn authenticate_user(
    State(state): State<UserState>,
    Json(body): Json<UserLoginBody>,
) -> Result<impl IntoResponse, StatusCode> {
    let user: User = sqlx::query_as("SELECT * FROM users WHERE email = $1")
        .bind(&body.email)
        .fetch_one(state.storage.get_pool())
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    let result = state.auth_service.verify(&user, &body.password)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    if result {
        let token = state.token_service.generate_token(user.to_owned())
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .token;

        Ok(token)
    } else {
        Err(StatusCode::BAD_REQUEST)
    }
}
