use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use axum::response::IntoResponse;
use jsonwebtoken::TokenData;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::configs::storage::Storage;
use crate::models::setting::Setting;
use crate::services::token_service::TokenClaims;

#[derive(Serialize, Deserialize, Clone)]
pub struct SettingBody {
    light: i32,
    temperature: f32,
}

#[derive(Clone)]
pub struct SettingState {
    pub storage: Arc<Storage>,
}

pub async fn save_setting(
    Extension(token_data): Extension<TokenClaims>,
    State(state): State<SettingState>,
    Json(body): Json<SettingBody>,
) -> Result<impl IntoResponse, StatusCode> {
    let result = sqlx::query_as::<_, Setting>("SELECT * FROM settings WHERE user_id = ?")
        .bind(&token_data.sub)
        .fetch_optional(state.storage.get_pool())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match result {
        Some(_) => {
            sqlx::query("UPDATE settings SET light = ?, temperature = ? WHERE user_id = ?")
                .bind(&body.light)
                .bind(&body.temperature)
                .bind(&token_data.sub)
                .execute(state.storage.get_pool())
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        },
        None => {
            sqlx::query("INSERT INTO settings (user_id, light, temperature) VALUES (?, ?, ?)")
                .bind(&token_data.sub)
                .bind(&body.light)
                .bind(&body.temperature)
                .execute(state.storage.get_pool())
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        }
    }

    Ok(Json(json!({ "message": "Settings updated successfully" })))
}