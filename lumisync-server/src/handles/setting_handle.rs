use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::configs::storage::Storage;

#[derive(Serialize, Deserialize, Clone)]
pub struct SettingBody {
    user_id: i32,
    light: i32,
    temperature: f32,
}

#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub struct Setting {
    id: i32,
    user_id: i32,
    light: i32,
    temperature: f32,
}

#[derive(Clone)]
pub struct SettingState {
    pub database: Arc<Storage>,
}

// TODO: multi setting prefab
pub async fn save_setting(
    State(state): State<SettingState>,
    Json(body): Json<SettingBody>,
) -> Result<impl IntoResponse, StatusCode> {
    let result = sqlx::query_as::<_, Setting>("SELECT * FROM settings WHERE user_id = ?")
        .bind(body.user_id)
        .fetch_optional(state.database.get_pool())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match result {
        Some(_setting) => {
            sqlx::query("UPDATE settings SET light = ?, temperature = ? WHERE user_id = ?")
                .bind(&body.light)
                .bind(&body.temperature)
                .bind(body.user_id)
                .execute(state.database.get_pool())
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        },
        None => {
            sqlx::query("INSERT INTO settings (user_id, light, temperature) VALUES (?, ?, ?)")
                .bind(body.user_id)
                .bind(&body.light)
                .bind(&body.temperature)
                .execute(state.database.get_pool())
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        }
    }

    Ok(Json(json!({ "message": "Settings updated successfully" })))
}