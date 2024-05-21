use std::sync::Arc;

use axum::{Extension, Json};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::configs::storage::Storage;
use crate::models::setting::Setting;
use crate::services::token_service::TokenClaims;

#[derive(Clone, Serialize, Deserialize)]
pub struct SettingBody {
    pub light: i32,
    pub temperature: f32,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub interval: i32,
}

#[derive(Clone)]
pub struct SettingState {
    pub storage: Arc<Storage>,
}

pub async fn create_setting(
    Extension(token_data): Extension<TokenClaims>,
    State(state): State<SettingState>,
    Json(body): Json<SettingBody>,
) -> Result<impl IntoResponse, StatusCode> {
    let setting: Setting = sqlx::query_as(
        r#"
        INSERT INTO settings (user_id, light, temperature, start, end, interval)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *;
        "#
    )
        .bind(&token_data.sub)
        .bind(&body.light)
        .bind(&body.temperature)
        .bind(body.start)
        .bind(body.end)
        .bind(&body.interval)
        .fetch_one(state.storage.get_pool())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(setting))
}

pub async fn update_setting(
    Path(setting_id): Path<i32>,
    State(state): State<SettingState>,
    Json(body): Json<SettingBody>,
) -> Result<impl IntoResponse, StatusCode> {
    let setting: Setting = sqlx::query_as(
        r#"
        UPDATE settings SET light = $1, temperature = $2, start = $3, end = $4, interval = $5
            WHERE id = $6
            RETURNING *;
        "#
    )
        .bind(&body.light)
        .bind(&body.temperature)
        .bind(body.start)
        .bind(body.end)
        .bind(&body.interval)
        .bind(&setting_id)
        .fetch_one(state.storage.get_pool())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(setting))
}

pub async fn get_settings(
    Extension(token_data): Extension<TokenClaims>,
    State(state): State<SettingState>,
) -> Result<impl IntoResponse, StatusCode> {
    let settings: Vec<Setting> = sqlx::query_as("SELECT * FROM settings WHERE user_id = $1")
        .bind(&token_data.sub)
        .fetch_all(state.storage.get_pool())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(settings))
}

pub async fn get_settings_by_region(
    Extension(token_data): Extension<TokenClaims>,
    Path(region_id): Path<i32>,
    State(state): State<SettingState>,
) -> Result<impl IntoResponse, StatusCode> {
    let row: (i64, ) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM users_regions_link ur
            WHERE ur.user_id = $1 AND ur.region_id = $2;
        "#
    )
        .bind(&token_data.sub)
        .bind(&region_id)
        .fetch_one(state.storage.get_pool())
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    let settings: Vec<Setting> = if row.0 > 0 {
        sqlx::query_as(
            r#"
            SELECT s.* FROM regions r
                JOIN regions_settings_link rs ON r.id = rs.region_id
                JOIN settings s ON rs.setting_id = s.id
                WHERE r.id = $1;
            "#
        )
            .bind(&region_id)
            .fetch_all(state.storage.get_pool())
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    } else {
        Vec::new()
    };

    Ok(Json(settings))
}