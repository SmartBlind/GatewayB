use std::sync::Arc;

use axum::{Extension, Json};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use crate::configs::storage::Storage;
use crate::models::region::Region;
use crate::services::token_service::TokenClaims;

#[derive(Serialize, Deserialize, Clone)]
pub struct RegionBody {
    #[serde(default)]
    pub user_ids: Vec<i32>,
    pub name: String,
    pub light: i32,
    pub temperature: f32,
}

#[derive(Clone)]
pub struct RegionState {
    pub storage: Arc<Storage>,
}

pub async fn create_region(
    Extension(token_data): Extension<TokenClaims>,
    State(state): State<RegionState>,
    Json(body): Json<RegionBody>,
) -> Result<impl IntoResponse, StatusCode> {
    let region: Region = sqlx::query_as(
        r#"
        INSERT INTO regions (group_id, name, light, temperature)
            VALUES ($1, $2, $3, $4)
            RETURNING *;
        "#
    )
        .bind(token_data.group_id.to_string())
        .bind(&body.name)
        .bind(body.light.to_string())
        .bind(body.temperature.to_string())
        .fetch_one(state.storage.get_pool())
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    let mut bind_users = vec![token_data.sub];
    bind_users.extend(body.user_ids);

    for bind_user in bind_users {
        sqlx::query("INSERT INTO users_regions_link (user_id, region_id) VALUES ($1, $2)")
            .bind(bind_user.to_string())
            .bind(region.id.to_string())
            .fetch_one(state.storage.get_pool())
            .await
            .map_err(|_| StatusCode::NOT_FOUND)?;
    }

    Ok(Json(region))
}

pub async fn get_regions(
    Extension(token_data): Extension<TokenClaims>,
    State(state): State<RegionState>,
) -> Result<impl IntoResponse, StatusCode> {
    let regions: Vec<Region> = sqlx::query_as("SELECT * FROM regions WHERE group_id = $1")
        .bind(&token_data.group_id)
        .fetch_all(state.storage.get_pool())
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    Ok(Json(regions))
}