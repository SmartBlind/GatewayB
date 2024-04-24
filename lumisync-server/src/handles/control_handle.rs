use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use axum::response::IntoResponse;
use serde_json::json;

use crate::services::actuator_service::ActuatorService;

#[derive(Clone)]
pub struct ControlState {
    pub actuator_service: Option<Arc<ActuatorService>>,
}

pub async fn execute_command(
    Path(command): Path<String>,
    State(state): State<ControlState>,
) -> Result<impl IntoResponse, StatusCode> {
    if let Some(service) = state.actuator_service {
        service.send(command.as_str())
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        Ok(Json(json!({ "message": format!("Submit command: {}", command) })))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}