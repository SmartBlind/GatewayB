use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::services::actuator_service::ActuatorService;

#[derive(Clone)]
pub struct ControlState {
    pub actuator_service: Arc<ActuatorService>,
}

pub async fn execute_command(
    Path(command): Path<String>,
    State(state): State<ControlState>,
) -> Result<impl IntoResponse, StatusCode> {
    state.actuator_service.send(command.as_str())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(format!("Submit command: {}", command))
}