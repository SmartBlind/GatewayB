use std::sync::Arc;

use axum::{Json, Router};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;
use tower_http::cors::CorsLayer;

use crate::mqtt_client;
use crate::settings::Settings;

#[derive(Deserialize)]
struct Input {
    message: String,
}

#[derive(Clone)]
struct RemoteState {
    tx: Arc<Sender<String>>,
}

async fn index(
    Json(input): Json<Input>,
    State(state): State<RemoteState>
) -> Result<String, StatusCode> {
    state.tx.send(input.message).await.unwrap();

    Ok("Message sent to MQTT".to_string())
}

pub async fn create_app(settings: &Arc<Settings>) -> Router {
    let (tx, _rx) = mpsc::channel(32);

    mqtt_client::start_mqtt_client(settings.remote.clone(), tx.clone()).await.unwrap();

    let remote = Router::new()
        .route("/", get(index))
        .with_state(RemoteState { tx: Arc::new(tx.clone()) });

    Router::new()
        .nest("/remote", remote)
        .layer(CorsLayer::permissive())
}