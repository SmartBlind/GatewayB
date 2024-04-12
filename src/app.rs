use std::sync::Arc;

use axum::{Extension, Json, Router};
use axum::routing::get;
use serde::Deserialize;
use tokio::sync::mpsc;

use crate::mqtt_client;
use crate::settings::Settings;

#[derive(Deserialize)]
struct Input {
    message: String,
}

async fn index(Json(input): Json<Input>, tx: Extension<mpsc::Sender<String>>) -> &'static str {
    tx.send(input.message).await.unwrap();
    "Message sent to MQTT"
}

pub async fn create_app(settings: &Arc<Settings>) -> Router {
    let (tx, _rx) = mpsc::channel(32);

    mqtt_client::start_mqtt_client(settings.remote.clone(), tx.clone()).await.unwrap();

    Router::new()
        .route("/", get(index))
        .layer(Extension(tx))
}