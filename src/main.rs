use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::{Extension, Json, Router};
use axum::routing::get;
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use crate::app::create_app;
use crate::settings::Settings;

mod mqtt_client;
mod settings;
mod app;

#[tokio::main]
async fn main() {
    let settings = Arc::new(Settings::new().expect("Failed to load settings."));

    let app = create_app(&settings).await;

    let ip_addr = settings.server.host.parse::<IpAddr>().unwrap();

    let address = SocketAddr::from((ip_addr, settings.server.port));

    let listener = TcpListener::bind(&address).await.unwrap();

    tracing::debug!("listening on {}", address);

    axum::serve(listener, app).await.unwrap();
}
