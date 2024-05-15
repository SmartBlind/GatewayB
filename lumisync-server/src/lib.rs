use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::net::TcpListener;

use crate::app::create_app;
use crate::configs::settings::Settings;

pub mod app;
pub mod configs;
pub mod handles;
pub mod middlewares;
pub mod models;
pub mod services;

pub async fn run(settings: &Arc<Settings>) {
    let app = create_app(settings).await;

    let ip_addr = settings.server.host.parse::<IpAddr>().unwrap();

    let address = SocketAddr::from((ip_addr, settings.server.port));

    let listener = TcpListener::bind(&address).await.unwrap();

    tracing::info!("listening on {:?}", address);

    axum::serve(listener, app).await.unwrap();
}
