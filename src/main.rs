use std::env;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::app::create_app;
use crate::settings::Settings;

mod app;
mod cache;
mod settings;

#[tokio::main]
async fn main() {
    let settings = Arc::new(Settings::new().expect("Failed to load settings."));

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            let app_name = env::var("CARGO_PKG_NAME").unwrap();
            let level = settings.logger.level.as_str();

            format!("{app_name}={level},tower_http={level}").into()
        }))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let app = create_app(&settings).await;

    let ip_addr = settings.server.host.parse::<IpAddr>().unwrap();

    let address = SocketAddr::from((ip_addr, settings.server.port));

    let listener = TcpListener::bind(&address).await.unwrap();

    tracing::debug!("listening on {}", address);

    axum::serve(listener, app).await.unwrap();
}
