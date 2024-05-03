use std::sync::Arc;

use lumisync_mock::run;
use lumisync_mock::settings::Settings;

#[tokio::main]
async fn main() {
    let settings = Arc::new(Settings::new().expect("Failed to load settings."));

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            let app_name = env!("CARGO_PKG_NAME").replace('-', "_");
            let level = settings.logger.level.as_str();

            format!("{app_name}={level}").into()
        }))
        .init();

    run(&settings).await;
}