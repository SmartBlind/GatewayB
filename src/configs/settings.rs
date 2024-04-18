use std::env;
use std::path::{Path, PathBuf};

use config::{Config, ConfigError, Environment, File};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Server {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Logger {
    pub level: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Gateway {
    pub address: String,
    pub port: u16,
    pub client_id: String,
    pub topic: GatewayTopic,
    pub auth: Option<GatewayAuth>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GatewayAuth {
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GatewayTopic {
    pub prefix_env: String,
    pub prefix_country: String,
    pub customer_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Database {
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Settings {
    pub server: Server,
    pub logger: Logger,
    pub gateway: Gateway,
    pub database: Database,
}

impl Settings {
    pub fn new() -> Result<Self, ConfigError> {
        let run_mode = env::var("RUN_MODE").unwrap_or("development".into());

        let builder = Config::builder()
            .add_source(File::with_name("configs/default"))
            .add_source(File::with_name(&format!("configs/{}", run_mode)).required(false))
            .add_source(Environment::default().separator("__"));

        let mut settings: Settings = builder.build()?.try_deserialize()?;

        if let Some(auth) = &settings.gateway.auth {
            let cert_path = Self::normalize_path(&auth.cert_path)?;
            let key_path = Self::normalize_path(&auth.key_path)?;

            if Path::new(&cert_path).exists() && Path::new(&key_path).exists() {
                settings.gateway.auth.as_mut().unwrap().cert_path = cert_path;
                settings.gateway.auth.as_mut().unwrap().key_path = key_path;
            } else {
                return Err(ConfigError::Message("File path does not exist".into()));
            }
        }

        Ok(settings)
    }

    fn project_root() -> Result<PathBuf, std::io::Error> {
        if let Ok(manifest_dir) = env::var("CARGO_MANIFEST_DIR") {
            // development and testing environments
            Ok(PathBuf::from(manifest_dir))
        } else {
            // runtime root relative path `folder/executable` -> `folder/`
            env::current_exe().map(|path| path.parent().unwrap().to_path_buf())
        }
    }

    fn normalize_path(path: &str) -> Result<String, ConfigError> {
        let path_buf = PathBuf::from(path);

        Ok(if path.starts_with("~/") {
            Self::project_root()
                .map_err(|e| ConfigError::Message(e.to_string()))?
                .join(path_buf.strip_prefix("~/").unwrap())
                .to_string_lossy()
                .into_owned()
        } else {
            path.to_string()
        })
    }
}
