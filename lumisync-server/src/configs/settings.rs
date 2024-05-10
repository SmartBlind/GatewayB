use std::{env, fs};
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
    pub host: String,
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
    pub prefix_type: String,
    pub prefix_mode: String,
    pub prefix_country: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Database {
    pub migrate: Option<String>,
    pub clean: bool,
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Embedded {
    pub port_path: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Auth {
    pub secret: String,
    pub expiration: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Settings {
    pub server: Server,
    pub logger: Logger,
    pub gateway: Gateway,
    pub database: Database,
    pub embedded: Option<Embedded>,
    pub auth: Auth,
}

impl Settings {
    pub fn new() -> Result<Self, ConfigError> {
        let run_mode = env::var("RUN_MODE").unwrap_or("development".into());

        let mut settings: Settings = Config::builder()
            .add_source(File::with_name("configs/default"))
            .add_source(File::with_name(&format!("configs/{run_mode}")).required(false))
            .add_source(Environment::default().separator("__"))
            .build()?
            .try_deserialize()?;

        if let Some(auth) = &settings.gateway.auth {
            let cert_path = Self::normalize_path(&auth.cert_path)?.to_string_lossy().to_string();
            let key_path = Self::normalize_path(&auth.key_path)?.to_string_lossy().to_string();

            settings.gateway.auth = Some(GatewayAuth { cert_path, key_path });
        }

        if let Some(migrate) = &settings.database.migrate {
            if Path::new(migrate).exists() {
                let migrate_path = Self::normalize_path(&migrate)?;

                let data = fs::read(migrate_path).unwrap();
                let script = String::from_utf8_lossy(&data);

                settings.database.migrate = Some(script.into_owned());
            }
        }

        Ok(settings)
    }

    fn normalize_path(path: &str) -> Result<PathBuf, ConfigError> {
        let path_buf = PathBuf::from(path);

        Ok(if path_buf.is_absolute() {
            path_buf.clone()
        } else {
            env::current_dir()
                .map_err(|e| ConfigError::Message(e.to_string()))?
                .as_path()
                .join(&path_buf)
        })
    }
}
