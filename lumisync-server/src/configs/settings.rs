use std::env;
use std::error::Error;
use std::path::Path;

use config::{Config, ConfigError, Environment, File};
use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;

use crate::configs::normalize_path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Server {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Logger {
    pub level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gateway {
    pub host: String,
    pub port: u16,
    pub client_id: String,
    pub topic: GatewayTopic,
    pub auth: Option<GatewayAuth>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayAuth {
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayTopic {
    pub prefix_type: String,
    pub prefix_mode: String,
    pub prefix_country: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Database {
    pub migration_path: Option<String>,
    pub clean_start: bool,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Embedded {
    pub baud_rate: u32,
    pub port_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Auth {
    pub secret: String,
    pub expiration: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
            .add_source(Environment::default().separator("_"))
            .build()?
            .try_deserialize()?;

        if let Some(auth) = &settings.gateway.auth {
            let cert_path = normalize_path(&auth.cert_path)
                .map_err(|e| ConfigError::Message(e.to_string()))?
                .to_string_lossy()
                .to_string();
            let key_path = normalize_path(&auth.key_path)
                .map_err(|e| ConfigError::Message(e.to_string()))?
                .to_string_lossy()
                .to_string();

            settings.gateway.auth = Some(GatewayAuth { cert_path, key_path });
        }

        if let Some(migrate) = &settings.database.migration_path {
            if Path::new(migrate).is_dir() {
                let migrate_path = normalize_path(&migrate)
                    .map_err(|e| ConfigError::Message(e.to_string()))?
                    .to_string_lossy()
                    .to_string();

                settings.database.migration_path = Some(migrate_path);
            } else {
                settings.database.migration_path = None;
            }
        }

        Ok(settings)
    }

    pub fn merge<L, R, T>(left: L, right: R) -> Result<T, Box<dyn Error>>
        where
            L: Serialize,
            R: Serialize,
            T: Serialize + DeserializeOwned,
    {
        let mut left_map = serde_json::to_value(&left)?
            .as_object()
            .map(|map| map.to_owned())
            .ok_or("Failed to serialize left value which is not an object")?;

        let mut right_map = serde_json::to_value(&right)?
            .as_object()
            .map(|map| map.to_owned())
            .ok_or("Failed to serialize right value which is not an object")?;

        right_map.retain(|_, v| !v.is_null());
        left_map.extend(right_map);

        let value = serde_json::to_value(&left_map)?;

        Ok(serde_json::from_value(value)?)
    }
}
