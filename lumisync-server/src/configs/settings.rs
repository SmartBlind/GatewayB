use std::{env, error, fs, io};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use toml::map::Map;
use toml::Value;

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
    pub fn new() -> Result<Self, Box<dyn error::Error>> {
        let run_mode = env::var("RUN_MODE").unwrap_or("development".into());

        // TODO: Need to be replaced until `CARGO_RUSTC_CURRENT_DIR` is stable
        let mut settings: Settings = toml::from_str(
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../", "configs/default.toml"))
        )?;

        let settings_path = Self::normalize_path(&format!("configs/{run_mode}.toml"))?;
        if settings_path.exists() {
            let file_buffer = String::from_utf8(fs::read(settings_path)?)?;
            let override_settings = Value::from_str(&file_buffer)?;
            let merged_settings = Self::merge(
                Value::try_from(settings.to_owned())?,
                override_settings,
                "$"
            )?;
            settings = Value::try_into(merged_settings)?;
        }

        if let Some(auth) = &settings.gateway.auth {
            let cert_path = Self::normalize_path(&auth.cert_path)?
                .to_string_lossy()
                .to_string();
            let key_path = Self::normalize_path(&auth.key_path)?
                .to_string_lossy()
                .to_string();

            settings.gateway.auth = Some(GatewayAuth { cert_path, key_path });
        }

        if let Some(migrate) = &settings.database.migration_path {
            if Path::new(migrate).is_dir() {
                let migrate_path = Self::normalize_path(&migrate)?
                    .to_string_lossy()
                    .to_string();

                settings.database.migration_path = Some(migrate_path);
            } else {
                settings.database.migration_path = None;
            }
        }

        Ok(settings)
    }

    fn merge_table(
        value: &mut Map<String, Value>,
        other: Map<String, Value>,
        path: &str,
    ) -> Result<(), Box<dyn error::Error>> {
        for (name, inner) in other {
            if let Some(existing) = value.remove(&name) {
                let inner_path = format!("{path}.{name}");
                value.insert(name, Self::merge(existing, inner, &inner_path)?);
            } else {
                value.insert(name, inner);
            }
        }

        Ok(())
    }

    fn merge(value: Value, other: Value, path: &str) -> Result<Value, Box<dyn error::Error>> {
        match (value, other) {
            (Value::String(_), Value::String(inner)) => Ok(Value::String(inner)),
            (Value::Integer(_), Value::Integer(inner)) => Ok(Value::Integer(inner)),
            (Value::Float(_), Value::Float(inner)) => Ok(Value::Float(inner)),
            (Value::Boolean(_), Value::Boolean(inner)) => Ok(Value::Boolean(inner)),
            (Value::Datetime(_), Value::Datetime(inner)) => Ok(Value::Datetime(inner)),
            (Value::Array(mut existing), Value::Array(inner)) => {
                existing.extend(inner);
                Ok(Value::Array(existing))
            }
            (Value::Table(mut existing), Value::Table(inner)) => {
                Self::merge_table(&mut existing, inner, path)?;
                Ok(Value::Table(existing))
            }
            (v, o) => Err(
                format!(
                    "Incompatible types at path {}, expected {} received {}.",
                    path,
                    v.type_str(),
                    o.type_str()
                ).into()
            ),
        }
    }

    fn normalize_path(path: &str) -> io::Result<PathBuf> {
        let path_buf = PathBuf::from(path);

        Ok(if path_buf.is_absolute() {
            path_buf.clone()
        } else {
            env::current_dir()?
                .as_path()
                .join(&path_buf)
        })
    }
}
