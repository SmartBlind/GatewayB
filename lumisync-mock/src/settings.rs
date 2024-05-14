use std::{env, error, io};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Logger {
    pub level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gateway {
    pub host: String,
    pub port: u16,
    pub topic: GatewayTopic,
    pub auth: Option<GatewayAuth>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mock {
    pub group_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayTopic {
    pub prefix_type: String,
    pub prefix_mode: String,
    pub prefix_country: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayAuth {
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub logger: Logger,
    pub mock: Mock,
    pub gateway: Gateway,
}

impl Settings {
    pub fn new() -> Result<Self, Box<dyn error::Error>> {
        // TODO: Need to be replaced until `CARGO_RUSTC_CURRENT_DIR` is stable
        let mut settings: Settings = toml::from_str(
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../", "configs/default.toml"))
        )?;

        if let Some(auth) = &settings.gateway.auth {
            let cert_path = Self::normalize_path(&auth.cert_path)?
                .to_string_lossy()
                .to_string();
            let key_path = Self::normalize_path(&auth.key_path)?
                .to_string_lossy()
                .to_string();

            settings.gateway.auth = Some(GatewayAuth { cert_path, key_path });
        }

        Ok(settings)
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
