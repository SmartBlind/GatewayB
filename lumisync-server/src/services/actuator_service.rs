use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use serialport::{available_ports, SerialPort};
use tokio::sync::Mutex;

use crate::configs::settings::Settings;

pub struct ActuatorService {
    port: Arc<Mutex<Box<dyn SerialPort>>>,
}

impl ActuatorService {
    pub fn new(settings: &Arc<Settings>) -> Result<Self, Box<dyn Error>> {
        let port_path = if let Some(embedded) = &settings.embedded {
            embedded.port_path.clone()
        } else {
            available_ports()?.first()
                .map(|port| port.port_name.clone())
                .ok_or("No config file found")?
        };

        tracing::debug!("Connect to port: {}", port_path);

        let port = serialport::new(&port_path, 9600)
            .timeout(Duration::from_millis(10))
            .open()?;

        Ok(Self { port: Arc::new(Mutex::new(port)) })
    }

    pub async fn send(&self, command: &str) -> Result<(), Box<dyn Error>> {
        let bytes_written = self.port.lock().await.write(command.as_bytes())?;

        if bytes_written != command.len() {
            Err("Incomplete write to serial port".into())
        } else {
            Ok(())
        }
    }
}