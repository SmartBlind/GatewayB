use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use serialport::{available_ports, SerialPort};
use tokio::sync::Mutex;

use crate::configs::settings::Embedded;

pub struct ActuatorService {
    serial_port: Arc<Mutex<Box<dyn SerialPort>>>,
}

impl ActuatorService {
    pub fn new(embedded: Option<Embedded>) -> Result<Self, Box<dyn Error>> {
        let (port_path, baud_rate) = match embedded {
            Some(embedded) => (embedded.port_path.clone(), embedded.baud_rate),
            None => {
                let path = available_ports()?
                    .first()
                    .map(|port| port.port_name.clone())
                    .ok_or("No config file found")?;
                (path, 9600)
            },
        };

        tracing::debug!("Connect to port: {}", port_path);

        let port = serialport::new(&port_path, baud_rate)
            .timeout(Duration::from_millis(10))
            .open()?;

        Ok(Self { serial_port: Arc::new(Mutex::new(port)) })
    }

    pub async fn send(&self, command: &str) -> Result<(), Box<dyn Error>> {
        let bytes_written = self.serial_port.lock().await.write(command.as_bytes())?;

        if bytes_written != command.len() {
            Err("Incomplete write to serial port".into())
        } else {
            Ok(())
        }
    }
}