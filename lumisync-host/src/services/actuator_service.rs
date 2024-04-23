use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use serialport::SerialPort;
use tokio::sync::Mutex;

use crate::configs::settings::Settings;

pub struct ActuatorService {
    port: Arc<Mutex<Box<dyn SerialPort>>>,
}

impl ActuatorService {
    pub fn new(settings: &Arc<Settings>) -> Result<Self, Box<dyn Error>> {
        if let Some(embedded) = &settings.embedded {
            let port = serialport::new(&embedded.port_path, 9600)
                .timeout(Duration::from_millis(10))
                .open()?;

            Ok(Self { port: Arc::new(Mutex::new(port)) })
        } else {
            Err("No config serial port path found".into())
        }
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