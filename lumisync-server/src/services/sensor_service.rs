use std::{error, fs, time};
use std::sync::Arc;

use rumqttc::{AsyncClient, Event, MqttOptions, Packet, QoS, TlsConfiguration, Transport};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::configs::settings::{GatewayTopic, Settings};
use crate::configs::storage::Storage;

#[derive(Serialize, Deserialize, Debug)]
pub struct SensorAirDataPayload {
    #[serde(rename = "tsmTuid")]
    id: String,
    #[serde(rename = "tsmTs")]
    time_stamp: i32,
    #[serde(rename = "lght")]
    light: i32,
    #[serde(rename = "temp")]
    temperature: f32,
}

pub struct SensorService {
    client: Arc<Mutex<AsyncClient>>,
    topic: Arc<GatewayTopic>,
}

impl SensorService {
    pub fn new(settings: &Arc<Settings>, storage: &Arc<Storage>) -> Result<Self, Box<dyn error::Error>> {
        let mut options = MqttOptions::new(
            &settings.gateway.client_id,
            &settings.gateway.address,
            settings.gateway.port
        );
        options.set_keep_alive(time::Duration::from_secs(5));

        if let Some(auth) = &settings.gateway.auth {
            let (client_cert, client_key) = (fs::read(&auth.cert_path)?, fs::read(&auth.key_path)?);
            let tls_config = TlsConfiguration::Simple {
                ca: client_cert.clone(),
                alpn: None,
                client_auth: Some((client_cert, client_key)),
            };
            options.set_transport(Transport::Tls(tls_config));
        }

        let (client, mut event_loop) = AsyncClient::new(options, 10);

        let storage_clone = Arc::clone(storage);
        tokio::spawn(async move {
            loop {
                match event_loop.poll().await {
                    Ok(notification) => match notification {
                        Event::Incoming(Packet::Publish(publish)) => {
                            Self::handle_message(&storage_clone, &publish.payload)
                                .await
                                .map_err(|e| tracing::error!("Error handling message: {}", e))
                                .unwrap();
                        }
                        _ => {}
                    },
                    Err(e) => tracing::error!("MQTT error: {}", e),
                }
            }
        });

        Ok(Self {
            client: Arc::new(Mutex::new(client)),
            topic: Arc::new(settings.gateway.topic.clone()),
        })
    }

    pub async fn subscribe(&self, sensor_id: &str) -> Result<(), Box<dyn error::Error>> {
        let client = self.client.lock().await;

        let target = format!("cloudext/json/{}/{}/{}/{}/#",
                             self.topic.prefix_env,
                             self.topic.prefix_country,
                             self.topic.customer_id,
                             sensor_id);

        client.subscribe(target, QoS::AtLeastOnce).await?;

        Ok(())
    }

    /// A mqtt client port
    /// https://support.haltian.com/knowledgebase/how-to-connect-to-thingsee-iot-data-stream/
    async fn handle_message(storage: &Arc<Storage>, payload: &[u8]) -> Result<(), Box<dyn error::Error>> {
        if let Ok(payload_str) = String::from_utf8(payload.to_vec()) {
            if let Ok(data) = serde_json::from_str::<SensorAirDataPayload>(&payload_str) {
                println!("{:?}", data);
                // write to database
                sqlx::query("INSERT INTO sensor_data (window_id, light, temperature, time) VALUES (?, ?, ?, ?)")
                    .bind(&data.id)
                    .bind(&data.light)
                    .bind(&data.temperature)
                    .bind(&data.time_stamp)
                    .execute(storage.get_pool())
                    .await?;
            }
        }

        Ok(())
    }
}
