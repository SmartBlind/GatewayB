use std::{error, fs, time};
use std::sync::Arc;
use chrono::DateTime;

use rumqttc::{AsyncClient, Event, EventLoop, MqttOptions, Packet, QoS, TlsConfiguration, Transport};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::configs::settings::{GatewayTopic, Settings};
use crate::configs::storage::Storage;
use crate::models::group::Group;

#[derive(Debug, Serialize, Deserialize)]
pub struct SensorPayload {
    #[serde(alias = "sId",alias = "tsmTuid")]
    id: String,
    #[serde(alias = "mTs", alias = "tsmTs")]
    time_stamp: i64,
    #[serde(alias = "lght")]
    light: i32,
    #[serde(alias = "temp")]
    temperature: f32,
}

pub struct SensorService {
    client: Arc<Mutex<AsyncClient>>,
    event_loop: Arc<Mutex<EventLoop>>,
    topic: Arc<GatewayTopic>,
    storage: Arc<Storage>,
}

impl SensorService {
    pub async fn new(settings: &Arc<Settings>, storage: &Arc<Storage>) -> Result<Self, Box<dyn error::Error>> {
        let mut options = MqttOptions::new(
            &settings.gateway.client_id,
            &settings.gateway.host,
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

        let (client, event_loop) = AsyncClient::new(options, 10);

        Ok(Self {
            client: Arc::new(Mutex::new(client)),
            event_loop: Arc::new(Mutex::new(event_loop)),
            topic: Arc::new(settings.gateway.topic.clone()),
            storage: Arc::clone(storage),
        })
    }

    pub async fn subscribe_all_groups(&self) -> Result<(), Box<dyn error::Error>> {
        let groups = sqlx::query_as::<_, Group>("SELECT * FROM groups;")
            .fetch_all(self.storage.get_pool())
            .await?;

        for group in groups {
            let target = format!("cloudext/{}/{}/{}/{}/#",
                                 self.topic.prefix_type,
                                 self.topic.prefix_mode,
                                 self.topic.prefix_country,
                                 group.name);

            self.subscribe(&target).await?;
        }

        Ok(())
    }

    pub async fn subscribe(&self, target: &str) -> Result<(), Box<dyn error::Error>> {
        let client = self.client.lock().await;

        client.subscribe(target, QoS::AtLeastOnce).await?;

        tracing::debug!("subscribe topic {}", target);

        let storage_clone = Arc::clone(&self.storage);
        let event_loop_clone = Arc::clone(&self.event_loop);
        tokio::spawn(async move {
            loop {
                let mut event_loop = event_loop_clone.lock().await;
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

        Ok(())
    }

    async fn handle_message(storage: &Arc<Storage>, payload: &[u8]) -> Result<(), Box<dyn error::Error>> {
        if let Ok(payload_str) = String::from_utf8(payload.to_vec()) {
            if let Ok(data) = serde_json::from_str::<SensorPayload>(&payload_str) {
                tracing::debug!("Receive: {:?}", data);

                sqlx::query("INSERT INTO sensor_data (sensor_id, light, temperature, time) VALUES (?, ?, ?, DATETIME(?))")
                    .bind(&data.id)
                    .bind(&data.light)
                    .bind(&data.temperature)
                    .bind(DateTime::from_timestamp_millis(data.time_stamp))
                    .execute(storage.get_pool())
                    .await?;
            }
        }

        Ok(())
    }
}
