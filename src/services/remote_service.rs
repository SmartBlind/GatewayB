use std::error::Error;
use std::fs;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use rumqttc::{AsyncClient, Event, EventLoop, MqttOptions, Packet, QoS, TlsConfiguration, Transport};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::configs::settings::Settings;
use crate::configs::storage::Storage;

#[derive(Serialize, Deserialize)]
pub struct SensorAirDataPayload {
    payload: String,
}

#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub struct SensorData {
    id: i32,
    payload: String,
    time: DateTime<Utc>,
}

pub struct RemoteService {
    client: Arc<Mutex<AsyncClient>>,
    event_loop: Arc<Mutex<EventLoop>>,
    storage: Arc<Storage>,
}

impl RemoteService {
    pub async fn new(settings: &Arc<Settings>, storage: &Arc<Storage>) -> Result<Self, Box<dyn Error>> {
        let mut options = MqttOptions::new(&settings.gateway.client_id, &settings.gateway.address, settings.gateway.port);
        options.set_keep_alive(std::time::Duration::from_secs(5));

        if let Some(auth) = settings.gateway.auth.clone() {
            let client_cert = fs::read(auth.cert_path)?;
            let client_key = fs::read(auth.key_path)?;

            let transport = Transport::Tls(TlsConfiguration::Simple {
                ca: client_cert.clone(),
                alpn: None,
                client_auth: Some((client_cert, client_key)),
            });

            options.set_transport(transport);
        }

        let (client, event_loop) = AsyncClient::new(options, 10);

        Ok(Self {
            client: Arc::new(Mutex::new(client)),
            event_loop: Arc::new(Mutex::new(event_loop)),
            storage: Arc::clone(storage),
        })
    }

    /// A mqtt client port
    /// https://support.haltian.com/knowledgebase/how-to-connect-to-thingsee-iot-data-stream/
    pub async fn connect_and_subscribe(&self, topic: String) -> Result<(), Box<dyn Error>> {
        let client = self.client.lock().await;
        client.subscribe(topic, QoS::AtLeastOnce).await.unwrap();
        drop(client);

        // let client_clone = self.client.clone();
        let event_loop_clone = self.event_loop.clone();
        let storage_clone = self.storage.clone();

        tokio::spawn(async move {
            let mut event_loop = event_loop_clone.lock().await;
            loop {
                match event_loop.poll().await {
                    Ok(notification) => match notification {
                        Event::Incoming(Packet::Publish(publish)) => {
                            let payload_str = String::from_utf8(publish.payload.to_vec()).unwrap();
                            println!("{}", payload_str);
                            if let Ok(data) = serde_json::from_str::<SensorAirDataPayload>(&payload_str) {
                                // write to database
                                sqlx::query("INSERT INTO sensor_data (payload, time) VALUES (?, ?)")
                                    .bind(data.payload.to_string())
                                    .bind(Utc::now())
                                    .execute(storage_clone.get_pool())
                                    .await
                                    .unwrap();
                            }
                        }
                        _ => {}
                    },
                    Err(e) => tracing::error!("MQTT error: {}", e),
                }
            }
        });

        Ok(())
    }
}