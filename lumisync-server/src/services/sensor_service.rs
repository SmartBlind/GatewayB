use std::{error, fs, io, time};
use std::sync::Arc;
use chrono::DateTime;

use rumqttc::{AsyncClient, Event, EventLoop, MqttOptions, Packet, QoS, TlsConfiguration, Transport};
use rumqttc::tokio_rustls::rustls::{ClientConfig, RootCertStore};
use rustls_pemfile::{certs, Item, read_one};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::configs::settings::{GatewayTopic, Settings};
use crate::configs::storage::Storage;

#[derive(Serialize, Deserialize, Debug)]
pub struct SensorAirDataPayload {
    #[serde(rename = "tsmTuid")]
    id: String,
    #[serde(rename = "tsmTs")]
    time_stamp: i64,
    #[serde(rename = "lght")]
    light: i32,
    #[serde(rename = "temp")]
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
            &settings.gateway.address,
            settings.gateway.port
        );
        options.set_keep_alive(time::Duration::from_secs(5));

        if let Some(auth) = &settings.gateway.auth {
            let mut root_cert_store = RootCertStore::empty();
            root_cert_store.add_parsable_certificates(rustls_native_certs::load_native_certs()?);

            let certs = certs(&mut io::BufReader::new(fs::File::open(&auth.cert_path)?))
                .map(|result| result.unwrap())
                .collect();
            let mut key_buffer = io::BufReader::new(fs::File::open(&auth.key_path)?);
            let key = loop {
                match read_one(&mut key_buffer)? {
                    Some(Item::Sec1Key(key)) => break key.into(),
                    Some(Item::Pkcs1Key(key)) => break key.into(),
                    Some(Item::Pkcs8Key(key)) => break key.into(),
                    None => return Err("no keys found or encrypted keys not supported".into()),
                    _ => {}
                }
            };

            let tls_config = ClientConfig::builder()
                .with_root_certificates(root_cert_store)
                .with_client_auth_cert(certs, key)?;

            options.set_transport(Transport::Tls(TlsConfiguration::from(tls_config)));
        }

        let (client, event_loop) = AsyncClient::new(options, 10);

        Ok(Self {
            client: Arc::new(Mutex::new(client)),
            event_loop: Arc::new(Mutex::new(event_loop)),
            topic: Arc::new(settings.gateway.topic.clone()),
            storage: Arc::clone(storage),
        })
    }

    pub async fn subscribe(&self, sensor_id: Option<&str>) -> Result<(), Box<dyn error::Error>> {
        let client = self.client.lock().await;

        let target = if let Some(id) = sensor_id {
            format!("cloudext/json/{}/{}/{}/{}/#",
                    self.topic.prefix_env,
                    self.topic.prefix_country,
                    self.topic.customer_id,
                    id)
        } else {
            format!("cloudext/json/{}/{}/{}/#",
                    self.topic.prefix_env,
                    self.topic.prefix_country,
                    self.topic.customer_id)
        };

        client.subscribe(&target, QoS::AtLeastOnce).await?;

        tracing::debug!("subscribe topic {}", &target);

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

    /// A mqtt client port
    /// https://support.haltian.com/knowledgebase/how-to-connect-to-thingsee-iot-data-stream/
    async fn handle_message(storage: &Arc<Storage>, payload: &[u8]) -> Result<(), Box<dyn error::Error>> {
        if let Ok(payload_str) = String::from_utf8(payload.to_vec()) {
            if let Ok(data) = serde_json::from_str::<SensorAirDataPayload>(&payload_str) {
                tracing::debug!("Receive: {:?}", data);
                // write to database
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
