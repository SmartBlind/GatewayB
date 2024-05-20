use std::{error, fs, io, time};
use std::sync::Arc;

use chrono::DateTime;
use rumqttc::{AsyncClient, Event, EventLoop, MqttOptions, Packet, QoS, TlsConfiguration, Transport};
use rumqttc::tokio_rustls::rustls::{ClientConfig, RootCertStore};
use rustls_pemfile::{certs, Item, read_one};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast::Sender;
use tokio::sync::Mutex;

use crate::configs::settings::{Gateway, GatewayTopic};
use crate::configs::storage::Storage;
use crate::handles::sse_handle::ServiceEvent;
use crate::handles::sse_handle::ServiceEvent::SensorDataCreate;
use crate::models::group::Group;
use crate::models::sensor_data::SensorData;

#[derive(Clone, Debug, Serialize, Deserialize)]
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
    sender: Sender<ServiceEvent>,
}

impl SensorService {
    pub async fn new(gateway: Gateway, storage: &Arc<Storage>, sender: &Sender<ServiceEvent>) -> Result<Self, Box<dyn error::Error>> {
        let mut options = MqttOptions::new(&gateway.client_id, &gateway.host, gateway.port);
        options.set_keep_alive(time::Duration::from_secs(5));

        if let Some(auth) = &gateway.auth {
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
            topic: Arc::new(gateway.topic.clone()),
            storage: Arc::clone(storage),
            sender: sender.clone(),
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
        let sender_clone = self.sender.clone();
        tokio::spawn(async move {
            loop {
                let mut event_loop = event_loop_clone.lock().await;
                match event_loop.poll().await {
                    Ok(notification) => match notification {
                        Event::Incoming(Packet::Publish(publish)) => {
                            match Self::handle_message(&storage_clone, &publish.payload).await {
                                Ok(data) => {
                                    if let Err(e) = sender_clone.send(SensorDataCreate(data)) {
                                        tracing::error!("Error sending event: {}", e);
                                    }
                                }
                                Err(e) => tracing::error!("Error handling message: {}", e),
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

    async fn handle_message(storage: &Arc<Storage>, payload: &[u8]) -> Result<SensorData, Box<dyn error::Error>> {
        if let Ok(payload_str) = String::from_utf8(payload.to_vec()) {
            if let Ok(data) = serde_json::from_str::<SensorPayload>(&payload_str) {
                tracing::debug!("Receive: {:?}", data);

                let sensor_data: SensorData = sqlx::query_as(
                    r#"
                    INSERT INTO sensor_data (sensor_id, light, temperature, time)
                        VALUES ((SELECT id from sensors WHERE name = $1), $2, $3, DATETIME($4))
                        RETURNING *;
                    "#
                )
                    .bind(&data.id)
                    .bind(&data.light)
                    .bind(&data.temperature)
                    .bind(DateTime::from_timestamp(data.time_stamp, 0))
                    .fetch_one(storage.get_pool())
                    .await?;

                return Ok(sensor_data)
            }
        }

        Err("Failed to parse payload".into())
    }
}
