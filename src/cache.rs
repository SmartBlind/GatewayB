use std::sync::Arc;
use chrono::{DateTime, Utc};

use rumqttc::{AsyncClient, Event, EventLoop, MqttOptions, Packet, QoS};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use tokio::sync::Mutex;

use crate::settings::Gateway;

#[derive(Serialize, Deserialize)]
pub struct SensorDataPayload {
    id: i32,
    payload: String,
}

#[derive(Serialize, Deserialize)]
pub struct SensorData {
    id: i32,
    payload: String,
    time: DateTime<Utc>,
}

pub struct RemoteGatway {
    client: Arc<Mutex<AsyncClient>>,
    event_loop: Arc<Mutex<EventLoop>>,
    pool: Arc<SqlitePool>,
}

impl RemoteGatway {
    pub async fn new(settings: Gateway, pool: &Arc<SqlitePool>) -> Self {
        let mut options = MqttOptions::new(settings.client_id, settings.address, settings.port);
        options.set_keep_alive(std::time::Duration::from_secs(5));

        let (client, event_loop) = AsyncClient::new(options, 10);

        Self {
            client: Arc::new(Mutex::new(client)),
            event_loop: Arc::new(Mutex::new(event_loop)),
            pool: pool.clone(),
        }
    }

    /// A mqtt client port
    /// https://support.haltian.com/knowledgebase/open-mqtt-data/
    pub async fn connect_and_subscribe(&mut self, topic: String) {
        let mut client = self.client.lock().await;
        client.subscribe(topic, QoS::AtLeastOnce).await.unwrap();
        drop(client);

        let pool = self.pool.clone();
        let event_loop = self.event_loop.clone();

        tokio::spawn(async move {
            let mut event_loop = event_loop.lock().await;
            loop {
                match event_loop.poll().await.unwrap() {
                    Event::Incoming(Packet::Publish(publish)) => {
                        let payload_str = String::from_utf8(publish.payload.to_vec()).unwrap();
                        if let Ok(data) = serde_json::from_str::<SensorDataPayload>(&payload_str) {
                            // write to database
                            let mut conn = pool.acquire().await.unwrap();

                            sqlx::query("INSERT INTO sensor_data (id, payload, time) VALUES (?, ?)")
                                .bind(data.id)
                                .bind(data.payload.to_string())
                                .bind(Utc::now())
                                .execute(&mut *conn)
                                .await
                                .unwrap();
                        }
                    }
                    _ => {}
                }
            }
        });
    }
}