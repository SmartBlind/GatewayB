use std::collections::HashMap;

use rumqttd::local::LinkTx;
use rumqttd::Notification;
use serde_json::from_slice;
use tokio::sync::mpsc;

use crate::broker::MockBroker;
use crate::SensorPayload;

pub struct CommandHandler {
    pub cmd_tx: mpsc::Sender<(SensorPayload, u32)>,
    pub cmd_rx: mpsc::Receiver<(SensorPayload, u32)>,
}

impl CommandHandler {
    pub fn new() -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel(32);

        CommandHandler { cmd_tx, cmd_rx }
    }

    pub async fn start_sensor_command_processor(&self, broker: &MockBroker) -> LinkTx {
        let (link_tx, mut link_rx) = broker.link("/internal/sensor/#").await;
        broker.start();

        tokio::spawn({
            let cmd_tx_owned = self.cmd_tx.to_owned();
            async move {

                let mut index_map: HashMap<String, u32> = HashMap::new();
                loop {
                    let notification = match link_rx.recv().unwrap() {
                        Some(v) => v,
                        None => continue,
                    };

                    match notification {
                        Notification::Forward(forward) => {
                            if let Ok(data) = from_slice::<SensorPayload>(&forward.publish.payload) {
                                tracing::debug!("Receive: {:?}", data);

                                let sensor_index = index_map.entry(data.id.clone()).or_insert(0);
                                cmd_tx_owned.send((data, sensor_index.clone())).await.unwrap();
                                *sensor_index += 1;
                            }
                        },
                        v => tracing::error!("{v:?}"),
                    }
                }
            }
        });

        link_tx
    }
}
