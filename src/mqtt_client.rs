use std::error::Error;

use rumqttc::{AsyncClient, MqttOptions, QoS};
use tokio::sync::mpsc;

use crate::settings::Gateway;

pub async fn start_mqtt_client(settings: Gateway, mut tx: mpsc::Sender<String>) -> Result<(), Box<dyn Error>> {
    let mut mqttoptions = MqttOptions::new(settings.client_id, settings.address, settings.port);
    mqttoptions.set_keep_alive(std::time::Duration::from_secs(5));

    let (mut client, mut eventloop) = AsyncClient::new(mqttoptions, 10);
    client.subscribe(settings.topic, QoS::AtMostOnce)?;

    tokio::spawn(async move {
        loop {
            match eventloop.poll().await {
                Ok(notification) => match notification {
                    rumqttc::Event::Incoming(rumqttc::Packet::Publish(p)) => {
                        let payload = String::from_utf8(p.payload.to_vec()).unwrap();
                        tx.send(payload).await.unwrap();
                    }
                    _ => {}
                },
                Err(e) => eprintln!("MQTT error: {}", e),
            }
        }
    });

    Ok(())
}