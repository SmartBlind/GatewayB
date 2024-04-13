use std::error::Error;

use rumqttc::{AsyncClient, Event, MqttOptions, Packet, QoS};
use tokio::sync::mpsc::Sender;

use crate::settings::Gateway;

/// A mqtt client port
/// https://support.haltian.com/knowledgebase/open-mqtt-data/
pub async fn start_mqtt_client(settings: Gateway, mut tx: Sender<String>) -> Result<(), Box<dyn Error>> {
    let mut mqttoptions = MqttOptions::new(settings.client_id, settings.address, settings.port);
    mqttoptions.set_keep_alive(std::time::Duration::from_secs(5));

    let (mut client, mut eventloop) = AsyncClient::new(mqttoptions, 10);
    client.subscribe(settings.topic, QoS::AtMostOnce).await?;

    tokio::spawn(async move {
        loop {
            match eventloop.poll().await {
                Ok(notification) => match notification {
                    Event::Incoming(Packet::Publish(p)) => {
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