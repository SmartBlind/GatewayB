use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use rand::Rng;
use rumqttd::local::LinkTx;
use serde_json::{json, to_vec};
use tokio::time;

use server::configs::settings::Settings;

use crate::broker::MockBroker;

mod broker;

pub async fn run() {
    let settings = Arc::new(Settings::new().expect("Failed to load settings."));
    let gateway = Arc::new(settings.gateway.clone());

    let topic = gateway.topic.clone();
    let prefix = format!("cloudext/json/{}/{}", &topic.prefix_env, &topic.prefix_country);

    let broker = MockBroker::new(&gateway).expect("Fail to create broker");
    let mut link_tx = broker.link(&format!("{prefix}/#"));
    broker.start();

    let mut id = 0;

    loop {
        let sensor_ids = vec!["SENSOR01", "SENSOR02"];
        for sensor_id in sensor_ids {
            publish_env_message(&mut link_tx, &prefix, &topic.customer_id, sensor_id, id)
                .await
                .unwrap();
            time::sleep(Duration::from_secs(1)).await;
        }
        id += 1;
    }
}

async fn publish_env_message(
    client: &mut LinkTx,
    prefix: &str,
    customer_id: &str,
    tuid: &str,
    id: i32
) -> Result<(), Box<dyn Error>> {
    let mut rng = rand::thread_rng();

    let env_msg = json!({
        "tsmId": id,
        "tsmEv": 10,
        "airp": rng.gen_range(100000.0..102000.0),
        "lght": rng.gen_range(0..100),
        "temp": rng.gen_range(20.0..40.0),
        "humd": rng.gen_range(0.0..100.0),
        "tsmTs": Utc::now().timestamp_millis(),
        "tsmTuid": tuid,
        "tsmGw": "TSGW00ABC12345678",
        "deploymentGroupId": customer_id
    });

    let env_topic = format!("{prefix}/{customer_id}/{tuid}/{id}");

    client.publish(env_topic, to_vec(&env_msg)?)?;

    Ok(())
}
