use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use rumqttd::local::LinkTx;
use serde_json::{json, to_vec};
use tokio::time;

use host::configs::settings::Settings;
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

    loop {
        publish_env_message(&mut link_tx, &prefix, &topic.customer_id, "TSEN01ABC12345678", 12100)
            .await
            .unwrap();
        time::sleep(Duration::from_secs(1)).await;
    }
}

async fn publish_env_message(
    client: &mut LinkTx,
    prefix: &str,
    customer_id: &str,
    tuid: &str,
    id: i32
) -> Result<(), Box<dyn Error>> {
    let env_msg = json!({
        "tsmId": id,
        "tsmEv": 10,
        "airp": 101364.599,
        "lght": 6,
        "temp": 21.3,
        "humd": 21.7,
        "tsmTs": 1520416221,
        "tsmTuid": tuid,
        "tsmGw": "TSGW00ABC12345678",
        "deploymentGroupId": customer_id
    });

    let env_topic = format!("{prefix}/{customer_id}/{tuid}/{id}");

    client.publish(env_topic, to_vec(&env_msg)?)?;

    Ok(())
}
