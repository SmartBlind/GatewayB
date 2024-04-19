use std::collections::HashMap;
use std::error::Error;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rumqttc::{AsyncClient, MqttOptions, QoS};
use rumqttd::{Broker, Config, ConnectionSettings, RouterConfig, ServerSettings, TlsConfig};
use serde_json::{json, to_vec};
use tokio::{task, time};

use host::configs::settings::{Gateway, Settings};

pub async fn run() {
    let settings = Arc::new(Settings::new().expect("Failed to load settings."));
    let gateway = Arc::new(Mutex::new(settings.gateway.clone()));

    let gateway_clone = Arc::clone(&gateway);
    std::thread::spawn(move || {
        mock_mqtt_broker(&gateway_clone).unwrap();
    });

    let (client_id, address, port) = {
        let g = gateway.lock().map_err(|e| format!("Failed to acquire lock: {}", e))?;
        let since_the_epoch = SystemTime::now().duration_since(UNIX_EPOCH)?;

        (format!("client-{}", since_the_epoch.as_secs()), g.address.clone(), g.port)
    };

    let mut mqttoptions = MqttOptions::new(client_id, &address, port);
    mqttoptions.set_keep_alive(Duration::from_secs(5));

    let (client, mut eventloop) = AsyncClient::new(mqttoptions, 10);

    task::spawn(async move {
        mock_mqtt_publish(&client, &gateway).await;
        time::sleep(Duration::from_secs(3)).await;
    });

    loop {
        let event = eventloop.poll().await;
        match &event {
            Ok(v) => {
                println!("Event = {v:?}");
            }
            Err(e) => {
                println!("Error = {e:?}");
            }
        }
    }
}

fn mock_mqtt_broker(gateway: &Arc<Mutex<Gateway>>) -> Result<(), Box<dyn Error>> {
    let (address, port, tls_config) = {
        let g = gateway.lock().map_err(|e| format!("Failed to acquire lock: {}", e))?;
        let tls_config = g.auth.as_ref().map(|auth| TlsConfig::Rustls {
            capath: None,
            certpath: auth.cert_path.clone(),
            keypath: auth.key_path.clone(),
        });
        (g.address.clone(), g.port, tls_config)
    };

    let mut broker = Broker::new(Config {
        id: 0,
        router: RouterConfig {
            max_connections: 10010,
            max_outgoing_packet_count: 200,
            max_segment_size: 104857600,
            max_segment_count: 10,
            custom_segment: None,
            initialized_filters: None,
            shared_subscriptions_strategy: Default::default(),
        },
        v4: Some(HashMap::from([
            (2.to_string(), ServerSettings {
                name: "v4-2".to_string(),
                listen: (address.parse::<IpAddr>()?, port).into(),
                tls: tls_config,
                next_connection_delay_ms: 10,
                connections: ConnectionSettings {
                    connection_timeout_ms: 60000,
                    max_payload_size: 20480,
                    max_inflight_count: 100,
                    auth: None,
                    external_auth: None,
                    dynamic_filters: true,
                },
            })
        ])),
        v5: None,
        ws: None,
        cluster: None,
        console: None,
        bridge: None,
        prometheus: None,
        metrics: None,
    });

    broker.start()?;

    Ok(())
}

async fn mock_mqtt_publish(client: &AsyncClient, gateway: &Arc<Mutex<Gateway>>) -> Option<Box<dyn Error>> {
    let topic = {
        let g = gateway.lock().map_err(|e| format!("Failed to acquire lock: {}", e)).ok()?;
        g.topic.clone()
    };

    let prefix = format!("cloudext/json/{}/{}", &topic.prefix_env, &topic.prefix_country);

    client
        .subscribe(prefix.clone(), QoS::AtMostOnce)
        .await
        .ok()?;

    loop {
        publish_env_message(client, &prefix, &topic.customer_id, "TSEN01ABC12345678", 12100)
            .await
            .ok()?;
        time::sleep(Duration::from_secs(1)).await;
    }
}

async fn publish_env_message(client: &AsyncClient, prefix: &str, customer_id: &str, tuid: &str, id: i32) -> Result<(), Box<dyn Error>> {
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

    client
        .publish(env_topic, QoS::AtLeastOnce, false, to_vec(&env_msg)?)
        .await?;

    Ok(())
}
