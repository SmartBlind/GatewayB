use std::collections::HashMap;
use std::error::Error;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use rumqttd::{Broker, Config, ConnectionSettings, Notification, RouterConfig, ServerSettings, TlsConfig};
use rumqttd::local::LinkTx;

use host::configs::settings::Gateway;

pub struct MockBroker {
    pub broker: Arc<Mutex<Broker>>,
    pub gateway: Arc<Gateway>,
}

impl MockBroker {
    pub fn new(gateway: &Arc<Gateway>) -> Result<Self, Box<dyn Error>> {
        let tls_config = gateway.auth.as_ref().map(|auth| TlsConfig::Rustls {
            capath: None,
            certpath: auth.cert_path.clone(),
            keypath: auth.key_path.clone(),
        });

        let broker = Broker::new(Config {
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
                    listen: (gateway.address.parse::<IpAddr>()?, gateway.port).into(),
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

        Ok(Self {
            broker: Arc::new(Mutex::new(broker)),
            gateway: Arc::clone(gateway),
        })
    }

    pub fn start(&self) {
        let broker = Arc::clone(&self.broker);

        thread::spawn(move || broker.lock().unwrap().start().unwrap());
    }

    pub fn link(&self, topic: &str) -> LinkTx {
        let difference = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let client_id = format!("client-{}", difference.as_secs());

        let (mut link_tx, mut link_rx) = {
            let broker_lock = self.broker.lock().unwrap();
            broker_lock.link(&client_id).unwrap()
        };

        link_tx.subscribe(topic).unwrap();

        thread::spawn(move || {
            let mut count = 0;
            loop {
                let notification = match link_rx.recv().unwrap() {
                    Some(v) => v,
                    None => continue,
                };

                match notification {
                    Notification::Forward(forward) => {
                        count += 1;
                        println!(
                            "Topic = {:?}, Count = {}, Payload = {} bytes",
                            forward.publish.topic,
                            count,
                            forward.publish.payload.len()
                        );
                    }
                    v => println!("{v:?}"),
                }
            }
        });

        link_tx
    }
}
