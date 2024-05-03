use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use chrono::{Timelike, Utc};
use rand::Rng;
use rumqttd::local::LinkTx;
use serde::{Deserialize, Serialize};
use serde_json::{json, to_vec};
use tokio::time;

use crate::settings::Settings;
use crate::command::CommandHandler;
use crate::broker::MockBroker;
use crate::simulate::{simulated_humidity, simulation_lux};

mod broker;
mod command;
pub mod settings;
mod simulate;

#[derive(Serialize, Deserialize, Debug)]
pub struct SensorPayload {
    id: String,
    airp: Option<f32>,
    lght: Option<i32>,
    temp: Option<f32>,
    humd: Option<f32>
}

pub async fn run(settings: &Arc<Settings>) {
    let gateway = Arc::new(settings.gateway.clone());
    let topic = Arc::new(gateway.topic.clone());
    let prefix = format!(
        "cloudext/{}/{}/{}/{}",
        &topic.prefix_type,
        &topic.prefix_mode,
        &topic.prefix_country,
        &gateway.group_id,
    );

    let broker = MockBroker::new(&gateway).expect("Fail to create broker");
    let mut command_handler = CommandHandler::new();
    let mut link_tx = command_handler.start_sensor_command_processor(&broker).await;

    let mut interval = time::interval(Duration::from_secs(10));
    let mut mock_index = 0;
    loop {
        tokio::select! {
            Some((data, sensor_index)) = command_handler.cmd_rx.recv() => {
                let seconds_since_midnight = Utc::now().num_seconds_from_midnight();
                let day_fraction = seconds_since_midnight as f64 / 86400.0; // Total seconds in a day = 86400

                publish_env_message(
                    &mut link_tx,
                    sensor_index,
                    &prefix,
                    &gateway.group_id,
                    data,
                    day_fraction,
                )
                    .await
                    .unwrap();
            },
            _ = interval.tick() => {
                const INTERVAL_COUNT: u32 = 180; // Number of intervals in a 30-minute period.

                let day_fraction = (mock_index % INTERVAL_COUNT) as f64 / INTERVAL_COUNT as f64 ;
                let data = SensorPayload {
                    id: "SENSOR-MOCK".to_string(),
                    airp: None,
                    lght: None,
                    temp: None,
                    humd: None,
                };

                publish_env_message(
                    &mut link_tx,
                    mock_index,
                    &prefix,
                    &gateway.group_id,
                    data,
                    day_fraction
                )
                    .await
                    .unwrap();

                mock_index += 1;
            }
        }
    }
}

async fn publish_env_message(
    client: &mut LinkTx,
    index: u32,
    prefix: &str,
    customer_id: &str,
    data: SensorPayload,
    day_fraction: f64,
) -> Result<(), Box<dyn Error>> {
    print!("{}", day_fraction);
    let SensorPayload { id, airp, lght, temp, humd } = data;
    let radians = day_fraction * 2.0 * std::f64::consts::PI;
    let mut rng = rand::thread_rng();

    let env_msg = json!({
        // Message id
        "mId": index,
        // Message time stamp
        "mTs": Utc::now().timestamp_millis(),
        // Air pressure in hPa: Defaults to standard pressure (1013.25 hPa) with a small random fluctuation between -3.0 to +3.0.
        "airp": airp.unwrap_or_else(|| (1013.25 + rng.gen_range(-3.0..3.0))),
        // Light level as a percentage in lx
        "lght": lght.unwrap_or_else(|| simulation_lux(day_fraction) as i32),
        // Temperature in degrees Celsius
        "temp": temp.unwrap_or_else(|| (radians.sin().max(0.0) * 20.0 + 10.0).round() as f32),
        // Humidity as a percentage (0-100%):
        "humd": humd.unwrap_or_else(|| simulated_humidity(day_fraction) as f32),
        // Sensor Id
        "sId": id,
        // User customer key
        "cId": customer_id
    });

    let env_topic = format!("{prefix}/{customer_id}/{id}/{index}");

    tracing::debug!("Send: {}", &env_msg);

    client.publish(env_topic, to_vec(&env_msg)?)?;

    Ok(())
}
