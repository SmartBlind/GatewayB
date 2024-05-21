use std::collections::HashMap;
use std::error;
use std::sync::Arc;

use chrono::Utc;
use tokio::sync::broadcast::Sender;
use tokio::sync::Mutex;

use analyser::pid_controller::PIDController;

use crate::configs::storage::Storage;
use crate::handles::sse_handle::ServiceEvent;
use crate::models::region::Region;
use crate::models::window::Window;

#[derive(Clone)]
pub struct AnalyserService {
    pub pid_controllers: Arc<Mutex<HashMap<i32, PIDController>>>,
    pub storage: Arc<Storage>,
    pub sender: Sender<ServiceEvent>,
}

impl AnalyserService {
    pub async fn new(storage: &Arc<Storage>, sender: &Sender<ServiceEvent>) -> Result<Self, Box<dyn error::Error>>{
        Ok(Self {
            pid_controllers: Arc::new(Mutex::new(HashMap::new())),
            storage: Arc::clone(&storage),
            sender: sender.clone(),
        })
    }

    pub fn start_listener(&self) {
        let mut receiver = self.sender.subscribe();
        let owned = self.to_owned();

        tokio::spawn(async move {
            while let Ok(event) = receiver.recv().await {
                if let ServiceEvent::SensorDataCreate(sensor_data) = event {
                    for data in sensor_data.iter() {
                        let dt = Utc::now().time() - data.time.time();

                        let region: Region = sqlx::query_as(
                            r#"
                            SELECT regions.* FROM sensors
                                JOIN regions ON sensors.region_id = regions.id
                                WHERE sensors.id = $1;
                            "#
                        )
                            .bind(&data.sensor_id)
                            .fetch_one(owned.storage.get_pool())
                            .await
                            .unwrap();

                        let average_light = (data.light + region.light) / 2;
                        let average_temperature = (data.temperature + region.temperature) / 2.0;

                        sqlx::query(
                            r#"
                            UPDATE regions SET light = $1, temperature = $2
                                WHERE id = $3;
                            "#
                        )
                            .bind(&average_light)
                            .bind(&average_temperature)
                            .bind(&data.sensor_id)
                            .execute(owned.storage.get_pool())
                            .await
                            .unwrap();

                        owned
                            .update(region.id, average_light, dt.num_seconds())
                            .await
                            .unwrap();
                    }
                }
            }
        });
    }

    pub async fn update(&self, region_id: i32, light: i32, dt: i64) -> Result<(), Box<dyn error::Error>> {
        let mut pid_controllers = self.pid_controllers.lock().await;

        if let Some(pid_controller) = pid_controllers.get_mut(&region_id) {
            let control_signal = pid_controller.update(light as f64, dt as f64);

            // Determine new state for the blinds based on control signal
            let new_state = (control_signal / 100.0).clamp(0.0, 1.0);

            let updated_windows: Vec<Window> = sqlx::query_as(
                r#"
                UPDATE windows SET state = $1
                    WHERE region_id = $2
                    RETURNING *;
                "#
            )
                .bind(&new_state)
                .bind(&region_id)
                .fetch_all(self.storage.get_pool())
                .await?;

            let event = ServiceEvent::WindowUpdate(updated_windows);

            self.sender.send(event)?;
        }

        Ok(())
    }
}
