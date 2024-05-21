use std::convert::Infallible;
use std::sync::Arc;

use axum::extract::State;
use axum::response::Sse;
use axum::response::sse::Event;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast::Sender;
use tokio_stream::{Stream, wrappers};
use tokio_stream::StreamExt;

use crate::configs::storage::Storage;
use crate::models::sensor_data::SensorData;
use crate::models::window::Window;
use crate::services::actuator_service::ActuatorService;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ServiceEvent {
    SensorDataCreate(Vec<SensorData>),
    WindowUpdate(Vec<Window>),
}

#[derive(Clone)]
pub struct SSEState {
    pub actuator_service: Option<Arc<ActuatorService>>,
    pub storage: Arc<Storage>,
    pub sender: Sender<ServiceEvent>,
}

pub async fn sse_handler(
    State(state): State<SSEState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let receiver = state.sender.subscribe();

    let stream = wrappers::BroadcastStream::new(receiver)
        .filter_map(|result| {
            match result {
                Ok(ServiceEvent::SensorDataCreate(payload)) => {
                    Some(Ok(Event::default().data(serde_json::to_string(&payload).unwrap())))
                },
                Ok(ServiceEvent::WindowUpdate(payload)) => {
                    Some(Ok(Event::default().data(serde_json::to_string(&payload).unwrap())))
                },
                Err(_) => None,
            }
        });

    Sse::new(stream)
}