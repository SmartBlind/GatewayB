pub mod group;
pub mod sensor;
pub mod sensor_data;
pub mod setting;
pub mod user;
pub mod window;
pub mod window_sensor;

pub trait Table {
    fn create(&self) -> String;
    fn dispose(&self) -> String;
}
