pub mod group;
pub mod sensor;
pub mod sensor_data;
pub mod setting;
pub mod user;
pub mod user_window;
pub mod window;
pub mod window_sensor;
pub mod window_setting;

pub trait Table {
    fn create(&self) -> String;
    fn dispose(&self) -> String;
}
