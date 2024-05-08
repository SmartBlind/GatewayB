pub struct PIDController {
    // Proportional gain
    kp: f64,
    // Integral gain
    ki: f64,
    // Derivative gain
    kd: f64,

    set_point: f64,
    previous_error: f64,
    integral: f64,
}

impl PIDController {
    fn new(kp: f64, ki: f64, kd: f64, set_point: f64) -> Self {
        Self {
            kp,
            ki,
            kd,
            set_point,
            previous_error: 0.0,
            integral: 0.0,
        }
    }

    fn update(&mut self, measurement: f64, dt: f64) -> f64 {
        let error = self.set_point - measurement;
        let derivative = (error - self.previous_error) / dt;

        self.integral += error * dt;
        self.previous_error = error;

        // PID: u(t) = Kp*e(t) + Ki*∫e(t)dt + Kd*de(t)/dt
        self.kp * error + self.ki * self.integral + self.kd * derivative
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integral_accumulation() {
        let mut pid = PIDController::new(1.2, 0.01, 0.1, 10.0);
        let dt = 0.1;
        let mut actual_value = 8.0; // Initial error of 2

        pid.update(actual_value, dt);

        actual_value = 9.0; // Reduced error of 1
        let control = pid.update(actual_value, dt);

        assert!(pid.integral > 0.0, "Integral should accumulate error over time");
        assert!(control > 0.0, "Control output should be positive after multiple updates");
    }
}