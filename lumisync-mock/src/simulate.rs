pub fn simulation_lux(day_fraction: f64) -> f64 {
    let radians = day_fraction * 2.0 * std::f64::consts::PI;

    // Define maximum sunlight and moonlight lux levels
    const MAX_SUNLIGHT_LUX: f64 = 500.0;
    const MAX_MOONLIGHT_LUX: f64 = 5.0;

    // Smooth transition factors
    const SUNRISE_START: f64 = 0.23;
    const SUNRISE_END: f64 = 0.25;
    const SUNSET_START: f64 = 0.73;
    const SUNSET_END: f64 = 0.75;

    if day_fraction >= SUNRISE_START && day_fraction <= SUNSET_END {
        if day_fraction <= SUNRISE_END {
            // Sunrise - increase light smoothly using a sine function
            let sunrise_radians = ((day_fraction - SUNRISE_START) / (SUNRISE_END - SUNRISE_START)) * std::f64::consts::PI / 2.0;
            sunrise_radians.sin() * MAX_SUNLIGHT_LUX
        } else if day_fraction >= SUNSET_START {
            // Sunset - decrease light smoothly using a cosine function
            let sunset_radians = ((day_fraction - SUNSET_START) / (SUNSET_END - SUNSET_START)) * std::f64::consts::PI / 2.0;
            sunset_radians.cos() * MAX_SUNLIGHT_LUX
        } else {
            // Full daylight
            MAX_SUNLIGHT_LUX
        }
    } else {
        // Calculate moonlight assuming a peak at midnight using a cosine function
        let moon_effect = ((radians + std::f64::consts::PI).cos().max(0.0) * (MAX_MOONLIGHT_LUX - 0.01)) + 0.01;
        moon_effect
    }
}

pub fn simulated_humidity(day_fraction: f64) -> f64 {
    let radians = day_fraction * 2.0 * std::f64::consts::PI;

    if day_fraction >= 0.3 && day_fraction <= 0.7 {
        ((radians.sin().max(0.0) * 25.0) + 65.0).round()
    } else {
        ((radians.cos().max(0.0) * 30.0) + 60.0).round()
    }
}