export const API = {
    "control": `${globalThis.__APP_API_URL__}/control`,
    "users": `${globalThis.__APP_API_URL__}/users`,
    "settings": `${globalThis.__APP_API_URL__}/settings`,
    "regions": `${globalThis.__APP_API_URL__}/regions`,
    "windows": `${globalThis.__APP_API_URL__}/windows`,
    "sensors": `${globalThis.__APP_API_URL__}/sensors`,
}

Object.defineProperty(globalThis, "token", {
    get() {
        return localStorage.getItem("auth_token");
    },
    set(value) {
        localStorage.setItem("auth_token", value);
    }
});

/**
 * Send serial port command [This is for debug]
 *
 * @param {string} command
 * @param {function(): void} callback
 * @return {Promise<void>}
 */
export async function control(command, callback) {
    try {
        const response = await fetch(`${API.control}/${command}`);

        if (response.ok) {
            callback?.();
            console.log("Send command successfully!");
        } else {
            console.error("Fail to send command.");
        }
    } catch (error) {
        console.error("Internal error:", error);
    }
}

/**
 * Register user, call `user_handle::create_user`.
 *
 * @param {{group: string, email: string, password: string, role: string}} data
 * @return {Promise<string>}
 */
export async function registerUser(data) {
    const response = await fetch(`${API.users}/register`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(data)
    });

    if (!response.ok) throw new Error("Failed to register user.");

    return await response.text();
}

/**
 * Authorize user, call `user_handle::authorize_user`.
 *
 * @param {function(string): void} callback
 * @return {Promise<string>}
 */
export async function authUser(callback) {
    const response = await fetch(`${API.users}/authorize`, {
        method: "GET",
        headers: {
            "Authorization": `Bearer ${globalThis.token}`
        }
    });

    if (!response.ok) throw new Error("Failed to auth account.");

    return await response.text();
}

/**
 * Authenticate user, call `user_handle::authenticate_user`.
 *
 * @param {{email: string, password: string}} data
 * @return {Promise<string>}
 */
export async function loginUser(data) {
    const response = await fetch(`${API.users}/authenticate`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(data)
    });

    if (!response.ok) throw new Error("Failed to login.");

    return await response.text();
}

/**
 * @typedef Region
 * @property {number} id - The region id.
 * @property {number} group_id - The group id who owns the region.
 * @property {string} name - The name of this region.
 * @property {number} light - The average light in region.
 * @property {number} temperature - The average temperature in region.
 */

/**
 * Get all regions control by current user, call `region_handle::get_regions`.
 *
 * @return {Promise<[Region]>}
 */
export async function getRegions() {
    const response = await fetch(API.regions, {
        method: "GET",
        headers: {
            "Authorization": `Bearer ${globalThis.token}`
        }
    });

    return response.ok ? await response.json() : [];
}

/**
 * Create region control by current user, call `region_handle::create_region`.
 *
 * @param {{user_ids?: number[], name: string, light?: number, temperature?: number}} data
 * @return {Promise<Region>}
 */
export async function createRegion(data) {
    const response = await fetch(API.regions, {
        method: "POST",
        headers: {
            "Authorization": `Bearer ${globalThis.token}`
        },
        body: JSON.stringify(data)
    });

    if (!response.ok) throw new Error("Fail to create regions.");

    return await response.json();
}

export async function saveSettings(data, callback) {
    try {
        const response = await fetch(API.settings, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(data)
        });

        if (response.ok) {
            callback?.();
            console.log("Configuration saved successfully!");
        } else {
            console.error("Failed to save configuration.");
        }
    } catch (error) {
        console.error("Internal error:", error);
    }
}

/**
 * @typedef Window
 * @property {number} id - The window id.
 * @property {number} region_id - The region id of this window.
 * @property {string} name - The name of this window.
 * @property {number} state - How much light pass through this window.
 */

/**
 * Get all windows control by current user, call `window_handle::get_windows`
 *
 * @return {Promise<[Window]>}
 */
export async function getWindows() {
    const response = await fetch(API.windows, {
        method: "GET",
        headers: {
            "Authorization": `Bearer ${globalThis.token}`
        }
    });

    return response.ok ? await response.json() : [];
}

/**
 * Get all sensors control by current user under target region, call
 * `window_handle::get_windows_by_region`
 *
 * @param {number} regionId
 * @return {Promise<[Window]>}
 */
export async function getWindowsByRegion(regionId) {
    const response = await fetch(`${API.windows}/region/${regionId}`, {
        method: "GET",
        headers: {
            "Authorization": `Bearer ${globalThis.token}`
        }
    });

    return response.ok ? await response.json() : [];
}

/**
 * @typedef Sensor
 * @property {number} id - The window id.
 * @property {number} region_id - The region id of this sensor.
 * @property {string} name - The name of this sensor.
 */

/**
 * Get all sensors control by current user, call `sensor_handle::get_sensors`
 *
 * @return {Promise<[Sensor]>}
 */
export async function getSensors() {
    const response = await fetch(API.sensors, {
        method: "GET",
        headers: {
            "Authorization": `Bearer ${globalThis.token}`
        }
    });

    return response.ok ? await response.json() : [];
}

/**
 * Get all sensors control by current user under target region, call
 * `sensor_handle::get_sensors_by_region`
 *
 * @param {number} regionId
 * @return {Promise<[Sensor]>}
 */
export async function getSensorsByRegion(regionId) {
    const response = await fetch(`${API.sensors}/region/${regionId}`, {
        method: "GET",
        headers: {
            "Authorization": `Bearer ${globalThis.token}`
        }
    });

    return response.ok ? await response.json() : [];
}

/**
 * @typedef SensorData
 * @property {number} id - The sensor record id.
 * @property {number} light - The light intensity.
 * @property {number} temperature - The temperature.
 * @property {Date} time - The record time.
 */

/**
 * Get freeze sensor data record, call `sensor_handle::get_sensor_data_in_range`
 *
 * @param {number} sensorId
 * @return {Promise<[SensorData]>}
 */
export async function getSensorData(sensorId) {
    const response = await fetch(`${API.sensors}/data/${sensorId}`, {
        method: "GET",
        headers: {
            "Authorization": `Bearer ${globalThis.token}`
        }
    });

    return response.ok ? await response.json() : [];
}

/**
 * Get live sensor data record by stream, call `sensor_handle::get_sensor_data`
 *
 * @param {number} sensorId
 * @param {function([SensorData]): void} callback
 * @return {EventSource}
 */
export function streamSensorData(sensorId, callback) {
    const eventSource = new EventSource(`${API.sensors}/data/sse/${sensorId}?token=${globalThis.token}`);

    eventSource.onmessage = (event) => callback?.(JSON.parse(event.data));

    return eventSource;
}
