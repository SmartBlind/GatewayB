export const API = {
    "control": `${globalThis.__APP_API_URL__}/control`,
    "users": `${globalThis.__APP_API_URL__}/users`,
    "settings": `${globalThis.__APP_API_URL__}/settings`,
    "windows": `${globalThis.__APP_API_URL__}/windows`,
    "sensors": `${globalThis.__APP_API_URL__}/sensors`,
}

// This is for debug
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

export async function registerUser(data, callback) {
    try {
        const response = await fetch(`${API.users}/register`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(data)
        });

        if (response.ok) {
            callback?.();
            console.log("Register user successfully!");
        } else {
            console.error("Failed to register user");
        }
    } catch (error) {
        console.error("Internal error:", error);
    }
}

export async function loginUser(data, callback) {
    try {
        const response = await fetch(`${API.users}/auth`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(data)
        });

        if (response.ok) {
            callback?.();
            console.log("Login successfully!");
        } else {
            console.error("Failed to login.");
        }
    } catch (error) {
        console.error("Internal error:", error);
    }
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

export async function getWindows(userId, callback) {
    try {
        const response = await fetch(`${API.windows}/user/${userId}`);

        if (response.ok) {
            callback?.(await response.json());
            console.log("Get windows successfully!");
        } else {
            console.error("Fail to get windows.");
        }
    } catch (error) {
        console.error("Internal error:", error);
    }
}

export async function getSensors(groupId, callback) {
    try {
        const response = await fetch(`${API.sensors}/${groupId}`);

        if (response.ok) {
            callback?.(await response.json());
            console.log("Get sensors successfully!");
        } else {
            console.error("Fail to get sensors.");
        }
    } catch (error) {
        console.error("Internal error:", error);
    }
}

export async function getSensorData(sensorId, callback) {
    try {
        const response = await fetch(`${API.sensors}/data/${sensorId}`);

        if (response.ok) {
            callback?.(await response.json());
            console.log("Get sensor data successfully!");
        } else {
            console.error("Fail to get sensor data.");
        }
    } catch (error) {
        console.error("Internal error:", error);
    }
}

export function streamSensorData(sensorId, callback) {
    const eventSource = new EventSource(`${API.sensors}/data/sse/${sensorId}`);

    eventSource.onmessage = (event) => callback?.(JSON.parse(event.data));

    return eventSource;
}