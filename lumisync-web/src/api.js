export const API = {
    "control": `${globalThis.__APP_API_URL__}/control`,
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

export function streamSensorData(sensorId, callback) {
    const eventSource = new EventSource(`${API.sensors}/${sensorId}`);

    eventSource.onmessage = (event) => callback?.(JSON.parse(event.data));

    return eventSource;
}