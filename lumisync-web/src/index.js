import { Dashboard, Debug, RegionList, SensorList, User, WindowList } from "./components/index.js";
import { authUser, loginUser } from "./api.js";

import "./style.css";

/** @type {{[key: string]: { event: CustomEvent<{type: string}>, element: HTMLElement}}} */
export const NAV_TARGET = {
    "region": {
        groups: new Set(["sensor", "window"]),
        event: new CustomEvent("navigate", { detail: "region" }),
        element: new RegionList(),
    },
    "sensor": {
        event: new CustomEvent("navigate", { detail: "sensor" }),
        element: new SensorList(),
    },
    "window": {
        event: new CustomEvent("navigate", { detail: "window" }),
        groups: new Set(["debug"]),
        element: new WindowList(),
    },
    "debug": {
        event: new CustomEvent("navigate", { detail: "debug" }),
        element: new Debug(),
    }
};

/**
 * In global context, defined few global events for resource management:
 * - **navigate**: Navigate to target scope.
 * - **login**: Render dashboard panel.
 * - **logout**: Render auth panel.
 */
void async function main(app) {
    const mode = globalThis.__APP_ENV__;

    const dashboard = new Dashboard(NAV_TARGET);
    const user = new User();

    function renderDashboardPage() {
        dashboard.removeAttribute("style");
        user.style.display = "none";
        app?.insertAdjacentElement("afterbegin", dashboard);
        self.removeEventListener("login", renderDashboardPage);
        self.addEventListener("logout", renderAuthPage);
    }

    function renderAuthPage() {
        user.removeAttribute("style");
        dashboard.style.display = "none";
        app?.insertAdjacentElement("afterbegin", user);
        self.removeEventListener("logout", renderAuthPage);
        self.addEventListener("login", renderDashboardPage);
    }

    renderAuthPage();

    // If token exist, auth it directly and open dashboard if success.
    if (!!globalThis.token) {
        await authUser(data => globalThis.token = data);
        app?.insertAdjacentElement("afterbegin", dashboard);
    }

    if (mode === "development") {
        // Clean development cache.
        window.addEventListener("beforeunload", () => localStorage.removeItem("auth_token"));

        let certified = false;
        loginUser({ email: "test@test.com", password: "test" }, data => globalThis.token = data);

        const text = [{ event: "login", description: "To dashboard" }, { event: "logout", description: "To auth"}];

        const enter = document.createElement("button");
        enter.textContent = text[certified | 0].description;
        Object.assign(enter.style, {
            position: "fixed", right: "10px", bottom: "10px", width: "135px", padding: "6px",
            backgroundColor: "#f39c12", color: "white", border: "none", borderRadius: "5px",
            cursor: "pointer", boxShadow: "0 4px 8px rgba(0, 0, 0, 0.1)"
        });

        app?.insertAdjacentElement("beforeend", enter);
        enter.addEventListener("click", () => {
            certified = !certified;
            self.dispatchEvent(new Event(text[certified ^ 1].event));
            enter.textContent = text[certified | 0].description;
        });
    }
}(document.getElementById("app"));
