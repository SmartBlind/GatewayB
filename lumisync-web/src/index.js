import { Dashboard, Debug, RegionList, Setting, User, WindowList } from "./components/index.js";
import { authUser, loginUser } from "./api.js";

import "./style.css";

/** @type {{[key: string]: { event: CustomEvent<{type: string}>, element: HTMLElement}}} */
export const NAV_TARGET = {
    "region": {
        event: new CustomEvent("navigate", { detail: "region" }),
        element: new RegionList(),
    },
    "setting": {
        event: new CustomEvent("navigate", { detail: "setting" }),
        element: new Setting(),
    },
    "window": {
        event: new CustomEvent("navigate", { detail: "window" }),
        element: new WindowList(),
    },
    "debug": {
        event: new CustomEvent("navigate", { detail: "debug" }),
        element: new Debug(),
    }
};

void async function main(app) {
    const mode = globalThis.__APP_ENV__;

    const dashboard = new Dashboard(NAV_TARGET);
    const user = new User();

    app?.insertAdjacentElement("afterbegin", user);
    self.addEventListener("login", () => {
        user.style.display = "none";
        app?.insertAdjacentElement("afterbegin", dashboard);
    });

    // If token exist, auth it directly and open dashboard if success.
    if (!!globalThis.token) {
        await authUser(data => globalThis.token = data);
        app?.insertAdjacentElement("afterbegin", dashboard);
    }

    if (mode === "development") {
        // Clean development cache.
        window.addEventListener("beforeunload", () => localStorage.removeItem("auth_token"));

        let sample_user = { email: "test@test.com", password: "test" };
        loginUser(sample_user, data => globalThis.token = data);

        const enter = document.createElement("button");
        enter.textContent = "Jump to dashboard";

        app?.insertAdjacentElement("afterbegin", enter);
        enter.addEventListener("click", () => {
            self.dispatchEvent(new Event("login"));
            enter.remove();
        });
    }
}(document.getElementById("app"));
