import { Dashboard, Debug, Setting, User, WindowList } from "./components/index.js";
import { authUser, loginUser } from "./api.js";

import "./style.css";

/** @type {{[key: string]: { event: CustomEvent<{type: string}>, element: HTMLElement}}} */
export const NAV_TARGET = {
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

void async function main() {
    const mode = globalThis.__APP_ENV__;

    const dashboard = new Dashboard(NAV_TARGET);
    const user = new User();

    document.body.insertAdjacentElement("afterbegin", user);
    self.addEventListener("login", () => {
        user.style.display = "none";
        dashboard.removeAttribute("style");
    });

    // If token exist, auth it directly and open dashboard if success.
    if (!!globalThis.token) {
        await authUser(data => {
            localStorage.setItem("auth_token", data);
            globalThis.token = data;
        });
        document.body.insertAdjacentElement("afterbegin", dashboard);
    } else {
        dashboard.style.display = "none";
        document.body.insertAdjacentElement("afterbegin", dashboard);
    }

    if (mode === "development") {
        loginUser({ email: "test@test.com", password: "test" }, data => {
            console.log("Gain sample account token.");
            localStorage.setItem("auth_token", data);
        });

        const enter = document.createElement("button");
        enter.textContent = "Jump to dashboard";

        document.body.insertAdjacentElement("afterbegin", enter);
        enter.addEventListener("click", () => {
            self.dispatchEvent(new Event("login"));
            enter.remove();
        });
    }
}();
