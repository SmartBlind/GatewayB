import { Dashboard, Debug, Setting, User, WindowList } from "./components/index.js";
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

void function main() {
    const dashboard = new Dashboard(NAV_TARGET);
    const mode = globalThis.__APP_ENV__;

    if (mode === "development") {
        const user = new User();
        const enter = document.createElement("button");
        enter.textContent = "Jump to dashboard";
        document.body.insertAdjacentElement("afterbegin", user);
        self.addEventListener("login", () => {
            user.style.display = "none";
            dashboard.removeAttribute("style");
        });

        document.body.insertAdjacentElement("afterbegin", enter);
        enter.addEventListener("click", () => {
            self.dispatchEvent(new Event("login"));
            enter.remove();
        });

        dashboard.style.display = "none";
        document.body.insertAdjacentElement("afterbegin", dashboard);
    } else {
        if (localStorage.getItem("auth_token")) {
            // TODO: validate the token
            document.body.insertAdjacentElement("afterbegin", dashboard);
        } else {
            const user = new User();
            document.body.insertAdjacentElement("afterbegin", user);
            self.addEventListener("login", () => {
                user.style.display = "none";
                dashboard.removeAttribute("style");
            });

            dashboard.style.display = "none";
            document.body.insertAdjacentElement("afterbegin", dashboard);
        }
    }
}();
