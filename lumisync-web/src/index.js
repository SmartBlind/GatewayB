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
}();
