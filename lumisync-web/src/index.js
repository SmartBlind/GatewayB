import { Setting, WindowList } from "./components/index.js";

export const API = {
    "setting": `${globalThis.__APP_API_URL__}/settings`,
    "windows": `${globalThis.__APP_API_URL__}/windows`,
    "sensors": `${globalThis.__APP_API_URL__}/sensors`,
}

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
};

class HomeDashboard extends HTMLElement {
    #shadowRoot;
    #panels = new Map();
    #activePanel;

    constructor() {
        super();

        this.#shadowRoot = this.attachShadow({ mode: "open" });
        this.#shadowRoot.append(this.createNavBar(), this.createPanel());
    }

    connectedCallback() {
        self.addEventListener("navigate", event => {
            if (this.#activePanel) this.#activePanel.style.display = "none";
            this.#activePanel = NAV_TARGET[event.detail].element;
            this.#activePanel.style.display = "block";
        });

        self.addEventListener("setup", event => {
            NAV_TARGET["window"].element.userId = event.detail["user_id"];
        });
    }

    createNavBar() {
        const container = document.createElement("ul");

        for (const [key, value] of Object.entries(NAV_TARGET)) {
            const element = container.appendChild(document.createElement("li"));
            const button = element.appendChild(document.createElement("button"));
            button.addEventListener("click", () => self.dispatchEvent(value.event));
            button.textContent = key;
        }

        return container;
    }

    createPanel() {
        const container = document.createElement("section");

        container.append(
            ...Object.values(NAV_TARGET).map(({ element }, index) => {
                if (index === 0) {
                    this.#activePanel = element;
                } else {
                    element.style.display = "none";
                }
                return element;
            })
        );

        return container;
    }
}

customElements.define("lumisync-dashboard", HomeDashboard);

document.body.innerHTML = "<lumisync-dashboard></lumisync-dashboard>";
