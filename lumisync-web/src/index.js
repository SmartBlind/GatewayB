import { Graph, Setting, Window } from "./components/index.js";

/** @type {{[key: string]: { event: CustomEvent<{type: string}>, element: HTMLElement}}} */
const NAV_TARGET = {
    "setting": {
        event: new CustomEvent("navigate", { detail: "setting" }),
        element: new Setting(),
    },
    "graph": {
        event: new CustomEvent("navigate", { detail: "graph" }),
        element: new Graph(),
    },
    "window": {
        event: new CustomEvent("navigate", { detail: "window" }),
        element: new Window(),
    },
};

class HomeDashboard extends HTMLElement {
    #activePanel;

    constructor() {
        super();
        this.attachShadow({ mode: "open" });
        this.shadowRoot.append(this.createNavBar(), this.createPanel());
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

        self.addEventListener("navigate", event => {
            if (this.#activePanel) this.#activePanel.style.display = "none";
            this.#activePanel = NAV_TARGET[event.detail].element;
            this.#activePanel.style.display = "block";
        });

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
