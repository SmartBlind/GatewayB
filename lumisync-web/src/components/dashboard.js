import styleSheet from "./dashboard.css?raw";

class Dashboard extends HTMLElement {
    #elements = {};
    #panels = {};
    #active;

    constructor(panels) {
        super();
        const shadowRoot = this.attachShadow({ mode: "open" });
        const sheet = new CSSStyleSheet();

        sheet.replace(styleSheet).then(style => shadowRoot.adoptedStyleSheets = [style]);

        this.#elements.navbar = shadowRoot.appendChild(document.createElement("ul"));

        this.#elements.section = shadowRoot.appendChild(document.createElement("section"));
        this.#elements.section.className = "section";

        this.#panels = panels;
    }

    connectedCallback() {
        this.#elements = {
            tabs: this.createTabs(this.#elements.navbar),
            panels: this.createPanels(this.#elements.section)
        }
        self.addEventListener("navigate", event => {
            if (event.detail in this.#panels) {
                if (this.#active) this.#active.style.display = "none";
                this.#active = this.#panels[event.detail].element;
                this.#active.style.display = "block";
            }
        });
    }

    createTabs(container) {
        const tabs = {};

        for (const [key, value] of Object.entries(this.#panels)) {
            const element = container.appendChild(document.createElement("li"));
            const button = element.appendChild(document.createElement("button"));
            button.addEventListener("click", () => self.dispatchEvent(value.event));
            button.textContent = key;
            button.className = "tab";

            tabs[key] = element;
        }

        return tabs;
    }

    createPanels(container) {
        const panels = {};

        container.append(
            ...Object.entries(this.#panels).map(([key, { element }], index) => {
                if (index === 0) {
                    this.#active = element;
                } else {
                    element.style.display = "none";
                }

                panels[key] = element;

                return element;
            })
        );

        return panels;
    }
}

customElements.define("lumisync-dashboard", Dashboard);

export default Dashboard;
