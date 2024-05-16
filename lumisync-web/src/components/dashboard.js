import styleSheet from "./dashboard.css?raw";

class Dashboard extends HTMLElement {
    #elements = {};
    #model = {};

    #activePanels = new Set();
    #activeTarget = null; // The initial focus
    #multiSelect = false;

    constructor(model) {
        super();
        const shadowRoot = this.attachShadow({ mode: "open" });
        const sheet = new CSSStyleSheet();

        sheet.replace(styleSheet).then(style => shadowRoot.adoptedStyleSheets = [style]);

        const navbar = shadowRoot.appendChild(document.createElement("ul"));
        const section = shadowRoot.appendChild(document.createElement("section"));
        section.className = "section";

        this.#elements = { navbar, section }
        this.#model = model;
    }

    connectedCallback() {
        this.createTabs(this.#elements.navbar);
        this.createPanels(this.#elements.section);
    }

    createTabs(container) {
        for (const [key, value] of Object.entries(this.#model)) {
            const element = container.appendChild(document.createElement("li"));
            if (value.groups?.size > 0) {
                const buttonGroup = element.appendChild(document.createElement("div"));
                buttonGroup.className = "button-group";

                const button = buttonGroup.appendChild(document.createElement("button"));
                button.textContent = key;
                button.addEventListener("click", () => this.updatePanels(key));

                const marker = buttonGroup.appendChild(document.createElement("button"));
                marker.className = "marker"
                marker.textContent = "off";
                marker.addEventListener("click", () => this.updateTabs(key, value.groups));
            } else {
                const button = element.appendChild(document.createElement("button"));
                button.addEventListener("click", () => this.updatePanels(key));
                button.textContent = key;
                button.className = "tab";
            }
        }
    }

    updateTabs(key, groups) {
        this.#multiSelect = !this.#multiSelect;
        this.#elements.navbar.querySelectorAll(".marker").forEach(element => {
            element.textContent = this.#multiSelect ? "On" : "Off";
        });
        if (this.#multiSelect) {
            this.#activeTarget = { key, groups };
            this.updatePanel(key);
        } else {
            this.#activeTarget = null;
            this.updatePanel(key);
        }
    }

    createPanels(container) {
        container.append(
            ...Object.entries(this.#model).map(([key, { element }], index) => {
                if (index === 0) {
                    this.#activePanels.add(key);
                } else {
                    element.style.display = "none";
                }

                return element;
            })
        );
    }

    updatePanels(key) {
        if (this.#multiSelect) {
            if (this.#activeTarget?.groups.has(key)) {
                this.togglePanel(key);
            }
        } else {
            this.updatePanel(key);
        }
    }

    togglePanel(key) {
        if (this.#activePanels.has(key)) {
            this.#activePanels.delete(key);
            this.#model[key].element.style.display = "none";
        } else {
            this.#activePanels.add(key);
            this.#model[key].element.style.display = "block";
        }
    }

    updatePanel(key) {
        this.#activePanels.forEach(panelKey => {
            this.#model[panelKey].element.style.display = "none";
        });
        this.#activePanels.clear();
        this.#activePanels.add(key);
        this.#model[key].element.style.display = "block";
    }
}

customElements.define("lumisync-dashboard", Dashboard);

export default Dashboard;
