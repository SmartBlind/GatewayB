import styleSheet from "./dashboard.css?raw";

class Dashboard extends HTMLElement {
    #navigateGraph = {};
    #activePanels = new Set();
    #activeTarget = null; // The initial focus
    #multiSelect = false;

    constructor(graph) {
        super();
        const shadowRoot = this.attachShadow({ mode: "open" });
        const sheet = new CSSStyleSheet();

        sheet.replace(styleSheet).then(style => shadowRoot.adoptedStyleSheets = [style]);

        this.#navigateGraph = { ...graph };

        const navbar = shadowRoot.appendChild(document.createElement("ul"));
        navbar.className = "navbar";
        this.createTabs(navbar);

        const section = shadowRoot.appendChild(document.createElement("section"));
        section.className = "section";
        this.createPanels(section);
    }

    createTabs(container) {
        for (const [key, value] of Object.entries(this.#navigateGraph)) {
            const element = container.appendChild(document.createElement("li"));
            if (value.groups?.size > 0) {
                const buttonGroup = element.appendChild(document.createElement("div"));
                buttonGroup.className = "button-group";

                const button = buttonGroup.appendChild(document.createElement("button"));
                button.textContent = key;
                button.addEventListener("click", () => this.updatePanels(key));

                const marker = buttonGroup.appendChild(document.createElement("button"));
                marker.textContent = `❎`;
                marker.addEventListener("click", () => {
                    this.#multiSelect = !this.#multiSelect;
                    this.dispatchEvent(new CustomEvent("switch", {
                        detail: this.#multiSelect
                    }));
                    this.updateTabs(key, value.groups);
                });

                this.addEventListener("switch", ({ detail }) => {
                    marker.textContent = detail ? `✅` : `❎`
                });
            } else {
                const button = element.appendChild(document.createElement("button"));
                button.addEventListener("click", () => this.updatePanels(key));
                button.textContent = key;
                button.className = "tab";
            }
        }
    }

    createPanels(container) {
        container.append(
            ...Object.entries(this.#navigateGraph).map(([key, { element }], index) => {
                if (index === 0) {
                    this.#activePanels.add(key);
                } else {
                    element.style.display = "none";
                }

                return element;
            })
        );
    }

    updateTabs(key, groups) {
        if (this.#multiSelect) {
            this.#activeTarget = { key, groups };
            this.updatePanel(key);
        } else {
            this.#activeTarget = null;
            this.updatePanel(key);
        }
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
            this.#navigateGraph[key].element.style.display = "none";
        } else {
            this.#activePanels.add(key);
            this.#navigateGraph[key].element.style.display = "block";
        }

        self.dispatchEvent(this.#navigateGraph[key].event);
    }

    updatePanel(key) {
        this.#activePanels.forEach(panelKey => {
            this.#navigateGraph[panelKey].element.style.display = "none";
        });
        this.#activePanels.clear();
        this.#activePanels.add(key);
        this.#navigateGraph[key].element.style.display = "block";

        self.dispatchEvent(this.#navigateGraph[key].event);
    }
}

customElements.define("lumisync-dashboard", Dashboard);

export default Dashboard;
