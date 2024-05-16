import SensorList from "./sensor-list.js";

import styleSheet from "./region.css?raw";

class Region extends HTMLElement {
    static observedAttributes = ["region-id"];
    #elements = {};
    #model = {};
    #show = false;

    constructor() {
        super();
        const shadowRoot = this.attachShadow({ mode: "open" });
        const sheet = new CSSStyleSheet();

        sheet.replace(styleSheet).then(style => shadowRoot.adoptedStyleSheets = [style]);

        const container = shadowRoot.appendChild(document.createElement("div"));
        container.className = "container";

        const summary = container.appendChild(document.createElement("div"));
        summary.className = "summary";

        const details = container.appendChild(document.createElement("div"));
        details.className = "details";

        this.#elements = { container, summary, details };
    }

    get regionId() { return this.getAttribute("region-id"); }

    set regionId(value) { this.setAttribute("region-id", value); }

    get regionModel() { return this.#model; }

    set regionModel(value) {
        this.#model = { ...this.#model, ...value };
        this.updateHeader(this.#elements.summary, this.#model);
    }

    connectedCallback() {
        this.updateHeader(this.#elements.summary, this.#model);

        this.#elements.summary.addEventListener("click", () => {
            this.#show = !this.#show;
            this.updateContent(this.#elements.details, this.#show);
        });
    }

    disconnectedCallback() {
        this.#elements.summary.removeEventListener("click", () => {
            this.#show = !this.#show;
            this.updateContent(this.#elements.details, this.#show);
        });
    }

    attributeChangedCallback(name, oldValue, newValue) {
        if (name === "region-id" && oldValue !== newValue) {
            this.updateHeader(this.#elements.summary);
        }
    }

    updateHeader(container, { name = "Unknown", light = "NaN", temperature = "NaN" } = {}) {
        container.innerHTML = `
          <span class="name">${name}</span>
          <div>
            <span class="light">${light}</span>
            <span class="temperature">${temperature}</span>
          </div>
        `;
    }

    updateContent() {
        this.#show = !this.#show;
        this.#elements.details.style.display = this.#show ? "block" : "none";
        const regionList = new SensorList();
        this.#elements.details.appendChild(regionList);
    }
}

customElements.define("lumisync-region", Region);

export default Region;