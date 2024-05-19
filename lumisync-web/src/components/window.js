import WindowControl from "./window-control.js";
import SensorGraph from "./sensor-graph.js";

import styleSheet from "./window.css?raw";

class Window extends HTMLElement {
    static observedAttributes = ["window-id"];
    #elements = {};
    #model = {};

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
        details.style.display = "none";

        const control = new WindowControl();
        details.append(control);

        this.toggleContent = this.toggleContent.bind(this);

        this.#elements = { container, summary, details, control };
    }

    get windowId() { return this.getAttribute("window-id"); }

    set windowId(value) { this.setAttribute("window-id", value); }

    get windowData() { return this.#model; }

    set windowData(value) {
        this.#model = { ...this.#model, ...value };
        this.updateHeader(this.#elements.summary, this.#model);
    }

    connectedCallback() {
        this.updateHeader(this.#elements.summary, this.#model);
        this.#elements.summary.addEventListener("click", this.toggleContent);
    }

    disconnectedCallback() {
        this.#elements.summary.removeEventListener("click", this.toggleContent);
        updateHeader(this.#elements.summary);
    }

    attributeChangedCallback(name, oldValue, newValue) {
        if (name === "window-id" && oldValue !== newValue) {
            this.updateHeader(this.#elements.summary);
        }
    }

    updateHeader(container, { name = "Unknown", state = NaN } = {}) {
        container.innerHTML = `
          <span class="name">${name}</span>
          <span class="state">${state}</span>
        `;
    }

    toggleContent() {
        this.#model.show = !this.#model.show;
        this.#elements.details.style.display = this.#model.show ? "block" : "none";
    }
}

customElements.define("lumisync-window", Window);

export default Window;
