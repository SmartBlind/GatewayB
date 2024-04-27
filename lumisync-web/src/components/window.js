import WindowControl from "./window-control.js";
import SensorGraph from "./sensor-graph.js";

import styleSheet from "./window.css?raw";

class Window extends HTMLElement {
    static observedAttributes = ["window-id", "window-data"];
    #container;

    constructor() {
        super();
        const shadowRoot = this.attachShadow({ mode: "open" });
        const sheet = new CSSStyleSheet();

        sheet.replace(styleSheet).then(style => shadowRoot.adoptedStyleSheets = [style]);

        this.#container = shadowRoot.appendChild(document.createElement("div"));
        this.#container.className = "container";
    }

    get windowId() { return this.getAttribute("window-id"); }

    set windowId(value) { this.setAttribute("window-id", value); }

    get windowData() { return JSON.parse(this.getAttribute("window-data")); }

    set windowData(value) { this.setAttribute("window-data", value); }

    connectedCallback() {
        const { sensor_id, ...data } = this.windowData;

        this.#container.innerHTML = null;

        this.updateHeader(data);
        this.updateSensors(sensor_id);
    }

    attributeChangedCallback(name, oldValue, newValue) {
        if (name === "window-data" && oldValue !== newValue) {
            const { sensor_id, ...data } = this.windowData;

            this.#container.innerHTML = null;

            this.updateHeader(data);
            this.updateSensors(sensor_id);
        }
    }

    updateHeader({ name, state } = {}) {
        const summary = this.#container.appendChild(document.createElement("div"));
        summary.className = "summary";

        const info = document.createElement("div");
        info.className = "info";
        info.innerHTML = `
          <span class="name">${name}</span>
          <span class="state">${state}</span>
        `;

        const controller = new WindowControl();

        summary.append(info, controller);
    }

    updateSensors(sensorId) {
        const graph = new SensorGraph();
        graph.sensorId = sensorId;

        this.#container.append(graph);
    }
}

customElements.define("lumisync-window", Window);

export default Window;
