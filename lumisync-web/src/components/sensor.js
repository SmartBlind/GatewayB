import SensorGraph from "./sensor-graph.js";

import styleSheet from "./sensor.css?raw";

class Sensor extends HTMLElement {
    static observedAttributes = ["sensor-id"];
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

        this.#elements = { container, summary, details };
    }

    get sensorId() { return this.getAttribute("sensor-id"); }

    set sensorId(value) { this.setAttribute("sensor-id", value); }

    set sensorModel(value) {
        this.#model = { ...this.#model, ...value };
        this.updateHeader(this.#elements.summary, this.#model);
    }

    connectedCallback() {
        this.updateHeader(this.#elements.summary, this.#model);
        this.updateSensors(this.#elements.details, this.sensorId);
    }

    attributeChangedCallback(name, oldValue, newValue) {
        if (name === "sensor-id" && oldValue !== newValue) {
            this.updateHeader(this.#elements.summary);
            this.updateSensors(this.#elements.details, this.sensorId);
        }
    }

    updateHeader(container, { name = "Unknown" } = {}) {
        container.innerHTML = `<span class="name">${name}</span>`;
    }

    updateSensors(container, id) {
        container.innerHTML = null;

        const graph = new SensorGraph();
        graph.sensorId = id;

        container.append(graph);
    }
}

customElements.define("lumisync-sensor", Sensor);

export default Sensor;