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
        details.style.display = "none";

        this.toggleContent = this.toggleContent.bind(this);

        this.#elements = { container, summary, details };
    }

    get sensorId() { return this.getAttribute("sensor-id"); }

    set sensorId(value) { this.setAttribute("sensor-id", value); }

    set sensorData(value) {
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
        this.graph?.dispose();
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

    toggleContent() {
        this.#model.show = !this.#model.show;
        this.#elements.details.style.display = this.#model.show ? "block" : "none";
        this.updateSensors(this.#elements.details, this.sensorId);
    }

    updateSensors(container, id) {
        if (this.#model.show) {
            if (!isNaN(Number(id)) && Number(id) > 0) {
                this.graph ??= new SensorGraph(container);
                this.graph.updateCanvas(Number(id));
            }
        } else {
            this.graph?.dispose();
        }
    }
}

customElements.define("lumisync-sensor", Sensor);

export default Sensor;
