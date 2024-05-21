import { getSensorsByRegion, getWindowsByRegion } from "../api.js";
import styleSheet from "./region.css?raw";
import GanttGraph from "./gantt-graph.js";

class Region extends HTMLElement {
    static observedAttributes = ["region-id"];
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

    get regionId() { return this.getAttribute("region-id"); }

    set regionId(value) { this.setAttribute("region-id", value); }

    get regionData() { return this.#model; }

    set regionData(value) {
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
        if (name === "region-id" && oldValue !== newValue) {
            this.updateHeader(this.#elements.summary);
            this.loadRegionData(this.regionId).then(() => {
                this.#elements.details.style.display = this.#model.show ? "block" : "none";
                this.updateContent(this.#elements.details, this.#model);
            });
        }
    }

    updateHeader(container, { name = "Unknown", light = NaN, temperature = NaN } = {}) {
        container.innerHTML = `
          <span class="name">${name}</span>
          <div>
            <span class="light">${light}</span>
            <span class="temperature">${temperature}</span>
          </div>
        `;
    }

    toggleContent() {
        this.#model.show = !this.#model.show;
        if (this.#model.show && this.#model.dirty) {
            this.loadRegionData(this.regionId).then(() => {
                this.#elements.details.style.display = this.#model.show ? "block" : "none";
                this.updateContent(this.#elements.details, this.#model);
            });
        } else {
            this.#elements.details.style.display = this.#model.show ? "block" : "none";
        }
    }

    updateContent(container, { sensors, windows }) {
        container.innerHTML = `
          <div>
            <h3>Sensors</h3>
            <ul>
              ${sensors.map(sensor =>
                  `<li>#${sensor.id}: ${sensor.name}</li>`).join('')}
            </ul>
          </div>
          <div>
            <h3>Windows</h3>
            <ul>
              ${windows.map(window =>
                  `<li>#${window.id}: ${window.name}</li>`).join('')}
            </ul>
          </div>
        `;
        const wrapper = container.appendChild(document.createElement("div"));
        const header = wrapper.appendChild(document.createElement("h3"));
        header.textContent = "Settings";
        this.graph ??= new GanttGraph(wrapper);
    }

    async loadRegionData(id) {
        try {
            const [sensors, windows] = await Promise.all([getSensorsByRegion(id), getWindowsByRegion(id)]);
            this.#model = { ...this.#model, sensors, windows, dirty: false };
        } catch (error) {
            console.error("Internal error:", error);
        }
    }
}

customElements.define("lumisync-region", Region);

export default Region;
