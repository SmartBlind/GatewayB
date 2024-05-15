import styleSheet from "./region.css?raw";

class Region extends HTMLElement {
    static observedAttributes = ["region-id"];
    #regionModel = {};
    #container;

    constructor() {
        super();
        const shadowRoot = this.attachShadow({ mode: "open" });
        const sheet = new CSSStyleSheet();

        sheet.replace(styleSheet).then(style => shadowRoot.adoptedStyleSheets = [style]);

        this.#container = shadowRoot.appendChild(document.createElement("div"));
        this.#container.className = "container";
    }

    get regionId() { return this.getAttribute("region-id"); }

    set regionId(value) { this.setAttribute("region-id", value); }

    get regionModel() { return this.#regionModel; }

    set regionModel(value) {
        this.#regionModel = { ...this.#regionModel, ...value };

        this.updateHeader(this.#container, this.#regionModel);
    }

    connectedCallback() {
        this.#container.innerHTML = null;

        this.updateHeader(this.#container, this.#regionModel);
    }

    attributeChangedCallback(name, oldValue, newValue) {
        if (name === "region-id" && oldValue !== newValue) {
            this.#regionModel = {};
            this.#container.innerHTML = null;

            this.updateHeader(this.#container, this.#regionModel);
        }
    }

    updateHeader(container, { name, light, temperature } = {}) {
        const summary = container.appendChild(document.createElement("div"));
        summary.className = "summary";

        const info = document.createElement("div");
        info.className = "info";
        info.innerHTML = `
          <span class="name">${name}</span>
          <span class="light">${light}</span>
          <span class="temperature">${temperature}</span>
        `;

        summary.append(info);
    }
}

customElements.define("lumisync-region", Region);

export default Region;