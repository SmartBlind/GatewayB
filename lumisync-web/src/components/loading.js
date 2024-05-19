import styleSheet from "./loading.css?raw";

class LoadingSpinner extends HTMLElement {
    #container;

    constructor() {
        super();
        const shadowRoot = this.attachShadow({ mode: "open" });
        const sheet = new CSSStyleSheet();

        sheet.replace(styleSheet).then(style => shadowRoot.adoptedStyleSheets = [style]);

        this.#container = shadowRoot.appendChild(document.createElement("div"));
        this.#container.classList.add("container");

        const spinner = this.#container.appendChild(document.createElement("div"));
        spinner.className = "spinner";
    }

    show() {
        this.#container.classList.remove("hidden");
    }

    hide() {
        this.#container.classList.add("hidden");
    }
}

customElements.define("lumisync-loading-spinner", LoadingSpinner);

export default LoadingSpinner;