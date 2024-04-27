import styleSheet from "./window-control-slider.css?raw";

class WindowControlSlider extends HTMLElement {
    #styleDeclaration;
    #elements = { };

    constructor() {
        super();
        const shadowRoot = this.attachShadow({ mode: "open" });
        const sheet = new CSSStyleSheet();

        sheet.replace(styleSheet).then(style => {
            shadowRoot.adoptedStyleSheets = [style];
            this.#styleDeclaration = [...style.cssRules]
                .find(rule => rule.selectorText === ".container")
                .style;
        });

        this.#elements = this.createElements(shadowRoot);
    }

    connectedCallback() {
        this.#elements.stateSlider.addEventListener("input", event => {
            const value = event.target.value;
            this.updateSlider({ expected: value });
            this.#elements.stateInput.value = parseFloat(value).toFixed(2);
        }, false);
        this.#elements.stateInput.addEventListener("change", event => {
            const value = event.target.value;
            this.#elements.stateSlider.value = parseFloat(value).toFixed(2);
            this.updateSlider({ expected: value });
        });
    }

    createElements(parent, { min = -1.0, max = 1.0, value = 0, step = 0.01 } = {}) {
        const sliderContainer = parent.appendChild(document.createElement("div"));
        sliderContainer.className = "container";

        const statePoint = sliderContainer.appendChild(document.createElement("input"));
        Object.assign(statePoint, { type: "range", id: "current", min, max, value, step });

        const stateSlider = sliderContainer.appendChild(document.createElement("input"));
        Object.assign(stateSlider, { type: "range", id: "expected", min, max, value, step });

        const stateInput = parent.appendChild(document.createElement("input"));
        Object.assign(stateInput, { type: "number", min, max, value, step });

        return  { statePoint, stateSlider, stateInput };
    }

    updateSlider(variables) {
        for (const [key, value] of Object.entries(variables)) {
            this.#styleDeclaration.setProperty(`--${key}`, value);
        }
    }
}

customElements.define("lumisync-window-control-slider", WindowControlSlider);

export default WindowControlSlider;