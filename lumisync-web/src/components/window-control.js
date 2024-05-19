import styleSheet from "./window-control.css?raw";

class WindowControl extends HTMLElement {
    static observedAttributes = ["window-id"];
    #styleDeclaration;
    #elements = { };

    constructor() {
        super();
        const shadowRoot = this.attachShadow({ mode: "open" });
        const sheet = new CSSStyleSheet();

        sheet.replace(styleSheet).then(style => {
            shadowRoot.adoptedStyleSheets = [style];
            this.#styleDeclaration = [...style.cssRules]
                .find(rule => rule.selectorText === ".slider")
                .style;
        });

        this.#elements = { ...this.createController(shadowRoot) };
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

    createController(container, { min = -1.0, max = 1.0, value = 0, step = 0.01 } = {}) {
        const sliderContainer = container.appendChild(document.createElement("div"));
        sliderContainer.className = "slider";

        const statePoint = sliderContainer.appendChild(document.createElement("input"));
        Object.assign(statePoint, { type: "range", id: "current", min, max, value, step });

        const stateSlider = sliderContainer.appendChild(document.createElement("input"));
        Object.assign(stateSlider, { type: "range", id: "expected", min, max, value, step });

        const stateInput = container.appendChild(document.createElement("input"));
        Object.assign(stateInput, { type: "number", min, max, value, step });

        const switchButton = container.appendChild(document.createElement("button"));
        switchButton.className = "switch";
        switchButton.textContent = "start";

        const calibrateButton = container.appendChild(document.createElement("button"));
        calibrateButton.className = "calibrate";
        calibrateButton.innerText = "↻";

        return  { statePoint, stateSlider, stateInput, switchButton, calibrateButton };
    }

    updateSlider(variables) {
        for (const [key, value] of Object.entries(variables)) {
            this.#styleDeclaration.setProperty(`--${key}`, value);
        }
    }
}

customElements.define("lumisync-window-control", WindowControl);

export default WindowControl;