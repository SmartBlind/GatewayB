import WindowControlSlider from "./window-control-slider.js";

import styleSheet from "./window-control.css?raw";

class WindowControl extends HTMLElement {
    static observedAttributes = ["window-id"];
    #elements = { };

    constructor() {
        super();
        const shadowRoot = this.attachShadow({ mode: "open" });
        const sheet = new CSSStyleSheet();

        sheet.replace(styleSheet).then(style => shadowRoot.adoptedStyleSheets = [style]);

        const slider = new WindowControlSlider();

        shadowRoot.appendChild(slider);

        const switchButton = shadowRoot.appendChild(document.createElement("button"));
        switchButton.className = "switch";
        switchButton.textContent = "start";

        const calibrateButton = shadowRoot.appendChild(document.createElement("button"));
        calibrateButton.className = "calibrate";
        calibrateButton.innerText = "↻";

        this.#elements = { slider, switchButton, calibrateButton };
    }

    connectedCallback() {
    }
}

customElements.define("lumisync-window-control", WindowControl);

export default WindowControl;