import { saveSettings } from "../api.js";

import styleSheet from "./setting.css?raw";

class Setting extends HTMLElement {
    #form;

    constructor() {
        super();
        const shadowRoot = this.attachShadow({ mode: "open" });
        const sheet = new CSSStyleSheet();

        sheet.replace(styleSheet).then(style => shadowRoot.adoptedStyleSheets = [style]);

        this.#form = this.createForm(shadowRoot);
        this.#form.addEventListener("submit", this.saveConfig.bind(this));
    }

    createForm(parent) {
        const form = parent.appendChild(document.createElement("form"));
        form.innerHTML = `
          <label for="light">Set Expected Light Lumen:</label>
          <input type="number" name="light" id="light"
                 min="0" max="20" step="1" value="6"
                 placeholder="Light Lux" />
          <label for="temperature">Set Expected Temperature:</label>
          <input type="number" name="temperature" id="temperature"
                 min="10" max="30" step="0.5" value="10"
                 placeholder="Temp °C" />
          <input type="submit" value="Save Configuration" />
        `;

        return form;
    }

    async saveConfig(event) {
        event.preventDefault();

        const formData = Object.fromEntries(
            Array.from(new FormData(event.target).entries()).map(([key, value]) => {
                const possibleNumber = Number(value);
                return [key, isNaN(possibleNumber) ? value : possibleNumber];
            })
        );

        await saveSettings(formData, () => {
            self.dispatchEvent(new CustomEvent("setup", { detail: formData }))
        });
    }
}

customElements.define("lumisync-setting", Setting);

export default Setting;
