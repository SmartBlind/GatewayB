import { createSetting } from "../api.js";

import styleSheet from "./setting.css?raw";

class Setting extends HTMLElement {
    static observedAttributes = ["setting-id"];
    #elements = {};
    #model = {};
    #form;

    constructor() {
        super();
        const shadowRoot = this.attachShadow({ mode: "open" });
        const sheet = new CSSStyleSheet();

        sheet.replace(styleSheet).then(style => shadowRoot.adoptedStyleSheets = [style]);

        this.#form = this.createForm(shadowRoot);
        this.#elements.inputs = this.#form.querySelectorAll("input");
        this.#elements.editButton = this.#form.querySelector(".edit-btn");
        this.#elements.saveButton = this.#form.querySelector(".save-btn");

        this.#elements.editButton.addEventListener("click", this.enableEditing.bind(this));
        this.#form.addEventListener("submit", this.saveConfig.bind(this));
        this.toggleEditing(false);
    }

    get settingId() { return this.getAttribute("setting-id"); }

    set settingId(value) { this.setAttribute("setting-id", value); }

    set settingData(value) {
        this.#model = { ...this.#model, ...value };
        this.updateForm();
    }

    connectedCallback() {
        this.updateForm();
    }

    attributeChangedCallback(name, oldValue, newValue) {
        if (name === "sensor-id" && oldValue !== newValue) {
            this.updateForm();
        }
    }

    createForm(parent) {
        const form = parent.appendChild(document.createElement("form"));
        form.innerHTML = `
          <div class="line">
            <label for="light">Light Lumen:</label>
            <input type="number" name="light" id="light"
                   min="0" max="20" step="1" value="6"
                   placeholder="Light Lux" />
            <label for="temperature">Temperature:</label>
            <input type="number" name="temperature" id="temperature"
                   min="10" max="30" step="0.5" value="10"
                   placeholder="Temp °C" />
          </div>
          <div class="line">
            <label for="start">Start Time:</label>
            <input type="time" name="start" id="start" />
            <label for="end">End Time:</label>
            <input type="time" name="end" id="end" />
          </div>
          <div class="line">
            <label for="interval">Repeat every 24 hours:</label>
            <input type="checkbox" name="interval" id="interval" />
          </div>
          <div class="actions">
            <button type="button" class="edit-btn">Edit</button>
            <input type="submit" value="Save Configuration" class="save-btn" />
          </div>
        `;

        return form;
    }

    updateForm() {
        for (const input of this.#elements.inputs) {
            switch (input.type) {
                case "number":
                    input.value = this.#model[input.name] ?? NaN;
                    break;
                case "time":
                    input.value = this.#model[input.name] ?? Date.now();
                    break;
                case "checkbox":
                    input.checked = this.#model[input.name] || false;
                    break;
            }
        }
    }

    toggleEditing(enable) {
        this.#elements.inputs.forEach(input => input.disabled = !enable);
        this.#elements.saveButton.style.display = enable ? "inline-block" : "none";
    }

    enableEditing() {
        this.toggleEditing(true);
    }

    async saveConfig(event) {
        event.preventDefault();

        const formData = Object.fromEntries(
            Array.from(new FormData(event.target).entries()).map(([key, value]) => {
                const possibleNumber = Number(value);
                return [key, isNaN(possibleNumber) ? value : possibleNumber];
            })
        );

        try {
            const data = await createSetting(formData);
            console.log(data);
        } catch (error) {
            console.error("Internal error:", error);
        }
    }
}

customElements.define("lumisync-setting", Setting);

export default Setting;
