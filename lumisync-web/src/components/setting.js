import { saveSettings } from "../api.js";

const sheet = new CSSStyleSheet();
sheet.replaceSync`
form {
  padding: 1.5rem;
  border: 1px solid #eee;
  border-radius: 5px;
  box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
  display: flex;
  flex-direction: column;
  gap: 15px;
}

label {
  display: block;
  color: black;
  font-weight: bold;
  margin-bottom: 0.5rem;
}

input[type="text"],
input[type="number"],
input[type="submit"] {
  padding: 0.5rem;
  border: 1px solid #ccc;
  border-radius: 5px;
  width: 100%;
  box-sizing: border-box;
}

input[type="submit"] {
  display: block;
  margin: 0.5rem auto;
  width: calc(100% - 1rem);
  background-color: #007bff;
  color: white;
  cursor: pointer;
  transition: background-color 0.3s;
  &:hover {
    background-color: #0056b3;
  }
}
`;

class Setting extends HTMLElement {
    #shadowRoot;
    #form;

    constructor() {
        super();
        this.#shadowRoot = this.attachShadow({ mode: "open" });
        this.#shadowRoot.adoptedStyleSheets = [sheet];

        this.#form = this.#shadowRoot.appendChild(this.createForm());
        this.#form.addEventListener("submit", this.saveConfig.bind(this));
    }

    createForm() {
        const form = document.createElement("form");

        form.innerHTML = `
          <div>
            <label for="user_id">Set User:</label>
            <input type="text" name="user_id" id="user_id" placeholder="User Id / Email">
          </div>
          <div>
            <label for="light">Set Expected Temperature:</label>
            <input type="number" name="light" id="light"
                    min="0" max="20" step="1" value="6" placeholder="Light Lux" />
          </div>
          <div>
            <label for="temperature">Set Expected Temperature:</label>
            <input type="number" name="temperature" id="temperature"
                    min="10" max="30" step="0.5" value="10" placeholder="Temp °C"/>
          </div>
          <div>
            <input type="submit" value="Save Configuration" />
          </div>
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

        await saveSettings(formData, () => self.dispatchEvent(new CustomEvent("setup", { detail: formData })));
    }
}

customElements.define("lumisync-setting", Setting);

export default Setting;
