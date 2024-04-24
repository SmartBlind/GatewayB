import { API } from "../index.js";

class Setting extends HTMLElement {
    connectedCallback() {
        const form = this.appendChild(this.createForm());

        form.addEventListener("submit", this.saveConfig.bind(this));
    }

    createForm() {
        const form = document.createElement("form");

        form.innerHTML = `
          <div>
            <label for="user">Set User:</label>
            <input type="text" name="user_id" placeholder="User Id / Email">
          </div>
          <div>
            <label for="temp">Set Expected Temperature:</label>
            <input type="number" name="light" min="0" max="20" step="1" value="6" placeholder="Light Lux" />
          </div>
          <div>
            <label for="temp">Set Expected Temperature:</label>
            <input type="number" name="temperature" min="10" max="30" step="0.5" value="10" placeholder="Temp °C"/>
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

        try {
            const response = await fetch(API.setting, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(formData)
            });

            if (response.ok) {
                self.dispatchEvent(new CustomEvent("setup", {
                    detail: formData
                }));
                console.log("Configuration saved successfully!");
            } else {
                console.error("Failed to save configuration");
            }
        } catch (error) {
            console.error("Internal error:", error);
        }
    }
}

customElements.define("lumisync-setting", Setting);

export default Setting;
