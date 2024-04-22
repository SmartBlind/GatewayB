class Setting extends HTMLElement {
    connectedCallback() {
        this.innerHTML = `
          <div id="config-form">
            <label for="user">Set Global User Keys:</label>
            <input type="text" id="user" name="user">

            <label for="temperature">Set Global Temperature:</label>
            <input type="number" id="temperature" name="temperature" min="10" max="30" step="0.5">

            <button onclick="this.saveConfig()">Save Configuration</button>
          </div>
        `;
    }

    saveConfig() {
        const temperature = this.querySelector("#temperature").value;

        console.log('Configuration Saved:', { temperature });
    }
}

customElements.define("lumisync-setting", Setting);

export default Setting;
