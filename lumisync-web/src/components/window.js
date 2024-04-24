import SensorGraph from "./sensor-graph.js";

const sheet = new CSSStyleSheet();
sheet.replaceSync`
.container {
  border: 1px solid #eee;
  border-radius: 5px;
  box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
  padding: 20px;
  display: flex;
  flex-direction: column;
  gap: 10px;

  & > .summary {
    display: flex;
    flex-direction: row;
    align-items: center;

    & > .info {
      flex: auto;

      .state {
        color: red;
        padding: 0 0.5rem;

        &::before {
          content: "State: ";
          color: black;
        }
      }

      .name {
        color: gray;
        padding: 0 0.5rem;

        &::before {
          content: "Name: ";
          color: black;
        }
      } 
    }

    & > button {
      padding: 0.3rem 1rem;
      border: 1px solid #ccc;
      border-radius: 5px;
      background-color: #007bff;
      color: white;
      cursor: pointer;
      transition: background-color 0.3s;
      &:hover {
        background-color: #0056b3;
      }
    }

    & > .calibrate {
      padding: 0.3rem 0.6rem;
      background-color: red;
      &:hover {
        background-color: #0056b3;
      }
    }
  }
}
`;

class Window extends HTMLElement {
    static observedAttributes = ["window-id", "window-data"];
    #shadowRoot;
    #container;

    constructor() {
        super();
        this.#shadowRoot = this.attachShadow({ mode: "open" });
        this.#shadowRoot.adoptedStyleSheets = [sheet];
        this.#container = this.#shadowRoot.appendChild(document.createElement("div"));
        this.#container.className = "container";
    }

    get windowId() { return this.getAttribute("window-id"); }

    set windowId(value) { this.setAttribute("window-id", value); }

    get windowData() { return JSON.parse(this.getAttribute("window-data")); }

    set windowData(value) { this.setAttribute("window-data", value); }

    connectedCallback() {
        const { sensor_id, ...data } = this.windowData;

        this.#container.innerHTML = null;

        this.updateHeader(data);
        this.updateSensors(sensor_id);
    }

    attributeChangedCallback(name, oldValue, newValue) {
        if (name === "window-data" && oldValue !== newValue) {
            const { sensor_id, ...data } = this.windowData;

            this.#container.innerHTML = null;

            this.updateHeader(data);
            this.updateSensors(sensor_id);
        }
    }

    updateHeader({ name, state } = {}) {
        const summary = this.#container.appendChild(document.createElement("div"));
        summary.className = "summary";

        const info = document.createElement("span");
        info.className = "info";
        info.innerHTML = `
          <span class="name">${name}</span>
          <span class="state">${state}</span>
        `;

        const switchBtn = document.createElement("button");
        switchBtn.innerText = "Start";

        const calibrateBtn = document.createElement("button");
        calibrateBtn.className = "calibrate"
        calibrateBtn.innerHTML = "&#x21bb;";

        summary.append(info, switchBtn, calibrateBtn);
    }

    updateSensors(sensorId) {
        const graph = new SensorGraph();
        graph.sensorId = sensorId;

        this.#container.append(graph);
    }
}

customElements.define("lumisync-window", Window);

export default Window;
