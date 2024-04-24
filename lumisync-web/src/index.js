import { Debug, Setting, WindowList } from "./components/index.js";
import "./style.css";

const sheet = new CSSStyleSheet();
sheet.replaceSync`
ul {
  list-style-type: none;
  margin: 0;
  padding: 0.3rem;
  display: flex;
  background-color: #f9f9f9;
  align-items: center;
  border-bottom: 1px solid gray;
}

li {
  float: left;
  margin: 0 0.3rem;
}

button {
  color: black;
  text-align: center;
  padding: 0.5rem 2.5rem;
  text-decoration: none;
  background-color: white;
  border: 1px solid gray;
  border-radius: 5px;
  cursor: pointer;
  transition: background-color 0.3s, box-shadow 0.3s;

  &:hover {
    background-color: #e8e8e8;
    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
  }
}

section {
  max-width: 600px;
  padding: 1rem;
  margin: 0 auto;
}
`;

/** @type {{[key: string]: { event: CustomEvent<{type: string}>, element: HTMLElement}}} */
export const NAV_TARGET = {
    "setting": {
        event: new CustomEvent("navigate", { detail: "setting" }),
        element: new Setting(),
    },
    "window": {
        event: new CustomEvent("navigate", { detail: "window" }),
        element: new WindowList(),
    },
    "debug": {
        event: new CustomEvent("navigate", { detail: "debug" }),
        element: new Debug(),
    }
};

class HomeDashboard extends HTMLElement {
    #shadowRoot;
    #activePanel;

    constructor() {
        super();
        this.#shadowRoot = this.attachShadow({ mode: "open" });
        this.#shadowRoot.adoptedStyleSheets = [sheet];
        this.#shadowRoot.append(this.createNavBar(), this.createPanel());
    }

    connectedCallback() {
        self.addEventListener("navigate", event => {
            if (this.#activePanel) this.#activePanel.style.display = "none";
            this.#activePanel = NAV_TARGET[event.detail].element;
            this.#activePanel.style.display = "block";
        });

        self.addEventListener("setup", event => {
            NAV_TARGET["window"].element.userId = event.detail["user_id"];
        });
    }

    createNavBar() {
        const container = document.createElement("ul");

        for (const [key, value] of Object.entries(NAV_TARGET)) {
            const element = container.appendChild(document.createElement("li"));
            const button = element.appendChild(document.createElement("button"));
            button.addEventListener("click", () => self.dispatchEvent(value.event));
            button.textContent = key;
        }

        return container;
    }

    createPanel() {
        const container = document.createElement("section");

        container.append(
            ...Object.values(NAV_TARGET).map(({ element }, index) => {
                if (index === 0) {
                    this.#activePanel = element;
                } else {
                    element.style.display = "none";
                }
                return element;
            })
        );

        return container;
    }
}

customElements.define("lumisync-dashboard", HomeDashboard);

document.body.innerHTML = `<lumisync-dashboard></lumisync-dashboard>`;
