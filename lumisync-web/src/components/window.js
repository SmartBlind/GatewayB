import { API } from "../index.js";

class Window extends HTMLElement {
    #container;

    connectedCallback() {
        this.#container = this.appendChild(document.createElement("ul"));
    }

    createItem({ name } = {}) {
        const item = document.createElement("li");

        item.textContent = name;

        this.#container.insertAdjacentElement("beforeend", item);
    }

    async fetchData() {
        try {
            const response = await fetch(`${API.windows}/1`)
            const data = await response.json();
            createItem(data.name);
        } catch (error) {
        }
    }
}

customElements.define("lumisync-window", Window);

export default Window;
