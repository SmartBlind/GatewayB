// import { API } from "../index.js";

class Window extends HTMLElement {
    static observedAttributes = ["window-id", "window-data"];
    #container;

    get windowId() { return this.getAttribute("window-id"); }

    set windowId(value) { this.setAttribute("window-id", value); }

    get windowData() { return JSON.parse(this.getAttribute("window-data")); }

    set windowData(value) { this.setAttribute("window-data", value); }

    connectedCallback() {
        this.#container = this.appendChild(document.createElement("div"));
    }

    attributeChangedCallback(name, oldValue, newValue) {
        if (oldValue === newValue) return;

        // switch (name) {
        //     case "window-id":
        //         this.#elements.id.textContent = newValue;
        //         break;
        //     case "window-data":
        //         this.#elements.count.textContent = newValue;
        //         break;
        // }
    }

    createElements({ name, data } = {}) {
        const item = document.createElement("li");

        item.textContent = name;

        this.#container.insertAdjacentElement("beforeend", item);

        return item;
    }
}

customElements.define("lumisync-window", Window);

export default Window;
