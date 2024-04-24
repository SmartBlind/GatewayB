import { Window } from "./index.js";
import { API } from "../index.js";

class WindowList extends HTMLElement {
    static observedAttributes = ["user-id"];
    #container;
    #windows = new Map();

    get userId() {
        return this.getAttribute("user-id");
    }

    set userId(value) {
        this.setAttribute("user-id", value);
    }

    connectedCallback() {
        this.#container = this.appendChild(document.createElement("div"));
        this.fetchData(this.userId).then();
    }

    attributeChangedCallback(name, oldValue, newValue) {
        if (name === "user-id" && oldValue !== newValue) {
            this.fetchData(this.userId).then();
        }
    }

    async fetchData(userId) {
        if (!!userId) {
            try {
                const response = await fetch(`${API.windows}/user/${userId}`);
                if (response.ok) {
                    this.#container.textContent = null;
                    const data = await response.json();

                    for (const { id, ...props } of data) {
                        let window = new Window();
                        window.windowId = id;
                        window.windowData = JSON.stringify(props);
                        this.#windows.set(id, window); // TODO: reduex style insert
                        this.#container.appendChild(window);
                    }
                }
            } catch (error) {
                console.error(error);
            }
        } else {
            this.#container.textContent = "Require setup user id";
        }
    }
}

customElements.define("lumisync-window-list", WindowList);

export default WindowList;