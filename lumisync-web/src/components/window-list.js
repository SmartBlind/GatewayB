import Window from "./window.js";
import { getWindows } from "../api.js";

class WindowList extends HTMLElement {
    static observedAttributes = ["user-id"];
    #container;
    #windows = new Map();

    constructor() {
        super();
        this.#container = this.appendChild(document.createElement("div"));
    }

    get userId() {
        return this.getAttribute("user-id");
    }

    set userId(value) {
        this.setAttribute("user-id", value);
    }

    connectedCallback() {
        this.updateContent(this.userId).then();
    }

    attributeChangedCallback(name, oldValue, newValue) {
        if (name === "user-id" && oldValue !== newValue) {
            this.updateContent(this.userId).then();
        }
    }

    async updateContent(userId) {
        if (!!userId) {
            this.innerHTML = null;
            await getWindows(userId, data => {
                for (const { id, ...props } of data) {
                    let window = new Window();
                    window.windowId = id;
                    window.windowData = JSON.stringify(props);
                    this.#windows.set(id, window); // TODO: reduex style insert
                    this.appendChild(window);
                }
            });
        } else {
            this.innerText = "Require setup user id.";
        }
    }
}

customElements.define("lumisync-window-list", WindowList);

export default WindowList;