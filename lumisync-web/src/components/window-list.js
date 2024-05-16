import { getWindows } from "../api.js";
import Window from "./window.js";

class WindowList extends HTMLElement {
    #windows = new Map();

    connectedCallback() {
        this.updateContent().then();
    }

    async updateContent() {
        await getWindows(data => {
            for (const { id, ...props } of data) {
                let window = new Window();
                window.windowId = id;
                window.windowData = JSON.stringify(props);
                this.#windows.set(id, window); // TODO: reduex style insert
                this.appendChild(window);
            }
        });
    }
}

customElements.define("lumisync-window-list", WindowList);

export default WindowList;