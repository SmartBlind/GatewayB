import { control } from "../api.js";

class Debug extends HTMLElement {
    constructor() {
        super();
        const container = this.appendChild(document.createElement("div"));
        container.style.display = "flex";
        container.style.flexDirection = "column";
        container.style.gap = "1rem"

        const start1 = document.createElement("button");
        start1.textContent = "Counter-clockwise START";

        start1.addEventListener("click", () => control("START1"));

        const start2 = document.createElement("button");
        start2.textContent = "Clockwise START";

        start2.addEventListener("click", () => control("START2"));

        const stop = document.createElement("button");
        stop.textContent = "STOP";

        stop.addEventListener("click", () => control("STOP"));

        const cali = document.createElement("button");
        cali.textContent = "Calibrate";

        cali.addEventListener("click", () => control("CALI"));

        container.append(start1, start2, stop, cali);
    }
}

customElements.define("lumisync-debug", Debug);

export default Debug;
