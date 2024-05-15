import { loginUser, registerUser } from "../api.js";

import styleSheet from "./user.css?raw";

const STATE = {
    login: 0,
    register: 1,
}

class User extends HTMLElement {
    #state = STATE.login;
    #elements = {};

    constructor() {
        super();
        const shadowRoot = this.attachShadow({ mode: "open" });
        const sheet = new CSSStyleSheet();

        sheet.replace(styleSheet).then(style => shadowRoot.adoptedStyleSheets = [style]);

        const container = shadowRoot.appendChild(document.createElement("div"));
        container.className = "container";

        const navbar = container.appendChild(document.createElement("ul"));
        this.createTabs(navbar);

        const section = container.appendChild(document.createElement("section"));
        section.className = "section";

        this.#elements = { ...this.createPanels(section) };
    }

    connectedCallback() {
        self.addEventListener("navigate", event => {
            if (event.detail in STATE) {
                this.updatePanel(STATE[event.detail]);
            }
        });

        for (const form of Object.values(this.#elements)) {
            form.addEventListener("submit", this.auth.bind(this));
        }
    }

    createTabs(container) {
        for (const key of Object.keys(STATE)) {
            const element = container.appendChild(document.createElement("li"));
            const button = element.appendChild(document.createElement("button"));
            button.addEventListener("click", () => {
                self.dispatchEvent(new CustomEvent("navigate", { detail: key }));
            });
            button.textContent = key;
        }
    }

    createPanels(container) {
        const loginForm = container.appendChild(document.createElement("form"));
        loginForm.style.display = "flex";
        loginForm.innerHTML = `
          <label for="email">Set User Email:</label>
          <input type="text" name="email" id="email" placeholder="User Email">
          <label for="password">Set Password:</label>
          <input type="text" name="password" id="password" placeholder="User Password">
          <input type="submit" value="Login" />
        `;
        const registerForm = container.appendChild(document.createElement("form"));
        registerForm.style.display = "none";
        registerForm.innerHTML = `
          <label for="group">Set User Group:</label>
          <input type="text" name="group" id="group" placeholder="User Group">
          <label for="email">Set User Email:</label>
          <input type="text" name="email" id="email" placeholder="User Email">
          <label for="password">Set Password:</label>
          <input type="text" name="password" id="password" placeholder="User Password">
          <input type="submit" value="Register" />
        `;

        return {
            register: registerForm,
            login: loginForm
        };
    }

    updatePanel(targetState) {
        const currentForm = this.#elements[Object.keys(STATE)[this.#state]];
        const nextForm = this.#elements[Object.keys(STATE)[targetState]];

        currentForm.style.display = "none";
        nextForm.style.display = "flex";

        this.#state = targetState;
    }

    async auth(event) {
        event.preventDefault();

        const formData = Object.fromEntries(Array.from(new FormData(event.target).entries()));

        switch (this.#state) {
            case STATE.login:
                await loginUser(formData, data => {
                    globalThis.token = data;
                    self.dispatchEvent(new Event("login"));
                });
                break;
            case STATE.register:
                await registerUser(formData, data => {
                    globalThis.token = data;
                    self.dispatchEvent(new Event("login"));
                });
                break;
            default:
                console.error("Unexpected user state.");
                break;
        }
    }
}

customElements.define("lumisync-user", User);

export default User;
