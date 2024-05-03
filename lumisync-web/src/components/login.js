import styleSheet from "./login.css?raw";

class Login extends HTMLElement {
    #form;

    constructor() {
        super();
        const shadowRoot = this.attachShadow({ mode: "open" });
        const sheet = new CSSStyleSheet();

        sheet.replace(styleSheet).then(style => shadowRoot.adoptedStyleSheets = [style]);

        this.#form = this.createForm(shadowRoot);
    }
}

customElements.define("lumisync-login", Login);

export default Login;