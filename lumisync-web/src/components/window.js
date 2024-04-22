class Window extends HTMLElement {
    connectedCallback() {
        this.innerHTML = `<ul id="windowList">${this.generateList()}</ul>`;
    }

    generateList() {
        const windows = [
            { temperature: 15, state: 'Open' },
            { temperature: 15, state: 'Closed' },
            { temperature: 15, state: 'Closed' },
            { temperature: 15, state: 'Open' }
        ];
        return windows.map((win, i) => `<li>${i}: ${win.temperature}, ${win.state}</li>`).join('');
    }
}

customElements.define("lumisync-window", Window);

export default Window;
