import { getWindows } from "../api.js";
import { Store } from "./index.js";
import LoadingSpinner from "./loading.js";
import Window from "./window.js";

const LOAD_WINDOWS_REQUEST = "LOAD_WINDOWS_REQUEST";
const LOAD_WINDOWS_SUCCESS = "LOAD_WINDOWS_SUCCESS";
const SET_WINDOW_FILTER = "SET_WINDOWS_FILTER";
const UPDATE_WINDOW = "UPDATE_WINDOW";

const loadWindowsRequest = () => ({ type: LOAD_WINDOWS_REQUEST });
const loadWindowsSuccess = (windows) => ({ type: LOAD_WINDOWS_SUCCESS, payload: windows });
const setWindowFilter = (filter) => ({ type: SET_WINDOW_FILTER, payload: filter });
const updateWindow = (window) => ({ type: UPDATE_WINDOW, payload: window });

const initialState = { loading: false, windows: {}, filter: () => true };

const windowsReducer = (state = initialState, action) => {
    switch (action.type) {
        case LOAD_WINDOWS_REQUEST:
            return {
                ...state,
                loading: true
            };
        case LOAD_WINDOWS_SUCCESS:
            return {
                ...state,
                loading: false,
                windows: action.payload.reduce((acc, { id, ...data }) => {
                    acc[id] = { data, visible: true, dirty: true };
                    return acc;
                }, {})
            };
        case SET_WINDOW_FILTER:
            return {
                ...state,
                filter: action.payload,
                windows: Object.fromEntries(
                    Object.entries(state.windows).map(([id, windowState]) => [
                        id,
                        { ...windowState, visible: action.payload(windowState.data) }
                    ])
                )
            };
        case UPDATE_WINDOW:
            const window = state.windows[action.payload.id];
            return {
                ...state,
                windows: {
                    ...state.windows,
                    [action.payload.id]: {
                        ...window,
                        data: { ...window.data, ...action.payload },
                        dirty: true
                    }
                }
            }
        default: return state;
    }
};

class WindowList extends HTMLElement {
    #store = new Store(windowsReducer, initialState);
    #windows = new Map();
    #unsubscribe;
    #spinner;

    constructor() {
        super();
        this.updateWindows = this.updateWindows.bind(this);

        this.#spinner = new LoadingSpinner();
        this.append(this.#spinner);
    }

    set filter(value) { this.#store.dispatch(setWindowFilter(value)); }

    connectedCallback() {
        this.#unsubscribe = this.#store.subscribe(this.updateWindows);
        this.loadWindows().finally();
        this.listenEvent();
    }

    disconnectedCallback() {
        this.#unsubscribe();
    }

    updateWindows() {
        const state = this.#store.state;
        if (state.loading) {
            this.#spinner?.show();
        } else {
            this.#spinner?.hide();
            this.innerHTML = '';
        }

        for (const [id, windowState] of Object.entries(state.windows)) {
            if (windowState.dirty) {
                if (this.#windows.has(id)) {
                    const windowElement = this.#windows.get(id);
                    windowElement.windowData = windowState.data;
                } else {
                    let window = new Window();
                    window.windowId = id;
                    window.windowData = windowState.data;
                    this.#windows.set(id, window);
                    this.appendChild(window);
                }
                windowState.dirty = false;
            }

            if (this.#windows.has(id)) {
                const windowElement = this.#windows.get(id);
                windowElement.style.display = windowState.visible ? "block" : "none";
            }
        }
    }

    async loadWindows() {
        this.#store.dispatch(loadWindowsRequest());

        try {
            this.#store.dispatch(loadWindowsSuccess(await getWindows()));
        } catch (error) {
            console.error("Internal error:", error);
        }
    }

    listenEvent() {
        // TODO: SSE for update
        // streamWindow(data => {
        //     this.#store.dispatch(updateWindow(data));
        // });
    }
}

customElements.define("lumisync-window-list", WindowList);

export default WindowList;
