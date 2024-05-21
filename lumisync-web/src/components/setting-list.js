import { getSettings } from "../api.js";
import { Store } from "./index.js";
import LoadingSpinner from "./loading.js";
import Setting from "./setting.js";

const LOAD_SETTINGS_REQUEST = "LOAD_SETTINGS_REQUEST";
const LOAD_SETTINGS_SUCCESS = "LOAD_SETTINGS_SUCCESS";
const SET_SETTINGS_FILTER = "SET_SETTINGS_FILTER";
const UPDATE_SETTING = "UPDATE_SETTING";

const loadSettingsRequest = () => ({ type: LOAD_SETTINGS_REQUEST });
const loadSettingsSuccess = (settings) => ({ type: LOAD_SETTINGS_SUCCESS, payload: settings });
const setSettingsFilter = (filter) => ({ type: SET_SETTINGS_FILTER, payload: filter });
const updateSetting = (setting) => ({ type: UPDATE_SETTING, payload: setting });

const initialState = { loading: false, settings: {}, filter: () => true };

const settingsReducer = (state = initialState, action) => {
    switch (action.type) {
        case LOAD_SETTINGS_REQUEST:
            return {
                ...state,
                loading: true
            };
        case LOAD_SETTINGS_SUCCESS:
            return {
                ...state,
                loading: false,
                settings: action.payload.reduce((acc, { id, ...data }) => {
                    acc[id] = { data, visible: true, dirty: true };
                    return acc;
                }, {})
            };
        case SET_SETTINGS_FILTER:
            return {
                ...state,
                filter: action.payload,
                sensors: Object.fromEntries(
                    Object.entries(state.settings).map(([id, settingState]) => [
                        id,
                        { ...settingState, visible: action.payload(settingState.data) }
                    ])
                )
            };
        case UPDATE_SETTING:
            const setting = state.settings[action.payload.id];
            return {
                ...state,
                settings: {
                    ...state.settings,
                    [action.payload.id]: {
                        ...setting,
                        data: { ...setting.data, ...action.payload },
                        dirty: true
                    }
                }
            }
        default: return state;
    }
}

class SettingList extends HTMLElement {
    #store = new Store(settingsReducer, initialState);
    #settings = new Map();
    #unsubscribe;
    #spinner;

    constructor() {
        super();
        this.updateSettings = this.updateSettings.bind(this);

        this.#spinner = new LoadingSpinner();
        this.append(this.#spinner);
    }

    set filter(value) { this.#store.dispatch(setSettingsFilter(value)); }

    connectedCallback() {
        this.#unsubscribe = this.#store.subscribe(this.updateSettings);
        this.loadSettings().finally();
        this.listenEvent();
    }

    disconnectedCallback() {
        this.#unsubscribe();
    }

    updateSettings() {
        const state = this.#store.state;
        if (state.loading) {
            this.#spinner?.show();
        } else {
            this.#spinner?.hide();
            this.innerHTML = '';
        }

        for (const [id, settingState] of Object.entries(state.settings)) {
            if (settingState.dirty) {
                if (this.#settings.has(id)) {
                    const settingElement = this.#settings.get(id);
                    settingElement.settingData = settingState.data;
                } else {
                    let setting = new Setting();
                    setting.settingId = id;
                    setting.settingData = settingState.data;
                    this.#settings.set(id, setting);
                    this.appendChild(setting);
                }
                settingState.dirty = false;
            }

            if (this.#settings.has(id)) {
                const settingElement = this.#settings.get(id);
                settingElement.style.display = settingState.visible ? "block" : "none";
            }
        }
    }

    async loadSettings() {
        this.#store.dispatch(loadSettingsRequest());

        try {
            this.#store.dispatch(loadSettingsSuccess(await getSettings()));
        } catch (error) {
            console.error("Internal error:", error);
        }
    }

    listenEvent() {

    }
}

customElements.define("lumisync-setting-list", SettingList);

export default SettingList;
