import { getSensors } from "../api.js";
import { Store } from "./index.js";
import LoadingSpinner from "./loading.js";
import Sensor from "./sensor.js";

const LOAD_SENSORS_REQUEST = "LOAD_SENSORS_REQUEST";
const LOAD_SENSORS_SUCCESS = "LOAD_SENSORS_SUCCESS";
const SET_SENSOR_FILTER = "SET_SENSORS_FILTER";
const UPDATE_SENSOR = "UPDATE_SENSOR";

const loadSensorsRequest = () => ({ type: LOAD_SENSORS_REQUEST });
const loadSensorsSuccess = (sensors) => ({ type: LOAD_SENSORS_SUCCESS, payload: sensors });
const setSensorsFilter = (filter) => ({ type: SET_SENSOR_FILTER, payload: filter });
const updateSensor = (sensor) => ({ type: UPDATE_SENSOR, payload: sensor });

const initialState = { loading: false, sensors: {}, filter: () => true };

const sensorsReducer = (state = initialState, action) => {
    switch (action.type) {
        case LOAD_SENSORS_REQUEST:
            return {
                ...state,
                loading: true
            };
        case LOAD_SENSORS_SUCCESS:
            return {
                ...state,
                loading: false,
                sensors: action.payload.reduce((acc, { id, ...data }) => {
                    acc[id] = { data, visible: true, dirty: true };
                    return acc;
                }, {})
            };
        case SET_SENSOR_FILTER:
            return {
                ...state,
                filter: action.payload,
                sensors: Object.fromEntries(
                    Object.entries(state.sensors).map(([id, sensorState]) => [
                        id,
                        { ...sensorState, visible: action.payload(sensorState.data) }
                    ])
                )
            };
        case UPDATE_SENSOR:
            const sensor = state.sensors[action.payload.id];
            return {
                ...state,
                sensors: {
                    ...state.sensors,
                    [action.payload.id]: {
                        ...sensor,
                        data: { ...sensor.data, ...action.payload },
                        dirty: true
                    }
                }
            }
        default: return state;
    }
};

class SensorList extends HTMLElement {
    #store = new Store(sensorsReducer, initialState);
    #sensors = new Map();
    #unsubscribe;
    #spinner;

    constructor() {
        super();
        this.updateSensors = this.updateSensors.bind(this);

        this.#spinner = new LoadingSpinner();
        this.append(this.#spinner);
    }

    set filter(value) { this.#store.dispatch(setSensorsFilter(value)); }

    connectedCallback() {
        this.#unsubscribe = this.#store.subscribe(this.updateSensors);
        this.loadSensors().finally();
        this.listenEvent();
    }

    disconnectedCallback() {
        this.#unsubscribe();
    }

    updateSensors() {
        const state = this.#store.state;
        if (state.loading) {
            this.#spinner?.show();
        } else {
            this.#spinner?.hide();
            this.innerHTML = '';
        }

        for (const [id, sensorState] of Object.entries(state.sensors)) {
            if (sensorState.dirty) {
                if (this.#sensors.has(id)) {
                    const windowElement = this.#sensors.get(id);
                    windowElement.windowData = sensorState.data;
                } else {
                    let sensor = new Sensor();
                    sensor.sensorId = id;
                    sensor.sensorData = sensorState.data;
                    this.#sensors.set(id, sensor);
                    this.appendChild(sensor);
                }
                sensorState.dirty = false;
            }

            if (this.#sensors.has(id)) {
                const windowElement = this.#sensors.get(id);
                windowElement.style.display = sensorState.visible ? "block" : "none";
            }
        }
    }

    async loadSensors() {
        this.#store.dispatch(loadSensorsRequest());

        try {
            this.#store.dispatch(loadSensorsSuccess(await getSensors()));
        } catch (error) {
            console.error("Internal error:", error);
        }
    }

    listenEvent() {
        // TODO: SSE for update
        // streamSensor(data => {
        //     this.#store.dispatch(updateSensor(data));
        // });
    }
}

customElements.define("lumisync-sensor-list", SensorList);

export default SensorList;
