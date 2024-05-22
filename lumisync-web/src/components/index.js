export { default as Dashboard } from "./dashboard.js";
export { default as GanttGraph } from "./gantt-graph.js";
export { default as LoadingSpinner } from "./loading.js";
export { default as Region } from "./region.js";
export { default as RegionList } from "./region-list.js";
export { default as SensorGraph } from "./sensor-graph.js";
export { default as Sensor } from "./sensor.js";
export { default as SensorList } from "./sensor-list.js";
export { default as Setting } from "./setting.js";
export { default as SettingList } from "./setting-list.js";
export { default as User } from "./user.js";
export { default as Window } from "./window.js";
export { default as WindowControl } from "./window-control.js";
export { default as WindowList } from "./window-list.js";

export { default as Debug } from "./debug.js";

export class Store {
    #reducer;
    #state;
    #listeners;

    constructor(reducer, initialState) {
        this.#reducer = reducer;
        this.#state = initialState;
        this.#listeners = [];
    }

    get state() { return this.#state; }

    dispatch(action) {
        this.#state = this.#reducer(this.#state, action);
        this.#listeners.forEach(listener => listener());
    }

    subscribe(listener) {
        this.#listeners.push(listener);
        return () => {
            this.#listeners = this.#listeners.filter(l => l !== listener);
        };
    }
}
