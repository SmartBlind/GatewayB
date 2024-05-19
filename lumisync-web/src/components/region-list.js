import { getRegions } from "../api.js";
import { Store } from "./index.js";
import LoadingSpinner from "./loading.js";
import Region from "./region.js";

const LOAD_REGIONS_REQUEST = "LOAD_REGIONS_REQUEST";
const LOAD_REGIONS_SUCCESS = "LOAD_REGIONS_SUCCESS";
const UPDATE_REGION = "UPDATE_REGION";

const loadRegionsRequest = () => ({ type: LOAD_REGIONS_REQUEST });
const loadRegionsSuccess = (regions) => ({ type: LOAD_REGIONS_SUCCESS, payload: regions });
const updateRegion = (region) => ({ type: UPDATE_REGION, payload: region });

const initialState = { loading: false, regions: {} };

const regionsReducer = (state = initialState, action) => {
    switch (action.type) {
        case LOAD_REGIONS_REQUEST:
            return {
                ...state,
                loading: true
            };
        case LOAD_REGIONS_SUCCESS:
            return {
                ...state,
                loading: false,
                regions: action.payload.reduce((acc, { id, ...data }) => {
                    acc[id] = { data, dirty: true };
                    return acc;
                }, {})
            };
        case UPDATE_REGION:
            const region = state.regions[action.payload.id];
            return {
                ...state,
                regions: {
                    ...state.regions,
                    [action.payload.id]: {
                        ...region,
                        data: { ...region.data, ...action.payload },
                        dirty: true
                    }
                }
            };
        default: return state;
    }
};

class RegionList extends HTMLElement {
    #store = new Store(regionsReducer, initialState);
    #regions = new Map();
    #unsubscribe;
    #spinner;

    constructor() {
        super();
        this.updateRegions = this.updateRegions.bind(this);

        this.#spinner = new LoadingSpinner();
        this.append(this.#spinner);
    }

    connectedCallback() {
        this.#unsubscribe = this.#store.subscribe(this.updateRegions);
        this.loadRegions().finally();
        this.listenEvent();
    }

    disconnectedCallback() {
        this.#unsubscribe();
    }

    updateRegions() {
        const state = this.#store.state;
        if (state.loading) {
            this.#spinner?.show();
        } else {
            this.#spinner?.hide();
            this.innerHTML = '';
        }

        for (const [id, regionState] of Object.entries(state.regions)) {
            if (regionState.dirty) {
                if (this.#regions.has(id)) {
                    const regionElement = this.#regions.get(id);
                    regionElement.regionModel = regionState.data;
                } else {
                    let region = new Region();
                    region.regionId = id;
                    region.regionData = regionState.data;
                    this.#regions.set(id, region);
                    this.appendChild(region);
                }
            }
        }
    }

    async loadRegions() {
        this.#store.dispatch(loadRegionsRequest());

        try {
            this.#store.dispatch(loadRegionsSuccess(await getRegions()));
        } catch (error) {
            console.error("Internal error:", error);
        }
    }

    listenEvent() {
        // TODO: SSE for update
        // streamRegion(data => {
        //     this.#store.dispatch(updateSensor(data));
        // });
    }
}

customElements.define("lumisync-region-list", RegionList);

export default RegionList;
