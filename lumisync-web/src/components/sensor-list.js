import { getSensors } from "../api.js";
import Sensor from "./sensor.js";

class SensorList extends HTMLElement {
    #sensors = new Map();

    connectedCallback() {
        this.updateContent().then();
    }

    async updateContent() {
        await getSensors(data => {
            for (const { id, ...props } of data) {
                const sensor = new Sensor();
                sensor.sensorId = id;
                sensor.sensorModel = props;
                this.#sensors.set(id, sensor);
                this.appendChild(sensor);
            }
        });
    }
}

customElements.define("lumisync-sensor-list", SensorList);

export default SensorList;