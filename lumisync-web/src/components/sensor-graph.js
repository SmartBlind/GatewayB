import { Chart } from "chart.js/auto";
import { streamSensorData } from "../api.js";

class SensorGraph extends HTMLElement {
    static observedAttributes = ["sensor-id"];
    #dataset = { temperature: [], light: [] };
    #source;

    constructor() {
        super();
        this.canvas = this.appendChild(document.createElement("canvas"));
    }

    get sensorId() { return this.getAttribute("sensor-id"); }

    set sensorId(value) { this.setAttribute("sensor-id", value); }

    connectedCallback() {
        this.renderChart(this.canvas);
        this.listen(this.sensorId);
    }

    attributeChangedCallback(name, oldValue, newValue) {
        if (name === "sensor-id" && oldValue !== newValue) {
            this.dispose();
            this.listen(this.sensorId);
        }
    }

    renderChart(ctx) {
        this.chart = new Chart(ctx, {
            type: "line",
            data: {
                labels: [],
                datasets: [{
                    label: 'Temperature (°C)',
                    data: this.#dataset.temperature,
                    borderColor: 'rgb(136, 243, 72)',
                    tension: 0.4
                }, {
                    label: 'Light (lux)',
                    data: this.#dataset.light,
                    borderColor: 'rgb(255, 219, 99)',
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
            }
        });
    }

    listen(sensorId) {
        if (!!sensorId) {
            this.#source = streamSensorData(sensorId, data => {
                data.forEach(({ time, light, temperature }) => {
                    this.chart.data.labels.push(new Date(time).toLocaleTimeString());
                    this.#dataset.temperature.push(temperature);
                    this.#dataset.light.push(light);
                });
                this.chart.update();
            });
        }
    }

    dispose() {
        this.#dataset = { temperature: [], light: [] };

        if (!!this.chart) {
            this.chart.data.labels = [];
            this.chart.update();
        }

        if (!!this.#source) this.#source.close();
    }
}

customElements.define("lumisync-sensor-graph", SensorGraph);

export default SensorGraph;
