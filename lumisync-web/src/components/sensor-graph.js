import { Chart } from "chart.js/auto";
import { streamSensorData } from "../api.js";

class SensorGraph extends HTMLElement {
    static observedAttributes = ["sensor-id"];
    #source;
    #chart;

    get sensorId() {
        return this.getAttribute("sensor-id");
    }

    set sensorId(value) {
        this.setAttribute("sensor-id", value);
    }

    connectedCallback() {
        const canvas = this.appendChild(document.createElement("canvas"));
        this.renderChart(canvas);
        this.listen(this.sensorId)
    }

    attributeChangedCallback(name, oldValue, newValue) {
        if (name === "sensor-id" && oldValue !== newValue) {
            this.dispose();
            this.listen(this.sensorId);
        }
    }

    renderChart(ctx) {
        this.#chart = new Chart(ctx, {
            type: "line",
            data: {
                labels: [],
                datasets: [{
                    label: 'Temperature (°C)',
                    data: [],
                    borderColor: 'rgba(255, 99, 132, 1)',
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
                data.forEach(({ time, temperature }) => {
                    this.#chart.data.labels.push(new Date(time).toLocaleTimeString());
                    this.#chart.data.datasets.forEach((dataset) => {
                        dataset.data.push(temperature);
                    });
                });
                this.#chart.update();
            });
        }
    }

    dispose() {
        if (!!this.#chart) {
            this.#chart.data.labels = [];
            this.#chart.data.datasets = [];
            this.#chart.update();
        }
        if (!!this.#source) {
            this.#source.close();
        }
    }
}

customElements.define("lumisync-sensor-graph", SensorGraph);

export default SensorGraph;
