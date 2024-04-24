import { Chart } from "chart.js/auto";
import { API } from "../index.js";

class SensorGraph extends HTMLElement {
    static observedAttributes = ["sensor-id"];
    #chart;

    get sensorId() {
        return this.getAttribute("sensor-id");
    }

    set sensorId(value) {
        this.setAttribute("sensor-id", value);
    }

    connectedCallback() {
        const canvas = this.appendChild(document.createElement("canvas"));
        canvas.width = 400;
        canvas.height = 200;

        this.renderChart(canvas);
        this.fetchData(this.sensorId)
    }

    attributeChangedCallback(name, oldValue, newValue) {
        if (name === "sensor-id" && oldValue !== newValue) {
            this.cleanData();
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

    fetchData(id) {
        const evtSource = new EventSource(`${API.sensors}/${id}`);
        evtSource.onmessage = (event) => {
            const sensorData = JSON.parse(event.data);
            sensorData.forEach(data => {
                this.#chart.data.labels.push(new Date(data.time).toLocaleTimeString());
                this.#chart.data.datasets.forEach((dataset) => {
                    dataset.data.push(data.temperature);
                });
            });
            this.#chart.update();
        };
    }

    cleanData() {
        this.#chart.data.labels.clear();
        this.#chart.data.datasets.clear();
        this.#chart.update();
    }
}

customElements.define("lumisync-sensor-graph", SensorGraph);

export default SensorGraph;
