import { Chart } from "chart.js/auto";
import { API } from "../index.js";

class Graph extends HTMLElement {
    #chart;

    connectedCallback() {
        const canvas = this.appendChild(document.createElement("canvas"));
        canvas.width = 400;
        canvas.height = 200;

        this.renderChart(canvas);
        this.fetchData("sensor001")
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
}

customElements.define("lumisync-graph", Graph);

export default Graph;
