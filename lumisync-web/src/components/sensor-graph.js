import { streamSensorData } from "../api.js";
import { Chart } from "chart.js/auto";

class SensorGraph extends EventTarget {
    #model = { id: NaN, labels: [], temperature: [], light: [] };
    #source;
    #chart;

    constructor(container) {
        super();
        const canvas = container.appendChild(document.createElement("canvas"));
        this.#chart = this.createChart(canvas);
    }

    createChart(canvas) {
        return new Chart(canvas, {
            type: "line",
            data: {
                labels: this.#model.labels,
                datasets: [{
                    label: "Temperature (°C)",
                    data: this.#model.temperature,
                    borderColor: "rgb(136, 243, 72)",
                    tension: 0.4
                }, {
                    label: "Light (lux)",
                    data: this.#model.light,
                    borderColor: "rgb(255, 219, 99)",
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
            }
        });
    }

    updateCanvas(sensorId) {
        this.#source = streamSensorData(sensorId, data => {
            data.forEach(({ time, light, temperature }) => {
                this.#model.labels.push(new Date(time).toLocaleTimeString());
                this.#model.temperature.push(temperature);
                this.#model.light.push(light);
            });
            this.#chart?.update();
        });
    }

    dispose() {
        this.#model = { ...this.#model, labels: [], temperature: [], light: [] };

        if (!!this.#chart) {
            this.#chart.update();
            this.#chart = null;
        }

        if (!!this.#source) {
            this.#source.close();
            this.#source = null;
        }
    }
}

export default SensorGraph;
