import { Chart } from "chart.js/auto";

class Graph extends HTMLElement {
    connectedCallback() {
        this.innerHTML = `<canvas id="temperatureChart" width="400" height="200"></canvas>`;
        this.renderChart();
    }

    renderChart() {
        const ctx = this.querySelector('#temperatureChart');
        new Chart(ctx, {
            type: "line",
            data: {
                labels: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'],
                datasets: [{
                    label: 'Temperature (°C)',
                    data: [22, 19, 21, 24, 23, 22],
                    borderColor: 'rgba(255, 99, 132, 1)',
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
            }
        });
    }
}

customElements.define("lumisync-graph", Graph);

export default Graph;
