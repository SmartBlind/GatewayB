import { Chart, _adapters } from "chart.js/auto";
import {
    parse, parseISO, toDate, isValid, format,
    startOfSecond, startOfMinute, startOfHour, startOfDay,
    startOfWeek, startOfMonth, startOfQuarter, startOfYear,
    addMilliseconds, addSeconds, addMinutes, addHours,
    addDays, addWeeks, addMonths, addQuarters, addYears,
    differenceInMilliseconds, differenceInSeconds, differenceInMinutes,
    differenceInHours, differenceInDays, differenceInWeeks,
    differenceInMonths, differenceInQuarters, differenceInYears,
    endOfSecond, endOfMinute, endOfHour, endOfDay,
    endOfWeek, endOfMonth, endOfQuarter, endOfYear
} from "date-fns";

const FORMATS = {
    datetime: "MMM d, yyyy, h:mm:ss aaaa",
    millisecond: "h:mm:ss.SSS aaaa",
    second: "h:mm:ss aaaa",
    minute: "h:mm aaaa",
    hour: "ha",
    day: "MMM d",
    week: "PP",
    month: "MMM yyyy",
    quarter: "qqq - yyyy",
    year: "yyyy"
};

_adapters._date.override({
    _id: "date-fns", // DEBUG

    formats: function() {
        return FORMATS;
    },

    parse: function(value, fmt) {
        if (value === null || typeof value === "undefined") return null;

        const type = typeof value;
        if (type === "number" || value instanceof Date) {
            value = toDate(value);
        } else if (type === "string") {
            if (typeof fmt === "string") {
                value = parse(value, fmt, new Date(), this.options);
            } else {
                value = parseISO(value, this.options);
            }
        }
        return isValid(value) ? value.getTime() : null;
    },

    format: function(time, fmt) {
        return format(time, fmt, this.options);
    },

    add: function(time, amount, unit) {
        switch (unit) {
            case "millisecond": return addMilliseconds(time, amount);
            case "second": return addSeconds(time, amount);
            case "minute": return addMinutes(time, amount);
            case "hour": return addHours(time, amount);
            case "day": return addDays(time, amount);
            case "week": return addWeeks(time, amount);
            case "month": return addMonths(time, amount);
            case "quarter": return addQuarters(time, amount);
            case "year": return addYears(time, amount);
            default: return time;
        }
    },

    diff: function(max, min, unit) {
        switch (unit) {
            case "millisecond": return differenceInMilliseconds(max, min);
            case "second": return differenceInSeconds(max, min);
            case "minute": return differenceInMinutes(max, min);
            case "hour": return differenceInHours(max, min);
            case "day": return differenceInDays(max, min);
            case "week": return differenceInWeeks(max, min);
            case "month": return differenceInMonths(max, min);
            case "quarter": return differenceInQuarters(max, min);
            case "year": return differenceInYears(max, min);
            default: return 0;
        }
    },

    startOf: function(time, unit, weekday) {
        switch (unit) {
            case "second": return startOfSecond(time);
            case "minute": return startOfMinute(time);
            case "hour": return startOfHour(time);
            case "day": return startOfDay(time);
            case "week": return startOfWeek(time);
            case "isoWeek": return startOfWeek(time, { weekStartsOn: +weekday });
            case "month": return startOfMonth(time);
            case "quarter": return startOfQuarter(time);
            case "year": return startOfYear(time);
            default: return time;
        }
    },

    endOf: function(time, unit) {
        switch (unit) {
            case "second": return endOfSecond(time);
            case "minute": return endOfMinute(time);
            case "hour": return endOfHour(time);
            case "day": return endOfDay(time);
            case "week": return endOfWeek(time);
            case "month": return endOfMonth(time);
            case "quarter": return endOfQuarter(time);
            case "year": return endOfYear(time);
            default: return time;
        }
    }
});

class GanttGraph extends HTMLElement {
    static observedAttributes = ["window-id", "target-type", "target-id"];

    constructor() {
        super();
        this.canvas = this.appendChild(document.createElement("canvas"));
    }

    connectedCallback() {
        this.renderChart(this.canvas);
    }

    renderChart(ctx) {
        const separator = {
            id: 'separator',
            afterDatasetDraw(chart, args, options) {
                const {
                    ctx,
                    data,
                    chartArea: { top, bottom, left, right},
                    scales: { x, y },
                } = chart;

                ctx.save();

                ctx.beginPath();
                ctx.lineWidth = 3;
                ctx.strokeStyle = 'rgb(255, 26, 104, 1)';
                ctx.setLineDash([6, 6]);
                ctx.moveTo(x.getPixelForValue(new Date()), top);
                ctx.lineTo(x.getPixelForValue(new Date()), bottom);
                ctx.stroke();
                ctx.restore();

                ctx.setLineDash([]);

                ctx.beginPath();
                ctx.lineWidth = 1;
                ctx.strokeStyle = "rgba(102, 102, 102, 1)";
                ctx.fillStyle = "rgba(102, 102, 102, 1)";
                ctx.moveTo(x.getPixelForValue(new Date()), top + 3);
                ctx.lineTo(x.getPixelForValue(new Date()) - 6, top - 6);
                ctx.lineTo(x.getPixelForValue(new Date()) + 6, top - 6);
                ctx.closePath();
                ctx.stroke();
                ctx.fill();
                ctx.restore();

                ctx.font = "bold 12px sans-serif";
                ctx.fillStyle = "rgba(102, 102, 102, 1)";
                ctx.textAlign = "center";
                ctx.fillText("Now", x.getPixelForValue(new Date()), bottom + 15);
                ctx.restore();
            }
        }

        this.chart = new Chart(ctx, {
            type: "bar",
            data: {
                datasets: [{
                    label: "range",
                    data: [
                        {x: ['2024-05-16 00:00:00', '2024-05-16 08:00:00'], y: 'task 1'},
                        {x: ['2024-05-16 07:30:00', '2024-05-16 09:00:00'], y: 'task 2'},
                        {x: ['2024-05-16 09:00:00', '2024-05-16 18:00:00'], y: 'task 3'},
                        {x: ['2024-05-16 16:00:00', '2024-05-16 20:00:00'], y: 'task 4'},
                        {x: ['2024-05-16 19:00:00', '2024-05-16 23:59:59'], y: 'task 5'},
                    ],
                    backgroundColor: [
                        'rgba(255, 26, 104, 0.2)',
                        'rgba(255, 26, 104, 0.2)',
                        'rgba(255, 26, 104, 0.2)',
                        'rgba(255, 26, 104, 0.2)',
                        'rgba(255, 26, 104, 0.2)',
                        'rgba(0, 0, 0, 0.2)',
                    ],
                    borderColor: [
                        'rgba(255, 26, 104, 1)',
                        'rgba(255, 26, 104, 1)',
                        'rgba(255, 26, 104, 1)',
                        'rgba(255, 26, 104, 1)',
                        'rgba(255, 26, 104, 1)',
                        'rgba(0, 0, 0, 1)',
                    ],
                    borderWidth: 1,
                    borderSkipped: false,
                    borderRadius: 10,
                    barPercentage: 0.5
                }]
            },
            options: {
                layout: {
                    padding: {
                        left: 20,
                        right: 20,
                        bottom: 20,
                    }
                },
                indexAxis: "y",
                scales: {
                    x: {
                        position: "top",
                        type: "time",
                        time: {
                            unit: "hour"
                        },
                        min: "2024-05-16 00:00:00",
                        max: "2024-05-16 23:59:59"
                    }
                },
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        callbacks: {
                            title(tooltipItems) {
                                const startDate = new Date(tooltipItems[0].raw.x[0]);
                                const endDate = new Date(tooltipItems[0].raw.x[1]);
                            }
                        }
                    }
                }
            },
            plugins: [separator]
        });
    }
}

customElements.define("lumisync-gantt-graph", GanttGraph);

export default GanttGraph;