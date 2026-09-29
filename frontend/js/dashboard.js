/**
 * SOC Analytics & Telemetry Charts Controller
 * Renders 6 real-time Chart.js visualizations from backend /api/dashboard/stats:
 * 1. Classification Distribution (Doughnut)
 * 2. Phishing vs. Legitimate Ratio (Pie)
 * 3. Top Detected Indicators (Horizontal Bar)
 * 4. Risk Score Distribution Bands (Bar)
 * 5. Detection Trend Timeline (Line)
 * 6. Most Common Suspicious Keywords (Bar)
 */

let chartClassification = null;
let chartRatio = null;
let chartIndicators = null;
let chartRiskBands = null;
let chartTrend = null;
let chartKeywords = null;

async function fetchAndUpdateDashboard() {
  let data = null;
  try {
    if (window.isApiOnline !== false) {
      const res = await fetch("/api/dashboard/stats");
      if (res.ok) data = await res.json();
    }
  } catch (err) {
    console.warn("API offline, rendering charts from local client engine:", err);
  }

  if (!data && window.phishEngine) {
    data = window.phishEngine.getStats();
  }
  if (!data) return;

  // Update KPI Metric Cards
  const kTotal = document.getElementById("kpi-total");
  const kPhish = document.getElementById("kpi-phishing");
  const kSusp = document.getElementById("kpi-suspicious");
  const kSafe = document.getElementById("kpi-safe");
  const kAvg = document.getElementById("kpi-avg-score");

  if (kTotal) kTotal.innerText = data.total_analyzed;
  if (kPhish) kPhish.innerText = data.likely_phishing;
  if (kSusp) kSusp.innerText = data.suspicious;
  if (kSafe) kSafe.innerText = data.low_risk;
  if (kAvg) kAvg.innerText = Number(data.average_risk_score).toFixed(1);

  // 1. Classification Donut Chart
  renderClassificationChart(data);

  // 2. Phishing vs Legitimate Ratio Pie Chart
  renderRatioChart(data);

  // 3. Top Indicators Horizontal Bar Chart
  renderIndicatorsChart(data.top_indicators);

  // 4. Risk Bands Bar Chart
  renderRiskBandsChart(data.distribution);

  // 5. Recent Trend Line Chart
  renderTrendChart(data.recent_trend);

  // 6. Suspicious Keywords Bar Chart
  renderKeywordsChart(data.top_keywords);
}

function renderClassificationChart(data) {
  const ctx = document.getElementById("chart-classification");
  if (!ctx) return;

  const chartData = {
    labels: ["Likely Phishing", "Suspicious", "Safe / Low Risk"],
    datasets: [{
      data: [data.likely_phishing, data.suspicious, data.low_risk],
      backgroundColor: ["#ef4444", "#f59e0b", "#10b981"],
      borderColor: "#162033",
      borderWidth: 2
    }]
  };

  if (chartClassification) {
    chartClassification.data = chartData;
    chartClassification.update();
  } else {
    chartClassification = new Chart(ctx, {
      type: "doughnut",
      data: chartData,
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: "bottom", labels: { color: "#9ca3af", font: { family: "Inter", size: 11 } } }
        }
      }
    });
  }
}

function renderRatioChart(data) {
  const ctx = document.getElementById("chart-ratio");
  if (!ctx) return;

  const threats = data.likely_phishing + data.suspicious;
  const legit = data.low_risk;

  const chartData = {
    labels: ["Threats (Phish & Suspicious)", "Legitimate Communications"],
    datasets: [{
      data: [threats, legit],
      backgroundColor: ["#f87171", "#34d399"],
      borderColor: "#162033",
      borderWidth: 2
    }]
  };

  if (chartRatio) {
    chartRatio.data = chartData;
    chartRatio.update();
  } else {
    chartRatio = new Chart(ctx, {
      type: "pie",
      data: chartData,
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: "bottom", labels: { color: "#9ca3af", font: { family: "Inter", size: 11 } } }
        }
      }
    });
  }
}

function renderIndicatorsChart(indicators) {
  const ctx = document.getElementById("chart-indicators");
  if (!ctx) return;

  const labels = indicators.map(i => i.title.length > 25 ? i.title.substring(0, 23) + "..." : i.title);
  const counts = indicators.map(i => i.count);

  const chartData = {
    labels: labels.length ? labels : ["No Threat Data"],
    datasets: [{
      label: "Occurrences",
      data: counts.length ? counts : [0],
      backgroundColor: "#3b82f6",
      borderRadius: 4
    }]
  };

  if (chartIndicators) {
    chartIndicators.data = chartData;
    chartIndicators.update();
  } else {
    chartIndicators = new Chart(ctx, {
      type: "bar",
      data: chartData,
      options: {
        indexAxis: "y",
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { beginAtZero: true, grid: { color: "#243452" }, ticks: { color: "#9ca3af" } },
          y: { grid: { display: false }, ticks: { color: "#9ca3af", font: { size: 10 } } }
        }
      }
    });
  }
}

function renderRiskBandsChart(dist) {
  const ctx = document.getElementById("chart-risk-bands");
  if (!ctx) return;

  const chartData = {
    labels: ["0-20 (Safe)", "21-40 (Moderate)", "41-70 (Suspicious)", "71-100 (High Risk)"],
    datasets: [{
      label: "Emails",
      data: [dist.safe_low || 0, dist.moderate || 0, dist.suspicious || 0, dist.high_risk || 0],
      backgroundColor: ["#10b981", "#eab308", "#f59e0b", "#ef4444"],
      borderRadius: 4
    }]
  };

  if (chartRiskBands) {
    chartRiskBands.data = chartData;
    chartRiskBands.update();
  } else {
    chartRiskBands = new Chart(ctx, {
      type: "bar",
      data: chartData,
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          y: { beginAtZero: true, grid: { color: "#243452" }, ticks: { color: "#9ca3af" } },
          x: { grid: { display: false }, ticks: { color: "#9ca3af" } }
        }
      }
    });
  }
}

function renderTrendChart(trend) {
  const ctx = document.getElementById("chart-trend");
  if (!ctx) return;

  const labels = trend.map((t, idx) => `#${idx + 1} (${t.time.split(" ")[1] || t.time})`);
  const scores = trend.map(t => t.score);

  const chartData = {
    labels: labels.length ? labels : ["Waiting for submissions"],
    datasets: [{
      label: "Risk Score",
      data: scores.length ? scores : [0],
      borderColor: "#8b5cf6",
      backgroundColor: "rgba(139, 92, 246, 0.1)",
      fill: true,
      tension: 0.3,
      pointRadius: 4,
      pointBackgroundColor: "#8b5cf6"
    }]
  };

  if (chartTrend) {
    chartTrend.data = chartData;
    chartTrend.update();
  } else {
    chartTrend = new Chart(ctx, {
      type: "line",
      data: chartData,
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          y: { min: 0, max: 100, grid: { color: "#243452" }, ticks: { color: "#9ca3af" } },
          x: { grid: { display: false }, ticks: { color: "#9ca3af" } }
        }
      }
    });
  }
}

function renderKeywordsChart(keywords) {
  const ctx = document.getElementById("chart-keywords");
  if (!ctx) return;

  const kwList = keywords || [];
  const labels = kwList.map(k => k.keyword);
  const counts = kwList.map(k => k.count);

  const chartData = {
    labels: labels.length ? labels : ["No Keyword Data"],
    datasets: [{
      label: "Occurrences",
      data: counts.length ? counts : [0],
      backgroundColor: "#06b6d4",
      borderRadius: 4
    }]
  };

  if (chartKeywords) {
    chartKeywords.data = chartData;
    chartKeywords.update();
  } else {
    chartKeywords = new Chart(ctx, {
      type: "bar",
      data: chartData,
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          y: { beginAtZero: true, grid: { color: "#243452" }, ticks: { color: "#9ca3af" } },
          x: { grid: { display: false }, ticks: { color: "#9ca3af" } }
        }
      }
    });
  }
}

document.addEventListener("DOMContentLoaded", () => {
  fetchAndUpdateDashboard();
  const btnRefresh = document.getElementById("btn-refresh-stats");
  if (btnRefresh) {
    btnRefresh.addEventListener("click", fetchAndUpdateDashboard);
  }
});
