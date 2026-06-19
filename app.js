var API_URL = "https://api.github.com/advisories?per_page=100&type=reviewed";

var allData       = [];
var processedData = [];

var tableBody = document.getElementById("tableBody");
var statusEl  = document.getElementById("status");
var resultEl  = document.getElementById("resultInfo");

function getCvss(item) {
  if (item.cvss && typeof item.cvss.score === "number") {
    return item.cvss.score;
  }
  var s = item.severity || "";
  if (s === "critical") return 9.0;
  if (s === "high")     return 7.0;
  if (s === "medium")   return 5.0;
  return 2.0;
}

function calculateRisk(item) {
  var score = getCvss(item) * 10;

  var days = (Date.now() - new Date(item.published_at)) / 86400000;
  var urgencyScore;
  if (days <= 7)       urgencyScore = 15;
  else if (days <= 30) urgencyScore = 10;
  else                 urgencyScore = 0;

  score = Math.min(100, Math.round(score + urgencyScore));

  var level;
  if      (score >= 80) level = "Kritik";
  else if (score >= 60) level = "Yüksek";
  else if (score >= 40) level = "Orta";
  else                  level = "Düşük";

  return { score: score, level: level };
}

function formatDate(str) {
  if (!str) return "-";
  var d = new Date(str);
  return d.getFullYear() + "-"
    + String(d.getMonth() + 1).padStart(2, "0") + "-"
    + String(d.getDate()).padStart(2, "0");
}

function getLevelClass(level) {
  if (level === "Kritik")  return "critical";
  if (level === "Yüksek")  return "high";
  if (level === "Orta")    return "medium";
  return "low";
}

async function fetchData() {
  statusEl.textContent = "Yükleniyor...";
  try {
    var response = await fetch(API_URL);

    if (!response.ok) {
      throw new Error("Sunucu hatası: HTTP " + response.status);
    }

    var data = await response.json();

    if (!Array.isArray(data)) {
      throw new Error("Beklenmedik veri formatı");
    }

    allData = data.filter(function(item) {
      return item.cve_id || item.ghsa_id;
    });

    if (allData.length === 0) {
      statusEl.textContent = "Veri bulunamadı.";
      return;
    }

    processedData = allData.map(function(item) {
      return { item: item, risk: calculateRisk(item) };
    });
    processedData.sort(function(a, b) { return b.risk.score - a.risk.score; });

    updateCounters(processedData);

    statusEl.textContent = "";
    showResults();

  } catch (error) {
    statusEl.textContent = "Veri çekilemedi. Lütfen daha sonra tekrar deneyin.";
    console.error(error);
  }
}

function showResults() {
  var search = document.getElementById("search").value.trim().toLowerCase();
  var filter = document.getElementById("filter").value;

  if (search.length === 1) return;

  var list = processedData;

  if (filter !== "all") {
    list = list.filter(function(x) {
      return x.risk.level === filter;
    });
  }

  if (search.length >= 2) {
    list = list.filter(function(x) {
      var item = x.item;
      var text = (item.cve_id || "") + " " + (item.ghsa_id || "") + " " + (item.summary || "");
      return text.toLowerCase().indexOf(search) !== -1;
    });
  }

  if (filter !== "all" || search.length >= 2) {
    resultEl.textContent = list.length + " sonuç gösteriliyor (toplam " + processedData.length + ")";
  } else {
    resultEl.textContent = "Toplam " + processedData.length + " kayıt yüklendi";
  }

  fillTable(list);
}

function updateCounters(list) {
  var critical = 0, high = 0, medium = 0, low = 0;
  list.forEach(function(x) {
    if      (x.risk.level === "Kritik")  critical++;
    else if (x.risk.level === "Yüksek")  high++;
    else if (x.risk.level === "Orta")    medium++;
    else                                 low++;
  });
  document.getElementById("countCritical").textContent = critical;
  document.getElementById("countHigh").textContent     = high;
  document.getElementById("countMedium").textContent   = medium;
  document.getElementById("countLow").textContent      = low;
}

function fillTable(list) {
  tableBody.textContent = "";

  if (list.length === 0) {
    statusEl.textContent = "Eşleşen kayıt bulunamadı.";
    return;
  }
  statusEl.textContent = "";

  list.forEach(function(x) {
    var item = x.item;
    var risk = x.risk;
    var row  = document.createElement("tr");

    addCell(row, item.cve_id || item.ghsa_id || "-");
    addCell(row, item.summary ? item.summary.slice(0, 130) : "-");
    addCell(row, item.cvss && item.cvss.score ? item.cvss.score.toFixed(1) : "-");

    var levelCell = addCell(row, risk.level);
    levelCell.className = getLevelClass(risk.level);

    addCell(row, risk.score);
    addCell(row, formatDate(item.published_at));

    tableBody.appendChild(row);
  });
}

function addCell(row, text) {
  var cell = document.createElement("td");
  cell.textContent = text;
  row.appendChild(cell);
  return cell;
}

document.getElementById("search").addEventListener("input", showResults);
document.getElementById("filter").addEventListener("change", showResults);

fetchData();
