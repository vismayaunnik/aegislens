const statusEl = document.getElementById("status");
const selectionEl = document.getElementById("selection");
const selectedTextEl = document.getElementById("selected-text");
const resultsEl = document.getElementById("results");
const iocListEl = document.getElementById("ioc-list");

function riskClass(score) {
  if (score === null || score === undefined) return "unknown";
  if (score > 50) return "high";
  if (score > 0) return "medium";
  return "low";
}

function render(data) {
  const { selectedText, analysisStatus, analysisResult, analysisError } = data;

  if (selectedText) {
    selectionEl.classList.remove("hidden");
    selectedTextEl.textContent = selectedText;
  } else {
    selectionEl.classList.add("hidden");
  }

  statusEl.className = "status";

  if (analysisStatus === "loading") {
    statusEl.classList.add("loading");
    statusEl.textContent = "Analyzing selection…";
    resultsEl.classList.add("hidden");
    return;
  }

  if (analysisStatus === "error") {
    statusEl.classList.add("error");
    statusEl.textContent = analysisError || "Analysis failed.";
    resultsEl.classList.add("hidden");
    return;
  }

  if (analysisStatus === "complete") {
    const iocs = analysisResult?.iocs || [];

    if (iocs.length === 0) {
      statusEl.classList.add("info");
      statusEl.textContent = "No IOCs found in selected text.";
      resultsEl.classList.add("hidden");
      return;
    }

    statusEl.classList.add("success");
    statusEl.textContent = `Found ${iocs.length} indicator${iocs.length === 1 ? "" : "s"}.`;
    resultsEl.classList.remove("hidden");
    iocListEl.innerHTML = "";

    for (const ioc of iocs) {
      const card = document.createElement("article");
      card.className = "ioc-card";

      const risk = riskClass(ioc.risk_score);
      const playbookBlock = ioc.playbook
        ? `<details class="playbook"><summary>Response playbook</summary><pre>${escapeHtml(ioc.playbook)}</pre></details>`
        : "";

      card.innerHTML = `
        <div class="ioc-header">
          <span class="ioc-type">${escapeHtml(ioc.ioc_type)}</span>
          ${ioc.cached ? '<span class="badge cached">cached</span>' : '<span class="badge live">live</span>'}
        </div>
        <div class="ioc-value">${escapeHtml(ioc.ioc)}</div>
        <div class="meta">
          <span class="risk ${risk}">Risk: ${ioc.risk_score ?? "—"}</span>
          <span class="source">Source: ${escapeHtml(ioc.source || "unknown")}</span>
        </div>
        ${playbookBlock}
      `;

      iocListEl.appendChild(card);
    }
    return;
  }

  statusEl.classList.add("info");
  statusEl.textContent = "Select text on a page, right-click, and choose “Analyze with AegisLens”.";
  resultsEl.classList.add("hidden");
}

function escapeHtml(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function loadFromStorage() {
  chrome.storage.local.get(
    ["selectedText", "analysisStatus", "analysisResult", "analysisError"],
    render
  );
}

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;

  chrome.storage.local.get(
    ["selectedText", "analysisStatus", "analysisResult", "analysisError"],
    render
  );
});

loadFromStorage();
