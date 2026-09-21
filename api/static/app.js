const $ = (id) => document.getElementById(id);

const HISTORY_KEY = "sentinel-triage-history-v1";
const MAX_HISTORY = 6;

const form = $("triage-form");
const input = $("indicator");
const submit = $("submit");
const errorBox = $("error");
const loading = $("loading");
const result = $("result");
const empty = $("empty");
const badges = $("badges");
const confidenceRing = $("confidence-ring");
const confidenceValue = $("confidence-value");
const action = $("action");
const reasoning = $("reasoning");
const evidence = $("evidence");
const meta = $("meta");
const verdictTime = $("verdict-time");
const raw = $("raw");
const apiStatus = $("api-status");
const apiStatusText = $("api-status-text");
const recent = $("recent");
const recentList = $("recent-list");
const clearHistory = $("clear-history");
const copyJson = $("copy-json");
const downloadJson = $("download-json");
const newTriage = $("new-triage");

let currentResult = null;

function setStatus(state, text) {
  apiStatus.dataset.state = state;
  apiStatusText.textContent = text;
}

async function checkReady() {
  try {
    const response = await fetch("/ready", { headers: { Accept: "application/json" } });
    if (response.ok) {
      setStatus("ready", "API ready");
    } else {
      setStatus("degraded", "API degraded");
    }
  } catch {
    setStatus("degraded", "API unreachable");
  }
}

function makeBadge(text, className) {
  const span = document.createElement("span");
  span.className = `badge ${className}`;
  span.textContent = text;
  return span;
}

function setBusy(busy) {
  submit.disabled = busy;
  input.disabled = busy;
  submit.textContent = busy ? "Investigating…" : "Triage";
  form.setAttribute("aria-busy", String(busy));
}

function showError(message) {
  errorBox.textContent = message;
  errorBox.hidden = false;
}

function clearError() {
  errorBox.hidden = true;
  errorBox.textContent = "";
}

function toolLatency(tools, toolName) {
  const matches = (tools || []).filter((tool) => tool.tool === toolName);
  if (!matches.length) return "";
  const latency = matches[matches.length - 1].latency_ms;
  return `${Math.round(latency)} ms`;
}

function renderEvidence(resultData) {
  evidence.replaceChildren();
  const tools = resultData.tools_called || [];
  for (const item of resultData.verdict.evidence || []) {
    const card = document.createElement("article");
    card.className = "evidence-card";

    const top = document.createElement("div");
    top.className = "evidence-top";

    const name = document.createElement("span");
    name.className = "tool-name";
    name.textContent = item.tool;

    const status = document.createElement("span");
    status.className = `tool-status status-${item.status}`;
    status.textContent = item.status;

    top.append(name, status);

    const summary = document.createElement("p");
    summary.className = "evidence-summary";
    summary.textContent = item.summary;

    card.append(top, summary);

    const latency = toolLatency(tools, item.tool);
    if (latency) {
      const timing = document.createElement("div");
      timing.className = "evidence-latency";
      timing.textContent = latency;
      card.append(timing);
    }

    evidence.append(card);
  }
}

function render(resultData) {
  const verdict = resultData.verdict;
  const classification = verdict.classification || "unknown";
  const severity = verdict.severity || "info";
  const status = verdict.status || "needs_review";

  badges.replaceChildren(
    makeBadge(classification, `class-${classification}`),
    makeBadge(severity, `sev-${severity}`),
    makeBadge(status.replaceAll("_", " "), `status-${status}`),
  );

  const confidence = Number(verdict.confidence || 0);
  const percent = Math.round(Math.max(0, Math.min(1, confidence)) * 100);
  confidenceValue.textContent = `${percent}%`;
  confidenceRing.style.setProperty("--value", String(percent));
  confidenceRing.style.setProperty(
    "--ring-color",
    confidence < 0.7 ? "#ff6b6b" : confidence < 0.85 ? "#f0b429" : "#7ee787",
  );
  confidenceRing.setAttribute("aria-label", `Confidence ${percent}%`);

  action.textContent = verdict.recommended_action || "—";
  reasoning.textContent = verdict.reasoning || "—";
  renderEvidence(resultData);

  const latency = Math.round(resultData.latency_ms || 0);
  const when = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  verdictTime.textContent = `${when} · ${latency} ms · ${resultData.model || "model"} · ML ${
    resultData.use_ml ? "on" : "off"
  }`;
  meta.textContent = [
    `run ${String(resultData.run_id || "").slice(0, 8)}`,
    `${latency} ms`,
    `ML ${resultData.use_ml ? "on" : "off"}`,
  ].join(" · ");

  raw.textContent = JSON.stringify(resultData, null, 2);
  currentResult = resultData;
  empty.hidden = true;
  result.hidden = false;
  result.scrollIntoView({ behavior: "smooth", block: "start" });
}

function loadHistory() {
  try {
    const parsed = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function saveHistory(items) {
  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(items.slice(0, MAX_HISTORY)));
  } catch {
    // Private browsing or storage disabled; history is optional.
  }
}

function renderHistory() {
  const items = loadHistory();
  recent.hidden = items.length === 0;
  recentList.replaceChildren();
  for (const item of items) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "recent-item";
    button.title = item.indicator;

    const label = document.createElement("span");
    label.textContent = item.indicator;

    const resultLabel = document.createElement("em");
    resultLabel.textContent = `${item.classification} · ${item.status.replaceAll("_", " ")}`;

    button.append(label, resultLabel);
    button.addEventListener("click", () => {
      input.value = item.indicator;
      input.focus();
      window.scrollTo({ top: 0, behavior: "smooth" });
    });
    recentList.append(button);
  }
}

function addHistory(resultData) {
  const verdict = resultData.verdict;
  const items = loadHistory().filter(
    (item) => item.indicator.toLowerCase() !== resultData.input.toLowerCase(),
  );
  items.unshift({
    indicator: resultData.input,
    classification: verdict.classification,
    severity: verdict.severity,
    status: verdict.status,
    confidence: verdict.confidence,
    at: Date.now(),
  });
  saveHistory(items);
  renderHistory();
}

function resetView() {
  currentResult = null;
  result.hidden = true;
  loading.hidden = true;
  empty.hidden = false;
  clearError();
  input.focus();
  window.scrollTo({ top: 0, behavior: "smooth" });
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const indicator = input.value.trim();
  if (!indicator) return;

  clearError();
  result.hidden = true;
  empty.hidden = true;
  loading.hidden = false;
  setBusy(true);

  try {
    const response = await fetch("/triage", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ indicator }),
    });

    if (!response.ok) {
      let detail = `Triage request failed (${response.status}).`;
      try {
        const payload = await response.json();
        if (payload.detail) detail = String(payload.detail);
      } catch {
        // Keep the status-based message.
      }
      throw new Error(detail);
    }

    const resultData = await response.json();
    render(resultData);
    addHistory(resultData);
  } catch (error) {
    loading.hidden = true;
    result.hidden = true;
    empty.hidden = false;
    showError(
      error instanceof Error
        ? `${error.message} The alert should be escalated, not closed.`
        : "Triage failed. The alert should be escalated, not closed.",
    );
  } finally {
    loading.hidden = true;
    setBusy(false);
  }
});

for (const chip of document.querySelectorAll(".chip")) {
  chip.addEventListener("click", () => {
    input.value = chip.dataset.example || "";
    input.focus();
  });
}

clearHistory.addEventListener("click", () => {
  saveHistory([]);
  renderHistory();
});

copyJson.addEventListener("click", async () => {
  if (!currentResult) return;
  const original = copyJson.textContent;
  const copied = await copyText(JSON.stringify(currentResult, null, 2));
  copyJson.textContent = copied ? "Copied" : "Copy failed";
  setTimeout(() => {
    copyJson.textContent = original;
  }, 1200);
});

downloadJson.addEventListener("click", () => {
  if (!currentResult) return;
  const blob = new Blob([JSON.stringify(currentResult, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `sentinel-triage-${String(currentResult.run_id || "run").slice(0, 8)}.json`;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
});

newTriage.addEventListener("click", resetView);

document.addEventListener("keydown", (event) => {
  const typing = ["INPUT", "TEXTAREA"].includes(document.activeElement?.tagName || "");
  if (event.key === "/" && !typing) {
    event.preventDefault();
    input.focus();
  }
  if ((event.metaKey || event.ctrlKey) && event.key === "Enter") {
    form.requestSubmit();
  }
});

renderHistory();
checkReady();
