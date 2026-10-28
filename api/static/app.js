const $ = (id) => document.getElementById(id);

const form = $("triage-form");
const input = $("indicator");
const submit = $("submit");
const errorBox = $("error");
const result = $("result");
const empty = $("empty");
const badges = $("badges");
const confidenceValue = $("confidence-value");
const confidenceFill = $("confidence-fill");
const action = $("action");
const reasoning = $("reasoning");
const evidence = $("evidence");
const meta = $("meta");
const raw = $("raw");
const apiStatus = $("api-status");
const apiStatusText = $("api-status-text");

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

function renderEvidence(result) {
  evidence.replaceChildren();
  const tools = result.tools_called || [];
  for (const item of result.verdict.evidence || []) {
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
  confidenceValue.textContent = `${Math.round(confidence * 100)}%`;
  confidenceFill.style.width = `${Math.max(0, Math.min(100, confidence * 100))}%`;
  confidenceFill.style.background =
    confidence < 0.7
      ? "linear-gradient(90deg, #ff6b6b, #f0b429)"
      : "linear-gradient(90deg, #f0b429, #7ee787)";

  action.textContent = verdict.recommended_action || "—";
  reasoning.textContent = verdict.reasoning || "—";
  renderEvidence(resultData);

  const latency = Math.round(resultData.latency_ms || 0);
  meta.textContent = [
    `run ${String(resultData.run_id || "").slice(0, 8)}`,
    `${latency} ms`,
    resultData.model || "model",
    `ML ${resultData.use_ml ? "on" : "off"}`,
  ].join(" · ");

  raw.textContent = JSON.stringify(resultData, null, 2);
  empty.hidden = true;
  result.hidden = false;
  result.scrollIntoView({ behavior: "smooth", block: "start" });
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const indicator = input.value.trim();
  if (!indicator) return;

  clearError();
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

    render(await response.json());
  } catch (error) {
    result.hidden = true;
    empty.hidden = false;
    showError(
      error instanceof Error
        ? `${error.message} The alert should be escalated, not closed.`
        : "Triage failed. The alert should be escalated, not closed.",
    );
  } finally {
    setBusy(false);
  }
});

for (const chip of document.querySelectorAll(".chip")) {
  chip.addEventListener("click", () => {
    input.value = chip.dataset.example || "";
    input.focus();
  });
}

checkReady();
