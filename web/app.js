"use strict";

// Vanilla JS, no build step, no dependencies — matches the CLI's
// zero-dependency ethos. Scoring runs entirely in the browser via
// scoring.js (a verified port of the Python model — see
// tests/test_js_parity.py), so this page works as a static file with no
// backend at all: the same web/ directory can be served by
// `phishguard serve` or hosted standalone (e.g. GitHub Pages).
//
// Only textContent/DOM APIs are used to insert values that came from user
// input, never innerHTML, so nothing typed into the form can run as markup.

const VERDICT_CLASS = {
  PHISHING: "verdict-phishing",
  SUSPICIOUS: "verdict-suspicious",
  SAFE: "verdict-safe",
};

const tabs = document.querySelectorAll(".tab");
const panels = {
  url: document.getElementById("panel-url"),
  email: document.getElementById("panel-email"),
};

tabs.forEach((tab) => {
  tab.addEventListener("click", () => {
    tabs.forEach((t) => {
      t.classList.toggle("active", t === tab);
      t.setAttribute("aria-selected", t === tab ? "true" : "false");
    });
    Object.entries(panels).forEach(([name, panel]) => {
      panel.classList.toggle("hidden", name !== tab.dataset.tab);
    });
    clearResult();
  });
});

const resultEl = document.getElementById("result");
const errorEl = document.getElementById("error");
const verdictBadge = document.getElementById("verdict-badge");
const probabilityText = document.getElementById("probability-text");
const probabilityFill = document.getElementById("probability-fill");
const featuresTableBody = document.querySelector("#features-table tbody");
const featuresDetails = document.getElementById("features-details");

function clearResult() {
  resultEl.classList.add("hidden");
  errorEl.classList.add("hidden");
  errorEl.textContent = "";
}

function showError(message) {
  clearResult();
  errorEl.textContent = message;
  errorEl.classList.remove("hidden");
}

function renderFeatures(features) {
  featuresTableBody.textContent = "";
  for (const [name, value] of Object.entries(features)) {
    const row = document.createElement("tr");
    const nameCell = document.createElement("td");
    nameCell.textContent = name;
    const valueCell = document.createElement("td");
    valueCell.textContent = String(value);
    row.append(nameCell, valueCell);
    featuresTableBody.appendChild(row);
  }
  featuresDetails.open = false;
}

function renderResult({ probability, features }) {
  errorEl.classList.add("hidden");

  const verdict = PhishGuardScoring.classify(probability);
  const verdictClass = VERDICT_CLASS[verdict] || "";
  verdictBadge.textContent = verdict;
  verdictBadge.className = `badge ${verdictClass}`;

  const pct = Math.round(probability * 1000) / 10;
  probabilityText.textContent = `${pct}% phishing probability`;
  probabilityFill.style.width = `${Math.min(100, Math.max(0, pct))}%`;
  probabilityFill.className = `bar-fill ${verdictClass}`;

  renderFeatures(features || {});
  resultEl.classList.remove("hidden");
}

document.getElementById("url-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const url = event.currentTarget.url.value.trim();
  if (!url) return;
  try {
    renderResult(PhishGuardScoring.scoreUrl(url));
  } catch (err) {
    showError("Could not analyze that input. Try a different URL.");
  }
});

document.getElementById("email-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const subject = form.subject.value;
  const body = form.body.value;
  const authenticationResults = form.authentication_results.value.trim() || null;
  try {
    renderResult(PhishGuardScoring.scoreEmail(subject, body, authenticationResults));
  } catch (err) {
    showError("Could not analyze that input. Try a different subject/body.");
  }
});
