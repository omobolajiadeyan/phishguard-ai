"use strict";

// Vanilla JS, no build step, no dependencies — matches the CLI's
// zero-dependency ethos. Only textContent/DOM APIs are used to insert
// values that came from user input or the API response, never innerHTML,
// so nothing typed into the form (or echoed back by the API) can run as
// markup in the page.

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
const redirectNote = document.getElementById("redirect-note");
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

function renderResult(payload) {
  errorEl.classList.add("hidden");

  const verdictClass = VERDICT_CLASS[payload.verdict] || "";
  verdictBadge.textContent = payload.verdict || "UNKNOWN";
  verdictBadge.className = `badge ${verdictClass}`;

  const pct = Math.round((payload.probability || 0) * 1000) / 10;
  probabilityText.textContent = `${pct}% phishing probability`;
  probabilityFill.style.width = `${Math.min(100, Math.max(0, pct))}%`;
  probabilityFill.className = `bar-fill ${verdictClass}`;

  if (payload.redirect_chain) {
    const { hops, crossed_domain: crossed } = payload.redirect_chain;
    redirectNote.textContent = crossed
      ? `Followed ${hops} redirect hop(s); the chain left the original domain.`
      : `Followed ${hops} redirect hop(s); stayed on the same domain.`;
    redirectNote.classList.remove("hidden");
  } else {
    redirectNote.classList.add("hidden");
  }

  renderFeatures(payload.features || {});
  resultEl.classList.remove("hidden");
}

async function submitJson(path, body) {
  let response;
  try {
    response = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch (networkError) {
    showError("Could not reach the API. Check your connection and try again.");
    return;
  }

  let payload;
  try {
    payload = await response.json();
  } catch (parseError) {
    showError(`Unexpected response from the server (HTTP ${response.status}).`);
    return;
  }

  if (!response.ok) {
    if (response.status === 429) {
      showError(payload.error || "Rate limit exceeded — please wait and try again.");
    } else {
      showError(payload.error || `Request failed (HTTP ${response.status}).`);
    }
    return;
  }

  renderResult(payload);
}

document.getElementById("url-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const url = form.url.value.trim();
  const followRedirects = Number(form.follow_redirects.value) || 0;
  if (!url) return;
  submitJson("/v1/url", { url, follow_redirects: followRedirects });
});

document.getElementById("email-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const subject = form.subject.value;
  const body = form.body.value;
  const authenticationResults = form.authentication_results.value.trim() || null;
  submitJson("/v1/email", {
    subject,
    body,
    authentication_results: authenticationResults,
  });
});
