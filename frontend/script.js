// Point this at your backend. Change this when you deploy (e.g. Render URL).
const API_BASE = "https://domain-scanner-s6oa.onrender.com";

const form = document.getElementById("scanForm");
const domainInput = document.getElementById("domainInput");
const scanButton = document.getElementById("scanButton");

const stateIdle = document.getElementById("stateIdle");
const stateLoading = document.getElementById("stateLoading");
const stateError = document.getElementById("stateError");
const stateResults = document.getElementById("stateResults");

const loadingDomainLabel = document.getElementById("loadingDomainLabel");
const loadingText = document.getElementById("loadingText");
const errorText = document.getElementById("errorText");

const scoreRing = document.getElementById("scoreRing");
const scoreValue = document.getElementById("scoreValue");
const riskStamp = document.getElementById("riskStamp");
const verdictDomain = document.getElementById("verdictDomain");

const laneWhois = document.getElementById("laneWhois");
const laneHeaders = document.getElementById("laneHeaders");
const laneReputation = document.getElementById("laneReputation");
const manifestList = document.getElementById("manifestList");

const apiStatusDot = document.getElementById("apiStatusDot");
const apiStatusText = document.getElementById("apiStatusText");

const RING_CIRCUMFERENCE = 2 * Math.PI * 88;

// Rotating status lines shown while the scan is in flight — the real work
// (WHOIS + headers + reputation) does take a few seconds, so this keeps
// the wait legible instead of feeling stuck.
const LOADING_MESSAGES = [
  "Querying registration records…",
  "Inspecting transport security headers…",
  "Cross-checking threat intelligence…",
  "Compiling manifest…",
];

function showState(state) {
  stateIdle.hidden = state !== "idle";
  stateLoading.hidden = state !== "loading";
  stateError.hidden = state !== "error";
  stateResults.hidden = state !== "results";
}

async function checkApiHealth() {
  try {
    const res = await fetch(`${API_BASE}/`, { method: "GET" });
    if (res.ok) {
      apiStatusDot.classList.add("is-online");
      apiStatusText.textContent = "checkpoint online";
    } else {
      throw new Error("bad status");
    }
  } catch {
    apiStatusDot.classList.add("is-offline");
    apiStatusText.textContent = "checkpoint offline — start the backend";
  }
}

function riskClass(level) {
  if (!level) return "";
  const lower = level.toLowerCase();
  if (lower === "low") return "risk-low";
  if (lower === "medium") return "risk-medium";
  return "risk-high";
}

function renderWhoisLane(whois) {
  laneWhois.innerHTML = "";
  if (whois.error) {
    laneWhois.innerHTML = `<div class="check-why">${whois.error}</div>`;
    return;
  }
  const rows = [
    ["REGISTRAR", whois.registrar || "unknown"],
    ["AGE", whois.age_days != null ? `${whois.age_days} days` : "unknown"],
    ["NEW DOMAIN FLAG", whois.flag_new_domain ? "TRUE" : "FALSE"],
  ];
  for (const [label, value] of rows) {
    const field = document.createElement("div");
    field.className = "lane__field";
    const dt = document.createElement("dt");
    dt.textContent = label;
    const dd = document.createElement("dd");
    dd.textContent = value;
    if (label === "NEW DOMAIN FLAG") {
      dd.style.color = whois.flag_new_domain ? "var(--amber)" : "var(--clear)";
    }
    field.append(dt, dd);
    laneWhois.appendChild(field);
  }
}

function renderHeadersLane(headers) {
  laneHeaders.innerHTML = "";
  if (headers.error || !headers.details) {
    laneHeaders.innerHTML = `<li class="check-why">${headers.error || "No data"}</li>`;
    return;
  }
  for (const [name, info] of Object.entries(headers.details)) {
    const li = document.createElement("li");
    const dot = document.createElement("span");
    dot.className = `check-dot ${info.present ? "pass" : "fail"}`;
    const nameSpan = document.createElement("span");
    nameSpan.className = "check-name";
    nameSpan.textContent = name;
    const whySpan = document.createElement("span");
    whySpan.className = "check-why";
    whySpan.textContent = info.present ? "present" : info.why_it_matters;
    li.append(dot, nameSpan, whySpan);
    laneHeaders.appendChild(li);
  }
}

function renderReputationLane(reputation) {
  laneReputation.innerHTML = "";
  if (reputation.error) {
    laneReputation.innerHTML = `<div class="check-why">${reputation.error}</div>`;
    return;
  }
  const abuse = reputation.abuseipdb || {};
  const vt = reputation.virustotal || {};
  const rows = [
    ["RESOLVED IP", reputation.resolved_ip || "—"],
    ["ABUSE SCORE", abuse.abuse_confidence_score != null ? `${abuse.abuse_confidence_score}%` : "n/a"],
    ["VT MALICIOUS VOTES", vt.malicious_votes != null ? vt.malicious_votes : "n/a"],
    ["VT HARMLESS VOTES", vt.harmless_votes != null ? vt.harmless_votes : "n/a"],
  ];
  for (const [label, value] of rows) {
    const field = document.createElement("div");
    field.className = "lane__field";
    const dt = document.createElement("dt");
    dt.textContent = label;
    const dd = document.createElement("dd");
    dd.textContent = value;
    field.append(dt, dd);
    laneReputation.appendChild(field);
  }
}

function renderManifest(reasons) {
  manifestList.innerHTML = "";
  if (!reasons || reasons.length === 0) {
    manifestList.innerHTML = `<li class="manifest__empty">No deductions — clean scan.</li>`;
    return;
  }
  for (const reason of reasons) {
    const li = document.createElement("li");
    li.textContent = reason;
    manifestList.appendChild(li);
  }
}

function renderResults(data) {
  verdictDomain.textContent = data.domain;

  // Animate the ring: offset = circumference * (1 - score/100)
  const offset = RING_CIRCUMFERENCE * (1 - data.score / 100);
  scoreRing.style.setProperty("--ring-circumference", RING_CIRCUMFERENCE);
  scoreRing.style.strokeDasharray = RING_CIRCUMFERENCE;
  // Reset then animate on next frame so the transition actually plays
  scoreRing.style.strokeDashoffset = RING_CIRCUMFERENCE;
  requestAnimationFrame(() => {
    scoreRing.style.strokeDashoffset = offset;
  });

  const colorVar =
    data.risk_level === "Low" ? "var(--clear)" :
    data.risk_level === "Medium" ? "var(--amber)" : "var(--danger)";
  scoreRing.style.stroke = colorVar;

  scoreValue.textContent = data.score;

  riskStamp.textContent = `${data.risk_level.toUpperCase()} CLEARANCE`;
  riskStamp.className = `stamp ${riskClass(data.risk_level)}`;

  renderWhoisLane(data.details.whois);
  renderHeadersLane(data.details.headers);
  renderReputationLane(data.details.reputation);
  renderManifest(data.reasons);

  showState("results");
}

async function runScan(domain) {
  showState("loading");
  loadingDomainLabel.textContent = domain;
  scanButton.disabled = true;

  let msgIndex = 0;
  loadingText.textContent = LOADING_MESSAGES[0];
  const msgInterval = setInterval(() => {
    msgIndex = (msgIndex + 1) % LOADING_MESSAGES.length;
    loadingText.textContent = LOADING_MESSAGES[msgIndex];
  }, 1400);

  try {
    const res = await fetch(`${API_BASE}/scan/full?domain=${encodeURIComponent(domain)}`);
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.detail || `Scan failed (HTTP ${res.status})`);
    }
    const data = await res.json();
    renderResults(data);
  } catch (err) {
    errorText.textContent = err.message || "Could not reach the checkpoint. Is the backend running?";
    showState("error");
  } finally {
    clearInterval(msgInterval);
    scanButton.disabled = false;
  }
}

form.addEventListener("submit", (e) => {
  e.preventDefault();
  const domain = domainInput.value.trim().replace(/^https?:\/\//, "").replace(/\/$/, "");
  if (!domain) return;
  runScan(domain);
});

checkApiHealth();