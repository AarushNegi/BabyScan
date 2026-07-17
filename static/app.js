const scanBtn = document.getElementById("scanBtn");
const networkInput = document.getElementById("network");
const portsInput = document.getElementById("ports");
const cveInput = document.getElementById("cve");
const mdnsInput = document.getElementById("mdns");
const statusLine = document.getElementById("statusText");
const statusDot = document.getElementById("statusDot");
const results = document.getElementById("results");
const sweep = document.getElementById("sweep");

function setStatus(text, state) {
  statusLine.textContent = text;
  statusDot.className = "status-dot" + (state ? " " + state : "");
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

function renderDevice(device) {
  const openPorts = device.open_ports || [];
  const hasFindings = openPorts.length > 0;
  const hasName = device.hostname && device.hostname !== "unknown";

  const portsHtml = openPorts.map(p => {
    const banner = p.banner ? `<div class="port-banner">${escapeHtml(p.banner.slice(0, 160))}</div>` : "";
    const cves = (p.cves || []).map(c =>
      `<div class="port-cve">! ${escapeHtml(c.id || "unknown")} \u00b7 severity ${escapeHtml(String(c.severity || "?"))} \u00b7 score ${escapeHtml(String(c.score ?? "?"))}</div>`
    ).join("");

    return `
      <div class="port-row">
        <div class="port-main">
          <span class="port-num">${p.port}/tcp</span>
          <span class="port-service">${escapeHtml(p.service || "unknown")}</span>
        </div>
        ${banner}
        ${cves}
      </div>`;
  }).join("");

  return `
    <div class="device ${hasFindings ? "has-findings" : ""}">
      <div class="device-head">
        ${hasName ? `<span class="device-name">${escapeHtml(device.hostname)}</span>` : ""}
        <span class="device-ip">${escapeHtml(device.ip)}</span>
        <span class="device-mac">${escapeHtml(device.mac)}</span>
        <span class="device-badge ${hasFindings ? "open" : ""}">${openPorts.length} open port${openPorts.length === 1 ? "" : "s"}</span>
      </div>
      ${hasFindings ? `<div class="ports">${portsHtml}</div>` : ""}
    </div>`;
}

async function runScan() {
  const network = networkInput.value.trim();

  if (!network) {
    setStatus("enter a target network first, e.g. 192.168.1.0/24", "error");
    networkInput.focus();
    return;
  }

  scanBtn.disabled = true;
  sweep.classList.add("active");
  results.innerHTML = "";
  setStatus("discovering devices and resolving names \u2014 this can take a moment...", "busy");

  try {
    const resp = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        network,
        ports: portsInput.value.trim() || "1-1000",
        cve: cveInput.checked,
        mdns: mdnsInput.checked,
      }),
    });

    const data = await resp.json();

    if (!resp.ok) {
      setStatus(data.error || "scan failed", "error");
      return;
    }

    const devices = data.devices || [];

    if (devices.length === 0) {
      results.innerHTML = `<div class="empty-state">${escapeHtml(data.message || "no devices found")}</div>`;
      setStatus("no devices found", "error");
      return;
    }

    devices.sort((a, b) => (b.open_ports?.length || 0) - (a.open_ports?.length || 0));
    results.innerHTML = devices.map(renderDevice).join("");

    const withFindings = devices.filter(d => (d.open_ports || []).length > 0).length;
    setStatus(`${devices.length} device(s) found \u00b7 ${withFindings} with open ports`, "done");
  } catch (err) {
    setStatus("could not reach the scan backend", "error");
  } finally {
    scanBtn.disabled = false;
    sweep.classList.remove("active");
  }
}

scanBtn.addEventListener("click", runScan);
networkInput.addEventListener("keydown", e => { if (e.key === "Enter") runScan(); });
portsInput.addEventListener("keydown", e => { if (e.key === "Enter") runScan(); });