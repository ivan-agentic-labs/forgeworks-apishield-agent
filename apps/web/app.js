(() => {
  const config = window.APISHIELD_CONFIG || {};
  const params = new URLSearchParams(window.location.search);
  const storageKey = "apishield.apiBaseUrl";
  const defaultBaseUrl = config.apiBaseUrl || "http://127.0.0.1:8000";
  function initialApiBase(candidate, trustedBase) {
    try {
      const trusted = new URL(trustedBase, location.origin);
      const selected = new URL(candidate || trustedBase, location.origin);
      if (!/^https?:$/.test(selected.protocol) || selected.origin !== trusted.origin || selected.username || selected.password || selected.search || selected.hash) return trustedBase;
      return selected.href.replace(/\/$/, '');
    } catch (_) { return trustedBase; }
  }
  const configuredBaseUrl = initialApiBase(params.get("apiBaseUrl") || localStorage.getItem(storageKey), defaultBaseUrl);

  const form = document.querySelector("#lookup-form");
  const baseUrlInput = document.querySelector("#api-base-url");
  const tokenInput = document.querySelector("#bearer-token");
  const analysisIdInput = document.querySelector("#analysis-id");
  const jobIdInput = document.querySelector("#job-id");
  const button = document.querySelector("#load-button");
  const status = document.querySelector("#status");
  const errorPanel = document.querySelector("#error-panel");
  const errorMessage = document.querySelector("#error-message");
  const results = document.querySelector("#results");
  const analysisStatus = document.querySelector("#analysis-status");
  const analysisDetails = document.querySelector("#analysis-details");
  const jobDetails = document.querySelector("#job-details");
  const findingsList = document.querySelector("#findings-list");
  const findingCount = document.querySelector("#finding-count");

  baseUrlInput.value = configuredBaseUrl;

  function setStatus(message, kind = "ready") {
    status.textContent = message;
    status.dataset.kind = kind;
  }

  function setLoading(loading) {
    button.disabled = loading;
    button.textContent = loading ? "Loading…" : "Load analysis";
  }

  function showError(message) {
    errorMessage.textContent = message;
    errorPanel.hidden = false;
  }

  function clearError() {
    errorPanel.hidden = true;
    errorMessage.textContent = "";
  }

  function apiUrl(baseUrl, path) {
    return `${baseUrl.replace(/\/+$/, "")}${path}`;
  }

  async function getJson(baseUrl, path, token) {
    const headers = { Accept: "application/json" };
    if (token) headers.Authorization = `Bearer ${token}`;
    const response = await fetch(apiUrl(baseUrl, path), { headers });
    let payload;
    try {
      payload = await response.json();
    } catch (_) {
      payload = {};
    }
    if (!response.ok) {
      const detail = payload.detail || payload.title || `HTTP ${response.status}`;
      throw new Error(`${response.status}: ${detail}`);
    }
    return payload;
  }

  function addDetails(target, values) {
    target.replaceChildren();
    Object.entries(values).forEach(([label, value]) => {
      const term = document.createElement("dt");
      term.textContent = label.replaceAll("_", " ");
      const description = document.createElement("dd");
      description.textContent = value === null || value === undefined || value === "" ? "—" : String(value);
      target.append(term, description);
    });
  }

  function renderFindings(payload) {
    const items = Array.isArray(payload.items) ? payload.items : [];
    findingCount.textContent = `${items.length} returned${payload.has_more ? ", more available" : ""}`;
    findingsList.replaceChildren();
    if (!items.length) {
      const empty = document.createElement("p");
      empty.className = "muted";
      empty.textContent = "No findings returned for this page.";
      findingsList.append(empty);
      return;
    }
    items.forEach((finding) => {
      const item = document.createElement("article");
      item.className = "finding";
      const heading = document.createElement("div");
      heading.className = "finding-heading";
      const rule = document.createElement("strong");
      rule.textContent = finding.rule_id || "Unnamed rule";
      const severity = document.createElement("span");
      severity.className = "pill";
      severity.textContent = finding.severity || "—";
      heading.append(rule, severity);
      const pointer = document.createElement("code");
      pointer.textContent = finding.openapi_pointer || "No OpenAPI pointer";
      item.append(heading, pointer);
      findingsList.append(item);
    });
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    clearError();
    results.hidden = true;
    const baseUrl = baseUrlInput.value.trim();
    const analysisId = analysisIdInput.value.trim();
    const jobId = jobIdInput.value.trim();
    const token = tokenInput.value.trim();
    if (!baseUrl || !analysisId || !jobId) {
      showError("API base URL, analysis ID, and job ID are required.");
      setStatus("Input required.", "error");
      return;
    }

    localStorage.setItem(storageKey, baseUrl);
    setLoading(true);
    setStatus("Loading analysis, job, and findings…", "loading");
    try {
      const [analysis, job, findings] = await Promise.all([
        getJson(baseUrl, `/v1/analyses/${encodeURIComponent(analysisId)}`, token),
        getJson(baseUrl, `/v1/jobs/${encodeURIComponent(jobId)}`, token),
        getJson(baseUrl, `/v1/analyses/${encodeURIComponent(analysisId)}/findings?limit=100`, token),
      ]);
      addDetails(analysisDetails, {
        id: analysis.id,
        status: analysis.status,
        repository_id: analysis.repository_id,
        base_sha: analysis.base_sha,
        head_sha: analysis.head_sha,
        finding_count: analysis.finding_count,
        created_at: analysis.created_at,
      });
      addDetails(jobDetails, {
        id: job.id,
        state: job.state,
        kind: job.kind,
        state_version: job.state_version,
        attempt_count: job.attempt_count,
        last_error_code: job.last_error_code,
      });
      analysisStatus.textContent = analysis.status || job.state || "UNKNOWN";
      renderFindings(findings);
      results.hidden = false;
      setStatus("Loaded successfully.", "success");
    } catch (error) {
      showError(error instanceof Error ? error.message : "The API request failed.");
      setStatus("Request failed.", "error");
    } finally {
      setLoading(false);
    }
  });
})();
