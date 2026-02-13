(function () {
  const form = document.getElementById("analysis-form");
  const overlay = document.getElementById("loading-overlay");
  const input = document.getElementById("sample");
  const picked = document.getElementById("picked-file");
  const zone = document.getElementById("upload-zone");
  let notifyStack = null;

  if (overlay) {
    overlay.hidden = true;
  }

  function ensureNotifyStack() {
    if (notifyStack) {
      return notifyStack;
    }
    const existing = document.getElementById("notify-stack");
    if (existing) {
      notifyStack = existing;
      return notifyStack;
    }
    const stack = document.createElement("div");
    stack.id = "notify-stack";
    stack.className = "notify-stack";
    document.body.appendChild(stack);
    notifyStack = stack;
    return notifyStack;
  }

  function showToast(message, status, jobUrl) {
    const stack = ensureNotifyStack();
    const toast = document.createElement("article");
    const tone = status === "completed" ? "ok" : status === "failed" ? "bad" : "info";
    toast.className = `notify-toast ${tone}`;

    const text = document.createElement("p");
    text.className = "notify-text";
    text.textContent = message;
    toast.appendChild(text);

    if (jobUrl) {
      const openLink = document.createElement("a");
      openLink.href = jobUrl;
      openLink.textContent = "Open report";
      toast.appendChild(openLink);
    }

    stack.appendChild(toast);
    window.setTimeout(function () {
      toast.classList.add("hide");
    }, 5200);
    window.setTimeout(function () {
      toast.remove();
    }, 5800);
  }

  function normalizeStatus(value) {
    return String(value || "").trim().toLowerCase();
  }

  function isActiveStatus(value) {
    const normalized = normalizeStatus(value);
    return normalized === "queued" || normalized === "running";
  }

  function isTerminalStatus(value) {
    const normalized = normalizeStatus(value);
    return normalized === "completed" || normalized === "failed";
  }

  function markNotificationSent(jobId, status) {
    if (!jobId || !status) {
      return true;
    }
    const key = `qs-notified:${jobId}:${status}`;
    try {
      if (window.sessionStorage.getItem(key) === "1") {
        return false;
      }
      window.sessionStorage.setItem(key, "1");
    } catch (_err) {
      // Ignore storage restrictions and continue best effort.
    }
    return true;
  }

  function analysisFinished(payload) {
    if (!payload || !payload.jobId) {
      return;
    }
    const status = normalizeStatus(payload.status);
    if (!isTerminalStatus(status)) {
      return;
    }
    if (!markNotificationSent(String(payload.jobId), status)) {
      return;
    }

    const sampleName = String(payload.sampleName || "Sample");
    const body = `${sampleName} is now ${status}.`;
    showToast(body, status, payload.jobUrl || "");
  }

  window.QSNotify = {
    analysisFinished,
    isActiveStatus,
    isTerminalStatus,
    normalizeStatus,
  };
  window.dispatchEvent(new Event("qsnotify-ready"));

  function refreshPresetSelection() {
    document.querySelectorAll(".preset-card").forEach((card) => {
      const radio = card.querySelector("input[type='radio']");
      if (radio && radio.checked) {
        card.classList.add("selected");
      } else {
        card.classList.remove("selected");
      }
    });
  }

  document.querySelectorAll(".preset-card input[type='radio']").forEach((node) => {
    node.addEventListener("change", refreshPresetSelection);
  });
  refreshPresetSelection();

  if (input && picked) {
    input.addEventListener("change", function () {
      if (input.files && input.files.length > 0) {
        picked.textContent = input.files[0].name;
      } else {
        picked.textContent = "No file selected";
      }
    });
  }

  if (zone && input) {
    ["dragenter", "dragover"].forEach((eventName) => {
      zone.addEventListener(eventName, function (event) {
        event.preventDefault();
        zone.classList.add("drag");
      });
    });
    ["dragleave", "drop"].forEach((eventName) => {
      zone.addEventListener(eventName, function (event) {
        event.preventDefault();
        zone.classList.remove("drag");
      });
    });
    zone.addEventListener("drop", function (event) {
      const files = event.dataTransfer ? event.dataTransfer.files : null;
      if (files && files.length) {
        if (window.DataTransfer) {
          const dataTransfer = new DataTransfer();
          dataTransfer.items.add(files[0]);
          input.files = dataTransfer.files;
        }
        picked.textContent = files[0].name;
      }
    });
  }

  if (form && overlay) {
    form.addEventListener("submit", function () {
      overlay.hidden = false;
    });
  }

  function loadKnownStates() {
    try {
      const raw = window.sessionStorage.getItem("qs-job-states");
      if (!raw) {
        return {};
      }
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === "object") {
        return parsed;
      }
    } catch (_err) {
      // Ignore parsing/storage errors and start fresh.
    }
    return {};
  }

  function saveKnownStates(mapObj) {
    try {
      window.sessionStorage.setItem("qs-job-states", JSON.stringify(mapObj));
    } catch (_err) {
      // Ignore storage errors.
    }
  }

  function updateHomeRecentCards(jobs) {
    if (!Array.isArray(jobs) || jobs.length === 0) {
      return;
    }
    const jobsById = {};
    jobs.forEach((row) => {
      if (!row || !row.id) {
        return;
      }
      jobsById[String(row.id)] = row;
    });

    const statusClasses = ["queued", "running", "completed", "failed"];
    document.querySelectorAll(".recent-job-card[data-job-id]").forEach((card) => {
      const jobId = String(card.getAttribute("data-job-id") || "");
      if (!jobId || !(jobId in jobsById)) {
        return;
      }
      const row = jobsById[jobId];
      const status = normalizeStatus(row.status);
      const pill = card.querySelector(".js-recent-status");
      const openBtn = card.querySelector(".js-recent-open");
      if (!pill) {
        return;
      }
      pill.textContent = status || "-";
      statusClasses.forEach((cls) => pill.classList.remove(cls));
      if (status) {
        pill.classList.add(status);
      }
      if (openBtn) {
        statusClasses.forEach((cls) => openBtn.classList.remove(cls));
        if (status) {
          openBtn.classList.add(status);
        }
      }
    });
  }

  function startGlobalJobNotifier() {
    if (window.__qsGlobalNotifierStarted) {
      return;
    }
    window.__qsGlobalNotifierStarted = true;

    const knownStates = loadKnownStates();

    async function pollJobTransitions() {
      try {
        const res = await fetch("/api/jobs", { cache: "no-store" });
        if (!res.ok) {
          return;
        }
        const payload = await res.json();
        if (!payload || !Array.isArray(payload.jobs)) {
          return;
        }

        updateHomeRecentCards(payload.jobs);

        payload.jobs.forEach((row) => {
          if (!row || !row.id) {
            return;
          }

          const jobId = String(row.id);
          const current = normalizeStatus(row.status);
          const previous = normalizeStatus(knownStates[jobId] || "");
          if (
            (previous === "queued" || previous === "running") &&
            isTerminalStatus(current)
          ) {
            analysisFinished({
              jobId,
              status: current,
              sampleName: row.sample_name,
              jobUrl: `/jobs/${encodeURIComponent(jobId)}`,
            });
          }
          knownStates[jobId] = current;
        });

        saveKnownStates(knownStates);
      } catch (_err) {
        // Keep silent on polling errors.
      }
    }

    pollJobTransitions();
    window.setInterval(pollJobTransitions, 2000);
  }

  startGlobalJobNotifier();

  function scalar(value) {
    if (value === null || value === undefined) {
      return "null";
    }
    if (typeof value === "boolean") {
      return value ? "true" : "false";
    }
    if (typeof value === "object") {
      return JSON.stringify(value);
    }
    return String(value);
  }

  function makeNode(key, value) {
    const wrapper = document.createElement("div");
    wrapper.className = "json-node";

    const line = document.createElement("div");
    const keyEl = document.createElement("span");
    keyEl.className = "json-key";
    keyEl.textContent = key + ": ";

    if (value !== null && typeof value === "object") {
      const details = document.createElement("details");
      details.open = true;
      const summary = document.createElement("summary");
      summary.appendChild(keyEl);
      const scalarEl = document.createElement("span");
      scalarEl.className = "json-scalar";
      scalarEl.textContent = Array.isArray(value)
        ? `[${value.length} items]`
        : `{${Object.keys(value).length} keys}`;
      summary.appendChild(scalarEl);
      details.appendChild(summary);

      Object.entries(value).forEach(([childKey, childValue]) => {
        details.appendChild(makeNode(childKey, childValue));
      });
      wrapper.appendChild(details);
    } else {
      line.appendChild(keyEl);
      const val = document.createElement("span");
      val.className = "json-scalar";
      val.textContent = scalar(value);
      line.appendChild(val);
      wrapper.appendChild(line);
    }

    return wrapper;
  }

  const reportScript = document.getElementById("report-data");
  const reportRoot = document.getElementById("json-report");
  if (reportScript && reportRoot) {
    try {
      const report = JSON.parse(reportScript.textContent);
      if (report && typeof report === "object") {
        Object.entries(report).forEach(([key, value]) => {
          reportRoot.appendChild(makeNode(key, value));
        });
      }
    } catch (error) {
      const fallback = document.createElement("pre");
      fallback.className = "console";
      fallback.textContent = `JSON parse error: ${error}`;
      reportRoot.appendChild(fallback);
    }
  }
})();
