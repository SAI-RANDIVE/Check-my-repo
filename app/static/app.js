/* CodeSentinel UI behaviour. Vanilla JS; builds DOM nodes with textContent only (no HTML string sinks). */
(function () {
  "use strict";

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k === "class") el.className = v;
      else if (k === "text") el.textContent = v;
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? "" : String(v));
    }
    for (const c of children.flat()) {
      if (c === null || c === undefined || c === false) continue;
      el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }

  function readJSON(id) {
    const el = document.getElementById(id);
    return el ? JSON.parse(el.textContent) : null;
  }

  const COLORS = {
    P0: "#e5534b", P1: "#ec835a", P2: "#f2b324", P3: "#8b8f99",
    series: "#3987e5", accent: "#7b83eb", grid: "#23262c", surface: "#15171b", ink: "#e7e8eb", muted: "#9096a2",
  };
  const MODULE_LABELS = { secrets: "Secrets", dependencies: "Dependencies", sast: "SAST", iac: "IaC / CI", crypto: "Crypto" };

  // Row links (tables whose rows navigate)
  document.addEventListener("click", (e) => {
    const tr = e.target.closest("tr.row-link");
    if (tr && !e.target.closest("a, button") && tr.dataset.href) window.location.assign(tr.dataset.href);
  });

  // Tabs: generic [role=tab] groups with data-tab -> [data-panel]
  function initTabs(container, onChange) {
    const tabs = $$('[role="tab"]', container);
    const select = (name) => {
      tabs.forEach((t) => t.setAttribute("aria-selected", String(t.dataset.tab === name)));
      $$("[data-panel]").forEach((p) => p.classList.toggle("hidden-tab", p.dataset.panel !== name));
      if (onChange) onChange(name);
    };
    tabs.forEach((t) => t.addEventListener("click", () => select(t.dataset.tab)));
    return select;
  }

  /* ------------------------------------------------------------------ home */
  const form = $("#scan-form");
  if (form) {
    let source = "url";
    const err = $("#form-error");
    const showError = (msg) => { err.textContent = msg; err.classList.toggle("hidden", !msg); };
    $$('[role="tab"]', form).forEach((t) => t.addEventListener("click", () => {
      source = t.dataset.source;
      $$('[role="tab"]', form).forEach((x) => x.setAttribute("aria-selected", String(x === t)));
      $$("[data-pane]", form).forEach((p) => p.classList.toggle("hidden", p.dataset.pane !== source));
      showError("");
    }));

    async function submitScan(fd) {
      const btn = $("#scan-btn");
      btn.disabled = true;
      btn.textContent = "Starting…";
      try {
        const res = await fetch("/api/scans", { method: "POST", body: fd });
        const body = await res.json().catch(() => ({}));
        if (!res.ok) {
          const d = body.detail;
          throw new Error(Array.isArray(d) ? d.map((x) => x.msg).join("; ") : d || `Request failed (${res.status})`);
        }
        window.location.assign(body.report_url);
      } catch (ex) {
        showError(ex.message);
        btn.disabled = false;
        btn.textContent = "Start scan";
      }
    }

    function baseFormData() {
      const fd = new FormData();
      fd.append("include_history", form.include_history.checked ? "true" : "false");
      fd.append("include_transitive", form.include_transitive.checked ? "true" : "false");
      if (form.fail_on.value) fd.append("fail_on", form.fail_on.value);
      return fd;
    }

    form.addEventListener("submit", (e) => {
      e.preventDefault();
      showError("");
      const fd = baseFormData();
      if (source === "url") {
        const url = form.url.value.trim();
        if (!/^https:\/\/github\.com\/[A-Za-z0-9-]+\/[A-Za-z0-9._-]+\/?$/.test(url.replace(/\.git$/, ""))) {
          return showError("Enter a repository URL like https://github.com/owner/repo");
        }
        fd.append("url", url);
      } else if (source === "file") {
        const f = form.file.files[0];
        if (!f) return showError("Choose a .zip file.");
        if (!f.name.toLowerCase().endsWith(".zip")) return showError("Only .zip archives are accepted.");
        fd.append("file", f);
      } else {
        const p = form.path.value.trim();
        if (!p) return showError("Enter a directory path.");
        fd.append("path", p);
      }
      submitScan(fd);
    });

    $$("[data-demo-path]").forEach((b) => b.addEventListener("click", () => {
      const fd = baseFormData();
      fd.append("path", b.dataset.demoPath);
      submitScan(fd);
    }));
  }

  /* ------------------------------------------------------------------ progress */
  const progress = $("#progress");
  if (progress) {
    const id = progress.dataset.scanId;
    const fmt = (s) => (s >= 60 ? `${Math.floor(s / 60)}m ${(s % 60).toFixed(0)}s` : `${s.toFixed(1)} s`);
    let timer = null;
    async function poll() {
      try {
        const res = await fetch(`/api/scans/${id}/status`, { headers: { Accept: "application/json" } });
        if (!res.ok) throw new Error(`status ${res.status}`);
        const s = await res.json();
        $("#elapsed").textContent = fmt(s.elapsed_seconds);
        for (const st of s.stages) {
          const row = $(`[data-stage="${CSS.escape(st.name)}"]`);
          if (!row) continue;
          row.dataset.state = st.state;
          $("[data-seconds]", row).textContent = st.seconds != null ? `${st.seconds.toFixed(1)} s` : st.state === "skipped" ? "skipped" : "";
        }
        if (s.status === "done") {
          $("#progress-status").textContent = "Complete";
          window.location.reload();
          return;
        }
        if (s.status === "error") {
          $("#progress-status").textContent = "Failed";
          const e = $("#progress-error");
          e.textContent = s.error || "The scan failed.";
          e.classList.remove("hidden");
          return;
        }
        $("#progress-status").textContent = s.stage === "Queued" ? "Queued" : `${s.stage}…`;
      } catch (ex) {
        $("#progress-status").textContent = "Reconnecting…";
      }
      timer = window.setTimeout(poll, 1000);
    }
    if (!$("#progress-error").textContent.trim()) poll();
    window.addEventListener("beforeunload", () => timer && clearTimeout(timer));
  }

  /* ------------------------------------------------------------------ charts */
  function chartDefaults() {
    if (!window.Chart) return false;
    Chart.defaults.color = COLORS.muted;
    Chart.defaults.font.family = "Inter, system-ui, sans-serif";
    Chart.defaults.font.size = 11;
    Chart.defaults.borderColor = COLORS.grid;
    Chart.defaults.plugins.tooltip.backgroundColor = "#0d0e11";
    Chart.defaults.plugins.tooltip.borderColor = "#31353d";
    Chart.defaults.plugins.tooltip.borderWidth = 1;
    Chart.defaults.plugins.tooltip.titleColor = COLORS.ink;
    Chart.defaults.plugins.tooltip.bodyColor = "#c9ccd3";
    Chart.defaults.plugins.tooltip.padding = 10;
    Chart.defaults.plugins.tooltip.cornerRadius = 6;
    Chart.defaults.maintainAspectRatio = false;
    return true;
  }

  // Draws dashed reference lines (P0 thresholds) on the scatter.
  const thresholdPlugin = {
    id: "thresholds",
    afterDatasetsDraw(chart, _args, opts) {
      const { ctx, chartArea: a, scales: { x, y } } = chart;
      ctx.save();
      ctx.setLineDash([4, 4]);
      ctx.strokeStyle = "#4a4f59";
      ctx.lineWidth = 1;
      if (opts.x != null) { const px = x.getPixelForValue(opts.x); ctx.beginPath(); ctx.moveTo(px, a.top); ctx.lineTo(px, a.bottom); ctx.stroke(); }
      if (opts.y != null) { const py = y.getPixelForValue(opts.y); ctx.beginPath(); ctx.moveTo(a.left, py); ctx.lineTo(a.right, py); ctx.stroke(); }
      ctx.restore();
    },
  };

  /* ------------------------------------------------------------------ report */
  const data = readJSON("report-data");
  if (data) {
    const rows = data.findings;
    const selectTab = initTabs($("#report-tabs"));

    if (chartDefaults()) {
      const mods = Object.keys(MODULE_LABELS);
      new Chart($("#chart-modules"), {
        type: "bar",
        data: { labels: ["Secrets", "Deps", "SAST", "IaC / CI", "Crypto"], datasets: [{ data: mods.map((m) => data.byModule[m] || 0), backgroundColor: COLORS.series, borderRadius: 4, maxBarThickness: 34 }] },
        options: {
          plugins: { legend: { display: false }, tooltip: { callbacks: { label: (c) => ` ${c.raw} open findings` } } },
          scales: { x: { grid: { display: false }, ticks: { maxRotation: 0, autoSkip: false } }, y: { beginAtZero: true, ticks: { precision: 0 }, grid: { color: COLORS.grid } } },
          onClick: (_e, els) => { if (els.length) { $("#f-module").value = mods[els[0].index]; renderTable(); selectTab("findings"); } },
        },
      });

      const tiers = ["P0", "P1", "P2", "P3"];
      new Chart($("#chart-priority"), {
        type: "doughnut",
        data: { labels: tiers, datasets: [{ data: tiers.map((t) => data.counts[t] || 0), backgroundColor: tiers.map((t) => COLORS[t]), borderColor: COLORS.surface, borderWidth: 2 }] },
        options: {
          cutout: "64%",
          plugins: {
            legend: { position: "right", labels: { boxWidth: 10, boxHeight: 10, useBorderRadius: true, borderRadius: 2, generateLabels: (c) => tiers.map((t, i) => ({ text: `${t}  ${c.data.datasets[0].data[i]}`, fillStyle: COLORS[t], strokeStyle: COLORS[t], fontColor: COLORS.ink, index: i })) } },
            tooltip: { callbacks: { label: (c) => ` ${c.label}: ${c.raw} findings` } },
          },
          onClick: (_e, els) => { if (els.length) { $("#f-priority").value = tiers[els[0].index]; renderTable(); selectTab("findings"); } },
        },
      });

      const deps = rows.filter((r) => r.module === "dependencies" && r.cvss != null && r.epss != null);
      const pt = (r) => ({ x: r.cvss, y: Math.max(r.epss, 0.0001), r });
      const scatter = $("#chart-scatter");
      if (deps.length) {
        new Chart(scatter, {
          type: "scatter",
          data: {
            datasets: [
              { label: "Not in KEV", data: deps.filter((r) => !r.kev).map(pt), backgroundColor: "rgba(57,135,229,.78)", borderColor: COLORS.surface, borderWidth: 1, pointRadius: 4, pointHoverRadius: 6, clip: 10 },
              { label: "In CISA KEV", data: deps.filter((r) => r.kev).map(pt), backgroundColor: COLORS.P0, borderColor: "#ffffff", borderWidth: 1.5, pointRadius: 7, pointHoverRadius: 9, clip: 10 },
            ],
          },
          plugins: [thresholdPlugin],
          options: {
            layout: { padding: { top: 6, right: 8 } },
            plugins: {
              thresholds: { x: 9, y: 0.1 },
              legend: { position: "top", align: "start", labels: { boxWidth: 8, boxHeight: 8, padding: 14, usePointStyle: true, color: COLORS.ink } },
              tooltip: { callbacks: {
                title: (items) => `${items[0].raw.r.package} ${items[0].raw.r.version}`,
                label: (c) => [` ${c.raw.r.rule}`, ` CVSS ${c.raw.r.cvss.toFixed(1)} · EPSS ${(c.raw.r.epss * 100).toFixed(2)}%`, ` ${c.raw.r.priority}${c.raw.r.kev ? " · CISA KEV" : ""}`],
              } },
            },
            scales: {
              x: { min: 0, max: 10, title: { display: true, text: "CVSS base score" }, grid: { color: COLORS.grid } },
              y: { type: "logarithmic", min: 0.0001, max: 1, title: { display: true, text: "EPSS" }, grid: { color: COLORS.grid },
                   ticks: { callback: (v) => ([0.0001, 0.001, 0.01, 0.1, 1].includes(Number(v)) ? `${+(v * 100).toPrecision(2)}%` : "") } },
            },
            onClick: (_e, els, chart) => {
              if (!els.length) return;
              const p = chart.data.datasets[els[0].datasetIndex].data[els[0].index];
              if (p.r.id) window.location.assign(`/findings/${p.r.id}`);
            },
          },
        });
      } else {
        scatter.replaceWith(h("p", { class: "text-muted text-[13px]", text: "No dependency vulnerabilities with both CVSS and EPSS scores." }));
      }
    }

    // ---- findings table: filter, search, sort, paginate
    const tbody = $("#findings-table tbody");
    const pager = $("#f-pager");
    const PAGE = 50;
    let page = 0;
    let sortKey = "priority";
    let sortDir = 1;
    const tierRank = { P0: 0, P1: 1, P2: 2, P3: 3 };

    function filtered() {
      const q = $("#f-search").value.trim().toLowerCase();
      const mod = $("#f-module").value, pri = $("#f-priority").value, st = $("#f-status").value;
      let out = rows.filter((r) => (!mod || r.module === mod) && (!pri || r.priority === pri) && (!st || r.status === st) &&
        (!q || [r.rule, r.title, r.file, r.package, r.reason].some((v) => v && String(v).toLowerCase().includes(q))));
      const key = (r) => (sortKey === "priority" ? tierRank[r.priority] * 1e6 - r.risk : sortKey === "risk" ? -r.risk : String(r[sortKey] || ""));
      out.sort((a, b) => { const ka = key(a), kb = key(b); return (ka > kb ? 1 : ka < kb ? -1 : 0) * sortDir; });
      return out;
    }

    function renderTable() {
      const list = filtered();
      const pages = Math.max(1, Math.ceil(list.length / PAGE));
      if (page >= pages) page = pages - 1;
      tbody.replaceChildren(...list.slice(page * PAGE, page * PAGE + PAGE).map((r) => {
        const badges = [];
        if (r.kev) badges.push(h("span", { class: "chip chip-kev ml-1.5", text: "KEV" }));
        if (r.tainted) badges.push(h("span", { class: "chip chip-p1 ml-1.5", text: "tainted" }));
        if (r.historical) badges.push(h("span", { class: "chip chip-p1 ml-1.5", text: "history" }));
        if (r.status !== "open") badges.push(h("span", { class: "chip chip-muted ml-1.5", text: r.status.replace("_", " ") }));
        return h("tr", { class: "row-link", "data-href": `/findings/${r.id}` },
          h("td", {}, h("span", { class: `chip chip-${r.priority.toLowerCase()}`, text: r.priority })),
          h("td", { class: "num font-mono text-[12.5px]", text: r.risk.toFixed(1) }),
          h("td", { class: "text-muted", text: MODULE_LABELS[r.module] }),
          h("td", { class: "font-mono text-[12.5px] whitespace-nowrap", text: r.rule }),
          h("td", { class: "max-w-[440px]" }, h("a", { href: `/findings/${r.id}`, class: "hover:underline", text: r.title }), ...badges),
          h("td", { class: "font-mono text-[12px] text-muted break-all", text: r.line ? `${r.file}:${r.line}` : r.file }),
          h("td", { class: "text-muted text-[12.5px]", text: r.reason || "" }),
        );
      }));
      if (!list.length) tbody.append(h("tr", {}, h("td", { colspan: 7, class: "text-muted", text: "No findings match these filters." })));
      $("#f-count").textContent = `${list.length} of ${rows.length}`;
      pager.replaceChildren();
      if (pages > 1) {
        pager.append(
          h("button", { class: "btn btn-sm", disabled: page === 0, onclick: () => { page--; renderTable(); } }, "Previous"),
          h("span", { class: "text-muted", text: `Page ${page + 1} of ${pages}` }),
          h("button", { class: "btn btn-sm", disabled: page >= pages - 1, onclick: () => { page++; renderTable(); } }, "Next"),
        );
      }
    }
    ["#f-search", "#f-module", "#f-priority", "#f-status"].forEach((s) => $(s).addEventListener("input", () => { page = 0; renderTable(); }));
    $$("#findings-table th[data-sort]").forEach((th) => th.addEventListener("click", () => {
      const k = th.dataset.sort;
      sortDir = sortKey === k ? -sortDir : 1;
      sortKey = k;
      renderTable();
    }));
    $$("[data-filter-package]").forEach((b) => b.addEventListener("click", () => {
      $("#f-search").value = b.dataset.filterPackage;
      $("#f-module").value = "dependencies";
      page = 0;
      renderTable();
      selectTab("findings");
    }));
    renderTable();
  }

  /* ------------------------------------------------------------------ finding */
  $$("[data-copy]").forEach((b) => b.addEventListener("click", async () => {
    const src = document.getElementById(b.dataset.copy);
    try { await navigator.clipboard.writeText(src.textContent.trim()); b.textContent = "Copied"; } catch { b.textContent = "Select & copy"; }
    setTimeout(() => { b.textContent = "Copy"; }, 1600);
  }));

  const triage = $("#triage-form");
  if (triage) {
    triage.addEventListener("submit", async (e) => {
      e.preventDefault();
      const msg = $("#triage-msg");
      const body = { status: triage.status.value, justification: triage.justification.value };
      if (body.status !== "open" && body.justification.trim().length < 10) {
        msg.textContent = "Add a justification (at least 10 characters).";
        msg.className = "text-2xs text-p0";
        return;
      }
      const res = await fetch(`/api/findings/${triage.dataset.findingId}/triage`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
      });
      const out = await res.json().catch(() => ({}));
      if (!res.ok) {
        msg.textContent = typeof out.detail === "string" ? out.detail : "Could not save.";
        msg.className = "text-2xs text-p0";
        return;
      }
      $("#triage-state").textContent = out.status.replace("_", " ");
      msg.textContent = `Saved. Scan is now grade ${out.scan.grade} (${Math.round(out.scan.score)}), gate ${out.scan.gate_passed ? "PASS" : "FAIL"}.`;
      msg.className = "text-2xs text-good";
    });
  }

  /* ------------------------------------------------------------------ history */
  const trendIds = readJSON("trend-data");
  if (trendIds && trendIds.length && chartDefaults() && $("#chart-trend")) {
    const scores = readJSON("trend-scores");
    const grades = readJSON("trend-grades");
    new Chart($("#chart-trend"), {
      type: "line",
      data: { labels: trendIds.map((i) => `#${i}`), datasets: [{ data: scores, borderColor: COLORS.accent, backgroundColor: COLORS.accent, borderWidth: 2, pointRadius: 4, pointHoverRadius: 6, tension: 0 }] },
      options: {
        plugins: { legend: { display: false }, tooltip: { callbacks: { label: (c) => ` score ${Math.round(c.raw)} · grade ${grades[c.dataIndex]}` } } },
        scales: { y: { min: 0, max: 100, ticks: { stepSize: 20 }, grid: { color: COLORS.grid } }, x: { grid: { display: false } } },
        onClick: (_e, els) => { if (els.length) window.location.assign(`/scans/${trendIds[els[0].index]}`); },
      },
    });
  }
})();
