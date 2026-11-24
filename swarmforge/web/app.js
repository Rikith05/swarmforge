/* Main SwarmForge Studio Controller & Live SSE Orchestrator Client */

(function () {
  const esc = window.SwarmDAG.esc;

  let missions = [];
  let currentRun = null;
  let currentNodes = [];
  let currentEdges = [];
  let selectedNodeId = null;
  let firewallEventsCount = 0;

  function setupTabs() {
    document.querySelectorAll(".tab-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        const target = btn.getAttribute("data-tab");
        document.querySelectorAll(".tab-btn").forEach((b) => {
          const active = b === btn;
          b.classList.toggle("active", active);
          b.setAttribute("aria-selected", String(active));
        });
        document.querySelectorAll(".tab-panel").forEach((p) => {
          p.classList.toggle("active", p.id === `tab-${target}`);
        });
      });
    });

    document.querySelectorAll(".subtab-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        const target = btn.getAttribute("data-subtab");
        document.querySelectorAll(".subtab-btn").forEach((b) => b.classList.toggle("active", b === btn));
        document.querySelectorAll(".subtab-body").forEach((b) => b.classList.toggle("active", b.id === `subtab-${target}`));
      });
    });
  }

  function renderInspector(nodeId) {
    selectedNodeId = nodeId;
    const box = document.getElementById("node-inspector");
    const node = currentNodes.find((n) => n.id === nodeId);
    if (!box || !node) return;
    const toolsHtml = (node.allowed_tools || [])
      .map((t) => `<span class="badge badge-slate" style="margin-right:4px;">${esc(t)}</span>`)
      .join("");
    box.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
        <strong>${esc(node.label)} <span class="muted mono">(${esc(node.role)})</span></strong>
        <span class="badge badge-cyan">${esc(node.status)}</span>
      </div>
      <div class="muted" style="font-size:12px;margin-bottom:6px;">${esc(node.description)}</div>
      <div style="margin-bottom:6px;">${toolsHtml}</div>
      <div style="font-size:12.5px;"><strong>Output:</strong> ${esc(node.summary || "Waiting for node execution...")}</div>
    `;
    window.SwarmDAG.render(document.getElementById("dag-svg"), currentNodes, currentEdges, selectedNodeId, renderInspector);
  }

  function renderFindingsAndPatches(run) {
    const pane = document.getElementById("subtab-findings");
    if (!pane) return;
    const findingsHtml = (run.findings || []).length
      ? run.findings
          .map((f) => {
            const sev = String(f.severity || "info").toUpperCase();
            const cls = sev === "CRITICAL" ? "badge-rose" : sev === "HIGH" ? "badge-amber" : "badge-cyan";
            return `<div class="event-card ev-block">
              <div class="event-head"><span class="badge ${cls}">${esc(sev)}</span><span class="mono">${esc(f.file || "")}</span></div>
              <div class="event-title">${esc(f.title || f.code)}</div>
              <div class="muted" style="font-size:12px;margin-top:3px;">${esc(f.evidence || f.message || "")}</div>
            </div>`;
          })
          .join("")
      : `<p class="muted">No security or complexity findings reported.</p>`;

    const patchesHtml = (run.patches || [])
      .map((p) => {
        const diffColored = (p.diff || "")
          .split("\n")
          .map((line) => {
            if (line.startsWith("+") && !line.startsWith("+++")) return `<span class="diff-add">${esc(line)}</span>`;
            if (line.startsWith("-") && !line.startsWith("---")) return `<span class="diff-del">${esc(line)}</span>`;
            if (line.startsWith("@@")) return `<span class="diff-hunk">${esc(line)}</span>`;
            return esc(line);
          })
          .join("\n");
        return `<div class="card" style="margin-top:10px;">
          <h3>Patch: <span class="mono">${esc(p.file)}</span></h3>
          <p class="muted" style="font-size:12px;margin:0 0 8px;">${esc(p.summary)}</p>
          <div class="diff-box">${diffColored}</div>
        </div>`;
      })
      .join("");

    pane.innerHTML = `<h3 style="margin-top:0;">Findings (${(run.findings || []).length})</h3>${findingsHtml}${patchesHtml}`;
  }

  function renderJudgeTab(run) {
    const pane = document.getElementById("subtab-judge");
    if (!pane) return;
    const j = run.judge;
    if (!j) {
      pane.innerHTML = `<p class="muted">Judge verdict will appear once verification finishes.</p>`;
      return;
    }
    const assertionsHtml = (j.assertions || [])
      .map(
        (a) => `<tr>
          <td>${esc(a.name)}</td>
          <td><span class="badge ${a.passed ? "badge-emerald" : "badge-rose"}">${a.passed ? "PASS" : "FAIL"}</span></td>
          <td class="mono">${esc(a.value)}</td>
        </tr>`
      )
      .join("");
    const notesHtml = (j.remediation_notes || []).length
      ? `<div class="event-card ev-heal" style="margin-top:10px;"><strong>Remediation Notes</strong><br/>${j.remediation_notes.map(esc).join("<br/>")}</div>`
      : "";

    pane.innerHTML = `
      <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <h3 style="margin:0;">Verdict Score: ${j.overall_score.toFixed(1)} / 100</h3>
          <span class="badge ${j.passed ? "badge-emerald" : "badge-rose"}">${j.passed ? "PASSED" : "FAILED"}</span>
        </div>
        <div class="muted mono" style="font-size:12px;margin-top:8px;">
          Groundedness: ${j.groundedness}% · Policy Compliance: ${j.policy_compliance}% · Completeness: ${j.completeness}%
        </div>
      </div>
      <table class="data-table" style="margin-top:10px;">
        <thead><tr><th>Assertion</th><th>Status</th><th>Measured</th></tr></thead>
        <tbody>${assertionsHtml}</tbody>
      </table>
      ${notesHtml}
    `;
  }

  function appendEventCard(ev) {
    const trace = document.getElementById("subtab-trace");
    const fwFeed = document.getElementById("subtab-fwfeed");
    let cls = "";
    if (ev.event_type === "firewall_decision") {
      const action = ev.detail?.action;
      cls = action === "block" ? "ev-block" : action === "redact" ? "ev-heal" : "ev-ok";
      firewallEventsCount += 1;
      const badge = document.getElementById("fw-count-badge");
      if (badge) badge.textContent = String(firewallEventsCount);

      if (fwFeed) {
        const fwCard = document.createElement("div");
        fwCard.className = `event-card ${cls}`;
        const triggers = (ev.detail?.findings || []).map((f) => `${f.engine}: ${f.code}`).join(" · ");
        fwCard.innerHTML = `
          <div class="event-head"><span>${esc(ev.agent_role || "")}</span><span class="mono">#${ev.seq}</span></div>
          <div class="event-title">${esc(ev.title)}</div>
          ${triggers ? `<div class="muted" style="font-size:11.5px;margin-top:3px;">${esc(triggers)}</div>` : ""}
        `;
        fwFeed.prepend(fwCard);
      }
    } else if (ev.event_type === "self_heal_triggered") {
      cls = "ev-heal";
    } else if (ev.event_type === "judge_verdict") {
      cls = "ev-judge";
    } else if (ev.event_type === "node_completed" || ev.event_type === "run_completed") {
      cls = "ev-ok";
    }

    if (trace) {
      const card = document.createElement("div");
      card.className = `event-card ${cls}`;
      card.innerHTML = `
        <div class="event-head"><span>${esc(ev.event_type)}</span><span class="mono">#${ev.seq}</span></div>
        <div class="event-title">${esc(ev.title)}</div>
      `;
      trace.prepend(card);
    }
  }

  function applyLiveEvent(ev) {
    appendEventCard(ev);
    if (ev.event_type === "run_started" && ev.detail?.nodes) {
      currentNodes = ev.detail.nodes;
      currentEdges = ev.detail.edges || [];
      selectedNodeId = currentNodes[0]?.id || null;
    } else if (ev.node_id) {
      const node = currentNodes.find((n) => n.id === ev.node_id);
      if (node) {
        if (ev.event_type === "node_started") node.status = "running";
        if (ev.event_type === "self_heal_triggered") node.status = "retrying";
        if (ev.event_type === "node_completed") {
          node.status = "verified";
          node.latency_ms = ev.detail?.latency_ms || node.latency_ms;
          node.summary = ev.detail?.summary || node.summary;
          node.tokens_in = ev.detail?.tokens || node.tokens_in;
        }
      }
    }

    if (ev.event_type === "firewall_decision" && ev.detail?.action === "block") {
      const fwMetric = document.getElementById("metric-fw");
      if (fwMetric) fwMetric.textContent = String(Number(fwMetric.textContent || 0) + 1);
    }
    if (ev.event_type === "self_heal_triggered") {
      const healMetric = document.getElementById("metric-heals");
      if (healMetric) healMetric.textContent = String(Number(healMetric.textContent || 0) + 1);
    }

    window.SwarmDAG.render(document.getElementById("dag-svg"), currentNodes, currentEdges, selectedNodeId, renderInspector);
    if (selectedNodeId) renderInspector(selectedNodeId);
  }

  function hydrateCompletedRun(run) {
    currentRun = run;
    currentNodes = run.nodes || [];
    currentEdges = run.edges || [];
    document.getElementById("metric-status").textContent = run.status.toUpperCase();
    document.getElementById("metric-score").textContent = run.judge ? `${run.judge.overall_score.toFixed(1)}/100` : "--";
    document.getElementById("metric-fw").textContent = String((run.firewall_blocks || 0) + (run.firewall_redactions || 0));
    document.getElementById("metric-heals").textContent = String(run.self_heals || 0);
    document.getElementById("metric-cost").textContent = `${run.total_tokens} / $${(run.total_cost_usd || 0).toFixed(4)}`;
    document.getElementById("metric-latency").textContent = `${Math.round(run.total_latency_ms || 0)} ms`;
    document.getElementById("dag-run-label").textContent = `${run.run_id} · ${run.title}`;
    document.getElementById("export-md-btn").disabled = false;

    window.SwarmDAG.render(document.getElementById("dag-svg"), currentNodes, currentEdges, selectedNodeId || currentNodes[0]?.id, renderInspector);
    renderInspector(selectedNodeId || currentNodes[0]?.id);
    renderFindingsAndPatches(run);
    renderJudgeTab(run);
  }

  async function launchMission() {
    const launchBtn = document.getElementById("launch-btn");
    const trace = document.getElementById("subtab-trace");
    const fwFeed = document.getElementById("subtab-fwfeed");
    trace.innerHTML = "";
    fwFeed.innerHTML = "";
    firewallEventsCount = 0;
    document.getElementById("fw-count-badge").textContent = "0";
    document.getElementById("metric-status").textContent = "RUNNING";
    document.getElementById("metric-score").textContent = "--";
    document.getElementById("metric-fw").textContent = "0";
    document.getElementById("metric-heals").textContent = "0";
    document.getElementById("export-md-btn").disabled = true;

    const payload = {
      mission_id: document.getElementById("mission-select").value,
      strategy: document.getElementById("strategy-select").value,
      policy_mode: document.getElementById("policy-select").value,
      provider: document.getElementById("provider-select").value,
      api_key: document.getElementById("api-key-input").value || null,
      target_path: document.getElementById("target-path-input").value.trim() || null,
      target_code: document.getElementById("target-code-input").value || null,
      rules: {
        capability_rbac: document.getElementById("rule-rbac").checked,
        secret_dlp: document.getElementById("rule-dlp").checked,
        prompt_injection_guard: document.getElementById("rule-inj").checked,
        filesystem_sandbox: document.getElementById("rule-fs").checked,
        loop_budget_breaker: document.getElementById("rule-loop").checked,
      },
    };
    document.getElementById("provider-pill").textContent = payload.provider;

    launchBtn.disabled = true;
    launchBtn.textContent = "Orchestrating Swarm...";
    try {
      const resp = await fetch("/api/runs/stream", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!resp.ok || !resp.body) {
        throw new Error(`HTTP ${resp.status}`);
      }
      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const chunks = buffer.split("\n\n");
        buffer = chunks.pop() || "";
        for (const chunk of chunks) {
          const lines = chunk.split("\n");
          let evName = "message";
          let dataLine = "";
          for (const line of lines) {
            if (line.startsWith("event:")) evName = line.slice(6).trim();
            if (line.startsWith("data:")) dataLine += line.slice(5).trim();
          }
          if (!dataLine) continue;
          const parsed = JSON.parse(dataLine);
          if (evName === "run_event") applyLiveEvent(parsed);
          if (evName === "run_done" && parsed.run) hydrateCompletedRun(parsed.run);
        }
      }
      await window.SwarmViews.loadRunsIntoSelectors();
    } catch (err) {
      document.getElementById("metric-status").textContent = "ERROR";
      trace.innerHTML = `<div class="event-card ev-block"><div class="event-title">Run failed: ${esc(err.message)}</div></div>`;
    } finally {
      launchBtn.disabled = false;
      launchBtn.textContent = "Launch Autonomous Swarm";
    }
  }

  async function bootstrap() {
    setupTabs();
    window.SwarmViews.initReplayAndDiff();
    window.SwarmViews.initFirewallLab();
    window.SwarmViews.initEvalArena();

    const [healthResp, missionsResp, runsResp] = await Promise.all([
      fetch("/api/health"),
      fetch("/api/missions"),
      fetch("/api/runs?limit=5"),
    ]);

    if (healthResp.ok) {
      const h = await healthResp.json();
      document.getElementById("health-pill").textContent = `Online v${h.version}`;
    }

    if (missionsResp.ok) {
      const mData = await missionsResp.json();
      missions = mData.missions || [];
      const sel = document.getElementById("mission-select");
      const sub = document.getElementById("mission-subtitle");
      sel.innerHTML = missions
        .map((m) => `<option value="${esc(m.mission_id)}">${esc(m.title)}</option>`)
        .join("");
      const updateSub = () => {
        const cur = missions.find((m) => m.mission_id === sel.value);
        if (sub && cur) sub.textContent = cur.subtitle;
      };
      sel.addEventListener("change", updateSub);
      updateSub();
      window.SwarmViews.renderRbacMatrix(mData.role_capabilities);
    }

    if (runsResp.ok) {
      const rData = await runsResp.json();
      const firstRun = (rData.runs || [])[0];
      if (firstRun) {
        const [fullResp, evResp] = await Promise.all([
          fetch(`/api/runs/${encodeURIComponent(firstRun.run_id)}`),
          fetch(`/api/runs/${encodeURIComponent(firstRun.run_id)}/events`),
        ]);
        if (evResp.ok) {
          const evData = await evResp.json();
          for (const ev of evData.events || []) {
            appendEventCard(ev);
          }
        }
        if (fullResp.ok) {
          const full = await fullResp.json();
          if (full.run) hydrateCompletedRun(full.run);
        }
      }
    }

    await window.SwarmViews.loadRunsIntoSelectors();

    document.getElementById("launch-btn")?.addEventListener("click", launchMission);
    document.getElementById("export-md-btn")?.addEventListener("click", () => {
      if (!currentRun?.final_report_md) return;
      const blob = new Blob([currentRun.final_report_md], { type: "text/markdown" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${currentRun.run_id}_report.md`;
      a.click();
      URL.revokeObjectURL(url);
    });
  }

  document.addEventListener("DOMContentLoaded", bootstrap);
})();
