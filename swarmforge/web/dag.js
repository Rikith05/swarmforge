/* Interactive SVG Multi-Agent DAG Renderer */

window.SwarmDAG = (function () {
  const STATUS_COLORS = {
    queued: { stroke: "#334155", fill: "#0f172a", pill: "#64748b", label: "QUEUED" },
    running: { stroke: "#06b6d4", fill: "#0c2233", pill: "#22d3ee", label: "RUNNING" },
    blocked_by_policy: { stroke: "#f43f5e", fill: "#2a0e1a", pill: "#fb7185", label: "BLOCKED" },
    retrying: { stroke: "#f59e0b", fill: "#291c07", pill: "#fbbf24", label: "SELF-HEAL" },
    verified: { stroke: "#10b981", fill: "#08241d", pill: "#34d399", label: "VERIFIED" },
    failed: { stroke: "#f43f5e", fill: "#2b0b12", pill: "#fb7185", label: "FAILED" },
  };

  function esc(val) {
    return String(val ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function computeLayout(nodes) {
    const layers = new Map();
    for (const n of nodes) {
      const l = Number(n.layer || 0);
      if (!layers.has(l)) layers.set(l, []);
      layers.get(l).push(n);
    }
    const maxLayer = Math.max(0, ...layers.keys());
    const width = 820;
    const height = 360;
    const colGap = maxLayer === 0 ? 0 : (width - 246) / maxLayer;
    const positions = {};

    for (const [layerIdx, list] of layers.entries()) {
      const x = maxLayer === 0 ? width / 2 - 93 : 28 + layerIdx * colGap;
      const rowStep = height / (list.length + 1);
      list.forEach((node, idx) => {
        const y = rowStep * (idx + 1) - 42;
        positions[node.id] = { x, y, w: 188, h: 84 };
      });
    }
    return positions;
  }

  function render(svgEl, nodes, edges, selectedNodeId, onSelectNode) {
    if (!svgEl) return;
    if (!nodes || nodes.length === 0) {
      svgEl.innerHTML = `<text x="410" y="180" text-anchor="middle" fill="#64748b" font-size="13">Launch a mission to compile and execute the agent DAG.</text>`;
      return;
    }

    const pos = computeLayout(nodes);
    const parts = [
      `<defs>
        <marker id="sf-arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
          <path d="M 0 1 L 10 5 L 0 9 z" fill="#38bdf8" />
        </marker>
      </defs>`,
    ];

    const nodeMap = Object.fromEntries(nodes.map((n) => [n.id, n]));
    for (const e of edges || []) {
      const a = pos[e.source];
      const b = pos[e.target];
      if (!a || !b) continue;
      const srcNode = nodeMap[e.source];
      const tgtNode = nodeMap[e.target];
      const isLiveEdge =
        tgtNode && (tgtNode.status === "running" || tgtNode.status === "retrying" || tgtNode.status === "blocked_by_policy");
      const isVerifiedEdge = srcNode?.status === "verified" && tgtNode?.status === "verified";
      const edgeStroke = isLiveEdge ? "#22d3ee" : isVerifiedEdge ? "#10b981" : "#2b4c70";
      const edgeClass = isLiveEdge ? "edge-active" : "";
      const x1 = a.x + a.w;
      const y1 = a.y + a.h / 2;
      const x2 = b.x;
      const y2 = b.y + b.h / 2;
      const cx = (x1 + x2) / 2;
      parts.push(
        `<path d="M ${x1} ${y1} C ${cx} ${y1}, ${cx} ${y2}, ${x2} ${y2}" fill="none" stroke="${edgeStroke}" stroke-width="${isLiveEdge ? 2.4 : 2}" class="${edgeClass}" marker-end="url(#sf-arrow)" />`
      );
    }

    for (const n of nodes) {
      const box = pos[n.id];
      const st = STATUS_COLORS[n.status] || STATUS_COLORS.queued;
      const isSelected = n.id === selectedNodeId;
      const strokeW = isSelected ? 2.6 : 1.6;
      const extraClass = n.status === "running" ? "node-running-rect" : "";
      const latencyTxt = n.latency_ms ? `${Math.round(n.latency_ms)} ms` : "pending";
      const tokensTxt = `${(n.tokens_in || 0) + (n.tokens_out || 0)} tok`;

      parts.push(
        `<g class="dag-node" data-node-id="${esc(n.id)}" style="cursor:pointer;">
          <rect x="${box.x}" y="${box.y}" width="${box.w}" height="${box.h}" rx="10"
            fill="${st.fill}" stroke="${isSelected ? "#38bdf8" : st.stroke}" stroke-width="${strokeW}" class="${extraClass}" />
          <text x="${box.x + 11}" y="${box.y + 22}" fill="#f1f5f9" font-size="12" font-weight="700">${esc(n.label.slice(0, 26))}</text>
          <text x="${box.x + 12}" y="${box.y + 40}" fill="#94a3b8" font-size="11">role: ${esc(n.role)}</text>
          <rect x="${box.x + 12}" y="${box.y + 52}" width="76" height="20" rx="5" fill="rgba(0,0,0,0.35)" stroke="${st.stroke}" stroke-width="0.9" />
          <text x="${box.x + 50}" y="${box.y + 66}" text-anchor="middle" fill="${st.pill}" font-size="10" font-weight="700">${st.label}</text>
          <text x="${box.x + box.w - 10}" y="${box.y + 66}" text-anchor="end" fill="#cbd5e1" font-size="10.5">${esc(latencyTxt)} · ${esc(tokensTxt)}</text>
        </g>`
      );
    }

    svgEl.innerHTML = parts.join("");
    svgEl.querySelectorAll(".dag-node").forEach((g) => {
      g.addEventListener("click", () => {
        const nid = g.getAttribute("data-node-id");
        if (onSelectNode) onSelectNode(nid);
      });
    });
  }

  return { render, esc };
})();
