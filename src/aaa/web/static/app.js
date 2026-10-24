/* AI-AGENT-AUDIT 面板（原生 JS，无框架；T5.2/T5.3）。
   流量列表 + 过滤器、事件详情（脱敏/解锁切换）、统计卡片、CSV/JSON 导出、confirm 决策。 */
"use strict";

const $ = (id) => document.getElementById(id);
const state = { limit: 50, offset: 0, total: 0, selected: null, revealed: false };

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
  ));
}

async function api(path, opts) {
  const resp = await fetch(path, opts);
  if (!resp.ok) {
    let detail = resp.statusText;
    try { detail = (await resp.json()).detail || detail; } catch (_) { /* 保留 statusText */ }
    throw new Error(`${resp.status}: ${detail}`);
  }
  return resp;
}

function currentFilters() {
  const p = new URLSearchParams();
  if ($("f-verdict").value) p.set("verdict", $("f-verdict").value);
  if ($("f-dim").value) p.set("dim", $("f-dim").value);
  if ($("f-pid").value) p.set("pid", $("f-pid").value);
  if ($("f-host").value) p.set("host", $("f-host").value.trim());
  if ($("f-since").value) p.set("since", $("f-since").value.trim());
  if ($("f-until").value) p.set("until", $("f-until").value.trim());
  return p;
}

/* ---------------------------------------------------------------- 统计卡片 */

async function loadStats() {
  try {
    const stats = await (await api("/api/stats")).json();
    $("c-total").textContent = stats.total;
    $("c-alert").textContent = stats.by_verdict.alert || 0;
    $("c-confirm").textContent = stats.pending_confirm || 0;
    $("c-block").textContent = stats.by_verdict.block || 0;
    $("c-hosts").textContent = stats.by_host.length;
    $("confirm-box").classList.toggle("hidden", !(stats.pending_confirm > 0));
  } catch (err) { console.error("stats", err); }
}

/* ---------------------------------------------------------------- 事件列表 */

function verdictBadge(ev) {
  const cls = ev.verdict || "unassessed";
  const action = ev.action_taken && ev.action_taken !== "logged" ? ` · ${esc(ev.action_taken)}` : "";
  return `<span class="v ${esc(cls)}">${esc(cls)}${action}</span>`;
}

async function loadEvents() {
  const p = currentFilters();
  p.set("limit", state.limit);
  p.set("offset", state.offset);
  try {
    const data = await (await api(`/api/events?${p}`)).json();
    state.total = data.total;
    const tbody = $("events tbody");
    tbody.innerHTML = "";
    for (const ev of data.items) {
      const tr = document.createElement("tr");
      tr.dataset.id = ev.id;
      if (ev.id === state.selected) tr.classList.add("selected");
      tr.innerHTML = `
        <td>${esc(ev.ts)}</td>
        <td>${verdictBadge(ev)}${ev.decision ? ` <span class="v unassessed">决策:${esc(ev.decision)}</span>` : ""}</td>
        <td>${esc(ev.risk_score)}</td>
        <td>${esc(ev.request.method)}</td>
        <td class="mono">${esc(ev.destination.host)}</td>
        <td class="mono">${esc(ev.request.path)}</td>
        <td>${ev.process ? esc(`${ev.process.name || "?"}(${ev.process.pid ?? "?"})`) : "–"}</td>
        <td>${esc(ev.action_taken)}</td>`;
      tr.addEventListener("click", () => openDetail(ev.id));
      tbody.appendChild(tr);
    }
    if (!data.items.length) {
      tbody.innerHTML = '<tr><td colspan="8" style="color:var(--dim)">无匹配事件</td></tr>';
    }
    $("page-info").textContent =
      `第 ${state.offset + 1}–${Math.min(state.offset + state.limit, data.total)} 条 / 共 ${data.total}`;
    $("b-prev").disabled = state.offset <= 0;
    $("b-next").disabled = state.offset + state.limit >= data.total;
  } catch (err) {
    $("events tbody").innerHTML = `<tr><td colspan="8" style="color:var(--blk)">加载失败：${esc(err.message)}</td></tr>`;
  }
}

/* ---------------------------------------------------------------- 事件详情 */

function metaRows(ev) {
  const rows = [
    ["时间", ev.ts], ["判定", `${ev.verdict}（风险 ${ev.risk_score}）`],
    ["动作", ev.action_taken],
    ["目标", `${ev.destination.host}:${ev.destination.port} (${ev.destination.classification})`],
    ["请求", `${ev.request.method} ${ev.request.path} · ${ev.request.size}B`],
    ["进程", ev.process ? `${ev.process.name || "?"} pid=${ev.process.pid ?? "?"} profile=${ev.process.profile || "?"}` : "未归因"],
    ["策略版本", ev.policy_version || "–"],
    ["用户决策", ev.decision ? `${ev.decision}（${ev.decision_ts || ""}）` : "未决策"],
    ["错误", ev.error || "–"],
  ];
  if (ev.response) rows.push(["响应", `HTTP ${ev.response.status_code} · ${ev.response.size}B`]);
  return rows.map(([k, v]) => `<tr><td>${esc(k)}</td><td class="mono">${esc(v)}</td></tr>`).join("");
}

function renderBody(ev) {
  const body = ev.body || {};
  $("d-body-hint").textContent = body.content == null
    ? (body.missing ? "证据文件缺失（可能已被 trim）" : "该请求无 body 证据")
    : (body.masked
        ? `默认脱敏视图：命中 ${Object.entries(body.hits).map(([r, n]) => `${r}×${n}`).join("、")}；查看原文会被记录。`
        : (state.revealed ? "已解锁原文（本次查看已记入审计日志）。" : "原文（无命中密钥）。"));
  const pre = $("d-body");
  if (body.content == null) { pre.textContent = ""; return; }
  if (state.revealed || !body.masked) {
    pre.textContent = body.content;
    return;
  }
  // 高亮脱敏区间 ⟦rule|masked⟧
  pre.innerHTML = body.content.split(/(⟦[^⟧]*⟧)/g).map((seg) =>
    seg.startsWith("⟦") ? `<span class="mask">${esc(seg)}</span>` : esc(seg)
  ).join("");
  $("b-reveal").classList.remove("hidden");
}

async function openDetail(id) {
  state.selected = id;
  state.revealed = false;
  $("b-reveal").textContent = "显示原文（解锁并记审计日志）";
  document.querySelectorAll("#events tr").forEach((tr) =>
    tr.classList.toggle("selected", tr.dataset.id === id));
  try {
    const ev = await (await api(`/api/events/${encodeURIComponent(id)}`)).json();
    $("detail-pane").classList.remove("hidden");
    $("d-id").textContent = ev.id;
    $("d-meta").innerHTML = metaRows(ev);
    $("d-rules tbody").innerHTML = (ev.matched_rules || []).map((r) => `
      <tr><td class="mono">${esc(r.id)}</td><td>${esc(r.dim || "")}</td>
      <td>${esc(r.action || "")}</td><td class="mono">${esc(r.evidence || "")}</td></tr>`
    ).join("") || '<tr><td colspan="4" style="color:var(--dim)">无命中规则</td></tr>';
    renderBody(ev);
    $("d-confirm-actions").classList.toggle("hidden", ev.verdict !== "confirm");
    $("d-decision-banner").innerHTML = ev.decision
      ? `<p class="hint">用户已决策：${esc(ev.decision)}（${esc(ev.decision_ts || "")}）</p>` : "";
    const audit = await (await api(`/api/decisions`)).json();
    const rows = (audit.decided_events || []).filter((d) => d.id === id);
    $("d-audit").innerHTML = rows.length
      ? rows.map((d) => `<li>${esc(d.decision_ts)} 决策=${esc(d.decision)}</li>`).join("")
      : "<li>（无决策记录）</li>";
  } catch (err) { alert(`详情加载失败：${err.message}`); }
}

async function reveal() {
  if (!state.selected || state.revealed) return;
  try {
    const ev = await (await api(`/api/events/${encodeURIComponent(state.selected)}?reveal=1`)).json();
    state.revealed = true;
    $("b-reveal").textContent = "原文已显示（已记审计日志）";
    renderBody(ev);
  } catch (err) { alert(`解锁失败：${err.message}`); }
}

/* ---------------------------------------------------------------- 决策 T5.3 */

async function decide(decision) {
  if (!state.selected) return;
  const payload = { event_id: state.selected, decision };
  if (decision === "deny") payload.ttl_seconds = parseInt($("d-ttl").value || "3600", 10);
  try {
    const resp = await (await api("/api/decisions", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    })).json();
    alert(decision === "allow"
      ? "已允许这一次（该事件已记录 allow）。"
      : `已拒绝；同类请求 ${resp.ttl_seconds ?? "?"} 秒内升级为 block。`);
    await Promise.all([openDetail(state.selected), loadEvents(), loadStats()]);
  } catch (err) { alert(`决策失败：${err.message}`); }
}

/* ---------------------------------------------------------------- 导出 */

function download(url) {
  const a = document.createElement("a");
  a.href = url;
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
}

function gotoConfirm() {
  $("f-verdict").value = "confirm";
  state.offset = 0;
  loadEvents();
}

/* ---------------------------------------------------------------- 绑定 */

$("b-query").addEventListener("click", () => { state.offset = 0; loadEvents(); });
$("b-prev").addEventListener("click", () => { state.offset = Math.max(0, state.offset - state.limit); loadEvents(); });
$("b-next").addEventListener("click", () => { state.offset += state.limit; loadEvents(); });
$("b-close").addEventListener("click", () => $("detail-pane").classList.add("hidden"));
$("b-reveal").addEventListener("click", reveal);
$("b-allow").addEventListener("click", () => decide("allow"));
$("b-deny").addEventListener("click", () => decide("deny"));
$("b-goto-confirm").addEventListener("click", gotoConfirm);
$("b-export-json").addEventListener("click", () => download(`/api/events/export?format=json&${currentFilters()}`));
$("b-export-csv").addEventListener("click", () => download(`/api/events/export?format=csv&${currentFilters()}`));
$("b-event-json").addEventListener("click", () => state.selected && download(`/api/events/${state.selected}/export?format=json`));
$("b-event-csv").addEventListener("click", () => state.selected && download(`/api/events/${state.selected}/export?format=csv`));

loadStats();
loadEvents();
setInterval(loadStats, 5000);
