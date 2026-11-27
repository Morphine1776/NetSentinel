(function () {
  const dataNode = document.getElementById("device-board-data");
  const board = document.getElementById("board");
  if (!dataNode || !board) return;

  const VIEW_KEY = "netsentinel.devices.view";
  const OPEN_KEY = "netsentinel.devices.expanded";
  const refreshSeconds = Number(board.dataset.refresh || "45");

  let payload = parse(dataNode.textContent);
  let serialized = JSON.stringify(payload);
  let query = "";
  let downOnly = false;
  let view = localStorage.getItem(VIEW_KEY) === "list" ? "list" : "grid";
  let openState = readOpen();

  const search = document.getElementById("device-search");
  const downToggle = document.getElementById("down-only");
  const expandAll = document.getElementById("expand-all");
  const collapseAll = document.getElementById("collapse-all");
  const viewGrid = document.getElementById("view-grid");
  const viewList = document.getElementById("view-list");

  if (search) {
    search.addEventListener("input", function () {
      query = search.value.trim().toLowerCase();
      render();
    });
  }
  if (downToggle) {
    downToggle.addEventListener("change", function () {
      downOnly = downToggle.checked;
      render();
    });
  }
  if (expandAll) {
    expandAll.addEventListener("click", function () {
      openState = { mode: "all", keys: [] };
      saveOpen();
      render();
    });
  }
  if (collapseAll) {
    collapseAll.addEventListener("click", function () {
      openState = { mode: "none", keys: [] };
      saveOpen();
      render();
    });
  }
  if (viewGrid) {
    viewGrid.addEventListener("click", function () { setView("grid"); });
  }
  if (viewList) {
    viewList.addEventListener("click", function () { setView("list"); });
  }

  board.addEventListener("click", function (event) {
    const button = event.target.closest(".bubble-toggle");
    if (!button || !board.contains(button)) return;
    toggle(button.dataset.key || "");
  });

  const ICONS = {
    ok: '<svg viewBox="0 0 24 24" width="18" height="18"><path fill="currentColor" d="M9.2 16.6 4.8 12.2l1.4-1.4 3 3 7.6-7.6 1.4 1.4z"/></svg>',
    partial: '<svg viewBox="0 0 24 24" width="18" height="18"><path fill="currentColor" d="M12 3.2 1.7 21h20.6L12 3.2zm0 6.1c.5 0 .9.4.9 1v4.4c0 .5-.4.9-.9.9s-.9-.4-.9-.9v-4.4c0-.6.4-1 .9-1zm0 9.1a1.15 1.15 0 1 0 0-2.3 1.15 1.15 0 0 0 0 2.3z"/></svg>',
    down: '<svg viewBox="0 0 24 24" width="18" height="18"><circle cx="12" cy="12" r="8" fill="none" stroke="currentColor" stroke-width="2"/><path d="M8.5 8.5l7 7M15.5 8.5l-7 7" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
    critical: '<svg viewBox="0 0 24 24" width="18" height="18"><path fill="currentColor" d="M12 2.8 4.2 5v6.2c0 4.6 3.2 8.8 7.8 10 4.6-1.2 7.8-5.4 7.8-10V5L12 2.8zm0 5.2c.5 0 .9.4.9.9v4.2c0 .5-.4.9-.9.9s-.9-.4-.9-.9V8.9c0-.5.4-.9.9-.9zm0 8.6a1.15 1.15 0 1 0 0-2.3 1.15 1.15 0 0 0 0 2.3z"/></svg>',
    waiting: '<svg viewBox="0 0 24 24" width="18" height="18"><circle cx="12" cy="12" r="8" fill="none" stroke="currentColor" stroke-width="2"/><path d="M12 7.5V12l3 2" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>'
  };

  render();
  window.setInterval(refresh, refreshSeconds * 1000);
  document.addEventListener("visibilitychange", function () {
    if (document.visibilityState === "visible") refresh();
  });

  function parse(text) {
    try {
      return JSON.parse(text || "{}");
    } catch (error) {
      return {};
    }
  }

  function readOpen() {
    try {
      const stored = JSON.parse(localStorage.getItem(OPEN_KEY) || "");
      if (stored && (stored.mode === "all" || stored.mode === "none" || stored.mode === "custom")) {
        return { mode: stored.mode, keys: Array.isArray(stored.keys) ? stored.keys.map(String) : [] };
      }
    } catch (error) {
      /* keep the default collapsed set */
    }
    return { mode: "custom", keys: [] };
  }

  function saveOpen() {
    localStorage.setItem(OPEN_KEY, JSON.stringify(openState));
  }

  function setView(next) {
    view = next === "list" ? "list" : "grid";
    localStorage.setItem(VIEW_KEY, view);
    render();
  }

  function filtering() {
    return query.length > 0 || downOnly;
  }

  function visibleDevices(group) {
    return (group.devices || []).filter(function (device) {
      if (downOnly && !device.down) return false;
      if (!query) return true;
      const blob = [device.name, device.host, device.location, group.name].join("\n").toLowerCase();
      return blob.indexOf(query) !== -1;
    });
  }

  function isOpen(key) {
    if (filtering()) return true;
    if (openState.mode === "all") return true;
    if (openState.mode === "none") return false;
    return openState.keys.indexOf(key) !== -1;
  }

  function toggle(key) {
    if (filtering()) return;
    const keysNow = (payload.groups || []).map(function (group) { return String(group.key); });
    if (openState.mode === "all") {
      openState = { mode: "custom", keys: keysNow.filter(function (item) { return item !== key; }) };
    } else if (openState.mode === "none") {
      openState = { mode: "custom", keys: [key] };
    } else if (openState.keys.indexOf(key) === -1) {
      openState = { mode: "custom", keys: openState.keys.concat([key]) };
    } else {
      openState = { mode: "custom", keys: openState.keys.filter(function (item) { return item !== key; }) };
    }
    saveOpen();
    render();
  }

  function render() {
    const watched = Number(payload.watched || 0);
    const tools = document.getElementById("device-tools");
    const empty = document.getElementById("device-empty");
    if (tools) tools.hidden = watched === 0;
    if (empty) empty.hidden = watched !== 0;
    setText("stat-up", payload.reachable);
    setText("stat-down", payload.down);
    setText("stat-pending", payload.waiting);
    setText("stat-watched", payload.watched);
    if (viewGrid) viewGrid.setAttribute("aria-pressed", view === "grid" ? "true" : "false");
    if (viewList) viewList.setAttribute("aria-pressed", view === "list" ? "true" : "false");

    board.className = "board " + view;
    board.replaceChildren();
    if (watched === 0) {
      setText("filter-summary", "");
      return;
    }

    const groups = payload.groups || [];
    let shown = 0;
    let matchedGroups = 0;
    groups.forEach(function (group, index) {
      const devices = visibleDevices(group);
      shown += devices.length;
      if (devices.length === 0) return;
      matchedGroups += 1;
      board.appendChild(renderGroup(group, devices, index));
    });

    const summary = document.getElementById("filter-summary");
    if (summary) {
      if (!filtering()) {
        summary.textContent = "";
      } else if (shown === 0) {
        summary.textContent = "No devices match.";
      } else {
        summary.textContent = "Showing " + shown + " of " + watched;
      }
    }
    if (filtering() && matchedGroups === 0) {
      board.appendChild(el("p", "empty-inline filter-empty", "No devices match that filter."));
    }
  }

  function renderGroup(group, devices, index) {
    const key = String(group.key);
    const open = isOpen(key);
    const article = el("article", "bubble health-" + (group.health || "waiting") + (open ? " open" : ""));
    article.dataset.key = key;

    const button = document.createElement("button");
    button.type = "button";
    button.className = "bubble-toggle";
    button.dataset.key = key;
    button.setAttribute("aria-expanded", open ? "true" : "false");
    const panelId = "location-panel-" + index;
    if (open) button.setAttribute("aria-controls", panelId);
    const cue = group.cue || "Waiting";
    button.setAttribute("aria-label", group.name + ", " + cue + ", " + (group.reporting || 0) + " of " + (group.total || 0) + " up");

    button.append(
      icon(iconKind(group)),
      copy(group),
      chevron()
    );
    const head = el("div", "bubble-head");
    const policy = el("a", "btn tiny policy-link", "Policy");
    policy.href = "/policies?location=" + encodeURIComponent(key.length ? key : "unassigned");
    policy.addEventListener("click", function (event) { event.stopPropagation(); });
    head.append(button, policy);
    article.appendChild(head);

    if (open) {
      const panel = el("div", "bubble-panel");
      panel.id = panelId;
      panel.appendChild(renderTable(devices));
      article.appendChild(panel);
    }
    return article;
  }

  function copy(group) {
    const block = el("span", "bubble-copy");
    block.append(
      el("span", "bubble-name", group.name || "Unassigned"),
      el("span", "bubble-fraction", (group.reporting || 0) + "/" + (group.total || 0) + " up"),
      el("span", "bubble-meta", meta(group)),
      cueLine(group)
    );
    return block;
  }

  function meta(group) {
    const total = group.total || 0;
    const parts = [total + " " + (total === 1 ? "device" : "devices")];
    if (group.down > 0) parts.push(group.down + " down");
    const waiting = (group.pending || 0) + (group.paused || 0);
    if (waiting > 0) parts.push(waiting + " waiting");
    return parts.join(" · ");
  }

  function cueLine(group) {
    const line = el("span", "bubble-cue");
    line.append(miniIcon(iconKind(group)), document.createTextNode(group.cue || "Waiting"));
    return line;
  }

  function iconKind(group) {
    if (group.health === "healthy") return "ok";
    if (group.health === "degraded") return "partial";
    if (group.health === "critical") return group.cue === "All down" ? "down" : "critical";
    return "waiting";
  }

  function renderTable(devices) {
    const wrap = el("div", "table-wrap");
    const table = el("table", "device-rows");
    const head = document.createElement("thead");
    const headRow = document.createElement("tr");
    ["Status", "HA", "Device", "SNMP", "sysName", "Uptime", "Response", "Ping", "Last poll"].forEach(function (label, index) {
      const cls = index === 0 ? "stick" : index === 1 ? "stick-ha" : null;
      headRow.appendChild(el("th", cls, label));
    });
    head.appendChild(headRow);
    table.appendChild(head);

    const body = document.createElement("tbody");
    devices.forEach(function (device) {
      const row = document.createElement("tr");
      row.append(
        statusCell(device),
        haCell(device),
        deviceCell(device),
        textCell("SNMP", device.version, true),
        textCell("sysName", device.sysName, false),
        textCell("Uptime", device.uptime, true),
        textCell("Response", device.response, true),
        textCell("Ping", device.ping, false),
        textCell("Last poll", device.lastPoll, true)
      );
      body.appendChild(row);
    });
    table.appendChild(body);
    wrap.appendChild(table);
    return wrap;
  }

  function haCell(device) {
    const cell = document.createElement("td");
    cell.dataset.label = "HA";
    cell.className = "stick-ha";
    const label = (device.haLabel || "").trim() || "N/A";
    const badge = el("span", "ha-badge " + (device.haClass || "ha-na"), label);
    badge.title = device.haPeer ? device.haPeer : "HA " + label;
    cell.appendChild(badge);
    return cell;
  }

  function statusCell(device) {
    const cell = document.createElement("td");
    cell.dataset.label = "Status";
    cell.className = "stick";
    const status = el("span", "status");
    status.append(el("span", "lamp " + (device.lamp || "off")), document.createTextNode(device.status || ""));
    cell.appendChild(status);
    return cell;
  }

  function deviceCell(device) {
    const cell = document.createElement("td");
    cell.dataset.label = "Device";
    const link = el("a", "device-link", device.name || "");
    link.href = "/devices/" + device.id;
    cell.append(
      link,
      el("div", "sub mono", (device.host || "") + ":" + device.port + " · every " + device.pollIntervalSeconds + " s")
    );
    if (device.lastError) cell.appendChild(el("div", "sub bad-text", device.lastError));
    return cell;
  }

  function textCell(label, value, mono) {
    const cell = document.createElement("td");
    cell.dataset.label = label;
    if (mono) cell.className = "mono";
    cell.textContent = value || "—";
    return cell;
  }

  function refresh() {
    fetch("/api/devices/board", { headers: { "Accept": "application/json" } })
      .then(function (response) {
        if (!response.ok) throw new Error(String(response.status));
        return response.json();
      })
      .then(function (next) {
        const encoded = JSON.stringify(next);
        stamp();
        if (encoded === serialized) return;
        serialized = encoded;
        payload = next;
        render();
      })
      .catch(function () {
        stamp();
      });
  }

  function stamp() {
    const node = document.getElementById("board-updated");
    if (!node) return;
    node.textContent = "Updated " + new Date().toLocaleTimeString() + " · refreshes every " + refreshSeconds + " seconds";
  }

  function setText(id, value) {
    const node = document.getElementById(id);
    if (node) node.textContent = value == null ? "0" : String(value);
  }

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = text;
    return node;
  }

  function icon(kind) {
    const node = el("span", "bubble-icon");
    node.setAttribute("aria-hidden", "true");
    node.innerHTML = ICONS[kind] || ICONS.waiting;
    return node;
  }

  function miniIcon(kind) {
    const node = el("span", "cue-icon");
    node.setAttribute("aria-hidden", "true");
    node.innerHTML = ICONS[kind] || ICONS.waiting;
    return node;
  }

  function chevron() {
    const node = el("span", "chevron");
    node.setAttribute("aria-hidden", "true");
    node.innerHTML = '<svg viewBox="0 0 24 24" width="18" height="18"><path d="M6 9l6 6 6-6" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>';
    return node;
  }
})();
