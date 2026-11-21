(function () {
  const root = document.getElementById("net-map");
  if (!root || typeof cytoscape === "undefined") return;

  let grouping = "none";
  let selectedManual = null;
  let dragging = false;
  let moved = false;
  const removeButton = document.getElementById("map-remove");
  const note = document.getElementById("map-note");

  const cy = cytoscape({
    container: root,
    wheelSensitivity: 0.2,
    style: [
      {
        selector: "node",
        style: {
          "background-color": "#5c675c",
          label: "data(label)",
          color: "#e7f0df",
          "font-family": "Sora, sans-serif",
          "font-size": 12,
          "text-valign": "bottom",
          "text-margin-y": 6,
          "text-outline-color": "#10140f",
          "text-outline-width": 2,
          width: 28,
          height: 28
        }
      },
      { selector: "node.up", style: { "background-color": "#b6f25c" } },
      { selector: "node.warn", style: { "background-color": "#f0c14a" } },
      { selector: "node.down", style: { "background-color": "#ff6d57" } },
      { selector: "node.off", style: { "background-color": "#5c675c" } },
      {
        selector: "node.group",
        style: {
          "background-color": "rgba(214,255,74,0.05)",
          "background-opacity": 0.2,
          shape: "round-rectangle",
          label: "data(label)",
          "text-valign": "top",
          "font-size": 13,
          color: "#93a394",
          padding: 18
        }
      },
      {
        selector: "edge",
        style: {
          width: 2,
          "line-color": "#7ddec7",
          "target-arrow-color": "#7ddec7",
          "curve-style": "bezier",
          label: "data(label)",
          color: "#d6ff4a",
          "font-size": 11,
          "font-family": "IBM Plex Mono, monospace",
          "text-margin-x": 72,
          "text-background-color": "#171d18",
          "text-background-opacity": 0.9,
          "text-background-padding": 3
        }
      },
      { selector: "edge.parent", style: { "line-color": "#d6ff4a", "line-style": "dashed" } },
      { selector: "edge.manual", style: { "line-color": "#f0c14a" } },
      { selector: "edge:selected", style: { width: 4 } }
    ]
  });

  function lampClass(lamp) {
    if (lamp === "up" || lamp === "warn" || lamp === "down") return lamp;
    return "off";
  }

  function apply(payload, relayout) {
    const nodes = [];
    const groups = new Set();
    payload.nodes.forEach(function (node) {
      const bucket = grouping === "group" ? node.group : grouping === "location" ? node.location : "";
      let parent = null;
      if (bucket) {
        parent = "group:" + bucket;
        if (!groups.has(parent)) {
          groups.add(parent);
          nodes.push({ data: { id: parent, label: bucket }, classes: "group" });
        }
      }
      const data = {
        id: "device:" + node.id,
        deviceId: node.id,
        label: node.name,
        parent: parent
      };
      const element = { data: data, classes: lampClass(node.lamp) };
      if (node.x != null && node.y != null) element.position = { x: node.x, y: node.y };
      nodes.push(element);
    });

    const edges = (payload.edges || []).map(function (edge, index) {
      const kinds = edge.kinds || [];
      return {
        data: {
          id: "edge:" + index + ":" + edge.source + ":" + edge.target,
          source: "device:" + edge.source,
          target: "device:" + edge.target,
          label: edge.label || kinds.join(" · "),
          manualId: edge.manualId
        },
        classes: kinds.join(" ")
      };
    });

    cy.elements().remove();
    cy.add(nodes.concat(edges));
    const missing = payload.nodes.some(function (node) { return node.x == null || node.y == null; });
    if (relayout || missing) {
      cy.layout({
        name: missing ? "cose" : "preset",
        animate: false,
        padding: 48,
        nodeRepulsion: 14000,
        idealEdgeLength: 180,
        gravity: 0.15,
        numIter: 1200
      }).run();
      if (missing) saveAll();
    }
    cy.fit(undefined, 40);
  }

  function saveAll() {
    const positions = [];
    cy.nodes().forEach(function (node) {
      if (!node.data("deviceId")) return;
      const position = node.position();
      positions.push({ id: node.data("deviceId"), x: position.x, y: position.y });
    });
    postJson("/api/map/positions", { positions: positions });
  }

  function postJson(url, body, method) {
    return fetch(url, {
      method: method || "POST",
      headers: { "Content-Type": "application/json", "X-NetSentinel": "1" },
      body: body ? JSON.stringify(body) : undefined
    });
  }

  function refresh(relayout) {
    if (dragging) return;
    fetch("/api/map").then(function (response) { return response.json(); }).then(function (payload) {
      apply(payload, relayout);
    }).catch(function () {});
  }

  cy.on("drag", "node", function () { dragging = true; moved = true; });
  cy.on("dragfree", "node", function (event) {
    dragging = false;
    const node = event.target;
    if (!node.data("deviceId")) return;
    const position = node.position();
    postJson("/api/map/positions", { positions: [{ id: node.data("deviceId"), x: position.x, y: position.y }] });
  });
  cy.on("tap", "node", function (event) {
    if (moved) {
      moved = false;
      return;
    }
    const id = event.target.data("deviceId");
    if (id) window.location.href = "/devices/" + id;
  });
  cy.on("tap", "edge", function (event) {
    selectedManual = event.target.data("manualId") || null;
    if (removeButton) removeButton.hidden = !selectedManual;
    if (note) note.textContent = event.target.data("label") || "";
  });
  cy.on("tap", function (event) {
    if (event.target === cy) {
      selectedManual = null;
      if (removeButton) removeButton.hidden = true;
    }
  });

  document.getElementById("map-groups").addEventListener("click", function (event) {
    const button = event.target.closest("[data-group]");
    if (!button) return;
    grouping = button.dataset.group;
    document.querySelectorAll("#map-groups .chip").forEach(function (chip) {
      chip.classList.toggle("on", chip === button);
    });
    refresh(true);
  });

  document.getElementById("map-link-form").addEventListener("submit", function (event) {
    event.preventDefault();
    const fromId = Number(document.getElementById("map-from").value);
    const toId = Number(document.getElementById("map-to").value);
    postJson("/api/map/links", { fromId: fromId, toId: toId }).then(function (response) {
      if (!response.ok) {
        response.json().then(function (body) {
          if (note) note.textContent = (body.errors || ["Could not add the link."]).join(" ");
        });
        return;
      }
      if (note) note.textContent = "Manual link saved.";
      refresh(false);
    });
  });

  if (removeButton) {
    removeButton.addEventListener("click", function () {
      if (!selectedManual) return;
      fetch("/api/map/links/" + selectedManual, { method: "DELETE", headers: { "X-NetSentinel": "1" } }).then(function () {
        selectedManual = null;
        removeButton.hidden = true;
        refresh(false);
      });
    });
  }

  refresh(true);
  window.setInterval(function () { refresh(false); }, 15000);
})();
