(function () {
  const body = document.body;
  const refresh = Number(body.dataset.refresh || "0");
  if (refresh > 0) {
    window.setTimeout(function () { window.location.reload(); }, refresh * 1000);
  }

  const importForm = document.getElementById("import-form");
  if (importForm) {
    let csvText = "";
    const preview = document.getElementById("import-preview");
    const rows = document.getElementById("import-rows");
    const summary = document.getElementById("import-summary");
    const fileError = document.getElementById("import-file-error");
    const result = document.getElementById("import-result");
    importForm.addEventListener("submit", function (event) {
      event.preventDefault();
      const file = document.getElementById("import-file").files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = function () {
        csvText = String(reader.result || "");
        fetch("/api/devices/import/preview", {
          method: "POST",
          headers: { "Content-Type": "text/csv", "X-NetSentinel": "1" },
          body: csvText
        }).then(function (response) { return response.json(); }).then(function (payload) {
          if (payload.fileError) {
            fileError.hidden = false;
            fileError.textContent = payload.fileError;
            preview.hidden = true;
            return;
          }
          fileError.hidden = true;
          preview.hidden = false;
          summary.textContent = payload.ready + " ready, " + payload.duplicates + " duplicates, " + payload.errors + " errors.";
          rows.replaceChildren();
          (payload.rows || []).forEach(function (row) {
            const tr = document.createElement("tr");
            tr.className = "row-" + row.status;
            function cell(text) {
              const td = document.createElement("td");
              td.textContent = text || "";
              return td;
            }
            tr.append(
              cell(String(row.line)),
              cell(row.status),
              cell(row.name),
              cell(row.host),
              cell(row.group),
              cell(row.parent),
              cell((row.errors || []).join(" ") || (row.duplicateMatch ? "Matches an existing device by " + row.duplicateMatch + "." : ""))
            );
            rows.appendChild(tr);
          });
        });
      };
      reader.readAsText(file);
    });
    document.getElementById("import-commit").addEventListener("submit", function (event) {
      event.preventDefault();
      const mode = document.querySelector("input[name=duplicateMode]:checked").value;
      fetch("/api/devices/import", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-NetSentinel": "1" },
        body: JSON.stringify({ csv: csvText, duplicateMode: mode })
      }).then(function (response) { return response.json().then(function (body) { return { ok: response.ok, body: body }; }); })
        .then(function (payload) {
          if (!payload.ok) {
            result.textContent = (payload.body.errors || ["Import failed."]).join(" ");
            return;
          }
          const body = payload.body;
          result.textContent = "Created " + body.created + ", updated " + body.updated + ", skipped " + body.skipped + ", rejected " + body.rejected + ".";
        });
    });
  }

  const version = document.getElementById("snmp-version");
  if (version) {
    const sync = function () {
      const v3 = version.value === "V3";
      document.querySelectorAll(".v2-field").forEach(function (node) { node.hidden = v3; });
      document.querySelectorAll(".v3-field").forEach(function (node) { node.hidden = !v3; });
    };
    version.addEventListener("change", sync);
    sync();
  }

  const oidList = document.getElementById("oid-list");
  const addOid = document.getElementById("add-oid");
  if (oidList && addOid) {
    addOid.addEventListener("click", function () {
      const row = document.createElement("div");
      row.className = "oid-row";
      row.innerHTML =
        '<input type="hidden" data-field="Id" value="0" />' +
        '<input data-field="Name" placeholder="Name" maxlength="80" />' +
        '<input data-field="Oid" placeholder="1.3.6.1.4.1…" class="mono" maxlength="200" />' +
        '<input data-field="Unit" placeholder="Unit" maxlength="16" />' +
        '<button class="btn ghost remove-oid" type="button">Remove</button>';
      oidList.appendChild(row);
    });
    oidList.addEventListener("click", function (event) {
      const button = event.target.closest(".remove-oid");
      if (!button) return;
      const row = button.closest(".oid-row");
      if (row && oidList.children.length > 1) row.remove();
      else if (row) row.querySelectorAll("input").forEach(function (input) { if (input.dataset.field !== "Id") input.value = ""; });
    });
    const form = document.getElementById("device-form");
    if (form) {
      form.addEventListener("submit", function () {
        Array.from(oidList.querySelectorAll(".oid-row")).forEach(function (row, index) {
          row.querySelectorAll("[data-field]").forEach(function (input) {
            input.name = "Input.CustomOids[" + index + "]." + input.dataset.field;
          });
        });
      });
    }
  }

  document.querySelectorAll("[data-select-iface]").forEach(function (row) {
    row.addEventListener("click", function (event) {
      if (event.target.closest("input, button, a, label, select, textarea")) return;
      const url = new URL(window.location.href);
      url.searchParams.set("iface", row.dataset.selectIface);
      window.location.href = url.toString();
    });
  });

  const selectAll = document.getElementById("iface-all");
  if (selectAll) {
    selectAll.addEventListener("change", function () {
      document.querySelectorAll(".iface-select").forEach(function (box) { box.checked = selectAll.checked; });
    });
  }

  document.querySelectorAll("[data-monitor-toggle]").forEach(function (box) {
    box.addEventListener("change", function () {
      const deviceId = document.body.dataset.device;
      const checked = box.checked;
      fetch("/api/devices/" + deviceId + "/interfaces/" + box.dataset.monitorToggle + "/monitored", {
        method: "PUT",
        headers: { "Content-Type": "application/json", "X-NetSentinel": "1" },
        body: JSON.stringify({ monitored: checked })
      }).then(function (response) {
        if (!response.ok) {
          box.checked = !checked;
          return;
        }
        window.location.reload();
      }).catch(function () { box.checked = !checked; });
    });
  });
  document.querySelectorAll("[data-select-custom]").forEach(function (row) {
    row.addEventListener("click", function () {
      const url = new URL(window.location.href);
      url.searchParams.set("custom", row.dataset.selectCustom);
      window.location.href = url.toString();
    });
  });

  if (!body.dataset.device || typeof Chart === "undefined") return;

  const id = body.dataset.device;
  const range = body.dataset.range || "60";
  Chart.defaults.color = "#93a394";
  Chart.defaults.borderColor = "rgba(214,230,196,0.12)";
  Chart.defaults.font.family = "IBM Plex Mono, ui-monospace, monospace";

  function stamp(iso) {
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) return iso;
    return date.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  }

  function line(canvas, labels, datasets, unit) {
    return new Chart(canvas, {
      type: "line",
      data: { labels: labels, datasets: datasets },
      options: {
        animation: false,
        responsive: true,
        maintainAspectRatio: false,
        interaction: { mode: "index", intersect: false },
        plugins: { legend: { labels: { boxWidth: 12 } } },
        scales: {
          x: { ticks: { maxTicksLimit: 6 } },
          y: { beginAtZero: true, title: { display: !!unit, text: unit || "" } }
        }
      }
    });
  }

  function style(label, color, data) {
    return {
      label: label,
      data: data,
      borderColor: color,
      backgroundColor: color + "22",
      fill: false,
      tension: 0.25,
      pointRadius: data.length < 12 ? 3 : 0,
      borderWidth: 2,
      spanGaps: true
    };
  }

  const responseCanvas = document.getElementById("response-chart");
  if (responseCanvas) {
    fetch("/api/devices/" + id + "/response?minutes=" + range)
      .then(function (response) { return response.json(); })
      .then(function (payload) {
        const points = payload.points || [];
        line(responseCanvas, points.map(function (point) { return stamp(point.t); }), [
          style("ms", "#8ec8ff", points.map(function (point) { return point.responseMs; }))
        ], "ms");
      })
      .catch(function () {});
  }

  const bandwidthCanvas = document.getElementById("bandwidth-chart");
  if (bandwidthCanvas && body.dataset.iface) {
    fetch("/api/devices/" + id + "/interfaces/" + body.dataset.iface + "/history?minutes=" + range)
      .then(function (response) { return response.json(); })
      .then(function (payload) {
        const points = payload.points || [];
        const note = document.getElementById("bandwidth-note");
        const hasRate = points.some(function (point) { return point.inBps != null || point.outBps != null; });
        if (note) note.hidden = hasRate;
        line(bandwidthCanvas, points.map(function (point) { return stamp(point.t); }), [
          style("In", "#d6ff4a", points.map(function (point) { return point.inBps == null ? null : point.inBps / 1000000; })),
          style("Out", "#7ddec7", points.map(function (point) { return point.outBps == null ? null : point.outBps / 1000000; }))
        ], "Mbps");
      })
      .catch(function () {});
  }

  const customCanvas = document.getElementById("custom-chart");
  if (customCanvas && body.dataset.custom) {
    fetch("/api/devices/" + id + "/custom/" + body.dataset.custom + "/history?minutes=" + range)
      .then(function (response) { return response.json(); })
      .then(function (payload) {
        const points = payload.points || [];
        line(customCanvas, points.map(function (point) { return stamp(point.t); }), [
          style("Value", "#d6ff4a", points.map(function (point) { return point.value; })),
          style("Rate", "#7ddec7", points.map(function (point) { return point.rate; }))
        ], "");
      })
      .catch(function () {});
  }
})();
