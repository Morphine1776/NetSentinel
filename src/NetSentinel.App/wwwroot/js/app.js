(function () {
  const body = document.body;
  const refresh = Number(body.dataset.refresh || "0");
  if (refresh > 0) {
    window.setTimeout(function () { window.location.reload(); }, refresh * 1000);
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
    row.addEventListener("click", function () {
      const url = new URL(window.location.href);
      url.searchParams.set("iface", row.dataset.selectIface);
      window.location.href = url.toString();
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
