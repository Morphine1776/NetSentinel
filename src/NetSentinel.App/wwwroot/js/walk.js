(function () {
  var open = document.getElementById("walk-open");
  var modal = document.getElementById("walk-modal");
  if (!open || !modal) return;

  var preset = document.getElementById("walk-preset");
  var oidInput = document.getElementById("walk-oid");
  var maxInput = document.getElementById("walk-max");
  var hint = document.getElementById("walk-hint");
  var large = document.getElementById("walk-large");
  var go = document.getElementById("walk-go");
  var cancel = document.getElementById("walk-cancel");
  var errorBox = document.getElementById("walk-error");
  var note = document.getElementById("walk-note");
  var filter = document.getElementById("walk-filter");
  var tbody = document.getElementById("walk-rows");
  var controller = null;
  var lastRows = [];

  function normalize(text) {
    var oid = (text || "").trim();
    if (oid.charAt(0) === ".") oid = oid.slice(1);
    return oid;
  }

  function selectedOption() {
    return preset.options[preset.selectedIndex];
  }

  function showPresetMeta() {
    var option = selectedOption();
    var text = option ? (option.getAttribute("data-hint") || "") : "";
    hint.textContent = text;
    hint.hidden = !text;
    var oid = normalize(oidInput.value);
    var flagged = option && option.getAttribute("data-large") === "true";
    large.hidden = !(flagged || oid === "1.3.6.1.2.1");
  }

  function matchPreset(oid) {
    var found = "custom";
    Array.prototype.forEach.call(preset.options, function (option) {
      if (option.getAttribute("data-oid") && option.getAttribute("data-oid") === oid) found = option.value;
    });
    return found;
  }

  preset.addEventListener("change", function () {
    var option = selectedOption();
    var next = option ? option.getAttribute("data-oid") || "" : "";
    if (next) oidInput.value = next;
    showPresetMeta();
  });

  oidInput.addEventListener("input", function () {
    preset.value = matchPreset(normalize(oidInput.value));
    showPresetMeta();
  });

  function field(name) {
    return document.querySelector('[name="' + name + '"]');
  }

  function checked(name) {
    var box = field(name);
    return !!(box && box.checked);
  }

  function text(name) {
    var box = field(name);
    return box ? box.value : "";
  }

  function numberOrNull(name) {
    var raw = text(name);
    if (raw === "") return null;
    var parsed = Number(raw);
    return Number.isFinite(parsed) ? parsed : null;
  }

  function policy() {
    return {
      useVersion: checked("Policy.UseVersion"),
      version: text("Policy.Version"),
      useCommunity: checked("Policy.UseCommunity"),
      community: text("Policy.Community"),
      useV3User: checked("Policy.UseV3User"),
      v3User: text("Policy.V3User"),
      useV3AuthProtocol: checked("Policy.UseV3AuthProtocol"),
      v3AuthProtocol: text("Policy.V3AuthProtocol"),
      useV3AuthSecret: checked("Policy.UseV3AuthSecret"),
      v3AuthSecret: text("Policy.V3AuthSecret"),
      useV3PrivProtocol: checked("Policy.UseV3PrivProtocol"),
      v3PrivProtocol: text("Policy.V3PrivProtocol"),
      useV3PrivSecret: checked("Policy.UseV3PrivSecret"),
      v3PrivSecret: text("Policy.V3PrivSecret"),
      usePort: checked("Policy.UsePort"),
      port: numberOrNull("Policy.Port"),
      useTimeout: checked("Policy.UseTimeout"),
      timeoutMs: numberOrNull("Policy.TimeoutMs"),
      useRetries: checked("Policy.UseRetries"),
      retries: numberOrNull("Policy.Retries"),
      usePollInterval: checked("Policy.UsePollInterval"),
      pollIntervalSeconds: numberOrNull("Policy.PollIntervalSeconds")
    };
  }

  function configured() {
    var set = {};
    document.querySelectorAll("#oid-list [data-field='Oid']").forEach(function (input) {
      var oid = normalize(input.value);
      if (oid) set[oid] = true;
    });
    return set;
  }

  function escapeHtml(text) {
    return String(text == null ? "" : text).replace(/[&<>"']/g, function (ch) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch];
    });
  }

  function labelHtml(row) {
    var main = row.label || "";
    var meta = [row.sensorType, row.scale].filter(Boolean).join(", ");
    var html = escapeHtml(main);
    if (meta) html += '<span class="walk-sub">' + escapeHtml(meta) + "</span>";
    return html || '<span class="walk-sub">—</span>';
  }

  function showError(message) {
    errorBox.hidden = !message;
    errorBox.textContent = message || "";
  }

  function showNote(message, warn) {
    note.hidden = !message;
    note.textContent = message || "";
    note.classList.toggle("warn", !!warn);
  }

  function render() {
    var known = configured();
    var query = (filter.value || "").trim().toLowerCase();
    tbody.innerHTML = "";
    var shown = 0;
    lastRows.forEach(function (row) {
      var haystack = [row.oid, row.label, row.sensorType, row.scale, row.type, row.value, row.kind, row.suggestedName]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      if (query && haystack.indexOf(query) === -1) return;
      shown++;
      var added = !!known[normalize(row.oid)];
      var tr = document.createElement("tr");
      if (added) tr.className = "added";
      var kind = row.kind ? " " + row.kind : "";
      tr.innerHTML =
        '<td class="mono" data-label="OID">' + escapeHtml(row.oid) + "</td>" +
        '<td data-label="Label">' + labelHtml(row) + "</td>" +
        '<td data-label="Type">' + escapeHtml(row.type || "") + (kind ? '<span class="walk-sub">' + escapeHtml(kind.trim()) + "</span>" : "") + "</td>" +
        '<td class="mono" data-label="Value">' + escapeHtml(row.value || "") + "</td>" +
        '<td data-label=""><button class="btn tiny walk-add" type="button"' + (added ? " disabled" : "") + ">" + (added ? "Added" : "Add") + "</button></td>";
      var button = tr.querySelector("button");
      button.addEventListener("click", function () { addRow(row); });
      tbody.appendChild(tr);
    });
    if (shown === 0) {
      var empty = document.createElement("tr");
      empty.innerHTML = '<td colspan="5" class="hint">' + (lastRows.length ? "No rows match the filter." : "Walk an OID to list it.") + "</td>";
      tbody.appendChild(empty);
    }
  }

  function blankRow() {
    var rows = document.querySelectorAll("#oid-list .oid-row");
    for (var i = 0; i < rows.length; i++) {
      var name = rows[i].querySelector("[data-field='Name']");
      var oid = rows[i].querySelector("[data-field='Oid']");
      if (name && oid && !name.value.trim() && !oid.value.trim()) return rows[i];
    }
    return null;
  }

  function addRow(row) {
    var list = document.getElementById("oid-list");
    var target = blankRow();
    if (!target) {
      document.getElementById("add-oid").click();
      var rows = list.querySelectorAll(".oid-row");
      target = rows[rows.length - 1];
    }
    var name = (row.suggestedName || row.label || row.oid || "").slice(0, 80);
    target.querySelector("[data-field='Name']").value = name;
    target.querySelector("[data-field='Oid']").value = row.oid || "";
    if (row.unit) target.querySelector("[data-field='Unit']").value = row.unit;
    var kind = target.querySelector(".oid-kind");
    if (kind) {
      kind.textContent = row.kind || "";
      kind.dataset.kind = row.kind || "";
    }
    target.classList.add("from-walk");
    render();
  }

  function close() {
    if (controller) controller.abort();
    controller = null;
    modal.hidden = true;
    go.disabled = false;
    go.textContent = "Walk";
  }

  open.addEventListener("click", function () {
    modal.hidden = false;
    showPresetMeta();
    render();
    oidInput.focus();
  });

  cancel.addEventListener("click", close);
  modal.addEventListener("click", function (event) {
    if (event.target === modal) close();
  });
  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape" && !modal.hidden) close();
  });
  filter.addEventListener("input", render);

  go.addEventListener("click", function () {
    var host = (text("Input.Host") || "").trim();
    showError("");
    showNote("");
    if (!host) {
      showError("Enter a host or IP before walking.");
      return;
    }
    var oid = normalize(oidInput.value);
    if (!oid) {
      showError("Enter an OID to walk, or choose a preset.");
      return;
    }
    var maxRows = Number(maxInput.value);
    if (!Number.isFinite(maxRows) || maxRows < 1) maxRows = 500;
    if (maxRows > 5000) maxRows = 5000;
    maxInput.value = String(maxRows);

    if (controller) controller.abort();
    controller = new AbortController();
    go.disabled = true;
    go.textContent = "Walking…";
    var deviceId = open.getAttribute("data-device-id");
    var body = {
      host: host,
      location: text("Input.Location"),
      v3Context: text("Input.V3Context"),
      deviceId: deviceId ? Number(deviceId) : null,
      baseOid: oid,
      maxRows: maxRows,
      policy: policy()
    };
    fetch("/api/devices/walk", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-NetSentinel": "1" },
      body: JSON.stringify(body),
      signal: controller.signal
    }).then(function (response) {
      return response.json().then(function (payload) {
        return { ok: response.ok, payload: payload };
      }).catch(function () {
        return { ok: response.ok, payload: {} };
      });
    }).then(function (result) {
      if (!result.ok) {
        var errors = (result.payload && result.payload.errors) || ["The walk failed."];
        showError(errors.join(" "));
        lastRows = [];
        render();
        return;
      }
      lastRows = result.payload.rows || [];
      var count = lastRows.length + (lastRows.length === 1 ? " object" : " objects");
      showNote(result.payload.message || count, !!result.payload.truncated);
      render();
    }).catch(function (error) {
      if (error && error.name === "AbortError") return;
      showError("The walk failed.");
    }).then(function () {
      go.disabled = false;
      go.textContent = "Walk";
    });
  });

  showPresetMeta();
  render();
})();
