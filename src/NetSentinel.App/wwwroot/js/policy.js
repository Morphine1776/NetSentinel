(function () {
  function sync(field) {
    var box = field.querySelector("[data-override]");
    if (!box) return;
    field.querySelectorAll("input, select, textarea").forEach(function (control) {
      if (control === box) return;
      control.disabled = !box.checked;
    });
    field.classList.toggle("inheriting", !box.checked);
  }

  document.querySelectorAll("[data-policy-field]").forEach(function (field) {
    var box = field.querySelector("[data-override]");
    if (!box) return;
    var reset = document.createElement("button");
    reset.type = "button";
    reset.className = "btn tiny reset-field";
    reset.textContent = "Reset";
    var head = field.querySelector(".policy-field-head") || box.parentElement;
    head.appendChild(reset);
    reset.addEventListener("click", function (event) {
      event.preventDefault();
      event.stopPropagation();
      box.checked = false;
      sync(field);
    });
    box.addEventListener("change", function () { sync(field); });
    sync(field);
  });

  var resetAll = document.getElementById("reset-all-inherited");
  if (resetAll) {
    resetAll.addEventListener("click", function () {
      document.querySelectorAll("[data-override]").forEach(function (box) {
        box.checked = false;
        var field = box.closest("[data-policy-field]");
        if (field) sync(field);
      });
    });
  }

  document.querySelectorAll("form").forEach(function (form) {
    form.addEventListener("submit", function () {
      form.querySelectorAll("[data-policy-field] input, [data-policy-field] select, [data-policy-field] textarea").forEach(function (control) {
        control.disabled = false;
      });
    });
  });
})();
