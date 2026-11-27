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
    box.addEventListener("change", function () { sync(field); });
    sync(field);
  });

  document.querySelectorAll("form").forEach(function (form) {
    form.addEventListener("submit", function () {
      form.querySelectorAll("[data-policy-field] input, [data-policy-field] select, [data-policy-field] textarea").forEach(function (control) {
        control.disabled = false;
      });
    });
  });
})();
