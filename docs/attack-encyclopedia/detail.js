"use strict";
document.querySelectorAll("[data-copy-query]").forEach((button) => {
  button.addEventListener("click", async () => {
    const initialLabel = button.textContent;
    const container = button.closest(".query-card, .log-sample");
    const query = container.querySelector("code").textContent;
    try {
      await navigator.clipboard.writeText(query);
      button.textContent = "COPIED";
    } catch {
      const area = document.createElement("textarea");
      area.value = query;
      document.body.appendChild(area);
      area.select();
      document.execCommand("copy");
      area.remove();
      button.textContent = "COPIED";
    }
    setTimeout(() => (button.textContent = initialLabel), 1600);
  });
});
