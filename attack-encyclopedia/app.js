"use strict";
const search = document.querySelector("#attack-search");
const rows = [...document.querySelectorAll("[data-attack-row]")];
const groups = [...document.querySelectorAll("[data-attack-group]")];
const filters = [...document.querySelectorAll("[data-filter]")];
const resultCount = document.querySelector("#result-count");
const emptyState = document.querySelector("#empty-state");
const reset = document.querySelector("#reset-search");
let category = "All";

function update() {
  const needle = search.value.trim().toLowerCase();
  let total = 0;
  rows.forEach((row) => {
    const visible =
      (category === "All" || row.dataset.category === category) &&
      (!needle || row.dataset.search.includes(needle));
    row.hidden = !visible;
    if (visible) total += 1;
  });
  groups.forEach((group) => {
    const visibleRows = [...group.querySelectorAll("[data-attack-row]")].filter(
      (row) => !row.hidden,
    );
    group.hidden = visibleRows.length === 0;
    group.querySelector("[data-group-count]").textContent = visibleRows.length;
  });
  resultCount.textContent = String(total).padStart(3, "0") + " RESULTS";
  emptyState.hidden = total !== 0;
}

filters.forEach((button) => {
  button.addEventListener("click", () => {
    category = button.dataset.filter;
    filters.forEach((item) => item.classList.toggle("active", item === button));
    update();
  });
});
search.addEventListener("input", update);
reset.addEventListener("click", () => {
  search.value = "";
  category = "All";
  filters.forEach((item) =>
    item.classList.toggle("active", item.dataset.filter === "All"),
  );
  update();
  search.focus();
});
document.addEventListener("keydown", (event) => {
  if (event.key === "/" && document.activeElement !== search) {
    event.preventDefault();
    search.focus();
  }
  if (event.key === "Escape") {
    search.value = "";
    update();
    search.blur();
  }
});
