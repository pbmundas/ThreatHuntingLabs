function normalizeLabel(element) {
  return element?.textContent.replace(/\s+/g, " ").trim() || "";
}

function addTabDropdowns() {
  const tabs = document.querySelectorAll(".md-tabs__item");
  const navigation = Array.isArray(window.thlNavigation)
    ? window.thlNavigation
    : [];

  tabs.forEach((tab) => {
    const tabLink = tab.querySelector(":scope > .md-tabs__link");
    if (!tabLink || tab.querySelector(":scope > .thl-tab-dropdown")) return;

    const navigationItem = navigation.find(
      (item) => item.title === normalizeLabel(tabLink)
    );
    const children = navigationItem?.children || [];

    if (!children.length) return;

    tab.classList.add("md-tabs__item--has-dropdown");
    tabLink.setAttribute("aria-haspopup", "true");
    tabLink.setAttribute("aria-expanded", "false");

    const dropdown = document.createElement("div");
    dropdown.className = "thl-tab-dropdown";
    dropdown.setAttribute("aria-label", `${normalizeLabel(tabLink)} submenu`);

    children.forEach((child) => {
      if (!child.url) return;

      const link = document.createElement("a");
      link.className = "thl-tab-dropdown__link";
      link.href = child.url;
      link.textContent = child.title;

      if (child.active) {
        link.classList.add("thl-tab-dropdown__link--active");
        link.setAttribute("aria-current", "page");
      }

      dropdown.appendChild(link);
    });

    tab.appendChild(dropdown);

    tabLink.addEventListener("click", (event) => {
      event.preventDefault();
      const willOpen = !tab.classList.contains("md-tabs__item--dropdown-open");

      document
        .querySelectorAll(".md-tabs__item--dropdown-open")
        .forEach((openTab) => {
          openTab.classList.remove("md-tabs__item--dropdown-open");
          openTab
            .querySelector(":scope > .md-tabs__link")
            ?.setAttribute("aria-expanded", "false");
        });

      tab.classList.toggle("md-tabs__item--dropdown-open", willOpen);
      tabLink.setAttribute("aria-expanded", String(willOpen));
    });
  });
}

function configureNavigation() {
  addTabDropdowns();

  const menuLinks = document.querySelectorAll(
    ".md-tabs__link, .thl-tab-dropdown__link, .md-nav--primary .md-nav__link[href]"
  );

  menuLinks.forEach((link) => {
    const url = new URL(link.href, window.location.href);
    const path = url.pathname.replace(/\/$/, "");
    const opensInNewTab =
      url.hostname === "blog.threathuntlabs.com" ||
      url.hostname === "intel.threathuntlabs.com" ||
      path === "/learn-known-cyber-attacks";

    if (opensInNewTab) {
      link.setAttribute("target", "_blank");
      link.setAttribute("rel", "noopener noreferrer");
    } else {
      link.removeAttribute("target");
      link.removeAttribute("rel");
    }
  });
}

document.addEventListener("DOMContentLoaded", configureNavigation);
document.addEventListener("click", (event) => {
  if (event.target.closest(".md-tabs__item--has-dropdown")) return;

  document
    .querySelectorAll(".md-tabs__item--dropdown-open")
    .forEach((tab) => {
      tab.classList.remove("md-tabs__item--dropdown-open");
      tab
        .querySelector(":scope > .md-tabs__link")
        ?.setAttribute("aria-expanded", "false");
    });
});
document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") return;

  document
    .querySelectorAll(".md-tabs__item--dropdown-open")
    .forEach((tab) => {
      tab.classList.remove("md-tabs__item--dropdown-open");
      const link = tab.querySelector(":scope > .md-tabs__link");
      link?.setAttribute("aria-expanded", "false");
      link?.focus();
    });
});

// Re-run after Material for MkDocs instant navigation replaces the page content.
if (typeof document$ !== "undefined") {
  document$.subscribe(configureNavigation);
}
