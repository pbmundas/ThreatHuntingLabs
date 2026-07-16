function normalizeLabel(element) {
  return element?.textContent.replace(/\s+/g, " ").trim() || "";
}

function addTabDropdowns() {
  const tabs = document.querySelectorAll(".md-tabs__item");
  const primaryItems = document.querySelectorAll(
    ".md-nav--primary > .md-nav__list > .md-nav__item"
  );

  tabs.forEach((tab) => {
    const tabLink = tab.querySelector(":scope > .md-tabs__link");
    if (!tabLink || tab.querySelector(":scope > .thl-tab-dropdown")) return;

    const matchingItem = Array.from(primaryItems).find((item) => {
      const link = item.querySelector(":scope > .md-nav__link");
      return normalizeLabel(link) === normalizeLabel(tabLink);
    });
    const childNav = matchingItem?.querySelector(":scope > .md-nav");
    const childLinks = childNav?.querySelectorAll(".md-nav__link[href]");

    if (!childLinks?.length) return;

    tab.classList.add("md-tabs__item--has-dropdown");
    tabLink.setAttribute("aria-haspopup", "true");

    const dropdown = document.createElement("div");
    dropdown.className = "thl-tab-dropdown";
    dropdown.setAttribute("aria-label", `${normalizeLabel(tabLink)} submenu`);

    childLinks.forEach((childLink) => {
      const link = document.createElement("a");
      link.className = "thl-tab-dropdown__link";
      link.href = childLink.href;
      link.textContent = normalizeLabel(childLink);

      if (childLink.classList.contains("md-nav__link--active")) {
        link.classList.add("thl-tab-dropdown__link--active");
        link.setAttribute("aria-current", "page");
      }

      dropdown.appendChild(link);
    });

    tab.appendChild(dropdown);
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

// Re-run after Material for MkDocs instant navigation replaces the page content.
if (typeof document$ !== "undefined") {
  document$.subscribe(configureNavigation);
}
