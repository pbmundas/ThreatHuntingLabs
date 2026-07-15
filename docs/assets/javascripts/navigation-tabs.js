document.addEventListener("DOMContentLoaded", () => {
  const menuLinks = document.querySelectorAll(
    ".md-tabs__link, .md-nav--primary .md-nav__link[href]"
  );

  menuLinks.forEach((link) => {
    const href = link.getAttribute("href");

    // Keep section toggles and same-page anchors in the current tab.
    if (!href || href.startsWith("#") || href.startsWith("javascript:")) return;

    link.setAttribute("target", "_blank");
    link.setAttribute("rel", "noopener noreferrer");
  });
});
