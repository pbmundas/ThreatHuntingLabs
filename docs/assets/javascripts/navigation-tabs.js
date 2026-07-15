document.addEventListener("DOMContentLoaded", () => {
  const menuLinks = document.querySelectorAll(
    ".md-tabs__link, .md-nav--primary .md-nav__link[href]"
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
});
