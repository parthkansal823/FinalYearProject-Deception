/* Northbridge Staff Portal -- client behaviour.
 *
 * Small and genuinely used. Two research reasons for it to exist at all
 * (spec §6.1, §6.7):
 *
 *   1. Fetching it is an automation signal. Browsers do; most attack tools
 *      do not.
 *   2. The invisibility gate compares the DOM *after* scripts have run, so
 *      there has to be a script stage for bait to survive.
 */
(function () {
  "use strict";

  // Keep the search box focused on the search page, the way a real internal
  // tool would.
  var search = document.querySelector('input[name="q"]');
  if (search && !search.value) {
    search.focus();
  }

  // Mark the current nav item.
  var here = window.location.pathname;
  Array.prototype.forEach.call(document.querySelectorAll(".site-header nav a"), function (link) {
    if (link.getAttribute("href") === here) {
      link.setAttribute("aria-current", "page");
    }
  });

  // Numeric-only verification field, trimmed on submit.
  var code = document.getElementById("code");
  if (code) {
    code.addEventListener("input", function () {
      code.value = code.value.replace(/[^0-9]/g, "").slice(0, 6);
    });
  }

  // Confirm before signing out, so the logout link is not a one-click trap
  // for someone who mis-aims.
  var logout = document.querySelector(".logout");
  if (logout) {
    logout.addEventListener("click", function (event) {
      if (!window.confirm("Sign out of the staff portal?")) {
        event.preventDefault();
      }
    });
  }
})();
