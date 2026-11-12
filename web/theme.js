"use strict";
// Light / dark theme. Follows the computer's setting until a person picks one
// with the switch in the sidebar; the choice is remembered in this browser.
(function () {
  var KEY = "compass_theme";
  var root = document.documentElement;
  var saved = null;
  try { saved = localStorage.getItem(KEY); } catch (_) { /* storage unavailable */ }
  var media = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;
  function system() { return media && media.matches ? "dark" : "light"; }
  function apply(t) {
    root.setAttribute("data-theme", t);
    var btns = document.querySelectorAll("[data-theme-set]");
    for (var i = 0; i < btns.length; i++) btns[i].setAttribute("aria-pressed", String(btns[i].getAttribute("data-theme-set") === t));
  }
  apply(saved === "light" || saved === "dark" ? saved : system());
  document.addEventListener("DOMContentLoaded", function () { apply(root.getAttribute("data-theme")); });
  document.addEventListener("click", function (e) {
    var b = e.target.closest && e.target.closest("[data-theme-set]");
    if (!b) return;
    var t = b.getAttribute("data-theme-set");
    try { localStorage.setItem(KEY, t); } catch (_) { /* storage unavailable */ }
    apply(t);
  });
  if (media && media.addEventListener) {
    media.addEventListener("change", function () {
      var s = null;
      try { s = localStorage.getItem(KEY); } catch (_) { /* storage unavailable */ }
      if (s !== "light" && s !== "dark") apply(system());
    });
  }
})();
