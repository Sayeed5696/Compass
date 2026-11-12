(function () {
  "use strict";
  const $ = (s, r = document) => r.querySelector(s);
  const state = { csrf: null };
  const reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // ------------------------------------------------------------ bearing dial
  function buildDial() {
    const g = $("#dialCard");
    const NS = "http://www.w3.org/2000/svg";
    const el = (tag, attrs) => { const n = document.createElementNS(NS, tag); for (const k in attrs) n.setAttribute(k, attrs[k]); return n; };
    const R = 468;
    g.appendChild(el("circle", { class: "ring", r: R }));
    g.appendChild(el("circle", { class: "ring", r: 360 }));
    for (let d = 0; d < 360; d += 2) {
      const major = d % 10 === 0;
      const len = d % 30 === 0 ? 30 : major ? 20 : 10;
      const a = (d - 90) * Math.PI / 180;
      g.appendChild(el("line", {
        class: "tick" + (major ? " major" : ""),
        x1: (R * Math.cos(a)).toFixed(1), y1: (R * Math.sin(a)).toFixed(1),
        x2: ((R - len) * Math.cos(a)).toFixed(1), y2: ((R - len) * Math.sin(a)).toFixed(1)
      }));
    }
    const cardinals = { 0: "N", 90: "E", 180: "S", 270: "W" };
    for (let d = 0; d < 360; d += 30) {
      const isCard = d in cardinals;
      const r = isCard ? 404 : 412;
      const t = el("text", {
        class: isCard ? ("cardinal" + (d === 0 ? " north" : "")) : "num",
        x: 0, y: -r, "text-anchor": "middle", "dominant-baseline": "middle",
        transform: `rotate(${d})`
      });
      t.textContent = isCard ? cardinals[d] : String(d).padStart(3, "0");
      g.appendChild(t);
    }
  }

  // ------------------------------------------------------------------ views
  const views = ["loginForm", "setupForm", "changeForm", "loadingView"];
  function show(id, focusSel) {
    views.forEach(v => { $("#" + v).hidden = v !== id; });
    const first = focusSel ? $(focusSel) : $("#" + id + " input:not([hidden])");
    if (first && id !== "loadingView") setTimeout(() => first.focus(), reduceMotion ? 0 : 420);
  }
  function setError(form, msg) {
    const box = $(".error", form);
    box.textContent = msg || "";
    box.hidden = !msg;
    if (msg && !reduceMotion) {
      const card = $("#card");
      card.classList.remove("shake"); void card.offsetWidth; card.classList.add("shake");
    }
  }
  function busy(form, on, label) {
    const b = $(".submit", form);
    if (on) { b.dataset.label = b.textContent; b.textContent = label; b.disabled = true; }
    else { b.textContent = b.dataset.label || b.textContent; b.disabled = false; }
  }

  async function post(path, body) {
    const r = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Compass-CSRF": state.csrf || "login" },
      body: JSON.stringify(body || {}),
      credentials: "same-origin"
    });
    let data = {};
    try { data = await r.json(); } catch (_) { /* empty body */ }
    if (!r.ok) throw new Error(data.error || `The server returned HTTP ${r.status}.`);
    return data;
  }

  function enterApp() {
    document.body.classList.add("is-leaving");
    setTimeout(() => { window.location.replace("/"); }, reduceMotion ? 0 : 480);
  }

  // ------------------------------------------------------- password helpers
  function score(pw) {
    if (!pw) return 0;
    let s = pw.length >= 8 ? 1 : 0;
    if (pw.length >= 12) s++;
    if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) s++;
    if (/\d/.test(pw) && /[^A-Za-z0-9]/.test(pw)) s++;
    if (pw.length >= 16) s++;
    return Math.max(pw.length ? 1 : 0, Math.min(4, s));
  }
  document.querySelectorAll(".meter").forEach(m => {
    const input = m.previousElementSibling.querySelector("input");
    input.addEventListener("input", () => { m.dataset.score = String(score(input.value)); });
  });
  document.querySelectorAll(".reveal").forEach(btn => {
    btn.addEventListener("click", () => {
      const input = document.getElementById(btn.dataset.for);
      const showing = input.type === "text";
      input.type = showing ? "password" : "text";
      btn.textContent = showing ? "Show" : "Hide";
      btn.setAttribute("aria-label", showing ? "Show password" : "Hide password");
      input.focus();
    });
  });
  document.addEventListener("keyup", e => {
    if (!e.getModifierState) return;
    const on = e.getModifierState("CapsLock");
    const form = e.target && e.target.form;
    if (form && e.target.type === "password") $(".caps", form).hidden = !on;
  });

  // ------------------------------------------------------------------ forms
  $("#loginForm").addEventListener("submit", async e => {
    e.preventDefault();
    const f = e.currentTarget;
    const username = f.username.value.trim(), password = f.password.value;
    if (!username || !password) { setError(f, "Enter your username and password."); return; }
    setError(f, ""); busy(f, true, "Signing in…");
    try {
      const d = await post("/api/auth/login", { username, password });
      state.csrf = d.csrf;
      if (d.user && d.user.must_change) {
        busy(f, false);
        $("#changeForm").username.value = d.user.username;
        $("#changeCurrent").value = password;
        show("changeForm", "#changeNew");
        return;
      }
      enterApp();
    } catch (err) {
      busy(f, false);
      f.password.value = "";
      setError(f, err.message);
      f.password.focus();
    }
  });

  $("#setupForm").addEventListener("submit", async e => {
    e.preventDefault();
    const f = e.currentTarget;
    const username = f.username.value.trim(), password = f.password.value;
    if (!username) { setError(f, "Choose a username for the administrator account."); return; }
    if (password.length < 8) { setError(f, "The password needs at least 8 characters."); return; }
    if (password !== f.password2.value) { setError(f, "The two passwords don't match."); f.password2.focus(); return; }
    setError(f, ""); busy(f, true, "Creating account…");
    try {
      const d = await post("/api/auth/setup", { username, password, display_name: f.display_name.value.trim() });
      state.csrf = d.csrf;
      enterApp();
    } catch (err) { busy(f, false); setError(f, err.message); }
  });

  $("#changeForm").addEventListener("submit", async e => {
    e.preventDefault();
    const f = e.currentTarget;
    const current = f.current.value, next = f.new.value;
    if (!current) { setError(f, "Enter the temporary password you signed in with."); return; }
    if (next.length < 8) { setError(f, "The new password needs at least 8 characters."); return; }
    if (next !== f.new2.value) { setError(f, "The two new passwords don't match."); f.new2.focus(); return; }
    setError(f, ""); busy(f, true, "Saving…");
    try {
      await post("/api/auth/password", { current_password: current, new_password: next });
      enterApp();
    } catch (err) { busy(f, false); setError(f, err.message); }
  });

  $("#changeSignOut").addEventListener("click", async () => {
    try { await post("/api/auth/logout", {}); } catch (_) { /* already signed out */ }
    state.csrf = null;
    $("#changeForm").reset();
    show("loginForm");
  });

  // ------------------------------------------------------------------- boot
  async function boot() {
    buildDial();
    requestAnimationFrame(() => requestAnimationFrame(() => {
      document.body.classList.remove("is-loading");
      document.body.classList.add("is-ready");
    }));
    try {
      const r = await fetch("/api/auth/state", { credentials: "same-origin" });
      const s = await r.json();
      if (s.version) $("#version").textContent = `Version ${s.version}`;
      if (s.setup_required) { show("setupForm"); return; }
      if (s.authenticated && s.user) {
        state.csrf = s.csrf;
        if (s.user.must_change) {
          $("#changeForm").username.value = s.user.username;
          show("changeForm");
          return;
        }
        window.location.replace("/");
        return;
      }
      show("loginForm");
    } catch (_) {
      $("#loadingView .lede").textContent = "Can't reach the Compass server. Check that it is running, then reload this page.";
      show("loadingView");
    }
  }
  boot();
})();
