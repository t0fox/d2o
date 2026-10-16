/* D2K — локальная панель. Состояние движка, управление службами и обновления.
   Данные из сети попадают в DOM исключительно через textContent. */
(function (global) {
  "use strict";

  var POLL_MS = 2000;
  var IDLE_POLL_MS = 6000;
  var STALE_MS = 9000;

  /* ─── Словарь ─── */

  var SHAPES = { 0: "", 1: "TLS 1.3", 2: "TLS 1.2", 3: "QUIC", 4: "любая форма", 5: "голос", 6: "TLS 1.3 + ECH" };
  var MODES = { apply: "применение", observe: "наблюдение", off: "выключен" };

  var TRACK = [
    { label: "Очередь", phases: ["ожидает безопасного слота замера", "заводим поиск"] },
    { label: "Форма", phases: ["ждём форму приветствия"] },
    { label: "Распознаём", phases: ["распознаём поведение"] },
    { label: "Свойства", phases: ["спрашиваем коробку о свойствах"] },
    { label: "Планы", phases: ["выводим планы"] },
    { label: "Проверка", phases: ["проверяем готовое узнанной коробки", "проверяем выведенный план"] },
    { label: "Подтверждено", phases: ["подтверждено, смотрим живой трафик"] }
  ];
  var VOICE_TRACK = [
    { label: "Замер голоса", phases: ["измеряем живой голосовой поток"] },
    { label: "Приём стоит", phases: ["приём голоса стоит, ждём разговора"] },
    { label: "Ждём ответа", phases: ["приём применился к разговору, ждём ответа сервера"] }
  ];

  function plural(n, one, few, many) {
    var m10 = n % 10, m100 = n % 100;
    if (m10 === 1 && m100 !== 11) return one;
    if (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14)) return few;
    return many;
  }
  function count(n, one, few, many) { return n + " " + plural(n, one, few, many); }

  function num(v) { return typeof v === "number" && isFinite(v) ? v : null; }
  function list(v) { return Array.isArray(v) ? v : []; }
  function str(v) { return v === undefined || v === null ? "" : String(v); }

  function shapeLabel(shape, transport) {
    var s = SHAPES[shape];
    if (s) return s;
    if (transport === 17) return "UDP";
    if (transport === 6) return "TCP";
    return "протокол не указан";
  }
  function familyLabel(f) { return f === 6 ? "IPv6" : f === 4 ? "IPv4" : "IP?"; }
  function targetLabel(t) {
    if (t === "@discord-voice") return "Голос Discord";
    return str(t) || "цель без имени";
  }

  function trackFor(phase) {
    var tracks = [TRACK, VOICE_TRACK];
    for (var t = 0; t < tracks.length; t++) {
      for (var i = 0; i < tracks[t].length; i++) {
        if (tracks[t][i].phases.indexOf(phase) >= 0) return { steps: tracks[t], at: i, voice: t === 1 };
      }
    }
    return null;
  }

  function parseTime(iso) {
    var t = Date.parse(iso);
    return isFinite(t) && t > 86400000 ? t : null;
  }

  function duration(ms) {
    var s = Math.max(0, Math.floor(ms / 1000));
    if (s < 60) return s + " с";
    var m = Math.floor(s / 60);
    if (m < 60) return m + " мин " + (s % 60 < 10 ? "0" : "") + (s % 60) + " с";
    var h = Math.floor(m / 60);
    if (h < 48) return h + " ч " + (m % 60) + " мин";
    return Math.floor(h / 24) + " дн " + (h % 24) + " ч";
  }
  function telegramRouteName(route) {
    return route === 1 ? "прямой WSS" :
      route === 2 ? "Worker Cloudflare" :
      route === 3 ? "CF proxy" : route === 4 ? "прямой TCP" : "неизвестный маршрут";
  }
  function telegramFailureStage(stage) {
    return stage === 1 ? "DNS" :
      stage === 2 ? "TCP" :
      stage === 3 ? "TLS" :
      stage === 4 ? "WebSocket" :
      stage === 5 ? "MTProto" :
      stage === 6 ? "настройка маршрута" : "неизвестный этап";
  }
  function telegramAge(ms) { return ms < 1000 ? "только что" : duration(ms); }
  function clock(ms) {
    var s = Math.max(0, Math.floor(ms / 1000));
    var m = Math.floor(s / 60), h = Math.floor(m / 60);
    var pad = function (x) { return (x < 10 ? "0" : "") + x; };
    return (h ? h + ":" + pad(m % 60) : m) + ":" + pad(s % 60);
  }
  function ago(ms) {
    if (ms < 45000) return "только что";
    return duration(ms).replace(/ \d+ с$/, "").replace(/ 0 (мин|ч)$/, "") + " назад";
  }
  function localTime(t) {
    try {
      return new Date(t).toLocaleString("ru-RU", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
    } catch (e) { return new Date(t).toISOString(); }
  }

  /* Краткая выжимка плана — только директивы, без полезной нагрузки. */
  function planGist(text) {
    var skip = { "d2k-plan": 1, id: 1, proto: 1, payload: 1, wire: 1, input: 1 };
    return str(text).split("\n").map(function (line) { return line.trim(); }).filter(function (line) {
      return line && !skip[line.split(/\s+/)[0]];
    }).map(function (line) {
      var parts = line.split(/\s+/);
      return parts.length > 3 ? parts.slice(0, 3).join(" ") + "…" : line;
    }).join(" · ");
  }

  /* Предел одновременных замеров считает движок по нагрузке роутера:
     от 1 на слабом до десятков на мощном. До 16 — клетками, больше — шкалой. */
  function slotsView(meas) {
    var limit = Math.max(0, Math.round(num(meas && meas.limit) || 0));
    var active = Math.max(0, Math.round(num(meas && meas.active) || 0));
    var queued = Math.max(0, Math.round(num(meas && meas.queued) || 0));
    var measured = num(meas && meas.free_pct) !== null;
    return {
      kind: limit <= 16 ? "cells" : "bar",
      limit: limit, active: Math.min(active, Math.max(limit, active)), queued: queued,
      short: measured ? "предел по нагрузке роутера" : "предел по умолчанию",
      note: measured
        ? "Сколько замеров идёт одновременно, решает движок: предел снижается, когда роутеру не хватает процессора, памяти или conntrack, и растёт, когда есть запас и очередь."
        : "Данных о нагрузке роутера нет — движок держит предел по умолчанию."
    };
  }

  function normName(n) { return str(n).toLowerCase().replace(/\.$/, ""); }

  /* Привязка, уже покрытая применяемым семейством, не дублируется как отдельный результат.
     Исключения семейства остаются видимыми. */
  function coveredBy(binding, groups) {
    if (binding.kind && binding.kind !== "name") return null;
    var name = normName(binding.target);
    for (var i = 0; i < groups.length; i++) {
      var g = groups[i];
      var suffix = normName(g.suffix);
      if (!g.active || (binding.transport || 6) !== g.transport || (binding.family || 4) !== g.family ||
          (binding.shape || 0) !== g.shape ||
          (binding.probe_path || "/") !== (g.probe_path || "/") ||
          (binding.ech_origin || "") !== (g.ech_origin || "")) continue;
      if (name !== suffix && name.slice(-suffix.length - 1) !== "." + suffix) continue;
      var excepted = list(g.exceptions).some(function (ex) {
        return normName(ex && typeof ex === "object" ? ex.name : ex) === name;
      });
      if (!excepted) return g;
    }
    return null;
  }

  /* ─── Модель: что можно честно утверждать по снимку ─── */

  function model(status, received, now) {
    var snap = (status && status.snapshot) || {};
    var k = (status && status.knowledge) || {};
    var linked = !!k.linked;
    var engine = !!snap.engine_running;
    var searches = linked ? list(k.searches) : [];
    var QUEUED = "ожидает безопасного слота замера";
    var active = searches.filter(function (s) { return s.phase !== "подтверждено, смотрим живой трафик"; });
    var m = {
      snap: snap, k: k, linked: linked, engine: engine,
      fresh: snap.live_fresh !== false,
      searches: searches, hunting: active.length,
      running: searches.filter(function (s) { return s.phase !== QUEUED; }),
      queued: searches.filter(function (s) { return s.phase === QUEUED; }),
      groups: list(k.groups), boxes: list(k.boxes),
      mode: str(snap.mode) || "observe"
    };

    if (!engine) {
      m.tone = "bad"; m.lamp = "bad";
      m.headline = ["Движок ", "остановлен"];
      m.state = "Движок остановлен";
      m.lede = m.snap.mode === "off"
        ? "В конфигурации задан режим MODE=off. Трафик не читается и обходы не применяются."
        : "Трафик не читается, подбор не идёт, сохранённые обходы не применяются. Каталог ниже — последнее сохранённое состояние.";
    } else if (!linked) {
      m.tone = "bad"; m.lamp = "warn";
      m.headline = ["Нет связи ", "с датапатом"];
      m.state = "Движок запущен, связи с датапатом нет";
      m.lede = (k.link_note ? "Причина: " + k.link_note + ". " : "") +
        "Идут ли поиски и применяются ли обходы, отсюда не видно. Это не «ноль поисков», а отсутствие измерения.";
    } else if (m.hunting > 0) {
      m.tone = "live"; m.lamp = "live";
      m.headline = ["Идёт ", count(m.hunting, "поиск", "поиска", "поисков")];
      m.state = "Движок работает, идёт подбор";
      m.lede = "D2K подтвердил блокировку и сам подбирает обход в протоколе, где она встретилась. Делать ничего не нужно." +
        (m.queued.length ? " Замеряется " + (m.hunting - m.queued.length) + ", " + m.queued.length + " " +
          plural(m.queued.length, "ждёт", "ждут", "ждут") + " свободного слота замера." : "");
    } else {
      m.tone = "ok"; m.lamp = "ok";
      m.headline = ["Поисков ", "нет"];
      m.state = "Движок работает";
      m.lede = "Подтверждённых блокировок без решения сейчас нет. Живой трафик под наблюдением: подбор начнётся, только если блокировка подтвердится измерением.";
    }
    if (engine && !m.fresh) {
      m.lamp = "warn";
      m.state = "Снимок движка устарел";
    }
    /* uptime_seconds — время работы процесса панели, а не движка. */
    m.panelUptime = num(snap.uptime_seconds);
    m.stateDetail = "режим: " + (MODES[m.mode] || m.mode);
    return m;
  }

  /* ─── Движение ───
     GSAP — локальный /assets/gsap.js. Без него (или при «уменьшить движение»)
     панель полностью работает: состояния выставляются сразу, без переходов. */

  var Motion = (function () {
    var g = global && global.gsap;
    var doc = global && global.document;
    var mq = global && global.matchMedia ? global.matchMedia("(prefers-reduced-motion: reduce)") : null;
    if (g) {
      var plugins = [global.Flip, global.MotionPathPlugin, global.DrawSVGPlugin, global.MorphSVGPlugin,
        global.ScrollToPlugin, global.SplitText, global.CustomEase, global.CustomWiggle].filter(Boolean);
      if (plugins.length) g.registerPlugin.apply(g, plugins);
      if (global.CustomEase) global.CustomEase.create("d2k", ".16,1,.3,1");
      g.defaults({ ease: global.CustomEase ? "d2k" : "power3.out", duration: 0.5 });
      if (global.CustomWiggle) global.CustomWiggle.create("d2kShake", { wiggles: 5, type: "easeOut" });
      if (doc && doc.documentElement) doc.documentElement.classList.add("has-gsap");
    }
    function on() { return !!g && !(mq && mq.matches); }
    /* Перестроения раскладки (Flip) при смене размера окна завершаются сразу:
       иначе зафиксированные на время анимации размеры вылезают за новый край. */
    var live = [];
    function track(anim) {
      if (anim) { live.push(anim); anim.eventCallback("onComplete", function () { live.splice(live.indexOf(anim), 1); }); }
      return anim;
    }
    if (g && global.addEventListener) global.addEventListener("resize", function () {
      live.splice(0).forEach(function (a) { a.progress(1); });
    });
    return { g: g, on: on, Flip: global && global.Flip, track: track };
  })();

  /* ─── DOM ─── */

  var SVG = "http://www.w3.org/2000/svg";
  var ICONS = {
    play: "M8 5.5v13l10.5-6.5z",
    stop: "M7 7h10v10H7z",
    restart: "M20 11.5a8 8 0 1 1-2.3-5.6M20 4.5v5h-5",
    reapply: "M4 7h11M4 12h16M4 17h9M17 15l3 2-3 2",
    erase: "M5 7h14M9 7V5h6v2M7 7l1 12h8l1-12M10.5 10.5v6M13.5 10.5v6",
    check: "M5 12.5l4.5 4.5L19 7.5",
    cross: "M6.5 6.5l11 11M17.5 6.5l-11 11",
    dash: "M6 12h12",
    send: "M21 3 3 10.5l7 2.5 2.5 7zM10 13l5-5"
  };

  function el(doc, tag, cls, text) {
    var n = doc.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = String(text);
    return n;
  }
  function add(parent) {
    for (var i = 1; i < arguments.length; i++) {
      var c = arguments[i];
      if (c === null || c === undefined || c === false) continue;
      parent.appendChild(typeof c === "string" ? parent.ownerDocument.createTextNode(c) : c);
    }
    return parent;
  }
  function icon(doc, name) {
    var s = doc.createElementNS(SVG, "svg");
    s.setAttribute("viewBox", "0 0 24 24");
    s.setAttribute("aria-hidden", "true");
    var p = doc.createElementNS(SVG, "path");
    p.setAttribute("d", ICONS[name]);
    s.appendChild(p);
    return s;
  }
  function tag(doc, text, tone) {
    var t = el(doc, "span", "tag", text);
    if (tone) t.setAttribute("data-tone", tone);
    return t;
  }

  /* Раздел перерисовывается, только если изменились его данные: так не теряются
     раскрытые подробности, фокус и выделение текста. */
  function section(node, key, build) {
    if (node.__d2kKey === key) return false;
    var open = {};
    var nodes = node.querySelectorAll("details[data-key]");
    for (var i = 0; i < nodes.length; i++) if (nodes[i].open) open[nodes[i].getAttribute("data-key")] = true;
    var fresh = build();
    if (Motion.g) {
      /* Анимации уходящих узлов не должны доживать после перерисовки. */
      var gone = node.querySelectorAll("[style]");
      if (gone.length) Motion.g.killTweensOf(gone);
      var tls = node.querySelectorAll(".crate");
      for (var ti = 0; ti < tls.length; ti++) if (tls[ti].__tl) tls[ti].__tl.kill();
    }
    node.replaceChildren.apply(node, fresh);
    var again = node.querySelectorAll("details[data-key]");
    for (var j = 0; j < again.length; j++) if (open[again[j].getAttribute("data-key")]) again[j].open = true;
    node.__d2kKey = key;
    return true;
  }

  function App(doc, win) {
    this.doc = doc;
    this.win = win;
    this.status = null;
    this.catalogRevision = null;
    this.lastPoll = 0;
    this.received = 0;
    this.lastOk = 0;
    this.failed = false;
    this.pending = null;
    this.armed = null;
    this.filter = "";
    this.openTags = {};
    this.flash = null;
    this.workerDialog = null;
    this.workerDomains = [];
    this.$ = function (id) { return doc.getElementById(id); };
  }

  App.prototype.trackMastHeight = function () {
    var doc = this.doc, win = this.win;
    var mast = doc.querySelector && doc.querySelector(".mast");
    var root = doc.documentElement;
    if (!mast || !root || !root.style || !root.style.setProperty) return;
    var update = function () {
      root.style.setProperty("--mast-offset", Math.ceil(mast.getBoundingClientRect().height) + "px");
    };
    update();
    if (win.ResizeObserver) {
      this.mastObserver = new win.ResizeObserver(update);
      this.mastObserver.observe(mast);
    } else { win.addEventListener("resize", update); }
  };

  App.prototype.start = function () {
    var self = this, doc = this.doc, win = this.win;
    this.trackMastHeight();
    var input = this.$("filter");
    input.addEventListener("input", function () {
      self.filter = input.value.trim().toLowerCase();
      var flip = Motion.on() && Motion.Flip;
      var state = flip ? Motion.Flip.getState(".ftag-wrap, .crate") : null;
      self.renderCatalog(true);
      if (state) {
        /* Оставшиеся бирки и коробки съезжаются; появившиеся проявляются. */
        Motion.track(Motion.Flip.from(state, {
          targets: doc.querySelectorAll(".ftag-wrap, .crate"),
          duration: 0.5, ease: "power3.inOut", absolute: false, nested: true, scale: true, simple: true,
          onEnter: function (els) { return Motion.g.fromTo(els, { autoAlpha: 0, scale: 0.94 }, { autoAlpha: 1, scale: 1, duration: 0.4, clearProps: "transform,opacity,visibility" }); }
        }));
      }
    });
    doc.addEventListener("visibilitychange", function () {
      if (doc.hidden) {
        if (Motion.g) Motion.g.killTweensOf(self.$("update-state"));
        var state = self.$("update-state");
        if (state && state.style) { state.style.opacity = ""; state.style.transform = ""; }
      } else { self.poll(); self.pollUpdates(); }
    });
    doc.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && self.armed) { self.armed = null; self.renderActions(); }
      if (e.key === "/" && doc.activeElement && doc.activeElement.tagName !== "INPUT") {
        e.preventDefault(); input.focus();
      }
    });
    this.spy();
    this.navMotion();
    this.drawMark();
    this.poll();
    this.initUpdates();
    this.checkUpdates(false);
    win.setInterval(function () { if (!doc.hidden) self.poll(true); }, POLL_MS);
    win.setInterval(function () { if (!doc.hidden) self.pollUpdates(); }, POLL_MS);
    win.setInterval(function () { self.tick(); }, 1000);
  };

  App.prototype.poll = function (scheduled) {
    var self = this;
    if (this.inflight) return;
    var idle = this.m && !this.m.hunting &&
      (!this.m.snap.engine_running || this.m.linked) &&
      this.m.snap.control_state !== "running" && !this.pending && !this.failed;
    if (scheduled && idle && Date.now() - this.lastPoll < IDLE_POLL_MS) return;
    this.lastPoll = Date.now();
    this.inflight = true;
    var ctrl = typeof AbortController === "function" ? new AbortController() : null;
    var timer = this.win.setTimeout(function () { if (ctrl) ctrl.abort(); }, 5000);
    var url = "/api/status" + (this.catalogRevision ? "?catalog_revision=" + encodeURIComponent(this.catalogRevision) : "");
    this.win.fetch(url, { cache: "no-store", signal: ctrl ? ctrl.signal : undefined })
      .then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
      .then(function (data) {
        if (data.catalog_unchanged === true) {
          if (!self.status || !self.status.knowledge || !data.knowledge ||
              !data.catalog_revision || data.catalog_revision !== self.status.catalog_revision) {
            throw new Error("catalog cache mismatch");
          }
          data.knowledge.boxes = self.status.knowledge.boxes;
          data.knowledge.groups = self.status.knowledge.groups;
        }
        self.catalogRevision = typeof data.catalog_revision === "string" ? data.catalog_revision : null;
        self.status = data;
        self.received = Date.now();
        self.lastOk = self.received;
        self.failed = false;
        self.render();
      })
      .catch(function () {
        self.catalogRevision = null;
        self.failed = true;
        self.renderNotice();
      })
      .then(function () { self.win.clearTimeout(timer); self.inflight = false; });
  };

  /* Автообновление: состояние — файл d2k-update.sh (GET /api/update), действия —
     команды службы, как у кнопок движка. Установка перезапускает и панель. */
  App.prototype.initUpdates = function () {
    var self = this;
    if (!this.$("updates-body") || this.updatesInitialized) return;
    this.updatesInitialized = true;
    this.$("update-check").addEventListener("click", function () { return self.checkUpdates(true); });
    this.$("update-install").addEventListener("click", function () {
      if (self.$("update-install").disabled) return;
      return self.updateCommand("install");
    });
    this.$("update-auto").addEventListener("change", function () {
      return self.updateCommand(self.$("update-auto").checked ? "auto-on" : "auto-off");
    });
  };

  App.prototype.updateRequest = function (path, post) {
    var win = this.win, ctrl = typeof AbortController === "function" ? new AbortController() : null;
    var timer = win.setTimeout(function () { if (ctrl) ctrl.abort(); }, 5000);
    return win.fetch(path, {
      method: post ? "POST" : "GET", cache: "no-store", credentials: "same-origin",
      signal: ctrl ? ctrl.signal : undefined
    }).then(function (r) {
      return r.json().then(function (data) { return { ok: r.ok, code: r.status, data: data || {} }; },
        function () { return { ok: false, code: r.status, data: {} }; });
    }).finally(function () { win.clearTimeout(timer); });
  };

  /* Без нажатия — только прочитать состояние: проверка по сети идёт ночью. */
  App.prototype.checkUpdates = function (force) {
    return force ? this.updateCommand("check") : this.pollUpdates();
  };

  var UPDATE_ACTIONS = {
    check: "Проверяем обновления…",
    install: "Устанавливаем обновление. Службы перезапустятся, панель подключится сама…",
    "auto-on": "Включаем автообновление…", "auto-off": "Выключаем автообновление…"
  };

  App.prototype.updateCommand = function (action) {
    var self = this;
    if (!this.$("updates-body") || this.updatePending) return Promise.resolve();
    this.updatePending = { action: action, at: Date.now() };
    this.updateMessage("");
    this.renderUpdates(this.updateStatus);
    return this.updateRequest("/api/control/update-" + action, true).then(function (reply) {
      if (!reply.ok) {
        self.updatePending = null;
        self.updateMessage(reply.code === 409 ? "Служба выполняет другую команду. Повторите через минуту." :
          reply.code === 403 ? "Управление разрешено только с этой панели." : "Команда не выполнена.");
      }
    }).catch(function () {
      /* Ответ на установку теряется законно: панель перезапускается. */
      if (action !== "install") { self.updatePending = null; self.updateMessage("Нет связи с панелью. Повторите позже."); }
    }).finally(function () {
      self.renderUpdates(self.updateStatus);
      return self.pollUpdates();
    });
  };

  App.prototype.updateMessage = function (text) {
    var node = this.$("update-action");
    if (node) { node.textContent = text; node.hidden = !text; }
  };

  App.prototype.pollUpdates = function () {
    var self = this;
    if (this.doc.hidden || this.updateInflight || !this.$("updates-body")) return Promise.resolve();
    /* Без автообновления опрашивать раз в минуту, а не на каждом шаге панели. */
    if (this.updaterAbsent && !this.updatePending && Date.now() - (this.updaterAbsentAt || 0) < 60000) return Promise.resolve();
    this.updateInflight = true;
    return this.updateRequest("/api/update").then(function (reply) {
      if (!reply.ok) throw new Error("HTTP " + reply.code);
      var s = reply.data, pending = self.updatePending;
      self.updaterAbsent = !!s.absent;
      if (self.updaterAbsent) self.updaterAbsentAt = Date.now();
      self.updateFailed = false;
      self.updateStatus = s;
      /* Команда завершена, когда служба снова свободна и состояние новее нажатия
         (установка — когда записан её итог). Тумблер завершается сразу. */
      if (pending && !s.busy) {
        var since = Math.floor(pending.at / 1000) - 5;
        var done = pending.action === "install" ? num(s.last_utc) >= since :
          pending.action === "check" ? num(s.checked_utc) >= since : true;
        if (done || Date.now() - pending.at > 15 * 60000) self.updatePending = null;
      }
      self.renderUpdates(s);
    }).catch(function () {
      self.updateFailed = true;
      self.renderUpdates(self.updateStatus);
    }).finally(function () { self.updateInflight = false; });
  };

  App.prototype.renderUpdates = function (status) {
    if (!this.$("updates-body")) return;
    if (status) this.updateStatus = status;
    var self = this, s = status || {}, pending = this.updatePending;
    var absent = !!s.absent, latest = s.latest || null, current = str(s.current);
    var busy = str(s.busy), action = busy === "installing" ? "install" : busy === "checking" ? "check" : pending && pending.action;
    var newer = latest && latest.release_id && latest.release_id !== current;
    var failedInstall = s.last_ok === false && num(s.last_utc) > 0 && str(s.last_release) && num(s.last_utc) >= num(s.checked_utc) - 5;
    var tone = "", reason = "", text;
    if (absent) { text = "Автообновление не подключено"; reason = "Эта установка обновляется командой установки."; }
    else if (action === "install" || action === "check") text = UPDATE_ACTIONS[action];
    else if (this.updateFailed && !s.current && !s.never && !latest) { text = "Нет связи с панелью"; tone = "warn"; }
    else if (s.never) text = "Обновления ещё не проверялись";
    else if (failedInstall) { text = "Не удалось установить обновление"; tone = "warn"; reason = str(s.last_message); }
    else if (s.check_ok === false) { text = "Не удалось проверить обновления"; tone = "warn"; reason = str(s.check_error); }
    else if (newer) text = "Доступна версия " + (str(latest.version) || latest.release_id);
    else text = "Установлена последняя версия";
    function write(id, value) { var node = self.$(id); if (node.textContent !== value) node.textContent = value; return node; }
    var body = this.$("updates-body");
    if (body.setAttribute) body.setAttribute("data-mode", absent ? "absent" : "ready");
    write("update-current", absent ? "без автообновления" : current || "не определена");
    var state = this.$("update-state"), changed = state.textContent !== text;
    write("update-state", text);
    if (state.parentElement) state.parentElement.setAttribute("data-tone", tone);
    var lamp = this.$("update-lamp");
    if (lamp) lamp.setAttribute("data-tone", tone || (!absent && !action && s.check_ok === true && !newer ? "ok" : "idle"));
    if (changed && !this.doc.hidden && Motion.on()) {
      Motion.g.killTweensOf(state);
      Motion.g.fromTo(state, { opacity: .55, y: 3 }, { opacity: 1, y: 0, duration: .2, clearProps: "opacity,transform" });
    }
    write("update-reason", reason).hidden = !reason;
    write("update-checked", num(s.checked_utc) > 0 ? "проверено " + localTime(num(s.checked_utc) * 1000) : "проверки ещё не было");
    this.$("update-release").hidden = !newer;
    write("update-version", newer ? "Что изменилось в " + (str(latest.version) || latest.release_id) : "");
    write("update-notes-text", str(latest && latest.notes) || "Описание изменений не опубликовано.");
    var install = this.$("update-install");
    install.hidden = !newer;
    install.disabled = !!action || absent;
    write("update-install", newer && str(latest.release_id) === str(s.bad_release) ? "Повторить установку вручную" : "Установить сейчас");
    this.$("update-check").disabled = !!action || absent;
    this.$("update-check").setAttribute("data-variant", "ghost");
    write("update-warning", newer ? "Службы кратковременно перезапустятся. Закрытие вкладки не отменяет установку." : "").hidden = !newer;
    this.$("update-progress").hidden = true;
    write("update-progress-text", "").hidden = true;
    var auto = this.$("update-auto");
    if (!(pending && /^auto-/.test(pending.action))) auto.checked = s.auto !== false;
    auto.disabled = absent || !!action || !!pending;
    var schedule = absent ? "Станет доступно, когда автообновление будет подключено" :
      "Ставит новые выпуски в 03:00–05:00 по времени роутера" + (s.auto === false ? " · выключено: ночью только проверка" : "");
    write("update-schedule", schedule);
    var result = !absent && num(s.last_utc) > 0 && str(s.last_message) ?
      "Последний результат: " + str(s.last_message) + " · " + localTime(num(s.last_utc) * 1000) : "";
    write("update-result", result).hidden = !result;
    var nav = write("nav-updates", absent ? "" : newer ? "новая" : action ? "…" : tone ? "!" : "");
    nav.setAttribute("data-tone", tone || "idle");
  };

  App.prototype.serverNow = function () {
    var taken = this.status && parseTime(this.status.snapshot && this.status.snapshot.taken);
    return taken ? taken + (Date.now() - this.received) : Date.now();
  };

  var CONTROL_RESULT = {
    done: { tone: "ok", text: "Команда службы выполнена." },
    failed: { tone: "bad", text: "Команда службы завершилась ошибкой." },
    timeout: { tone: "bad", text: "Команда службы не завершилась вовремя и была прервана." }
  };

  App.prototype.render = function () {
    var m = model(this.status, this.received, Date.now());
    var cs = str(m.snap.control_state);
    if (this.lastControl === "running" && CONTROL_RESULT[cs]) {
      this.flash = { tone: CONTROL_RESULT[cs].tone, text: CONTROL_RESULT[cs].text, what: this.lastAction || "", at: Date.now() };
    }
    this.lastControl = cs;
    this.m = m;
    this.renderMast(m);
    this.renderNotice();
    this.renderNow(m);
    this.renderCatalog(false);
    this.renderTelegram(m);
    this.renderDiagnostics(m);
    this.renderNav(m);
    if (!this.arrived) {
      this.arrived = true;
      if (Motion.on()) {
        var d = this.doc;
        var rows = [].slice.call(d.querySelectorAll("#searches > li")).slice(0, 4);
        Motion.g.timeline({ defaults: { ease: "power4.out", clearProps: "transform,opacity,visibility" } })
          .from("#now-title", { y: 36, autoAlpha: 0, duration: 0.7 })
          .from("#now-lede", { y: 16, autoAlpha: 0, duration: 0.55 }, "-=0.5")
          .from(".slot-cell", { scale: 0.3, autoAlpha: 0, duration: 0.4, stagger: 0.05, ease: "back.out(2.4)" }, "-=0.4")
          .from(rows, { y: 24, autoAlpha: 0, duration: 0.6, stagger: 0.08 }, "-=0.35");
      }
    }
  };

  /* ─── Мачта ─── */

  App.prototype.renderMast = function (m) {
    var doc = this.doc;
    var host = this.$("host");
    host.textContent = str(m.snap.panel_listen);
    var state = this.$("engine-state");
    var lamp = state.querySelector(".lamp");
    lamp.setAttribute("data-tone", m.lamp);
    var text = state.querySelector(".mast-state-text");
    /* Живой регион трогаем только при смене текста: иначе диктор повторяет его на каждом опросе. */
    var stateKey = m.state + "|" + m.stateDetail;
    if (text.__d2kKey !== stateKey) {
      text.__d2kKey = stateKey;
      text.replaceChildren(doc.createTextNode(m.state), el(doc, "small", "", m.stateDetail));
    }
    doc.title = (m.hunting ? "● " : "") + "D2K — " + m.state;
    this.renderActions();
  };

  App.prototype.renderActions = function () {
    var self = this, doc = this.doc, m = this.m;
    var box = this.$("engine-actions");
    if (!m) return;
    var snap = m.snap;
    var busy = snap.control_state === "running" || !!this.pending;
    var key = JSON.stringify([snap.controls_enabled, m.engine, busy, this.pending, this.armed, snap.mode]);
    if (box.__d2kKey === key) return;
    box.__d2kKey = key;
    var focused = doc.activeElement && box.contains(doc.activeElement) ? doc.activeElement.getAttribute("data-control") : null;
    var buttons = [];
    if (!snap.controls_enabled) {
      buttons.push(el(doc, "span", "tag", "Управление отключено в конфигурации"));
    } else {
      if (m.engine) {
        if (this.armed === "stop") {
          buttons.push(this.button("stop", "Остановить движок?", "stop", "confirm", busy));
          buttons.push(this.button("cancel", "Отмена", null, "ghost", false));
        } else {
          /* «Очистить подобранное» стоит там, где прежде была «Восстановить
             правила»: правила и без кнопки ставит сторож (S99d2k heal каждые
             60 с), а снять найденное замером руками было нечем. Вариант
             danger, и нажатие само ничего не делает — спрашивает диалог. */
          buttons.push(this.button("clear-found", "Очистить подобранное", "erase", "danger", busy, "Очистить"));
          buttons.push(this.button("restart", "Перезапустить", "restart", null, busy));
          buttons.push(this.button("stop", "Остановить", "stop", "danger", busy));
        }
      } else {
        buttons.push(this.button("start", "Запустить движок", "play", "primary", busy || snap.mode === "off"));
      }
    }
    var flipState = Motion.on() && Motion.Flip && box.children.length ? Motion.Flip.getState(box.children) : null;
    var oldIcons = {};
    for (var oi = 0; oi < box.children.length; oi++) {
      var op = box.children[oi].querySelector && box.children[oi].querySelector("svg path");
      if (op) oldIcons[box.children[oi].getAttribute("data-flip-id")] = op.getAttribute("d");
    }
    box.replaceChildren.apply(box, buttons);
    if (flipState) {
      /* Кнопки перетекают: «Остановить» ↔ «Остановить движок?», «стоп» ↔ «запуск». */
      Motion.track(Motion.Flip.from(flipState, {
        targets: box.children, duration: 0.45, ease: "power3.inOut", scale: false, simple: true,
        onEnter: function (els) { return Motion.g.fromTo(els, { autoAlpha: 0, scale: 0.85 }, { autoAlpha: 1, scale: 1, duration: 0.35, clearProps: "transform,opacity,visibility" }); }
      }));
      if (global.MorphSVGPlugin) {
        for (var ni = 0; ni < box.children.length; ni++) {
          var np = box.children[ni].querySelector && box.children[ni].querySelector("svg path");
          var was = oldIcons[box.children[ni].getAttribute("data-flip-id")];
          if (np && was && was !== np.getAttribute("d")) Motion.g.from(np, { morphSVG: was, duration: 0.5, ease: "power2.inOut" });
        }
      }
    }
    if (focused) {
      var again = box.querySelector('[data-control="' + focused + '"]') || box.querySelector("button");
      if (again) again.focus();
    }
    void self;
  };

  App.prototype.button = function (action, label, iconName, variant, disabled, shortLabel) {
    var self = this, doc = this.doc;
    var b = el(doc, "button", "btn");
    b.type = "button";
    b.setAttribute("data-control", action);
    b.setAttribute("data-flip-id", action === "start" || action === "stop" ? "power" : action);
    if (variant) b.setAttribute("data-variant", variant);
    if (this.pending === action) b.setAttribute("data-busy", "true");
    if (iconName) add(b, icon(doc, this.pending === action ? "restart" : iconName));
    if (shortLabel) {
      add(b, el(doc, "span", "btn-label-long", label));
      b.setAttribute("aria-label", label);
    } else {
      add(b, el(doc, "span", "", label));
    }
    b.setAttribute("aria-label", label);
    b.title = label;
    if (disabled) b.disabled = true;
    b.addEventListener("click", function () { self.act(action); });
    return b;
  };

  var ENDPOINTS = {
    start: "start", stop: "stop", restart: "restart", "clear-found": "clear-found",
    "telegram-enable": "telegram-enable", "telegram-disable": "telegram-disable"
  };

  /* ОПЕРАЦИИ, КОТОРЫЕ СПРАШИВАЮТ ДИАЛОГОМ.
     Второго нажатия кнопки (приём «Остановить движок?») здесь мало: то
     нажатие защищает от промаха, а здесь надо сказать, ЧТО именно исчезнет и
     что обратно это не вернуть. В подпись кнопки такой текст не влезает. */
  var CONFIRM = {
    "clear-found": {
      title: "Очистить подобранное?",
      text: "Это сотрёт всё, что движок подобрал замером: подтверждённые планы, "
          + "привязки имён к адресам и каталог коробок. Восстановить нельзя — "
          + "подбор начнётся с нуля, и на каждый сайт его придётся пройти заново. "
          + "Точно очищаем?",
      yes: "Очистить"
    }
  };

  /* Спрашивает и зовёт done() только на согласие. Нативный <dialog> даёт Esc,
     ::backdrop и ловушку фокуса; где его нет — обычный confirm(), потому что
     необратимая операция обязана спросить ХОТЬ ЧЕМ-ТО, а не пройти молча. */
  App.prototype.ask = function (what, done) {
    var doc = this.doc, dlg = this.$("ask");
    if (!dlg || typeof dlg.showModal !== "function") {
      if (this.win.confirm(what.title + "\n\n" + what.text)) done();
      return;
    }
    var title = this.$("ask-title"), text = this.$("ask-text");
    if (title) title.textContent = what.title;
    if (text) text.textContent = what.text;
    var yes = dlg.querySelector('[data-ask="yes"]');
    var no = dlg.querySelector('[data-ask="no"]');
    if (yes) yes.replaceChildren(doc.createTextNode(what.yes));
    var agreed = false;
    function close() { agreed = false; dlg.close(); }
    function accept() { agreed = true; dlg.close(); }
    /* Слушатели снимаются на закрытии: диалог один на все операции, и
       оставленный слушатель применил бы прошлое согласие к новой. */
    function onClose() {
      if (yes) yes.removeEventListener("click", accept);
      if (no) no.removeEventListener("click", close);
      dlg.removeEventListener("close", onClose);
      if (agreed) done();
    }
    if (yes) yes.addEventListener("click", accept);
    if (no) no.addEventListener("click", close);
    dlg.addEventListener("close", onClose);
    dlg.showModal();
    if (no && no.focus) no.focus();   /* фокус на отказе, не на необратимом */
  };

  function normalizeWorkerInput(value) {
    var domain = str(value).trim().toLowerCase();
    if (!domain || domain.length > 253) return null;
    var labels = domain.split("."), tld = labels[labels.length - 1];
    if (labels.length < 2 || tld.length < 2 || !/[a-z]/.test(tld)) return null;
    for (var i = 0; i < labels.length; i++) {
      if (labels[i].length < 1 || labels[i].length > 63 ||
          !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(labels[i])) return null;
    }
    return domain;
  }

  App.prototype.renderWorkerDialog = function () {
    var dialog = this.workerDialog;
    if (!dialog) return;
    var listNode = dialog.querySelector("[data-worker-list]");
    var input = dialog.querySelector("[data-worker-input]");
    var addButton = dialog.querySelector("[data-worker-add]");
    var saveButton = dialog.querySelector("[data-worker-save]");
    var note = dialog.querySelector("[data-worker-note]");
    var editable = !!(this.m && this.m.snap.controls_enabled) && !this.pending;
    input.disabled = !editable || this.workerDomains.length >= 8;
    addButton.disabled = !editable || this.workerDomains.length >= 8;
    saveButton.disabled = !editable;
    listNode.replaceChildren();
    if (!this.workerDomains.length) {
      listNode.appendChild(el(this.doc, "li", "tg-worker-empty", "Пока нет добавленных доменов"));
    }
    var self = this;
    this.workerDomains.forEach(function (domain, index) {
      var row = el(self.doc, "li", "tg-worker-row");
      var name = el(self.doc, "span", "", domain);
      var remove = el(self.doc, "button", "tg-worker-remove", "Удалить");
      remove.type = "button";
      remove.disabled = !editable;
      remove.setAttribute("aria-label", "Удалить " + domain);
      remove.addEventListener("click", function () {
        self.workerDomains.splice(index, 1);
        self.renderWorkerDialog();
      });
      row.append(name, remove);
      listNode.appendChild(row);
    });
    if (note) {
      note.textContent = this.m && !this.m.snap.controls_enabled
        ? "Управление отключено в конфигурации. Список доступен только для просмотра."
        : this.workerDomains.length >= 8 ? "Добавлено 8 из 8 доменов." : "Добавьте hostname Worker без схемы и пути.";
    }
  };

  App.prototype.openTelegramWorkers = function () {
    var self = this, doc = this.doc;
    if (this.pending) return;
    if (!this.workerDialog) {
      var dialog = this.workerDialog = el(doc, "dialog", "tg-worker-dialog");
      dialog.setAttribute("aria-labelledby", "tg-worker-title");
      var heading = el(doc, "h2", "", "Мои Workers");
      heading.id = "tg-worker-title";
      var intro = el(doc, "p", "tg-worker-intro", "Добавьте до 8 доменов Cloudflare Worker. Настройки сохранятся и перезапустят только C11.");
      var listNode = el(doc, "ul", "tg-worker-list");
      listNode.setAttribute("data-worker-list", "");
      var field = el(doc, "label", "tg-worker-field", "Домен Worker");
      var input = el(doc, "input", "");
      input.type = "text";
      input.autocomplete = "url";
      input.spellcheck = false;
      input.placeholder = "my-worker.example.com";
      input.setAttribute("data-worker-input", "");
      field.appendChild(input);
      var addButton = el(doc, "button", "btn", "Добавить домен");
      addButton.type = "button";
      addButton.setAttribute("data-worker-add", "");
      var note = el(doc, "p", "tg-worker-note", "");
      note.setAttribute("data-worker-note", "");
      var message = el(doc, "p", "tg-worker-message", "");
      message.setAttribute("aria-live", "polite");
      var cancel = el(doc, "button", "btn", "Отмена");
      cancel.type = "button";
      var save = el(doc, "button", "btn", "Сохранить");
      save.type = "button";
      save.setAttribute("data-variant", "primary");
      save.setAttribute("data-worker-save", "");
      var footer = el(doc, "div", "tg-worker-footer");
      footer.append(cancel, save);
      dialog.append(heading, intro, listNode, field, addButton, note, message, footer);
      doc.body.appendChild(dialog);
      function addDomain() {
        var domain = normalizeWorkerInput(input.value);
        if (!domain) { message.textContent = "Введите корректный домен, например my-worker.example.com."; return; }
        if (self.workerDomains.indexOf(domain) >= 0) { message.textContent = "Этот домен уже добавлен."; return; }
        if (self.workerDomains.length >= 8) { message.textContent = "Можно добавить не больше 8 доменов."; return; }
        self.workerDomains.push(domain);
        input.value = "";
        message.textContent = "";
        self.renderWorkerDialog();
        input.focus();
      }
      addButton.addEventListener("click", addDomain);
      input.addEventListener("keydown", function (event) {
        if (event.key === "Enter") { event.preventDefault(); addDomain(); }
      });
      cancel.addEventListener("click", function () { dialog.close(); });
      save.addEventListener("click", function () { self.saveTelegramWorkers(message); });
    }
    var dialog = this.workerDialog;
    var message = dialog.querySelector(".tg-worker-message");
    message.textContent = "Загружаем список…";
    if (typeof dialog.showModal === "function") dialog.showModal();
    this.win.fetch("/api/telegram/workers", { cache: "no-store" })
      .then(function (reply) {
        return reply.json().then(function (body) {
          if (!reply.ok || !Array.isArray(body.domains)) throw new Error(body.message || "Не удалось загрузить домены");
          self.workerDomains = body.domains.slice(0, 8);
          message.textContent = "";
          self.renderWorkerDialog();
        });
      })
      .catch(function (error) { message.textContent = str(error && error.message) || "Не удалось загрузить список Workers."; });
  };

  App.prototype.saveTelegramWorkers = function (message) {
    var self = this;
    if (this.pending || !(this.m && this.m.snap.controls_enabled)) return;
    this.pending = "telegram-workers";
    this.renderTelegram(this.m, true);
    this.renderWorkerDialog();
    this.win.fetch("/api/telegram/workers", {
      method: "POST", cache: "no-store", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domains: this.workerDomains })
    }).then(function (reply) {
      return reply.json().catch(function () { return {}; }).then(function (body) {
        if (!reply.ok) throw new Error(str(body.message) || "Не удалось сохранить Workers.");
        self.workerDialog.close();
        self.flash = { tone: "info", text: str(body.message) || "Настройки Workers сохранены.", at: Date.now() };
      });
    }).catch(function (error) {
      message.textContent = str(error && error.message) || "Не удалось сохранить список Workers.";
    }).then(function () {
      self.pending = null;
      self.renderTelegram(self.m, true);
      self.renderWorkerDialog();
      self.renderNotice();
      self.poll();
      self.win.setTimeout(function () { self.poll(); }, 800);
    });
  };

  /* Неудавшаяся команда — короткое покачивание её кнопки рядом с текстом ошибки. */
  App.prototype.shake = function (action) {
    if (!Motion.on()) return;
    var b = this.doc.querySelector('[data-control="' + action + '"]');
    if (b) Motion.g.fromTo(b, { x: 0 }, { x: 7, duration: 0.6, ease: global.CustomWiggle ? "d2kShake" : "power1.inOut", clearProps: "transform" });
  };

  App.prototype.act = function (action, confirmed) {
    var self = this;
    if (action === "telegram-workers") { this.openTelegramWorkers(); return; }
    if (action === "cancel") { this.armed = null; this.renderActions(); return; }
    if (CONFIRM[action] && !confirmed) {
      if (this.pending) return;
      this.ask(CONFIRM[action], function () { self.act(action, true); });
      return;
    }
    if (action === "stop" && this.armed !== "stop") {
      this.armed = "stop";
      this.renderActions();
      this.win.setTimeout(function () { if (self.armed === "stop") { self.armed = null; self.renderActions(); } }, 6000);
      return;
    }
    this.armed = null;
    if (!ENDPOINTS[action] || this.pending) return;
    this.pending = action;
    this.renderActions();
    this.renderTelegram(this.m, true);
    this.win.fetch("/api/control/" + ENDPOINTS[action], { method: "POST", cache: "no-store" })
      .then(function (r) {
        return r.json().catch(function () { return {}; }).then(function (body) {
          if (body.action) self.lastAction = str(body.action);
          if (!r.ok) self.shake(action);
          self.flash = {
            tone: r.ok ? "info" : "bad",
            text: str(body.message) || (r.ok ? "Команда принята" : "Команда не выполнена (HTTP " + r.status + ")"),
            what: str(body.action),
            at: Date.now()
          };
        });
      })
      .catch(function () {
        self.shake(action);
        self.flash = { tone: "bad", text: "Панель не ответила на команду. Состояние ниже — последнее полученное.", at: Date.now() };
      })
      .then(function () {
        self.pending = null;
        self.renderNotice();
        self.poll();
        self.win.setTimeout(function () { self.poll(); }, 800);
      });
  };

  /* ─── Уведомление ─── */

  App.prototype.renderNotice = function () {
    var doc = this.doc, n = this.$("notice");
    var parts = null, tone = null;
    var now = Date.now();
    var stale = this.lastOk && now - this.lastOk > STALE_MS;
    doc.body.setAttribute("data-stale", String(!!(this.failed && (stale || !this.lastOk))));
    if (this.failed && !this.lastOk) {
      tone = "bad"; parts = [el(doc, "b", "", "Панель не получает состояние."), " Повторяем запрос каждые две секунды."];
    } else if (this.failed && stale) {
      tone = "bad";
      parts = [el(doc, "b", "", "Нет ответа от панели."), " Показан снимок, полученный " + ago(now - this.lastOk) + "."];
    } else if (this.m && this.m.snap.control_state === "running" && !(this.flash && now - this.flash.at < 1500)) {
      tone = "info"; parts = [el(doc, "b", "", "Выполняется команда службы."), " Управление станет доступно, когда она завершится."];
    } else if (this.flash && now - this.flash.at < 8000) {
      tone = this.flash.tone;
      parts = [this.flash.what ? el(doc, "b", "", this.flash.what + ".") : null, " " + this.flash.text];
    } else if (this.m && this.m.snap.preview) {
      tone = "info"; parts = [el(doc, "b", "", "Демонстрационные данные."), " Это локальный стенд, а не роутер."];
    } else if (this.m && this.m.engine && !this.m.fresh) {
      tone = "warn"; parts = [el(doc, "b", "", "Снимок движка устарел."), " Движок давно не обновлял состояние; цифры ниже могут быть не текущими."];
    }
    if (!parts) {
      if (n.hidden || n.__closing) return;
      if (Motion.on()) {
        n.__closing = true;
        Motion.g.to(n, { height: 0, paddingTop: 0, paddingBottom: 0, autoAlpha: 0, duration: 0.3, ease: "power2.in", onComplete: function () {
          n.__closing = false; n.hidden = true; n.replaceChildren(); Motion.g.set(n, { clearProps: "all" });
        } });
      } else { n.hidden = true; n.replaceChildren(); }
      return;
    }
    var key = tone + "|" + parts.map(function (x) { return x && x.textContent !== undefined ? x.textContent : String(x); }).join("");
    if (key === n.__d2kKey && !n.hidden && !n.__closing) return;
    n.__d2kKey = key;
    var appearing = n.hidden || n.__closing;
    if (n.__closing) { Motion.g.killTweensOf(n); n.__closing = false; Motion.g.set(n, { clearProps: "all" }); }
    n.hidden = false;
    n.setAttribute("data-tone", tone);
    n.replaceChildren();
    add.apply(null, [n].concat(parts));
    if (appearing && Motion.on()) Motion.g.from(n, { height: 0, paddingTop: 0, paddingBottom: 0, autoAlpha: 0, duration: 0.4, clearProps: "all" });
  };

  /* ─── Сейчас ─── */

  App.prototype.renderNow = function (m) {
    var doc = this.doc;
    var title = this.$("now-title");
    var h = JSON.stringify(m.headline);
    if (title.__d2kKey !== h) {
      var prev = title.__d2kHeadline;
      title.__d2kKey = h;
      title.__d2kHeadline = m.headline;
      var apply = function () { title.replaceChildren(doc.createTextNode(m.headline[0]), el(doc, "em", "", m.headline[1])); };
      var from = prev && /^(\d+) /.exec(prev[1]), to = /^(\d+) /.exec(m.headline[1]);
      if (!prev || !Motion.on()) {
        apply();
      } else if (from && to && prev[0] === m.headline[0]) {
        /* Тот же заголовок, другое число: число прокручивается. */
        apply();
        var em = title.lastChild, n = { v: +from[1] };
        Motion.g.to(n, { v: +to[1], duration: 0.6, ease: "power2.out", onUpdate: function () {
          var v = Math.round(n.v);
          em.textContent = count(v, "поиск", "поиска", "поисков");
        } });
        Motion.g.fromTo(em, { y: -6 }, { y: 0, duration: 0.5, ease: "back.out(3)" });
      } else {
        /* Новая фраза собирается по буквам; разбиение снимается по окончании. */
        Motion.g.timeline()
          .to(title, { y: -14, autoAlpha: 0, duration: 0.18, ease: "power2.in" })
          .add(function () {
            apply();
            Motion.g.set(title, { y: 0, autoAlpha: 1 });
            if (!global.SplitText) { Motion.g.from(title, { y: 22, autoAlpha: 0, duration: 0.5, clearProps: "all" }); return; }
            var split = new global.SplitText(title, { type: "words,chars" });
            Motion.g.from(split.chars, { yPercent: 70, autoAlpha: 0, rotation: 4, duration: 0.55, stagger: 0.018, ease: "power4.out",
              onComplete: function () { split.revert(); Motion.g.set(title, { clearProps: "all" }); } });
          });
      }
    }
    title.setAttribute("data-tone", m.tone);
    this.$("now-lede").textContent = m.lede;

    var slots = this.$("slots");
    var meas = m.k.measurements;
    var wasActive = slots.__d2kActive;
    var rebuilt = section(slots, JSON.stringify([m.linked, meas, m.k.targets, m.k.confirms, m.k.probes_used, m.k.client_unfit, m.groups.length, m.boxes.length]), function () {
      var out = [];
      if (m.linked && meas && num(meas.limit)) {
        var sv = slotsView(meas);
        var row = el(doc, "div", "slot-row");
        row.title = sv.note;
        if (sv.kind === "cells") {
          var cells = el(doc, "div", "slot-cells");
          cells.setAttribute("aria-hidden", "true");
          for (var i = 0; i < sv.limit; i++) {
            var c = el(doc, "span", "slot-cell");
            c.setAttribute("data-on", String(i < sv.active));
            cells.appendChild(c);
          }
          row.appendChild(cells);
        } else {
          /* Десятки замеров клетками не нарисовать честно — шкала с долей занятых. */
          var bar = el(doc, "span", "slot-bar");
          bar.setAttribute("aria-hidden", "true");
          var fill = el(doc, "span", "slot-bar-fill");
          fill.style.setProperty("--share", String(sv.active / sv.limit));
          bar.appendChild(fill);
          row.appendChild(bar);
        }
        add(row, el(doc, "span", "", "Замеры: " + sv.active + " из " + sv.limit +
          (sv.queued ? ", в очереди " + sv.queued : "")), el(doc, "small", "slot-note", sv.short));
        out.push(row);
        if (num(meas.free_pct) !== null) {
          out.push(el(doc, "span", "", "Свободно процессора " + meas.free_pct + "%" +
            (num(meas.cores) ? " на " + count(meas.cores, "ядре", "ядрах", "ядрах") : "")));
        }
      }
      if (m.linked) {
        var facts = el(doc, "span", "");
        add(facts,
          el(doc, "b", "", String(num(m.k.confirms) || 0)), " " + plural(num(m.k.confirms) || 0, "подтверждение", "подтверждения", "подтверждений") + ", ",
          el(doc, "b", "", String(num(m.k.probes_used) || 0)), " " + plural(num(m.k.probes_used) || 0, "зонд", "зонда", "зондов") + " за работу движка");
        out.push(facts);
        if (num(m.k.client_unfit)) {
          var unfit = el(doc, "span", "");
          add(unfit, tag(doc, "план не подошёл клиенту: " + m.k.client_unfit, "warn"));
          out.push(unfit);
        }
      }
      return out;
    });
    var nowActive = meas && num(meas.active) !== null ? meas.active : null;
    if (rebuilt && Motion.on() && wasActive !== undefined && nowActive !== null && nowActive !== wasActive) {
      var cellsNow = slots.querySelectorAll(".slot-cell");
      var lit = [], dim = [];
      for (var ci = 0; ci < cellsNow.length; ci++) {
        if (ci >= Math.min(wasActive || 0, nowActive) && ci < Math.max(wasActive || 0, nowActive)) (ci < nowActive ? lit : dim).push(cellsNow[ci]);
      }
      if (lit.length) Motion.g.from(lit, { scale: 0.2, autoAlpha: 0, duration: 0.45, stagger: 0.07, ease: "back.out(2.4)", clearProps: "all" });
      if (dim.length) {
        var sig = global.getComputedStyle(doc.documentElement).getPropertyValue("--signal").trim();
        Motion.g.from(dim, { backgroundColor: sig, duration: 0.6, ease: "power2.out", clearProps: "all" });
      }
    }
    slots.__d2kActive = nowActive === null ? undefined : nowActive;

    this.renderSearches(m);
  };

  App.prototype.renderSearches = function (m) {
    var doc = this.doc, self = this;
    var listNode = this.$("searches");
    if (!m.linked || !m.engine) {
      section(listNode, "absent:" + m.engine + ":" + m.linked, function () {
        var li = el(doc, "li", "quiet");
        add(li, el(doc, "b", "", "Поиски не измеряются."), m.engine
          ? " Контроллер не подключён к датапату, поэтому список поисков недоступен."
          : " Движок остановлен.");
        return [li];
      });
      return;
    }
    if (!m.searches.length) {
      section(listNode, "none", function () {
        var li = el(doc, "li", "quiet");
        add(li, el(doc, "b", "", "Рабочий прямой трафик подбор не запускает"),
          " — он начинается только после подтверждённой блокировки, а найденное решение сохраняется в каталоге ниже.");
        return [li];
      });
      return;
    }
    if (listNode.__d2kKey === "none" || (listNode.__d2kKey && listNode.__d2kKey.indexOf("absent:") === 0)) {
      listNode.replaceChildren();
    }
    var firstLive = listNode.__d2kKey !== "live";
    listNode.__d2kKey = "live";
    var animate = Motion.on() && Motion.Flip;
    var stable = [];
    for (var si = 0; si < listNode.children.length; si++) if (!listNode.children[si].__leaving) stable.push(listNode.children[si]);
    var wantKeys = m.running.map(function (x) { return JSON.stringify([x.target, x.family, x.transport, x.ip, x.port]); });
    if (m.queued.length) wantKeys.push("queue");
    var haveKeys = stable.map(function (r) { return r.__d2kKey; });
    var flipState = animate && stable.length && wantKeys.join("\n") !== haveKeys.join("\n") ? Motion.Flip.getState(stable) : null;
    if (flipState) stable.forEach(function (r) { r.__oldTop = r.getBoundingClientRect().top; });
    var entered = [], moved = false;

    var keep = {};
    m.running.forEach(function (s, index) {
      var key = JSON.stringify([s.target, s.family, s.transport, s.ip, s.port]);
      keep[key] = true;
      var row = null;
      for (var i = 0; i < listNode.children.length; i++) {
        if (listNode.children[i].__d2kKey === key) { row = listNode.children[i]; break; }
      }
      if (!row) {
        row = self.searchRow(s);
        row.__d2kKey = key;
        entered.push(row);
      }
      self.updateSearch(row, s);
      if (listNode.children[index] !== row) { listNode.insertBefore(row, listNode.children[index] || null); moved = true; }
    });
    var queue = null;
    for (var q = 0; q < listNode.children.length; q++) if (listNode.children[q].__d2kKey === "queue") queue = listNode.children[q];
    if (m.queued.length) {
      if (!queue) { queue = el(doc, "li", "queue"); queue.__d2kKey = "queue"; }
      keep.queue = true;
      this.updateQueue(queue, m.queued);
      if (listNode.lastChild !== queue) { listNode.appendChild(queue); moved = true; }
    }
    var leaving = [];
    for (var j = listNode.children.length - 1; j >= 0; j--) {
      var gone = listNode.children[j];
      if (keep[gone.__d2kKey] || gone.__leaving) continue;
      if (animate) leaving.push(gone); else listNode.removeChild(gone);
    }
    if (!animate) return;
    if (!entered.length && !leaving.length && !moved) return;
    /* Ушедшая строка уезжает и гаснет; остальные плавно занимают её место. */
    leaving.forEach(function (row) {
      row.__leaving = true;
      var done = row.getAttribute("data-done") === "true";
      Motion.g.timeline({ onComplete: function () {
        var rest = [];
        for (var k = 0; k < listNode.children.length; k++) if (listNode.children[k] !== row && !listNode.children[k].__leaving) rest.push(listNode.children[k]);
        var st = rest.length ? Motion.Flip.getState(rest) : null;
        if (row.parentNode) row.parentNode.removeChild(row);
        if (st) Motion.track(Motion.Flip.from(st, { duration: 0.5, ease: "power3.inOut", scale: true, simple: true }));
      } })
        .to(row, { x: done ? 0 : 36, y: done ? 18 : 0, autoAlpha: 0, duration: 0.4, ease: "power2.in" });
    });
    if (flipState) {
      /* Переставляемые строки «приподнимаются» и проезжают поверх соседних, не сквозь них. */
      var movers = stable.filter(function (r) { return !r.__leaving; });
      movers.forEach(function (r) { r.__goesUp = r.getBoundingClientRect().top < r.__oldTop - 1; });
      Motion.track(Motion.Flip.from(flipState, {
        duration: 0.6, ease: "power3.inOut", scale: true, simple: true, targets: movers,
        onStart: function () { movers.forEach(function (r) { r.classList.add("is-moving"); r.style.zIndex = r.__goesUp ? 3 : 2; }); },
        onComplete: function () { movers.forEach(function (r) { r.classList.remove("is-moving"); r.style.zIndex = ""; }); }
      }));
    }
    if (entered.length && !firstLive) {
      Motion.g.fromTo(entered, { y: 28, autoAlpha: 0 }, { y: 0, autoAlpha: 1, duration: 0.6, stagger: 0.08, ease: "power4.out", clearProps: "transform,opacity,visibility" });
    }
  };

  App.prototype.updateQueue = function (li, queued) {
    var doc = this.doc, self = this;
    var key = JSON.stringify(queued.map(function (s) { return [s.target, s.family, s.transport, s.ip, s.port, s.since]; }));
    if (li.__d2kData !== key) {
      li.__d2kData = key;
      var head = el(doc, "p", "queue-head");
      add(head, el(doc, "b", "", "Ждут свободного слота замера: " + queued.length),
        " — замеры идут не больше, чем позволяет свободный процессор.");
      var ul = el(doc, "ul", "queue-list");
      queued.forEach(function (s) {
        var row = el(doc, "li");
        var wait = el(doc, "span", "queue-wait");
        wait.__since = parseTime(s.since);
        add(row, el(doc, "span", "queue-target", targetLabel(s.target)),
          tag(doc, shapeLabel(s.shape, s.transport)), tag(doc, familyLabel(s.family)), wait);
        ul.appendChild(row);
      });
      li.replaceChildren(head, ul);
    }
    var waits = li.querySelectorAll(".queue-wait");
    var now = this.serverNow();
    for (var i = 0; i < waits.length; i++) waits[i].textContent = waits[i].__since ? "ждёт " + clock(now - waits[i].__since) : "";
    void self;
  };

  App.prototype.searchRow = function (s) {
    var doc = this.doc;
    var li = el(doc, "li", "search");
    li.__parts = {
      target: el(doc, "h2", "search-target"),
      meta: el(doc, "div", "search-meta"),
      clock: el(doc, "div", "search-clock"),
      phase: el(doc, "p", "search-phase"),
      question: el(doc, "p", "search-question"),
      track: el(doc, "div", "track")
    };
    li.__parts.track.setAttribute("aria-hidden", "true");
    li.__parts.fill = el(doc, "span", "track-fill");
    li.__parts.puck = el(doc, "span", "track-puck");
    li.__parts.question.hidden = true;
    add(li, li.__parts.target, li.__parts.clock, li.__parts.meta, li.__parts.phase, li.__parts.question, li.__parts.track);
    void s;
    return li;
  };

  App.prototype.updateSearch = function (li, s) {
    var doc = this.doc, p = li.__parts;
    p.target.textContent = targetLabel(s.target);
    var metaKey = JSON.stringify([s.shape, s.transport, s.family, s.ip, s.port, s.source, s.attempts, s.probes]);
    if (p.meta.__d2kKey !== metaKey) {
      p.meta.__d2kKey = metaKey;
      var addr = s.ip ? (s.family === 6 ? "[" + s.ip + "]" : s.ip) + (s.port ? ":" + s.port : "") : "";
      p.meta.replaceChildren();
      add(p.meta,
        tag(doc, shapeLabel(s.shape, s.transport)),
        tag(doc, familyLabel(s.family)),
        addr ? el(doc, "span", "mono", addr) : null,
        s.source ? el(doc, "span", "", s.source) : null);
    }
    li.__since = parseTime(s.since);
    var counters = [];
    if (num(s.attempts)) counters.push(count(s.attempts, "план", "плана", "планов"));
    if (num(s.probes)) counters.push(count(s.probes, "зонд", "зонда", "зондов"));
    li.__counters = counters.join(" · ");
    this.updateClock(li);

    var phase = str(s.phase) || "этап не указан";
    var phaseText = phase.charAt(0).toUpperCase() + phase.slice(1) + (s.candidate ? " — " + s.candidate : "");
    if (p.phase.textContent !== phaseText) {
      if (p.phase.textContent && Motion.on()) {
        Motion.g.timeline()
          .to(p.phase, { y: -8, autoAlpha: 0, duration: 0.16, ease: "power2.in" })
          .add(function () { p.phase.textContent = phaseText; })
          .fromTo(p.phase, { y: 10, autoAlpha: 0 }, { y: 0, autoAlpha: 1, duration: 0.45, ease: "power3.out", clearProps: "transform,opacity,visibility" });
      } else {
        p.phase.textContent = phaseText;
      }
    }
    var classifying = s.phase === TRACK[2].phases[0] && !!str(s.question);
    p.question.hidden = !classifying;
    var qText = classifying ? "Вопрос коробке: " + str(s.question) : "";
    if (p.question.textContent !== qText) p.question.textContent = qText;
    var tr = trackFor(s.phase);
    li.setAttribute("data-done", String(!!tr && !tr.voice && tr.at === TRACK.length - 1));
    if (!tr) { p.track.hidden = true; return; }
    p.track.hidden = false;
    var trackKey = (tr.voice ? "v" : "t");
    if (p.track.__d2kKey !== trackKey) {
      p.track.__d2kKey = trackKey;
      p.track.replaceChildren(p.fill, p.puck);
      tr.steps.forEach(function (step) { p.track.appendChild(el(doc, "span", "track-step", step.label)); });
      p.track.style.setProperty("--steps", String(tr.steps.length));
    }
    var steps = p.track.querySelectorAll(".track-step");
    var paint = function (cur, target) {
      for (var i = 0; i < steps.length; i++) {
        steps[i].setAttribute("data-state", i === target && cur >= target - 0.02 ? "now" : i < cur + 0.02 ? "past" : "next");
      }
    };
    var oldAt = p.track.__d2kAt;
    p.track.__d2kAt = tr.at;
    if (p.track.__tween) p.track.__tween.kill();
    if (oldAt !== undefined && oldAt !== tr.at && Motion.on()) {
      /* Маркер переезжает к новому этапу; точки загораются, когда он их проходит. */
      var pos = { at: oldAt };
      p.track.__tween = Motion.g.to(pos, { at: tr.at, duration: 0.9, ease: "power3.inOut", onUpdate: function () {
        p.track.style.setProperty("--at", String(pos.at));
        paint(pos.at, tr.at);
      } });
      Motion.g.fromTo(p.puck, { scale: 1 }, { scale: 1.7, duration: 0.22, delay: 0.75, yoyo: true, repeat: 1, ease: "power2.out" });
    } else {
      p.track.style.setProperty("--at", String(tr.at));
      paint(tr.at, tr.at);
    }
  };

  App.prototype.updateClock = function (li) {
    var doc = this.doc, p = li.__parts;
    var text = li.__since ? clock(this.serverNow() - li.__since) : "—";
    if (!p.clock.firstChild) add(p.clock, el(doc, "strong"), el(doc, "span"));
    p.clock.firstChild.textContent = text;
    p.clock.firstChild.title = li.__since ? "С " + localTime(li.__since) : "";
    p.clock.lastChild.textContent = li.__counters || "идёт";
  };

  App.prototype.tick = function () {
    var rows = this.$("searches").children;
    for (var i = 0; i < rows.length; i++) {
      if (rows[i].__parts) this.updateClock(rows[i]);
      else if (rows[i].__d2kKey === "queue") this.updateQueue(rows[i], this.m ? this.m.queued : []);
    }
    this.renderNotice();
  };

  /* ─── Каталог: семейства и коробки ─── */

  App.prototype.matches = function (text) {
    return !this.filter || normName(text).indexOf(this.filter) >= 0;
  };

  App.prototype.renderCatalog = function (force) {
    var m = this.m;
    if (!m) return;
    var key = JSON.stringify([this.filter, m.linked, m.k.catalog_at, m.groups, m.boxes, this.status.snapshot.catalog_available]);
    if (!force && key === this.catalogKey) return;
    this.catalogKey = key;
    var self = this;
    var famBody = this.$("families-body"), famKey = famBody.__d2kKey;
    this.renderFamilies(m);
    if (famBody.__d2kKey !== famKey && !force) this.swingTags();
    if (this.renderBoxes(m) === false) this.catalogKey = null;
    var families = m.groups.filter(function (g) { return self.familyMatches(g); }).length;
    var bindings = 0;
    m.boxes.forEach(function (b) { list(b.bindings).forEach(function (bd) { if (self.matches(bd.target)) bindings++; }); });
    var c = this.$("filter-count");
    c.textContent = this.filter
      ? "Найдено: " + count(families, "семейство", "семейства", "семейств") + ", " + count(bindings, "цель", "цели", "целей")
      : "";
  };

  App.prototype.familyMatches = function (g) {
    var self = this;
    return this.matches(g.suffix) || list(g.evidence).some(function (e) { return self.matches(e); });
  };

  App.prototype.renderFamilies = function (m) {
    var doc = this.doc, self = this;
    var body = this.$("families-body");
    section(body, JSON.stringify([this.filter, m.linked, m.groups]), function () {
      var groups = m.groups.filter(function (g) { return self.familyMatches(g); });
      if (!m.groups.length) {
        var e = el(doc, "p", "empty");
        add(e, el(doc, "b", "", "Семейств пока нет. "),
          "Они появляются, когда один и тот же обход подтверждается на нескольких доменах одного суффикса.");
        return [e];
      }
      if (!groups.length) return [el(doc, "p", "empty", "Ни одно семейство не подходит под запрос.")];
      /* Семейство — бирка на общей струне: суффикс, контекст протокола, штамп
         применения, дерево доменов-доказательств, исключения и коробки с этим планом. */
      var rail = el(doc, "div", "tag-rail");
      groups.forEach(function (g, gi) {
        var active = !!(m.linked && g.active);
        var wrap = el(doc, "div", "ftag-wrap");
        wrap.setAttribute("data-flip-id", "fam:" + JSON.stringify([g.suffix, g.family, g.transport, g.shape, g.probe_path || "/", g.ech_origin || ""]));
        wrap.setAttribute("data-active", String(active));
        var swing = el(doc, "div", "ftag-swing");
        swing.appendChild(el(doc, "span", "ftag-string"));
        wrap.appendChild(swing);
        var card = el(doc, "article", "ftag");
        card.appendChild(el(doc, "span", "ftag-eyelet"));
        var name = el(doc, "h3", "ftag-name");
        add(name, el(doc, "span", "", "*."), str(g.suffix));
        var ctx = el(doc, "div", "ftag-ctx");
        add(ctx, tag(doc, shapeLabel(g.shape, g.transport)), tag(doc, familyLabel(g.family)));
        if (g.ech_origin) ctx.appendChild(tag(doc, "ECH: " + g.ech_origin));
        if (g.probe_path && g.probe_path !== "/") ctx.appendChild(tag(doc, "путь " + g.probe_path));
        var stamp = el(doc, "span", "ftag-stamp", active ? "Применяется" : "Не подтверждено");
        stamp.setAttribute("data-active", String(active));
        if (!active) stamp.title = "Решение сохранено, но применение к семейству сейчас не подтверждено";
        var ev = list(g.evidence);
        /* Отказы узла — по одной строке на узел, с причиной: d2k хранит отказ
           каждого плана отдельно, человеку нужен узел, а не журнал. */
        var dead = [], seen = {};
        list(g.exceptions).forEach(function (x) {
          var nm = str(x && typeof x === "object" ? x.name : x);
          if (!nm || seen[nm]) { if (nm) seen[nm].n++; return; }
          seen[nm] = { name: nm, reason: str(x && x.reason) || "общий план не подошёл", n: 1 };
          dead.push(seen[nm]);
        });
        var fid = wrap.getAttribute("data-flip-id");
        var open = !!self.openTags[fid] || (!!self.filter && !self.matches(g.suffix));
        var regionId = "ftag-more-" + gi;
        var fold = el(doc, "button", "ftag-fold");
        fold.type = "button";
        fold.setAttribute("aria-expanded", String(open));
        fold.setAttribute("aria-controls", regionId);
        var foldText = el(doc, "span", "ftag-fold-text",
          "Подтверждено на " + count(num(g.evidence_count) || ev.length, "домене", "доменах", "доменах"));
        if (dead.length) foldText.appendChild(el(doc, "span", "ftag-fold-dead", " · без плана " + dead.length));
        fold.appendChild(foldText);
        fold.appendChild(foldMark(doc));
        var more = el(doc, "div", "ftag-more");
        more.id = regionId;
        if (!open) more.hidden = true;
        var tree = el(doc, "ul", "ftag-tree");
        ev.forEach(function (d) { tree.appendChild(el(doc, "li", "", d)); });
        dead.forEach(function (x) {
          var li = el(doc, "li", "ex");
          add(li, x.name, el(doc, "small", "", " — " + x.reason.toLowerCase() + (x.n > 1 ? " (планов: " + x.n + ")" : "")));
          tree.appendChild(li);
        });
        more.appendChild(tree);
        fold.addEventListener("click", function () { self.toggleTag(wrap, fold, more, fid); });
        var sub = fold;
        var foot = el(doc, "div", "ftag-foot");
        if (g.plan_id) {
          foot.appendChild(el(doc, "code", "", str(g.plan_id)));
          var owners = [];
          m.boxes.forEach(function (b, bi) {
            if (list(b.plans).some(function (p) { return p.id === g.plan_id; })) owners.push({ id: str(b.id), n: bi + 1 });
          });
          if (owners.length) {
            var links = el(doc, "span", "ftag-boxes", owners.length > 1 ? "план есть в коробках " : "план из коробки ");
            owners.forEach(function (o, oi) {
              if (oi) links.appendChild(doc.createTextNode(" · "));
              var b = el(doc, "button", "ftag-box", String(o.n));
              b.type = "button";
              b.setAttribute("aria-label", "Показать коробку " + o.n);
              b.addEventListener("click", function () { self.showBox(o.id); });
              links.appendChild(b);
            });
            foot.appendChild(links);
          }
        }
        add(card, name, ctx, stamp, sub, more, foot);
        swing.appendChild(card);
        var tilt = ([-1.4, 0.9, -0.5, 1.6, -1.1, 0.4])[gi % 6];
        wrap.style.setProperty("--tilt", tilt + "deg");
        swing.__tilt = tilt;
        if (Motion.on()) {
          /* Наклон, раскачивание и наведение ведёт GSAP — без спора с CSS-переходом. */
          Motion.g.set(swing, { rotation: tilt, transformOrigin: "50% -44px" });
          var straighten = function () { Motion.g.to(swing, { rotation: 0, duration: 0.5, ease: "power3.out", overwrite: "auto" }); };
          var release = function () {
            if (wrap.matches(":hover") || wrap.contains(doc.activeElement)) return;
            Motion.g.to(swing, { rotation: tilt, duration: 1.6, ease: "elastic.out(1, 0.32)", overwrite: "auto" });
          };
          wrap.addEventListener("mouseenter", straighten);
          wrap.addEventListener("mouseleave", release);
          wrap.addEventListener("focusin", straighten);
          wrap.addEventListener("focusout", function () { setTimeout(release, 0); });
        }
        rail.appendChild(wrap);
      });
      var grid = rail;
      return [grid];
    });
  };

  /* Знак раскрытия бирки: рисованная галочка в тон крафта. */
  function foldMark(doc) {
    var s = svgEl(doc, "svg", { viewBox: "0 0 16 16", width: "16", height: "16", "aria-hidden": "true" }, "ftag-fold-mark");
    s.appendChild(svgEl(doc, "path", { d: "M3.5 6 8 10.5 12.5 6" }));
    return s;
  }

  /* Бирка разворачивается как сложенная бумага: лист выходит из-под штампа,
     ветки дерева вырастают по очереди, потяжелевшая бирка качается на нитке.
     Свёртка — та же сцена назад, быстрее; повторный клик разворачивает её на ходу. */
  App.prototype.toggleTag = function (wrap, fold, more, fid) {
    var open = fold.getAttribute("aria-expanded") !== "true";
    fold.setAttribute("aria-expanded", String(open));
    if (open) this.openTags[fid] = true; else delete this.openTags[fid];
    if (!Motion.on()) { more.hidden = !open; return; }
    var tl = more.__tl;
    if (tl && tl.isActive()) { tl.timeScale(open ? 1 : 1.6).reversed(!open); return; }
    if (tl) tl.kill();
    var g = Motion.g, swing = wrap.querySelector(".ftag-swing"), mark = fold.querySelector(".ftag-fold-mark");
    var tilt = swing.__tilt || 0;
    var rows = [].slice.call(more.querySelectorAll("li")).slice(0, 40);
    more.hidden = false;
    tl = g.timeline({ paused: true, defaults: { ease: "power3.out" },
      onComplete: function () { g.set([more, rows], { clearProps: "all" }); more.__tl = null; },
      onReverseComplete: function () { more.hidden = true; g.set([more, rows], { clearProps: "all" }); more.__tl = null; } });
    tl.fromTo(more, { height: 0, clipPath: "inset(0% 0% 100% 0%)", overflow: "hidden" },
        { height: "auto", clipPath: "inset(0% 0% 0% 0%)", duration: 0.55, ease: "power3.inOut" }, 0)
      .fromTo(mark, { rotation: 0 }, { rotation: 180, duration: 0.45, ease: "back.out(2)", transformOrigin: "50% 50%" }, 0)
      .fromTo(swing, { rotation: tilt }, { rotation: tilt + (tilt < 0 ? -2.6 : 2.6), duration: 0.22, ease: "power2.out" }, 0.05)
      .to(swing, { rotation: tilt, duration: 1.1, ease: "elastic.out(1, 0.35)" }, 0.27);
    if (rows.length) tl.fromTo(rows, { x: -10, autoAlpha: 0 }, { x: 0, autoAlpha: 1, duration: 0.36,
      stagger: { amount: Math.min(0.4, rows.length * 0.04) } }, 0.16);
    more.__tl = tl;
    if (open) tl.timeScale(1).play(0); else tl.progress(1).timeScale(1.6).reverse();
  };

  /* Бирки раскачиваются, когда блок впервые попадает на экран и когда набор семейств меняется. */
  App.prototype.swingTags = function () {
    var body = this.$("families-body"), win = global;
    if (!Motion.on()) return;
    var run = function () {
      var swings = body.querySelectorAll(".ftag-swing");
      if (!swings.length) return;
      Motion.g.fromTo(swings, { rotation: function (i) { return (i % 2 ? 7 : -7) + i % 3; } },
        { rotation: function (i, t) { return t.__tilt || 0; }, duration: 1.8, ease: "elastic.out(1, 0.3)", stagger: 0.07, overwrite: "auto" });
    };
    if (body.__seen) { run(); return; }
    if (typeof win.IntersectionObserver !== "function") { body.__seen = true; return; }
    if (body.__io) return;
    body.__io = new win.IntersectionObserver(function (entries) {
      if (!entries[entries.length - 1].isIntersecting) return;
      body.__seen = true;
      body.__io.disconnect();
      run();
    }, { threshold: 0.25 });
    body.__io.observe(body);
  };

  /* Переход от бирки к коробке: прокрутка к ней, раскрытие и короткая подсветка. */
  App.prototype.showBox = function (id) {
    var doc = this.doc;
    var crates = doc.querySelectorAll(".crate"), crate = null;
    for (var i = 0; i < crates.length; i++) if (crates[i].getAttribute("data-key") === "box:" + id) crate = crates[i];
    if (!crate) return;
    var open = function () {
      if (!crate.open) { if (Motion.on()) crateToggle(crate); else crate.open = true; }
      if (Motion.on()) {
        var sig = global.getComputedStyle(doc.documentElement).getPropertyValue("--signal").trim() || "#e8470f";
        Motion.g.fromTo(crate, { boxShadow: "0 0 0 4px " + sig }, { boxShadow: "0 0 0 0px transparent", duration: 1.4, ease: "power2.out", clearProps: "boxShadow" });
      }
      var lid = crate.querySelector(".crate-lid");
      if (lid) lid.focus({ preventScroll: true });
    };
    var mast = doc.getElementById("mast");
    var offset = (mast ? mast.offsetHeight : 0) + 24;
    if (Motion.on() && global.ScrollToPlugin) {
      Motion.g.to(global, { scrollTo: { y: crate, offsetY: offset }, duration: 0.8, ease: "power3.inOut", onComplete: open });
    } else {
      global.scrollTo(0, crate.getBoundingClientRect().top + global.pageYOffset - offset);
      open();
    }
  };

  App.prototype.renderBoxes = function (m) {
    var doc = this.doc, self = this;
    var body = this.$("boxes-body");
    var busy = body.querySelectorAll(".crate");
    for (var bi0 = 0; bi0 < busy.length; bi0++) {
      /* Пока коробка в движении, перерисовку отложим до следующего опроса. */
      if (busy[bi0].__tl && busy[bi0].__tl.isActive()) return false;
    }
    var available = this.status.snapshot.catalog_available !== false || m.boxes.length;
    section(body, JSON.stringify([this.filter, m.linked, available, m.boxes, m.groups]), function () {
      if (!available) {
        var na = el(doc, "p", "empty");
        add(na, el(doc, "b", "", "Каталог не открыт. "), "Сохранённые коробки и решения сейчас недоступны — это не означает, что их нет.");
        return [na];
      }
      if (!m.boxes.length) {
        var e = el(doc, "p", "empty");
        add(e, el(doc, "b", "", "Каталог пуст. "),
          "Коробка появится, когда D2K подтвердит блокировку, измерит её поведение и найдёт обход. Начальных списков нет — всё узнаётся по живому трафику.");
        return [e];
      }
      var out = [];
      m.boxes.forEach(function (b, bi) {
        var binds = list(b.bindings);
        var visible = [], covered = [];
        binds.forEach(function (bd) {
          if (!self.matches(bd.target)) return;
          var g = m.linked ? coveredBy(bd, m.groups) : null;
          (g ? covered : visible).push({ bd: bd, g: g });
        });
        if (self.filter && !visible.length && !covered.length) return;
        out.push(self.boxNode(b, bi, visible, covered, binds.length));
      });
      if (!out.length) return [el(doc, "p", "empty", "Ни одна цель в коробках не подходит под запрос.")];
      return out;
    });
  };

  function svgEl(doc, tag, attrs, cls) {
    var n = doc.createElementNS(SVG, tag);
    for (var k in attrs) n.setAttribute(k, attrs[k]);
    if (cls) n.setAttribute("class", cls);
    return n;
  }

  /* Коробка в изометрии: закрытая — с лентой на крышке; открытая — откинутые клапаны. */
  /* Иконка коробки в изометрии. Верх — два клапана на шарнирах: левый на переднем
     ребре A–D, правый на заднем B–C; шов между ними (M1–M2) заклеен лентой.
     Положение клапана считается по углу поворота вокруг его ребра:
     0° — лежит плашмя (закрыто), 90° — стоит, ~135° — откинут наружу. */
  var BOX = { A: [8, 24], B: [32, 12], C: [56, 24], D: [32, 36] };
  var FLAP_W = Math.sqrt(12 * 12 + 6 * 6);
  /* Углы раскрытия подобраны под изометрию: передний клапан при большем угле
     смотрел бы на зрителя ребром и пропадал. */
  var CRATE_OPEN = { l: 105, r: 130 };
  function flapPoints(side, deg) {
    var r = deg * Math.PI / 180, c = Math.cos(r), sn = Math.sin(r);
    /* В плоскости верха клапан тянется от шарнира к шву; «вверх» в изометрии — это −y. */
    var inward = side === "l" ? [12, -6] : [-12, 6];
    var off = [c * inward[0], c * inward[1] - sn * FLAP_W];
    var h1 = side === "l" ? BOX.A : BOX.B, h2 = side === "l" ? BOX.D : BOX.C;
    var f = function (p) { return (p[0] + off[0]).toFixed(2) + "," + (p[1] + off[1]).toFixed(2); };
    return h1.join(",") + " " + h2.join(",") + " " + f(h2) + " " + f(h1);
  }
  function setFlaps(icon, degL, degR) {
    var l = icon.querySelector(".flap-l"), r = icon.querySelector(".flap-r");
    l.setAttribute("points", flapPoints("l", degL));
    r.setAttribute("points", flapPoints("r", degR));
    /* За вертикалью видна внутренняя сторона клапана. */
    l.setAttribute("data-inner", String(degL > 90));
    r.setAttribute("data-inner", String(degR > 90));
  }

  function crateIcon(doc) {
    var s = svgEl(doc, "svg", { viewBox: "0 0 64 64", "aria-hidden": "true" }, "crate-icon");
    var pg = function (pts, cls) { s.appendChild(svgEl(doc, "polygon", { points: pts }, cls)); };
    pg("8,24 32,36 32,60 8,48", "face-l");
    pg("32,36 56,24 56,48 32,60", "face-r");
    pg("8,24 32,12 56,24 32,36", "inside");
    s.appendChild(svgEl(doc, "polygon", { points: flapPoints("r", 0) }, "flap flap-r"));
    s.appendChild(svgEl(doc, "polygon", { points: flapPoints("l", 0) }, "flap flap-l"));
    s.appendChild(svgEl(doc, "path", { d: "M20 18 44 30" }, "tape"));
    s.appendChild(svgEl(doc, "path", { d: "M14 39v7l6 3" }, "mark"));
    return s;
  }

  /* Сцена коробки — один таймлайн: вперёд открывает, назад закрывает.
     Повторный клик во время анимации разворачивает её с текущего места.
     Лента на крышке рвётся пополам, крышка приподнимается, клапаны откидываются,
     наклейка качается, тело раскрывается, строки проявляются все, по очереди. */
  function crateTimeline(crate) {
    var g = Motion.g;
    var lidEl = crate.querySelector(".crate-lid"), body = crate.querySelector(".crate-body");
    var icon = crate.querySelector(".crate-icon");
    var iconTape = icon.querySelector(".tape");
    var hinge = { l: 0, r: 0 };
    var drawFlaps = function () { setFlaps(icon, hinge.l, hinge.r); };
    var tapeL = lidEl.querySelector(".crate-tape-l"), tapeR = lidEl.querySelector(".crate-tape-r");
    var label = crate.querySelector(".crate-label");
    var bits = [].slice.call(body.querySelectorAll(".box-aside > *, .bindings tbody tr, .covered")).slice(0, 60);
    var all = [lidEl, body, iconTape, tapeL, tapeR, label, bits];
    var cs = global.getComputedStyle(body), padT = cs.paddingTop, padB = cs.paddingBottom;
    var done = function () {
      g.set(all, { clearProps: "all" });
      crate.__tl = null;
      setFlaps(icon, crate.open ? CRATE_OPEN.l : 0, crate.open ? CRATE_OPEN.r : 0);
    };
    var tl = g.timeline({ paused: true, defaults: { ease: "power3.out" },
      onComplete: done,
      onReverseComplete: function () { crate.open = false; done(); } });
    /* Начало ленты задано явно: CSS прячет её у открытой коробки, а коробка
       помечается открытой в самом начале сцены. */
    var tape0 = { xPercent: 0, yPercent: 0, rotation: 0, autoAlpha: 1 };
    tl.fromTo(tapeL, tape0, { xPercent: -10, yPercent: -160, rotation: -9, autoAlpha: 0, duration: 0.42, ease: "power2.in", transformOrigin: "0% 50%" }, 0)
      .fromTo(tapeR, tape0, { xPercent: 10, yPercent: -160, rotation: 9, autoAlpha: 0, duration: 0.42, ease: "power2.in", transformOrigin: "100% 50%" }, 0.05)
      .fromTo(iconTape, { drawSVG: "0% 100%", opacity: 0.8 }, { drawSVG: "50% 50%", opacity: 0.8, duration: 0.2, ease: "power2.in" }, 0)
      .to(lidEl, { y: -5, duration: 0.16, ease: "power2.out" }, 0.02)
      .to(lidEl, { y: 0, duration: 0.45, ease: "back.out(3)" }, 0.18)
      .to(iconTape, { opacity: 0, duration: 0.08 }, 0.17)
      .fromTo(hinge, { l: 0 }, { l: CRATE_OPEN.l, duration: 0.6, ease: "back.out(1.6)", onUpdate: drawFlaps }, 0.14)
      .fromTo(hinge, { r: 0 }, { r: CRATE_OPEN.r, duration: 0.6, ease: "back.out(1.6)", onUpdate: drawFlaps }, 0.22)
      .fromTo(label, { rotation: -1.5 }, { rotation: 3.5, duration: 0.18, ease: "power2.out" }, 0.06)
      .to(label, { rotation: -1.5, duration: 0.7, ease: "elastic.out(1, 0.4)" }, 0.24)
      .fromTo(body, { height: 0, paddingTop: 0, paddingBottom: 0, overflow: "hidden" },
        { height: "auto", paddingTop: padT, paddingBottom: padB, duration: 0.6, ease: "power3.inOut" }, 0.14);
    if (bits.length) tl.fromTo(bits, { y: 16, autoAlpha: 0 }, { y: 0, autoAlpha: 1, duration: 0.42, stagger: { amount: Math.min(0.45, bits.length * 0.03) } }, 0.3);
    return tl;
  }

  function crateToggle(crate) {
    var tl = crate.__tl;
    if (tl && tl.isActive()) {
      /* Разворот на ходу: та же сцена в обратную сторону с текущего кадра. */
      tl.timeScale(tl.reversed() ? 1 : 1.6).reversed(!tl.reversed());
      return;
    }
    if (tl) tl.kill();
    if (!crate.open) {
      crate.open = true;
      crate.__tl = crateTimeline(crate);
      crate.__tl.timeScale(1).play(0);
    } else {
      crate.__tl = crateTimeline(crate);
      crate.__tl.progress(1).timeScale(1.6).reverse();
    }
  }

  function boxFacts(binds) {
    var protos = {}, v6 = false, recheck = 0, off = 0;
    binds.forEach(function (bd) {
      protos[shapeLabel(bd.shape, bd.transport)] = true;
      if (bd.family === 6) v6 = true;
      if (bd.recheck) recheck++;
      if (bd.enabled === false) off++;
    });
    return { protos: Object.keys(protos), v6: v6, recheck: recheck, off: off };
  }

  App.prototype.boxNode = function (b, bi, visible, covered, total) {
    var doc = this.doc;
    var crate = el(doc, "details", "crate");
    crate.addEventListener("toggle", function () {
      if (crate.__tl) return;
      var ic = crate.querySelector(".crate-icon");
      if (ic) setFlaps(ic, crate.open ? CRATE_OPEN.l : 0, crate.open ? CRATE_OPEN.r : 0);
    });
    crate.setAttribute("data-key", "box:" + str(b.id));
    crate.setAttribute("data-flip-id", "box:" + str(b.id));
    if (this.filter) crate.open = true;
    var lid = el(doc, "summary", "crate-lid");
    var head = el(doc, "div", "crate-head");
    var sigs = list(b.signals);
    var first = sigs.length ? (str(sigs[0].human) || str(sigs[0].kind)) : "приметы не записаны";
    add(head, el(doc, "h3", "crate-name", "Коробка " + (bi + 1)),
      el(doc, "p", "crate-signal", first + (sigs.length > 1 ? " · ещё " + (sigs.length - 1) : "")));
    var facts = boxFacts(list(b.bindings));
    var meta = el(doc, "div", "crate-meta");
    facts.protos.forEach(function (p) { meta.appendChild(tag(doc, p)); });
    if (facts.v6) meta.appendChild(tag(doc, "IPv6"));
    if (facts.recheck) meta.appendChild(tag(doc, "перепроверяется: " + facts.recheck, "live"));
    var updated = parseTime(b.updated);
    if (updated) meta.appendChild(el(doc, "span", "crate-when", "обновлена " + ago(this.serverNow() - updated)));
    head.appendChild(meta);
    var label = el(doc, "div", "crate-label");
    var nPlans = list(b.plans).length;
    add(label,
      el(doc, "code", "crate-id", str(b.id)),
      el(doc, "strong", "", String(total)),
      el(doc, "span", "", plural(total, "цель", "цели", "целей") + " · " + count(nPlans, "план", "плана", "планов")));
    var tapeL = el(doc, "span", "crate-tape crate-tape-l"), tapeR = el(doc, "span", "crate-tape crate-tape-r");
    tapeL.setAttribute("aria-hidden", "true");
    tapeR.setAttribute("aria-hidden", "true");
    add(lid, tapeL, tapeR, crateIcon(doc), head, label);
    lid.addEventListener("click", function (e) {
      if (!Motion.on()) return;
      e.preventDefault();
      crateToggle(crate);
    });
    var art = el(doc, "div", "box crate-body");
    var aside = el(doc, "div", "box-aside");
    var self = this;
    var dates = [];
    var created = parseTime(b.created), updated = parseTime(b.updated);
    if (created) dates.push("найдена " + localTime(created));
    if (updated && updated !== created) dates.push("обновлена " + localTime(updated));
    if (dates.length) aside.appendChild(el(doc, "p", "box-dates", dates.join(" · ")));

    var sigWrap = el(doc, "div");
    sigWrap.appendChild(el(doc, "h4", "", "Поведение"));
    if (sigs.length) {
      var sl = el(doc, "ul", "signal-list");
      sigs.forEach(function (s) {
        var li = el(doc, "li", "", str(s.human) || str(s.kind));
        if (num(s.seen)) li.appendChild(el(doc, "small", "", "×" + s.seen));
        sl.appendChild(li);
      });
      sigWrap.appendChild(sl);
    } else {
      sigWrap.appendChild(el(doc, "p", "box-dates", "Приметы не записаны"));
    }
    aside.appendChild(sigWrap);

    var plansWrap = el(doc, "div");
    plansWrap.appendChild(el(doc, "h4", "", "Планы"));
    var plans = el(doc, "div", "plans");
    list(b.plans).forEach(function (p, pi) {
      var d = el(doc, "details", "plan");
      d.setAttribute("data-key", "plan:" + str(b.id) + ":" + (p.id || pi));
      d.setAttribute("data-enabled", String(p.enabled !== false));
      var sum = el(doc, "summary");
      add(sum,
        tag(doc, str(p.proto).toUpperCase() || "—"),
        el(doc, "span", "plan-gist", str(p.human) || planGist(p.text) || str(p.id)),
        el(doc, "span", "plan-wins", count(num(p.successes) || 0, "успех", "успеха", "успехов")));
      var pre = el(doc, "pre", "", (p.id ? "# " + p.id + (p.enabled === false ? " (выключен)" : "") + "\n" : "") + str(p.text));
      pre.tabIndex = 0;
      pre.setAttribute("aria-label", "Текст плана " + (str(p.id) || String(pi + 1)));
      add(d, sum, pre);
      plans.appendChild(d);
    });
    if (!list(b.plans).length) plans.appendChild(el(doc, "p", "box-dates", "Планов нет"));
    plansWrap.appendChild(plans);
    aside.appendChild(plansWrap);

    var main = el(doc, "div");
    main.appendChild(el(doc, "h4", "", count(total, "цель", "цели", "целей")));
    if (visible.length) {
      var table = el(doc, "table", "bindings");
      var cg = el(doc, "colgroup");
      ["c-target", "c-proto", "c-level", "c-wins", "c-when"].forEach(function (c) { cg.appendChild(el(doc, "col", c)); });
      table.appendChild(cg);
      var thead = el(doc, "thead"), hr = el(doc, "tr");
      ["Цель", "Протокол", "Доказательство", "Успехи", "Подтверждено"].forEach(function (h) { hr.appendChild(el(doc, "th", "", h)); });
      thead.appendChild(hr);
      var tb = el(doc, "tbody");
      var now = self.serverNow();
      visible.sort(function (a, c) { return (parseTime(c.bd.confirmed) || 0) - (parseTime(a.bd.confirmed) || 0); });
      visible.forEach(function (v) {
        var bd = v.bd;
        var tr = el(doc, "tr");
        tr.setAttribute("data-enabled", String(bd.enabled !== false));
        var t = el(doc, "td", "t", targetLabel(bd.target));
        if (bd.kind === "addr") t.appendChild(el(doc, "small", "", "адрес"));
        var proto = el(doc, "td", "n c-proto", shapeLabel(bd.shape, bd.transport) + " · " + familyLabel(bd.family));
        var lv = el(doc, "td", "c-level");
        add(lv, tag(doc, str(bd.level_name) || "не измерено", (bd.level || 0) >= 3 ? "ok" : (bd.level || 0) > 0 ? "warn" : "mute"));
        if (bd.recheck) add(lv, " ", tag(doc, "перепроверяется", "live"));
        if (bd.enabled === false) add(lv, " ", tag(doc, "выключено", "mute"));
        var nw = num(bd.successes) || 0;
        var wins = el(doc, "td", "n c-wins", String(nw));

        var c = parseTime(bd.confirmed);
        var when = el(doc, "td", "n c-when", c ? ago(now - c) : "—");
        if (c) when.title = localTime(c);
        proto.setAttribute("data-tail", count(nw, "успех", "успеха", "успехов") + " · " + (c ? ago(now - c) : "время неизвестно"));
        add(tr, t, proto, lv, wins, when);
        tb.appendChild(tr);
      });
      add(table, thead, tb);
      main.appendChild(table);
    } else if (!covered.length) {
      main.appendChild(el(doc, "p", "box-dates", "Привязанных целей нет"));
    }
    if (covered.length) {
      var det = el(doc, "details", "covered");
      det.setAttribute("data-key", "covered:" + str(b.id));
      det.appendChild(el(doc, "summary", "",
        (visible.length ? "Ещё " : "") + count(covered.length, "цель покрыта", "цели покрыты", "целей покрыты") + " семействами"));
      var ul = el(doc, "ul");
      covered.forEach(function (v) { ul.appendChild(el(doc, "li", "", targetLabel(v.bd.target) + " → *." + v.g.suffix)); });
      det.appendChild(ul);
      main.appendChild(det);
    }
    add(art, aside, main);
    add(crate, lid, art);
    return crate;
  };

  /* ─── Telegram ─── */

  var TG = {
    connected: { word: "Подключён", lamp: "ok", note: "Получен подтверждённый ответ Telegram." },
    connecting: { word: "Подключается", lamp: "warn", note: "Служба запущена и проверяет доступные маршруты." },
    local: { word: "Локальный прокси", lamp: "warn", note: "Прокси запущен. Ответ Telegram появится после подтверждённого обмена." },
    stopped: { word: "Остановлен", lamp: "idle", note: "Служба не запущена." },
    not_configured: { word: "Не настроен", lamp: "idle", note: "Для C11 укажите TG_MODE=local в конфигурации." }
  };

  function tunnelScene(doc) {
    var root = el(doc, "div", "tg-flow");
    var canvas = el(doc, "canvas", "tg-flow-canvas");
    canvas.setAttribute("role", "img");
    canvas.setAttribute("aria-label", "Схема активных маршрутов Telegram");
    var caption = el(doc, "p", "tg-flow-caption", "Активные маршруты появятся после подключения.");
    caption.id = "tg-flow-caption";
    var panels = el(doc, "div", "tg-flow-panels");
    var active = el(doc, "section", "tg-flow-block");
    active.setAttribute("data-tg-active-sessions", "");
    var activeTitle = el(doc, "div", "tg-flow-block-head");
    add(activeTitle, el(doc, "h3", "", "Активные сессии"),
      el(doc, "span", "tg-flow-count", "0"));
    activeTitle.lastChild.setAttribute("data-tg-session-count", "");
    var sessionList = el(doc, "div", "tg-flow-session-list");
    sessionList.setAttribute("data-tg-session-list", "");
    sessionList.setAttribute("role", "list");
    active.append(activeTitle, sessionList);

    var summary = el(doc, "section", "tg-flow-block");
    summary.setAttribute("data-tg-connection-summary", "");
    summary.appendChild(el(doc, "h3", "", "Краткая сводка подключений"));
    var metrics = el(doc, "div", "tg-flow-metrics");
    [
      ["Сессии сейчас", "tg-flow-metric-active", "data-tg-active-count"],
      ["Всего подключений", "tg-flow-metric-total", "data-tg-accepted-count"],
      ["Ответы Telegram", "tg-flow-metric-confirmed", "data-tg-confirmed-count"]
    ].forEach(function (item) {
      var metric = el(doc, "div", "tg-flow-metric " + item[1]);
      metric.append(el(doc, "span", "", item[0]), el(doc, "b", "", "—"));
      metric.lastChild.setAttribute(item[2], "");
      metrics.appendChild(metric);
    });
    var lastSuccess = el(doc, "p", "tg-flow-last-success", "Подтверждённых ответов пока нет");
    lastSuccess.setAttribute("data-tg-last-success", "");
    summary.append(metrics, lastSuccess);
    panels.append(active, summary);
    root.append(canvas, caption, panels);
    if (global.D2kTelegramFlow && global.D2kTelegramFlow.mountTelegramFlow) {
      root.__flow = global.D2kTelegramFlow.mountTelegramFlow(canvas);
    }
    root.__sessionRows = new Map();
    return root;
  }

  function telegramSessionRoute(session) {
    if (session.selected_transport) return session.selected_transport;
    if (session.fallback_transport && ["connecting", "connected", "first_binary_response"].indexOf(session.fallback_state) >= 0)
      return session.fallback_transport;
    return session.direct_transport || session.fallback_transport || null;
  }

  function telegramTransportLabel(transport) {
    return transport === "direct_wss" ? "Прямой WSS" :
      transport === "cloudflare_worker" ? "Cloudflare Worker" :
      transport === "cloudflare_proxy" ? "Прокси Cloudflare" :
      transport === "tcp_fallback" ? "Резервный TCP" :
      transport === "tcp_passthrough" ? "Прямой TCP" : "Маршрут определяется";
  }

  function updateTelegramSessions(ui, stats) {
    var listNode = ui.scene.querySelector("[data-tg-session-list]");
    var countNode = ui.scene.querySelector("[data-tg-session-count]");
    if (!listNode || !countNode) return;
    var sessions = stats && Array.isArray(stats.active_sessions) ? stats.active_sessions : [];
    var activeCount = stats && Number.isFinite(Number(stats.active_connections))
      ? Math.max(0, Number(stats.active_connections)) : null;
    var countText = activeCount === null ? "—" : String(activeCount);
    if (stats && stats.route_sessions_truncated) countText += "+";
    if (countNode.textContent !== countText) countNode.textContent = countText;
    var live = new Set(sessions.map(function (session) { return String(session.id); }));
    ui.scene.__sessionRows.forEach(function (row, id) {
      if (!live.has(id)) { row.remove(); ui.scene.__sessionRows.delete(id); }
    });
    if (!stats) {
      ui.sessionEmpty = ui.sessionEmpty || el(ui.scene.ownerDocument, "p", "tg-flow-empty", "Статистика маршрутов пока недоступна");
      if (ui.sessionEmpty.parentNode !== listNode) listNode.replaceChildren(ui.sessionEmpty);
      return;
    }
    if (!sessions.length) {
      ui.sessionEmpty = ui.sessionEmpty || el(ui.scene.ownerDocument, "p", "tg-flow-empty", activeCount
        ? "Сессии есть, маршрут ещё определяется" : "Нет активных сессий");
      ui.sessionEmpty.textContent = activeCount ? "Сессии есть, маршрут ещё определяется" : "Нет активных сессий";
      if (ui.sessionEmpty.parentNode !== listNode) listNode.replaceChildren(ui.sessionEmpty);
      return;
    }
    if (ui.sessionEmpty && ui.sessionEmpty.parentNode === listNode) ui.sessionEmpty.remove();
    sessions.forEach(function (session) {
      var id = String(session.id);
      var row = ui.scene.__sessionRows.get(id);
      if (!row) {
        row = el(ui.scene.ownerDocument, "div", "tg-flow-session");
        row.setAttribute("role", "listitem");
        row.__fields = [el(ui.scene.ownerDocument, "b"), el(ui.scene.ownerDocument, "span"), el(ui.scene.ownerDocument, "span")];
        row.__fields.forEach(function (field) { row.appendChild(field); });
        ui.scene.__sessionRows.set(id, row);
      }
      var dc = session.dc == null ? "DC неизвестен" : "DC" + session.dc;
      var kind = session.is_media === true ? "media" : session.is_media === false ? "основная" : "тип не определён";
      var confirmed = session.telegram_response_seen === true;
      var route = telegramTransportLabel(telegramSessionRoute(session));
      var status = confirmed ? "Ответ Telegram подтверждён" :
        session.selected_transport ? "Маршрут выбран · ждём ответ Telegram" : "Соединение устанавливается";
      var values = [dc + " · " + kind, "Маршрут: " + route, status];
      row.__fields.forEach(function (field, index) {
        if (field.textContent !== values[index]) field.textContent = values[index];
      });
      if (row.parentNode !== listNode) listNode.appendChild(row);
    });
  }

  function updateTelegramSummary(ui, stats) {
    var scene = ui.scene;
    var active = stats ? String(Math.max(0, Number(stats.active_connections) || 0)) : "—";
    var total = stats ? String(Math.max(0, Number(stats.accepted_connections) || 0)) : "—";
    var confirmed = stats ? String(Math.max(0, Number(stats.wss_responses) || 0)) : "—";
    var activeNode = scene.querySelector("[data-tg-active-count]");
    var totalNode = scene.querySelector("[data-tg-accepted-count]");
    var confirmedNode = scene.querySelector("[data-tg-confirmed-count]");
    if (activeNode && activeNode.textContent !== active) activeNode.textContent = active;
    if (totalNode && totalNode.textContent !== total) totalNode.textContent = total;
    if (confirmedNode && confirmedNode.textContent !== confirmed) confirmedNode.textContent = confirmed;
    var last = scene.querySelector("[data-tg-last-success]");
    if (!last) return;
    var successCount = Number(stats && stats.wss_responses) || 0;
    var text = successCount && Number.isFinite(Number(stats.last_success_age_ms))
      ? "Последний ответ: " + (stats.last_success_dc ? "DC" + stats.last_success_dc + " · " : "") +
        telegramRouteName(Number(stats.last_success_route)) + " · " + telegramAge(Number(stats.last_success_age_ms))
      : successCount ? "Подтверждён ответ Telegram" : "Подтверждённых ответов пока нет";
    if (last.textContent !== text) last.textContent = text;
  }

  App.prototype.renderTelegram = function (m, force) {
    if (!m) return;
    var doc = this.doc, snap = m.snap;
    var st = TG[snap.telegram_status] ? snap.telegram_status : (snap.telegram_configured ? "stopped" : "not_configured");
    var info = TG[st];
    var busy = snap.control_state === "running" || !!this.pending;
    var body = this.$("telegram-body");
    var stale = doc.body.getAttribute("data-stale") === "true";
    var stats = snap.telegram_stats;
    var key = JSON.stringify([st, snap.telegram_enabled, snap.telegram_configured, stats,
      snap.controls_enabled, busy, this.pending, stale]);
    if (!force && body.__d2kKey === key) return;
    var focused = doc.activeElement && body.contains(doc.activeElement)
      ? doc.activeElement.getAttribute("data-control") : null;
    body.__d2kKey = key;
    var ui = body.__tgUi;
    if (!ui) {
      ui = body.__tgUi = {
        state: el(doc, "div", "tunnel-state"),
        lamp: el(doc, "span", "lamp"),
        word: el(doc, "span", "tunnel-word"),
        actions: el(doc, "div", "tunnel-actions"),
        scene: tunnelScene(doc),
        note: el(doc, "p", "tunnel-note"),
      };
      ui.state.append(ui.lamp, ui.word);
      body.replaceChildren(ui.state, ui.actions, ui.scene, ui.note);
      if (ui.scene.__flow) ui.scene.__flow.attach();
    }
    ui.lamp.setAttribute("data-tone", info.lamp);
    if (ui.word.textContent !== info.word) ui.word.textContent = info.word;
    var buttons = [];
    if (snap.controls_enabled) {
      if (snap.telegram_enabled) {
        buttons.push(this.button("telegram-disable", "Выключить туннель", "stop", null, busy));
      } else {
        buttons.push(this.button("telegram-enable", "Включить туннель", "send", "primary", busy || !snap.telegram_configured));
      }
    }
    buttons.push(this.button("telegram-workers", "Мои Workers", null, null, busy));
    ui.actions.replaceChildren.apply(ui.actions, buttons);
    var note = info.note;
    if (snap.telegram_enabled && st === "stopped") note = "Туннель включён в конфигурации, но служба не запущена.";
    if (ui.note.textContent !== note) ui.note.textContent = note;
    body.setAttribute("data-state", st);
    if (ui.scene.__flow) ui.scene.__flow.update(stats);
    updateTelegramSessions(ui, stats);
    updateTelegramSummary(ui, stats);
    if (focused) {
      var again = body.querySelector("button");
      if (again) again.focus();
    }
  };

  /* ─── Диагностика ─── */

  App.prototype.drawStages = function () {
    var body = this.$("diagnostics-body"), win = global;
    if (!Motion.on()) return;
    var run = function () {
      var paths = body.querySelectorAll(".stages svg path");
      if (paths.length) Motion.g.fromTo(paths, { drawSVG: "0%" }, { drawSVG: "100%", duration: 0.5, stagger: 0.07, ease: "power2.out", clearProps: "strokeDasharray,strokeDashoffset" });
    };
    if (body.__seen) { run(); return; }
    if (typeof win.IntersectionObserver !== "function" || body.__io) return;
    body.__io = new win.IntersectionObserver(function (entries) {
      if (!entries[entries.length - 1].isIntersecting) return;
      body.__seen = true; body.__io.disconnect(); run();
    }, { threshold: 0.2 });
    body.__io.observe(body);
  };

  App.prototype.renderDiagnostics = function (m) {
    var doc = this.doc;
    var snap = m.snap;
    var body = this.$("diagnostics-body");
    var col = this.$("colophon");
    var meas = m.k.measurements || {};
    var key = JSON.stringify([snap.stages, snap.absent, snap.config_path, snap.config_exists, snap.mode, snap.state_dir,
      snap.state_dir_note, snap.queue_num, snap.unknown_keys, snap.engine_running, snap.controller_running,
      snap.live_fresh, m.linked, m.k.catalog_at, m.k.client_unfit, meas.cores, snap.controls_enabled, snap.control_state]);
    var redrawn = section(body, key, function () {
      var wrap = el(doc, "div", "diag");

      var left = el(doc, "div");
      left.appendChild(el(doc, "h3", "", "Цепочка движка"));
      var ul = el(doc, "ul", "stages");
      list(snap.stages).forEach(function (s) {
        var li = el(doc, "li");
        li.setAttribute("data-ok", String(!!s.built));
        add(li, icon(doc, s.built ? "check" : "cross"), el(doc, "b", "", str(s.title)), el(doc, "p", "", str(s.detail)));
        ul.appendChild(li);
      });
      list(snap.absent).forEach(function (s) {
        var li = el(doc, "li");
        li.setAttribute("data-absent", "true");
        add(li, icon(doc, "dash"), el(doc, "b", "", str(s.title) + " — не измеряется"), el(doc, "p", "", str(s.detail)));
        ul.appendChild(li);
      });
      if (!list(snap.stages).length && !list(snap.absent).length) ul.appendChild(el(doc, "li", "", "Сведений о цепочке нет."));
      left.appendChild(ul);

      var right = el(doc, "div");
      right.appendChild(el(doc, "h3", "", "Запуск и настройки"));
      var dl = el(doc, "dl", "facts");
      function fact(label, value, tone, mono) {
        var dd = el(doc, "dd", mono ? "mono" : "", value);
        if (tone) dd.setAttribute("data-tone", tone);
        add(dl, el(doc, "dt", "", label), dd);
      }
      fact("Режим", (MODES[snap.mode] || str(snap.mode) || "не указан") + (snap.mode ? " (MODE=" + snap.mode + ")" : ""));
      fact("Движок", snap.engine_running ? "процесс запущен" : "процесс не найден", snap.engine_running ? null : "bad");
      fact("Контроллер", snap.controller_running ? "процесс запущен" : "процесс не найден", snap.controller_running ? null : "bad");
      fact("Управление", snap.controls_enabled
        ? "включено; команды принимаются только со страницы этой панели"
        : "отключено в конфигурации", null);
      var last = { idle: "", running: "выполняется", done: "выполнена", failed: "завершилась ошибкой", timeout: "не завершилась вовремя" }[str(snap.control_state)];
      if (last) fact("Последняя команда", last, snap.control_state === "failed" || snap.control_state === "timeout" ? "warn" : null);
      if (m.panelUptime) fact("Панель запущена", duration(m.panelUptime * 1000) + " назад");
      fact("Связь с датапатом", m.linked ? "есть" : "нет", m.linked ? null : "bad");
      fact("Снимок движка", snap.live_fresh ? "свежий" : "устарел или отсутствует", snap.live_fresh ? null : "warn");
      fact("Конфигурация", str(snap.config_path) + (snap.config_exists ? "" : " — файла нет, действуют умолчания"),
        snap.config_exists ? null : "warn", true);
      fact("Каталог состояния", str(snap.state_dir) + " — " + str(snap.state_dir_note), null, true);
      if (m.k.catalog_at) fact("Файл каталога", str(m.k.catalog_at), null, true);
      if (num(snap.queue_num) !== null) fact("Очередь NFQUEUE", String(snap.queue_num), null, true);
      if (num(m.k.client_unfit) !== null) fact("План не подошёл клиенту", String(m.k.client_unfit), m.k.client_unfit ? "warn" : null);
      var unknown = list(snap.unknown_keys);
      if (unknown.length) fact("Непонятные ключи", unknown.join(", ") + " — эта сборка их не читает", "warn", true);
      right.appendChild(dl);

      add(wrap, left, right);
      return [wrap];
    });
    if (redrawn) this.drawStages();
    col.replaceChildren();
    add(col,
      el(doc, "span", "", "D2K " + str(snap.version) + (snap.dirty ? " (изменённая сборка)" : "")),
      snap.commit ? el(doc, "span", "mono", str(snap.commit).slice(0, 12)) : null,
      parseTime(snap.built) ? el(doc, "span", "", "собран " + localTime(parseTime(snap.built))) : null,
      parseTime(snap.taken) ? el(doc, "span", "", "снимок " + localTime(parseTime(snap.taken))) : null);
  };

  /* ─── Навигация ─── */

  App.prototype.renderNav = function (m) {
    var set = function (id, text, tone) {
      var n = this.$(id);
      n.textContent = text;
      if (tone) n.setAttribute("data-tone", tone); else n.removeAttribute("data-tone");
    }.bind(this);
    set("nav-now", !m.engine ? "стоп" : !m.linked ? "нет связи" : m.hunting ? String(m.hunting) : "", m.hunting ? "live" : null);
    set("nav-families", m.groups.length ? String(m.groups.length) : "");
    set("nav-boxes", m.boxes.length ? String(m.boxes.length) : "");
    var tg = m.snap.telegram_status;
    set("nav-telegram", tg === "connected" ? "вкл" : tg === "local" ? "лок." : tg === "connecting" ? "…" : "выкл");
    var bad = list(m.snap.stages).filter(function (s) { return !s.built; }).length;
    set("nav-diagnostics", bad ? "!" + bad : "", bad ? "warn" : null);
  };

  /* Оглавление: плавный переход к разделу с учётом шапки, маркер переезжает
     к активному пункту, тонкая полоса под шапкой показывает прокрутку страницы. */
  App.prototype.navMotion = function () {
    var doc = this.doc, win = this.win, self = this;
    var nav = doc.querySelector(".index"), mast = doc.getElementById("mast");
    if (!nav) return;
    nav.addEventListener("click", function (e) {
      var a = e.target.closest ? e.target.closest("a[href^='#']") : null;
      if (!a || !Motion.on() || !win.ScrollToPlugin) return;
      var target = doc.querySelector(a.getAttribute("href"));
      if (!target) return;
      e.preventDefault();
      var off = (mast ? mast.offsetHeight : 0) + (win.innerWidth <= 1080 ? 72 : 20);
      Motion.g.to(win, { scrollTo: { y: target, offsetY: off, autoKill: true }, duration: 0.8, ease: "power3.inOut" });
      if (win.history && win.history.replaceState) win.history.replaceState(null, "", a.getAttribute("href"));
    });
    var marker = el(doc, "span", "index-marker");
    marker.setAttribute("aria-hidden", "true");
    nav.insertBefore(marker, nav.firstChild);
    this.navMarker = marker;
    var bar = el(doc, "span", "mast-progress");
    bar.setAttribute("aria-hidden", "true");
    if (mast) mast.appendChild(bar);
    var setBar = Motion.g ? Motion.g.quickSetter(bar, "scaleX") : function (v) { bar.style.transform = "scaleX(" + v + ")"; };
    var ticking = false;
    var onScroll = function () {
      if (ticking) return;
      ticking = true;
      win.requestAnimationFrame(function () {
        ticking = false;
        var max = doc.documentElement.scrollHeight - win.innerHeight;
        setBar(max > 0 ? Math.min(1, win.pageYOffset / max) : 0);
      });
    };
    win.addEventListener("scroll", onScroll, { passive: true });
    win.addEventListener("resize", function () { onScroll(); self.moveMarker(true); });
    onScroll();
  };

  App.prototype.moveMarker = function (instant) {
    var marker = this.navMarker, nav = marker && marker.parentNode;
    if (!marker) return;
    var cur = nav.querySelector("a[aria-current='true']");
    if (!cur) { marker.style.opacity = "0"; return; }
    var box = { x: cur.offsetLeft, y: cur.offsetTop, width: cur.offsetWidth, height: cur.offsetHeight, opacity: 1 };
    if (Motion.on() && !instant && marker.__placed) Motion.g.to(marker, Object.assign({ duration: 0.45, ease: "power3.out" }, box));
    else if (Motion.g) Motion.g.set(marker, box);
    else { marker.style.transform = "translate(" + box.x + "px," + box.y + "px)"; marker.style.width = box.width + "px"; marker.style.height = box.height + "px"; marker.style.opacity = "1"; }
    marker.__placed = true;
  };

  /* Знак D2K: линия обхода прорисовывается один раз, препятствие садится на место. */
  App.prototype.drawMark = function () {
    if (!Motion.on()) return;
    var d = this.doc;
    Motion.g.timeline({ delay: 0.1 })
      .from(d.querySelector(".mark-line"), { drawSVG: "0%", duration: 0.9, ease: "power2.inOut" })
      .from(d.querySelector(".mark-block"), { y: -10, autoAlpha: 0, duration: 0.6, ease: "bounce.out", svgOrigin: "18 20" }, "-=0.45");
  };

  App.prototype.spy = function () {
    var doc = this.doc, self = this;
    if (typeof IntersectionObserver !== "function") return;
    var links = doc.querySelectorAll("[data-nav]");
    var seen = {};
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) { seen[e.target.id] = e.isIntersecting ? e.intersectionRatio : 0; });
      var best = null, score = 0;
      Object.keys(seen).forEach(function (id) { if (seen[id] > score) { score = seen[id]; best = id; } });
      if (!best) return;
      for (var i = 0; i < links.length; i++) {
        if (links[i].getAttribute("data-nav") === best) links[i].setAttribute("aria-current", "true");
        else links[i].removeAttribute("aria-current");
      }
      self.moveMarker();
    }, { rootMargin: "-20% 0px -55% 0px", threshold: [0, .1, .3, .6] });
    ["now", "families", "boxes", "telegram", "updates", "diagnostics"].forEach(function (id) {
      var s = doc.getElementById(id);
      if (s) io.observe(s);
    });
  };

  var api = {
    model: model, coveredBy: coveredBy, slotsView: slotsView, trackFor: trackFor, shapeLabel: shapeLabel,
    planGist: planGist, plural: plural, duration: duration,
    telegramRouteName: telegramRouteName,
    telegramFailureStage: telegramFailureStage,
    App: App
  };
  if (typeof module === "object" && module.exports) module.exports = api;
  if (global && global.document && global.document.getElementById) {
    var boot = function () { new App(global.document, global).start(); };
    if (global.document.readyState === "loading") global.document.addEventListener("DOMContentLoaded", boot);
    else boot();
  }
})(typeof window !== "undefined" ? window : this);
