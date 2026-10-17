(function (global) {
"use strict";

const W = 900, H = 420;
const PORTRAIT_WIDTH = 420, COMPACT_WIDTH = 600;
const CLI = [70, 210], HUB = [300, 210], COL = [720, 210];
const GX = [465, 500, 535, 570, 605], GN = ["DNS", "TCP", "TLS", "WS", "MTP"];
const COOL = 30000;
const COLORS = {
  sig: [232, 71, 15], ok: [143, 220, 178], bad: [255, 150, 123],
  mute: [193, 189, 175], ink: [246, 243, 235], rule: [101, 100, 87], warn: [224, 176, 80],
};
const ROUTES = [
  ["direct_wss", "Прямой WSS", 62, COLORS.ok],
  ["cloudflare_worker", "Cloudflare Worker", 148, COLORS.sig],
  ["cloudflare_proxy", "Прокси Cloudflare", 272, COLORS.sig],
  ["tcp_passthrough", "Прямой TCP · диагностика", 358, COLORS.warn],
];
const LANE_INDEX = new Map(ROUTES.map((route, index) => [route[0], index]));
const GATE_BY_STAGE = { 1: 0, 2: 1, 3: 2, 4: 3, 5: 4 };
const GATE_ACCESSIBLE = ["DNS", "TCP", "TLS", "WebSocket", "MTProto"];
const STATE_ACCESSIBLE = { selected: "активен", connecting: "подключается", race: "гонка",
  connected: "upstream готов", failed: "отказ", cooldown: "пауза", cancelled: "отменён", skipped: "пропущен" };
const EVENT_WINDOW = { connecting: 1100, connected: 300, selected: 900, failed: 1800,
  cancelled: 600, cooldown: 600, first_binary_response: 1100 };

const rgba = (color, alpha) => `rgba(${color[0] | 0},${color[1] | 0},${color[2] | 0},${alpha})`;
const cubic = (a, b, c, d, count) => {
  const points = [];
  for (let index = 1; index <= count; index += 1) {
    const t = index / count, u = 1 - t;
    points.push([0, 1].map(axis => a[axis] * u ** 3 + 3 * b[axis] * u * u * t
      + 3 * c[axis] * u * t * t + d[axis] * t ** 3));
  }
  return points;
};
const makePath = points => {
  const cumulative = [0];
  for (let index = 1; index < points.length; index += 1) {
    cumulative.push(cumulative[index - 1]
      + Math.hypot(points[index][0] - points[index - 1][0], points[index][1] - points[index - 1][1]));
  }
  return { points, cumulative, length: cumulative[cumulative.length - 1] };
};
const pointAt = (path, fraction) => {
  const distance = Math.max(0, Math.min(1, fraction)) * path.length;
  let index = 1;
  while (index < path.cumulative.length - 1 && path.cumulative[index] < distance) index += 1;
  const span = path.cumulative[index] - path.cumulative[index - 1] || 1;
  const part = (distance - path.cumulative[index - 1]) / span;
  return [0, 1].map(axis => path.points[index - 1][axis]
    + (path.points[index][axis] - path.points[index - 1][axis]) * part);
};
function makeLane(route, index) {
  const [key, name, y, color] = route;
  const points = [HUB].concat(cubic(HUB, [360, 210], [380, y], [440, y], 22), [[620, y]],
    cubic([620, y], [680, y], [670, 210], COL, 22));
  const path = makePath(points);
  const gates = GX.map(x => {
    let point = 0;
    while (point < points.length - 1 && points[point][0] < x) point += 1;
    return path.cumulative[point] / path.length;
  });
  return { key, name, index, y, color, path, gates, gate: [0, 0, 0, 0, 0],
    coolUntil: 0, failT: -1e9, failStage: "", skipT: -1e9, winT: -1e9,
    glow: 0, selected: 0, connecting: 0, counts: {}, cooldownCount: 0, full: new Map() };
}

function mountTelegramFlow(canvas) {
  const api = global.D2kTelegramFlow;
  const context = canvas.getContext("2d", { alpha: false });
  if (!context || !api) throw new Error("Сцена Telegram недоступна");
  const root = canvas.closest(".tg-flow");
  const reduceMotion = global.matchMedia?.("(prefers-reduced-motion: reduce)") || null;
  const lanes = ROUTES.map(makeLane);
  const dcs = Array.from({ length: 5 }, () => ({ count: 0, media: 0, confirmed: 0, ping: 0 }));
  const sessions = new Map(), cursors = new Map(), previousTraffic = new Map();
  const parts = [], sparks = [], ripples = [], spikes = [];
  const hub = { pulse: 0, angle: 0 }, client = { pulse: 0 };
  let view = api.summarizeTelegramFlow(null);
  let processStartedAt = 0, acceptedConnections = null;
  let now = performance.now(), lastFrame = now, canvasWidth = 900;
  let pixelRatio = 1, inView = true, destroyed = false, frameId = 0;

  function fullPath(lane, dc) {
    if (!lane.full.has(dc)) lane.full.set(dc, makePath([CLI, HUB]
      .concat(lane.path.points.slice(1), [api.telegramDcPosition(dc) || COL])));
    return lane.full.get(dc);
  }

  function byId(session) {
    const id = Number(session.id);
    let item = sessions.get(id);
    if (!item) {
      item = { id, seed: Math.random() * Math.PI * 2, tries: Object.create(null) };
      sessions.set(id, item);
    }
    Object.assign(item, {
      dc: Number(session.dc) || null, media: session.is_media === true,
      stage: session.stage, selectedTransport: session.selected_transport,
      responseSeen: session.telegram_response_seen === true, session,
    });
    return item;
  }

  function startAttempt(item, lane, at) {
    item.tries[lane.key] = { kind: "try", lane, item, t0: at, f: 0,
      state: "run", path: lane.path, gate: 0, ft: 0, sparked: false };
  }

  function eventTime(event) {
    const age = Number(event.age_ms);
    return Number.isFinite(age) && age >= 0 ? now - age : now;
  }

  function processEvent(item, event) {
    const laneIndex = LANE_INDEX.get(event.transport);
    if (laneIndex === undefined) return;
    const lane = lanes[laneIndex], at = eventTime(event), attempt = item.tries[lane.key];
    if (event.state === "connecting") {
      startAttempt(item, lane, at);
      hub.pulse = Math.max(hub.pulse, 0.8);
    } else if (event.state === "connected") {
      const current = item.tries[lane.key];
      if (current) current.state = "ok";
    } else if (event.state === "selected") {
      item.selectedTransport = event.transport;
      lane.winT = at;
      parts.push({ kind: "win", lane, path: fullPath(lane, item.dc), t0: at, dur: 900 });
      hub.pulse = Math.max(hub.pulse, 0.8);
    } else if (event.state === "failed") {
      lane.failT = at;
      lane.failStage = Number(event.failure_stage) || 0;
      const current = attempt || (startAttempt(item, lane, at), item.tries[lane.key]);
      current.state = "fail";
      current.gate = Object.hasOwn(GATE_BY_STAGE, lane.failStage) ? GATE_BY_STAGE[lane.failStage] : null;
      current.ft = at;
    } else if (event.state === "cooldown") {
      lane.skipT = at;
    } else if (event.state === "cancelled") {
      if (attempt) { attempt.state = "cancel"; attempt.ft = at; }
    } else if (event.state === "first_binary_response") {
      item.responseSeen = true;
      parts.push({ kind: "resp", lane, path: fullPath(lane, item.dc), t0: at,
        dur: 1100, back: true, item });
      hub.pulse = 1;
    }
  }

  function resetProcess() {
    cursors.clear(); previousTraffic.clear(); sessions.clear(); parts.length = 0;
    sparks.length = 0; ripples.length = 0; spikes.length = 0;
    dcs.forEach(dc => { dc.ping = 0; });
    lanes.forEach(lane => { lane.coolUntil = 0; lane.failT = -1e9; lane.winT = -1e9; });
  }

  function readEvents(snapshot) {
    if (!snapshot) return;
    const started = Number(snapshot.process_started_at) || 0;
    const accepted = Number(snapshot.accepted_connections) || 0;
    const restarted = started && ((processStartedAt && started !== processStartedAt)
      || (acceptedConnections !== null && accepted < acceptedConnections));
    if (restarted) resetProcess();
    if (started) processStartedAt = started;
    acceptedConnections = accepted;
    const live = new Set();
    (Array.isArray(snapshot.active_sessions) ? snapshot.active_sessions : []).forEach(session => {
      const item = byId(session), id = item.id, events = Array.isArray(session.events) ? session.events : [];
      live.add(id);
      const newest = events.length ? Number(events[events.length - 1].sequence) || 0 : 0;
      const previous = cursors.get(id);
      if (previous == null || restarted) {
        cursors.set(id, newest);
        if (!restarted) events.filter(event => {
          const age = Number(event.age_ms);
          return Number.isFinite(age) && age >= 0 && age <= (EVENT_WINDOW[event.state] || 0);
        }).slice().sort((a, b) => a.sequence - b.sequence).forEach(event => processEvent(item, event));
        return;
      }
      const oldest = events.length ? Number(events[0].sequence) || newest : newest;
      if (previous < oldest - 1) { cursors.set(id, newest); return; }
      events.filter(event => Number(event.sequence) > previous).slice()
        .sort((a, b) => a.sequence - b.sequence).forEach(event => processEvent(item, event));
      cursors.set(id, newest);
    });
    for (const id of sessions.keys()) if (!live.has(id)) sessions.delete(id);
    for (const id of cursors.keys()) if (!live.has(id)) cursors.delete(id);
  }

  function readTraffic(snapshot) {
    if (!snapshot) return;
    const deltas = api.collectConfirmedTrafficDeltas(previousTraffic, snapshot.active_sessions);
    if (reduceMotion?.matches) return;
    deltas.forEach((delta, deltaIndex) => {
      const lane = lanes[delta.laneIndex];
      if (!lane) return;
      const path = fullPath(lane, delta.dc);
      const count = Math.min(8, Math.max(1, Math.ceil(delta.bytes / 1024)));
      for (let index = 0; index < count; index += 1) {
        const representedBytes = delta.bytes / count;
        parts.push({ kind: "pkt", lane, path, t0: now + deltaIndex * 55 + index * 45,
          dur: 1200 + Math.random() * 500, back: delta.direction === "response",
          dc: delta.dc, size: 3 + Math.min(9, Math.log2(1 + representedBytes / 256)) });
      }
      while (parts.length > 110) parts.shift();
    });
  }

  function setRouteState(snapshot) {
    lanes.forEach((lane, index) => {
      const state = view.lanes[index] || {};
      lane.counts = state.counts || {};
      lane.selected = Number(lane.counts.selected) || 0;
      lane.confirmed = Number(state.confirmed) || 0;
      lane.connecting = (Number(lane.counts.connecting) || 0) + (Number(lane.counts.race) || 0);
      lane.cooldownCount = Number(state.cooldownCount) || 0;
      lane.coolUntil = now + Math.max(0, Number(state.cooldownRemainingMs) || 0);
      lane.failStage = Number(state.failureStage) || 0;
      if (Number.isFinite(Number(state.failureAgeMs))) lane.failT = now - Number(state.failureAgeMs);
      else if (state.status !== "failed") lane.failT = -1e9;
      if (lane.failStage >= 1 && lane.failStage <= 5) lane.gate[lane.failStage - 1] = now;
    });
    dcs.forEach((dc, index) => Object.assign(dc, view.dcActivity[index] ||
      { active: 0, media: 0, confirmed: 0 }, {
        count: Number(view.dcActivity[index]?.active) || 0,
        media: Number(view.dcActivity[index]?.media) || 0,
        confirmed: Number(view.dcActivity[index]?.confirmed) || 0,
      }));
    if (snapshot && Number(snapshot.last_failure_stage) >= 1) {
      const index = Number(snapshot.last_failure_route) - 1;
      if (lanes[index]) {
        lanes[index].failStage = Number(snapshot.last_failure_stage) || lanes[index].failStage;
        lanes[index].failT = now - Math.max(0, Number(snapshot.last_failure_age_ms) || 0);
      }
    }
  }

  function updateAccessibility() {
    const activeLanes = view.lanes.filter(lane => lane.status !== "idle" || lane.cooldownCount);
    const description = activeLanes.map(lane => {
      const states = Object.entries(lane.counts || {}).filter(([, count]) => Number(count) > 0)
        .map(([state, count]) => `${STATE_ACCESSIBLE[state] || state}: ${count}`).join(", ");
      const gate = api.failureGateIndex(lane.failureStage);
      const failure = gate === null ? "" : `, отказ на воротах ${GATE_ACCESSIBLE[gate]}`;
      const cooldown = lane.cooldownCount
        ? `, пауза ${lane.cooldownCount} маршрута, ещё ${Math.ceil(lane.cooldownRemainingMs)} мс` : "";
      return `${lane.label} — ${states || STATE_ACCESSIBLE[lane.status] || "резерв"}${failure}${cooldown}`;
    }).join("; ")
      || "Сейчас нет активных маршрутов";
    const confirmed = view.state !== "stale"
      && view.sessions.some(session => session.telegram_response_seen === true);
    canvas.setAttribute("aria-label", `Схема соединений: Клиент → d2o. `
      + (confirmed ? "Ответ Telegram подтверждён." : "Ответ Telegram не подтверждён.")
      + ` ${description}. ${view.caption}`);
    canvas.dataset.state = view.state;
    if (root) root.dataset.state = view.state;
    const caption = root?.querySelector("#tg-flow-caption");
    if (caption && caption.textContent !== view.caption) caption.textContent = view.caption;
  }

  function update(snapshot, isStale) {
    if (destroyed) return null;
    const stale = isStale === true;
    view = api.summarizeTelegramFlow(snapshot || null, stale ? "stale" : undefined);
    if (!snapshot) {
      sessions.clear(); cursors.clear(); previousTraffic.clear(); parts.length = 0;
      sparks.length = 0; ripples.length = 0; spikes.length = 0;
      dcs.forEach(dc => { dc.count = 0; dc.media = 0; dc.confirmed = 0; });
    } else if (stale) {
      previousTraffic.clear(); parts.length = 0; sparks.length = 0;
      ripples.length = 0; spikes.length = 0;
      sessions.forEach(item => { item.tries = Object.create(null); });
      lanes.forEach(lane => { lane.glow = 0; });
      hub.pulse = 0; client.pulse = 0;
    } else {
      readEvents(snapshot);
      readTraffic(snapshot);
    }
    setRouteState(snapshot);
    updateAccessibility();
    if (stale) { stopLoop(); draw(); }
    else if (reduceMotion?.matches || !inView || document.hidden) draw();
    else startLoop();
    return view;
  }

  function line(points, color, alpha, width, dash, offset) {
    context.beginPath(); context.moveTo(points[0][0], points[0][1]);
    for (let index = 1; index < points.length; index += 1) context.lineTo(points[index][0], points[index][1]);
    context.setLineDash(dash || []); context.lineDashOffset = offset || 0;
    context.lineWidth = width; context.strokeStyle = rgba(color, alpha); context.lineCap = "round";
    context.stroke(); context.setLineDash([]);
  }

  function text(value, x, y, size, color, alpha, align) {
    const portrait = canvasWidth < PORTRAIT_WIDTH;
    const scale = Math.max(1, (portrait ? H : W) / canvasWidth * 0.85);
    context.font = `600 ${size * scale}px Onest,system-ui,sans-serif`;
    context.textAlign = align || "center"; context.fillStyle = rgba(color, alpha);
    if (portrait) {
      context.save(); context.translate(x, y); context.rotate(-Math.PI / 2);
      context.fillText(value, 0, 0); context.restore();
    } else context.fillText(value, x, y);
  }

  function setSceneTransform() {
    const portrait = canvasWidth < PORTRAIT_WIDTH, scale = canvas.width / (portrait ? H : W);
    if (portrait) context.setTransform(0, scale, -scale, 0, H * scale, 0);
    else context.setTransform(scale, 0, 0, scale, 0, 0);
  }

  function statusColor() {
    if (view.state === "stale") return COLORS.warn;
    if (view.state === "unavailable") return COLORS.bad;
    if (view.sessions.some(session => session.telegram_response_seen === true)) return COLORS.ok;
    return COLORS.warn;
  }

  function draw() {
    const t = now / 1000;
    setSceneTransform();
    context.globalCompositeOperation = "source-over";
    context.fillStyle = "#171813"; context.fillRect(0, 0, W, H);
    const color = statusColor(), portrait = canvasWidth < PORTRAIT_WIDTH, compact = canvasWidth < COMPACT_WIDTH;

    context.beginPath(); context.moveTo(CLI[0] + 30, 210);
    for (let x = CLI[0] + 30; x <= HUB[0] - 34; x += 3) {
      let dy = 0;
      for (const beat of spikes) {
        const distance = x - (HUB[0] - 34 - (now - beat) * 0.17);
        dy += -distance * Math.exp(-distance * distance / 260) * 0.9;
      }
      context.lineTo(x, 210 + Math.max(-34, Math.min(34, dy)));
    }
    context.strokeStyle = rgba(COLORS.ok, 0.35 + Math.min(0.5, spikes.length * 0.2));
    context.lineWidth = 2.2; context.lineJoin = "round"; context.stroke();

    dcs.forEach((dc, index) => {
      const position = api.telegramDcPosition(index + 1), level = Math.min(1, dc.count / 5);
      const dcColor = view.state === "stale" ? COLORS.rule
        : dc.count && dc.confirmed >= dc.count ? COLORS.ok
          : dc.count ? COLORS.sig : COLORS.rule;
      line([COL, position], COLORS.rule, 0.25 + Math.min(0.5, dc.count * 0.08), 1.2);
      context.beginPath(); context.arc(position[0], position[1], 9 + level * 3, 0, Math.PI * 2);
      context.fillStyle = rgba(dcColor, 0.12 + 0.5 * level); context.fill();
      context.lineWidth = 2; context.strokeStyle = rgba(COLORS.ink, 0.55 + 0.3 * level); context.stroke();
      if (dc.media) {
        context.beginPath(); context.arc(position[0], position[1], 15 + level * 3, 0, Math.PI * 2);
        context.setLineDash([2, 4]); context.strokeStyle = rgba(COLORS.sig, 0.7);
        context.lineWidth = 1.4; context.stroke(); context.setLineDash([]);
      }
      text(`DC${index + 1}`, position[0] + (compact ? 0 : 24),
        position[1] + (compact ? -22 : 4), 11, COLORS.ink, 0.75, compact ? "center" : "left");
      if (!compact && dc.count) text(`${dc.count}${dc.media ? ` · media ${dc.media}` : ""}`,
        position[0] + 24, position[1] + 18, 10, COLORS.mute, 0.8, "left");
    });
    context.beginPath(); context.arc(COL[0], COL[1], 6, 0, Math.PI * 2);
    context.fillStyle = rgba(COLORS.ink, 0.5); context.fill();

    for (const lane of lanes) {
      const cool = lane.coolUntil > now, live = lane.selected || lane.connecting;
      const responseConfirmed = lane.selected > 0 && lane.confirmed >= lane.selected;
      lane.glow += ((responseConfirmed ? 1 : live ? 0.5 : 0) - lane.glow) * 0.08;
      const colorLane = view.state === "stale" ? COLORS.rule
        : cool && !lane.selected ? COLORS.bad
          : responseConfirmed ? COLORS.ok : live ? COLORS.sig : COLORS.rule;
      let alpha = 0.2, width = 2, dash = null;
      if (lane.connecting && !lane.selected) { alpha = 0.5; dash = [6, 8]; }
      if (lane.selected) { alpha = 0.55 + 0.35 * Math.min(1, lane.selected / 3); width = 3.4; }
      if (cool && !lane.selected) { alpha = 0.4; dash = [3, 9]; }
      const winner = Math.max(0, 1 - (now - lane.winT) / 1200);
      if (lane.glow > 0.05) { context.shadowColor = rgba(colorLane, 0.9); context.shadowBlur = 10 * lane.glow; }
      line(lane.path.points, colorLane, alpha + winner * 0.3, width, dash, 0);
      context.shadowBlur = 0;
      const showGates = live || cool || now - lane.failT < 4000;
      for (let gate = 0; gate < 5; gate += 1) {
        const pulse = Math.max(0, 1 - (now - lane.gate[gate]) / 1800), x = GX[gate];
        context.beginPath(); context.arc(x, lane.y, 3 + pulse * 2.5, 0, Math.PI * 2);
        context.fillStyle = rgba(cool && !lane.selected ? COLORS.bad : colorLane,
          (showGates ? 0.25 : 0.12) + pulse * 0.7); context.fill();
        if (showGates && !compact) text(GN[gate], x, lane.y + (lane.y < 210 ? -12 : 19),
          9, COLORS.mute, 0.35 + pulse * 0.6);
      }
      const label = lane.selected ? `активен · ${lane.selected}`
        : lane.connecting ? "подключение" : cool ? "пауза" : "резерв";
      const titleOffset = compact ? (lane.y < 210 ? -20 : 20) : (lane.y < 210 ? -26 : 36);
      const stateOffset = compact ? (lane.y < 210 ? -42 : 42) : (lane.y < 210 ? -39 : 49);
      const labelX = portrait ? 350 + lane.index * 100 : 540;
      const stateX = portrait ? labelX + 24 : labelX;
      const labelAlign = portrait ? (lane.y < 210 ? "right" : "left") : "center";
      text(lane.name, labelX, lane.y + titleOffset, compact ? 10 : 13,
        COLORS.ink, live || cool ? 0.95 : 0.4, labelAlign);
      text(label, stateX, lane.y + stateOffset, compact ? 9 : 10,
        cool && !lane.selected ? COLORS.bad : colorLane, live || cool ? 0.9 : 0.35, labelAlign);
      if (cool) {
        const left = (lane.coolUntil - now) / COOL;
        const pulse = Math.max(0, 1 - (now - lane.failT) / 700);
        const skip = Math.max(0, 1 - (now - lane.skipT) / 600);
        context.save(); context.translate(540, lane.y); context.fillStyle = "#171813";
        context.beginPath(); context.arc(0, 0, 13, 0, Math.PI * 2); context.fill();
        context.strokeStyle = rgba(COLORS.bad, 0.18); context.lineWidth = 2.5;
        context.beginPath(); context.arc(0, 0, 13, 0, Math.PI * 2); context.stroke();
        context.strokeStyle = rgba(COLORS.bad, 0.9); context.beginPath();
        context.arc(0, 0, 13, -1.571, -1.571 + Math.PI * 2 * Math.max(0, Math.min(1, left))); context.stroke();
        const factor = 1 + 0.35 * pulse + 0.2 * skip; context.scale(factor, factor);
        context.lineWidth = 2.2; context.lineCap = "round"; context.beginPath();
        context.moveTo(-4.5, -4.5); context.lineTo(4.5, 4.5);
        context.moveTo(4.5, -4.5); context.lineTo(-4.5, 4.5); context.stroke(); context.restore();
        if (lane.failStage && canvasWidth >= 520) text(GN[lane.failStage - 1] || "MTP",
          560, lane.y + 4, 9, COLORS.bad, 0.9, "left");
      }
    }

    context.globalCompositeOperation = "lighter";
    for (const item of sessions.values()) for (const key of Object.keys(item.tries)) {
      const particle = item.tries[key], position = pointAt(particle.path, particle.f);
      const tint = particle.state === "fail" ? COLORS.bad
        : particle.state === "cancel" ? COLORS.rule : COLORS.sig;
      const pulse = 1 + 0.25 * Math.sin(now / 90);
      for (let tail = 1; tail <= 7; tail += 1) {
        const point = pointAt(particle.path, particle.f - tail * 0.012);
        context.beginPath(); context.arc(point[0], point[1], 3.2 * (1 - tail / 9), 0, Math.PI * 2);
        context.fillStyle = rgba(tint, 0.28 * (1 - tail / 8)); context.fill();
      }
      context.beginPath(); context.arc(position[0], position[1], 4.2 * pulse, 0, Math.PI * 2);
      context.shadowColor = rgba(tint, 1); context.shadowBlur = 12;
      context.fillStyle = rgba(tint, particle.state === "cancel" ? 0.35 : 0.95); context.fill();
      context.shadowBlur = 0;
    }
    for (const particle of parts) {
      const fraction = Math.min(1, (now - particle.t0) / particle.dur), eased = ease(fraction);
      const progress = particle.back ? 1 - eased : eased, point = pointAt(particle.path, progress);
      if (particle.kind === "pkt") {
        const next = pointAt(particle.path, progress + (particle.back ? -0.01 : 0.01));
        const angle = Math.atan2(next[1] - point[1], next[0] - point[0]);
        const normalX = -Math.sin(angle) * (particle.back ? 4 : -4);
        const normalY = Math.cos(angle) * (particle.back ? 4 : -4);
        context.save(); context.translate(point[0] + normalX, point[1] + normalY); context.rotate(angle);
        context.fillStyle = rgba(particle.back ? COLORS.ok : particle.lane.color,
          0.85 * Math.sin(Math.PI * Math.min(1, fraction * 1.05)));
        context.shadowColor = rgba(particle.back ? COLORS.ok : particle.lane.color, 1);
        context.shadowBlur = 12; context.fillRect(-particle.size / 2, -1.2, particle.size, 2.4);
        context.shadowBlur = 0; context.restore();
      } else if (particle.kind === "win") {
        context.beginPath(); context.arc(point[0], point[1], 5, 0, Math.PI * 2);
        context.fillStyle = rgba(COLORS.sig, 0.95);
        context.shadowColor = rgba(COLORS.sig, 1); context.shadowBlur = 16;
        context.fill(); context.shadowBlur = 0;
      } else if (particle.kind === "resp") {
        for (let tail = 0; tail < 8; tail += 1) {
          const pointTail = pointAt(particle.path, progress + (particle.back ? 1 : -1) * tail * 0.014);
          context.beginPath(); context.arc(pointTail[0], pointTail[1], 4.4 * (1 - tail / 9), 0, Math.PI * 2);
          context.fillStyle = rgba(COLORS.ok, 0.55 * (1 - tail / 8)); context.fill();
        }
        context.beginPath(); context.arc(point[0], point[1], 5, 0, Math.PI * 2);
        context.fillStyle = rgba(COLORS.ok, 1); context.shadowColor = rgba(COLORS.ok, 1);
        context.shadowBlur = 16; context.fill(); context.shadowBlur = 0;
        if (fraction > 0.97) {
          const number = api.telegramDcNumber(particle.item.dc);
          if (number) dcs[number - 1].ping = now;
        }
      }
    }
    for (const spark of sparks) {
      context.beginPath(); context.arc(spark.x, spark.y, 1.6, 0, Math.PI * 2);
      context.fillStyle = rgba(COLORS.bad, 0.8 * (1 - (now - spark.t0) / 800)); context.fill();
    }
    context.globalCompositeOperation = "source-over";

    dcs.forEach((dc, index) => {
      const age = (now - dc.ping) / 1400;
      if (age > 0 && age < 1) {
        const position = api.telegramDcPosition(index + 1); context.beginPath();
        context.arc(position[0], position[1], 10 + 34 * (1 - (1 - age) ** 3), 0, Math.PI * 2);
        context.strokeStyle = rgba(COLORS.ok, 0.5 * (1 - age)); context.lineWidth = 2; context.stroke();
      }
    });
    ripples.forEach(ripple => {
      const fraction = (now - ripple.t0) / ripple.dur;
      context.beginPath(); context.arc(ripple.x, ripple.y,
        ripple.r + 50 * (1 - (1 - fraction) ** 3), 0, Math.PI * 2);
      context.strokeStyle = rgba(ripple.color, 0.35 * (1 - fraction)); context.lineWidth = 2; context.stroke();
    });

    context.beginPath(); context.arc(CLI[0], CLI[1], 28, 0, Math.PI * 2);
    context.fillStyle = "#171813"; context.fill(); context.lineWidth = 2.5;
    context.strokeStyle = rgba(COLORS.sig, 0.45 + 0.55 * client.pulse);
    context.shadowColor = rgba(COLORS.sig, 1); context.shadowBlur = 14 * client.pulse;
    context.stroke(); context.shadowBlur = 0; context.strokeStyle = rgba(COLORS.ink, 0.85);
    context.lineWidth = 2; context.strokeRect(CLI[0] - 8, CLI[1] - 13, 16, 26);
    text("Клиент", CLI[0], CLI[1] + 52, 12, COLORS.ink, 0.75);

    const hubX = HUB[0], hubY = HUB[1], active = Math.min(1, sessions.size / 20);
    context.beginPath(); context.arc(hubX, hubY, 60, -1.571,
      -1.571 + Math.PI * 2 * Math.min(1, sessions.size / 40));
    context.strokeStyle = rgba(color, 0.28); context.lineWidth = 2; context.stroke();
    context.save(); context.translate(hubX, hubY);
    context.scale(1 + 0.07 * hub.pulse, 1 + 0.07 * hub.pulse);
    context.beginPath();
    for (let index = 0; index < 6; index += 1) {
      const angle = hub.angle + index * Math.PI / 3;
      context[index ? "lineTo" : "moveTo"](31 * Math.cos(angle), 31 * Math.sin(angle));
    }
    context.closePath(); context.fillStyle = "#171813"; context.fill(); context.lineWidth = 2.8;
    context.strokeStyle = rgba(color, 0.95); context.shadowColor = rgba(color, 1);
    context.shadowBlur = 6 + 10 * hub.pulse; context.stroke(); context.shadowBlur = 0;
    context.beginPath(); context.arc(0, 0, 5 + 2 * hub.pulse, 0, Math.PI * 2);
    context.fillStyle = rgba(COLORS.ink, 0.95); context.fill(); context.restore();
    Array.from(sessions.values()).forEach((item, index) => {
      const orbit = index % 2, angle = item.seed + t * (reduceMotion?.matches ? 0 : (orbit ? -0.68 : 0.5))
        + index * 2.399, radius = 45 + orbit * 8;
      const x = hubX + radius * Math.cos(angle), y = hubY + radius * Math.sin(angle);
      let tint = COLORS.mute, alpha = 0.4, dotRadius = 2.4;
      if (view.state === "stale") { tint = COLORS.rule; alpha = 0.3; }
      else if (item.responseSeen) { tint = COLORS.ok; alpha = 0.95; dotRadius = 2.8; }
      else if (item.selectedTransport) { tint = COLORS.sig; alpha = 0.9; }
      else if (item.stage === "routing") { tint = COLORS.sig; alpha = 0.35 + 0.5 * Math.abs(Math.sin(now / 130 + index)); }
      else if (item.stage === "upstream_ready") { tint = COLORS.sig; alpha = 0.9; }
      context.beginPath(); context.arc(x, y, dotRadius, 0, Math.PI * 2);
      context.fillStyle = rgba(tint, alpha);
      if (item.responseSeen) { context.shadowColor = rgba(tint, 1); context.shadowBlur = 6; }
      context.fill(); context.shadowBlur = 0;
    });
    text("d2o", hubX, hubY + 86, 12, COLORS.ink, 0.75);
    setSceneTransform();
  }

  function animate(delta) {
    hub.pulse *= Math.exp(-delta * 2.4); client.pulse *= Math.exp(-delta * 2.2);
    if (!reduceMotion?.matches) hub.angle += delta * (0.12 + 0.25 * hub.pulse);
    for (const lane of lanes) { lane.selected = Number(lane.counts.selected) || 0;
      lane.connecting = (Number(lane.counts.connecting) || 0) + (Number(lane.counts.race) || 0); }
    for (const item of sessions.values()) for (const key of Object.keys(item.tries)) {
      const particle = item.tries[key], lane = particle.lane, age = now - particle.t0;
      if (particle.state === "run") {
        particle.f = lane.gates[0] * 0.55
          + (lane.gates[4] - lane.gates[0] * 0.55) * (1 - Math.exp(-age / 1100)) * 0.92;
      } else if (particle.state === "ok") particle.f += (1 - particle.f) * Math.min(1, delta * 7);
      else if (particle.state === "fail") {
        const stop = particle.gate === null ? lane.gates[0] * 0.55 : lane.gates[particle.gate] - 0.004;
        particle.f += (stop - particle.f) * Math.min(1, delta * 6);
        if (particle.gate !== null && !particle.sparked
            && Math.abs(lane.gates[particle.gate] - particle.f) < 0.02) {
          particle.sparked = true;
          const point = pointAt(lane.path, particle.f);
          for (let count = 0; count < 7 && sparks.length < 8; count += 1) {
            const angle = Math.random() * Math.PI * 2, speed = 20 + Math.random() * 40;
            sparks.push({ x: point[0], y: point[1], vx: Math.cos(angle) * speed,
              vy: Math.sin(angle) * speed, t0: now });
          }
        }
      } else if (particle.state === "cancel") particle.f -= delta * 0.5;
      for (let gate = 0; gate < 5; gate += 1) {
        if (particle.gate !== null && particle.f >= lane.gates[gate] - 0.002 && particle.state !== "cancel")
          lane.gate[gate] = Math.max(lane.gate[gate], now);
      }
      if ((particle.state === "ok" && particle.f > 0.985)
          || (particle.state === "cancel" && now - particle.ft > 600)
          || (particle.state === "fail" && now - particle.ft > 1800)) delete item.tries[key];
    }
    for (let index = parts.length - 1; index >= 0; index -= 1) {
      const part = parts[index];
      if (now - part.t0 < part.dur) continue;
      if (part.kind === "resp") {
        client.pulse = 1; spikes.push(now);
        const number = api.telegramDcNumber(part.item.dc);
        if (number) dcs[number - 1].ping = now;
        ripples.push({ x: CLI[0], y: CLI[1], t0: now, color: COLORS.ok, r: 30, dur: 1200 });
      } else if (part.kind === "pkt" && part.back && Number.isInteger(part.dc) && part.dc >= 1 && part.dc <= 5) {
        client.pulse = 1; spikes.push(now);
        dcs[part.dc - 1].ping = now;
      }
      parts.splice(index, 1);
    }
    for (let index = sparks.length - 1; index >= 0; index -= 1) {
      const spark = sparks[index]; spark.x += spark.vx * delta; spark.y += spark.vy * delta;
      spark.vx *= 0.94; spark.vy *= 0.94; if (now - spark.t0 > 800) sparks.splice(index, 1);
    }
    for (let index = ripples.length - 1; index >= 0; index -= 1)
      if (now - ripples[index].t0 > ripples[index].dur) ripples.splice(index, 1);
    for (let index = spikes.length - 1; index >= 0; index -= 1)
      if (now - spikes[index] > 1400) spikes.splice(index, 1);
  }

  function frame(timestamp) {
    frameId = 0;
    if (destroyed || view.state === "stale" || !inView || document.hidden || reduceMotion?.matches) return;
    const delta = Math.min(0.05, Math.max(0, (timestamp - lastFrame) / 1000));
    lastFrame = timestamp; now += delta * 1000; animate(delta); draw(); startLoop();
  }
  function startLoop() {
    if (!destroyed && view.state !== "stale" && !frameId && inView && !document.hidden && !reduceMotion?.matches)
      frameId = global.requestAnimationFrame(frame);
  }
  function stopLoop() { if (frameId) global.cancelAnimationFrame(frameId); frameId = 0; }
  function resize() {
    if (destroyed) return;
    const rect = canvas.getBoundingClientRect();
    canvasWidth = rect.width || 900;
    pixelRatio = Math.min(2.5, Math.max(1, global.devicePixelRatio || 1));
    const portrait = canvasWidth < PORTRAIT_WIDTH;
    const aspectRatio = portrait ? H + " / " + W : W + " / " + H;
    if (canvas.style.aspectRatio !== aspectRatio) canvas.style.aspectRatio = aspectRatio;
    canvas.width = Math.round(canvasWidth * pixelRatio);
    canvas.height = Math.round(canvasWidth * pixelRatio * (portrait ? W / H : H / W));
    draw(); startLoop();
  }
  function onVisibility() { if (document.hidden) stopLoop(); else startLoop(); }
  function onIntersection(entries) { inView = Boolean(entries[0]?.isIntersecting); inView ? startLoop() : stopLoop(); }
  function onMotionChange() { if (reduceMotion?.matches) stopLoop(); else startLoop(); draw(); }
  const resizeObserver = typeof global.ResizeObserver === "function" ? new global.ResizeObserver(resize) : null;
  const intersectionObserver = typeof global.IntersectionObserver === "function"
    ? new global.IntersectionObserver(onIntersection, { rootMargin: "80px" }) : null;
  resizeObserver?.observe(canvas); intersectionObserver?.observe(canvas);
  global.addEventListener("resize", resize, { passive: true });
  document.addEventListener("visibilitychange", onVisibility);
  reduceMotion?.addEventListener("change", onMotionChange);
  resize();

  return {
    update,
    attach() { if (!destroyed && canvas.isConnected) resize(); },
    destroy() {
      if (destroyed) return;
      destroyed = true; stopLoop(); resizeObserver?.disconnect(); intersectionObserver?.disconnect();
      global.removeEventListener("resize", resize); document.removeEventListener("visibilitychange", onVisibility);
      reduceMotion?.removeEventListener("change", onMotionChange);
      cursors.clear(); sessions.clear(); previousTraffic.clear(); parts.length = 0;
      sparks.length = 0; ripples.length = 0; spikes.length = 0;
    },
  };
}

function ease(progress) {
  return progress < 0.5 ? 4 * progress ** 3 : 1 - ((-2 * progress + 2) ** 3) / 2;
}

global.D2kTelegramPrototype = { mountTelegramFlow };
})(typeof window !== "undefined" ? window : globalThis);
