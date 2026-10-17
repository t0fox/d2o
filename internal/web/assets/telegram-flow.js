(function (global) {
"use strict";

const PROTOTYPE_GEOMETRY = Object.freeze({
  width: 900,
  height: 420,
  client: Object.freeze([70, 210]),
  hub: Object.freeze([300, 210]),
  collector: Object.freeze([720, 210]),
  laneY: Object.freeze([62, 148, 272, 358]),
  gateX: Object.freeze([465, 500, 535, 570, 605]),
  dcPositions: Object.freeze([[802, 70], [816, 140], [830, 210], [816, 280], [802, 350]]
    .map(position => Object.freeze(position))),
});
const WIDTH = PROTOTYPE_GEOMETRY.width;
const HEIGHT = PROTOTYPE_GEOMETRY.height;
const CLIENT = PROTOTYPE_GEOMETRY.client;
const ROUTE_HUB = PROTOTYPE_GEOMETRY.hub;
const TELEGRAM_HUB = PROTOTYPE_GEOMETRY.collector;
const MOTION = Object.freeze({
  maxParticles: 12,
  maxSparks: 8,
  maxRipples: 6,
  attemptDurationMs: 1100,
  failureDurationMs: 1800,
  responseDurationMs: 1100,
  winnerDurationMs: 900,
  upstreamDurationMs: 300,
  sparkDurationMs: 800,
  fadeDurationMs: 600,
  rippleDurationMs: 1200,
});
const LANE_Y = PROTOTYPE_GEOMETRY.laneY;
const GATE_NAMES = ["DNS", "TCP", "TLS", "WS", "MTP"];
const GATE_ACCESSIBLE_NAMES = ["DNS", "TCP", "TLS", "WS", "MTProto"];
const GATE_X = PROTOTYPE_GEOMETRY.gateX;
const TELEGRAM_DCS = PROTOTYPE_GEOMETRY.dcPositions;
const TELEGRAM_DC_PATHS = TELEGRAM_DCS.map(position => makePath([TELEGRAM_HUB, position]));
const MAX_PARTICLES = MOTION.maxParticles;
const MAX_SPARKS = MOTION.maxSparks;
const MAX_RIPPLES = MOTION.maxRipples;

const ROUTES = [
  { transport: "direct_wss", label: "Прямой WSS" },
  { transport: "cloudflare_worker", label: "Cloudflare Worker" },
  { transport: "cloudflare_proxy", label: "Прокси Cloudflare" },
  { transport: "tcp_passthrough", label: "Прямой TCP · диагностика" },
];

const TRANSPORT_TO_LANE = new Map([
  ["direct_wss", 0],
  ["cloudflare_worker", 1],
  ["cloudflare_proxy", 2],
  ["tcp_passthrough", 3],
]);

const STATE_LABELS = {
  idle: "резерв",
  connecting: "подключение",
  connected: "upstream готов",
  selected: "активен",
  race: "гонка",
  cooldown: "на паузе",
  failed: "отказ",
  cancelled: "отменён",
  skipped: "пропуск",
};

const STATUS_ORDER = ["selected", "race", "connecting", "connected", "cooldown", "failed", "cancelled", "skipped"];
const VISIBLE_ROUTE_STATES = new Set(["selected", "race", "connecting", "connected", "cooldown", "failed", "cancelled"]);

function sessionOrbState(session) {
  const stage = session?.stage;
  return ["accepted", "routing", "upstream_ready", "first_wss_binary_response"].includes(stage)
    ? stage : "unknown";
}

function telegramDcNumber(dc) {
  const number = Number(dc);
  if (number === 203) return 2;
  return Number.isInteger(number) && number >= 1 && number <= 5 ? number : null;
}

function telegramDcActivity(sessions) {
  const dcs = Array.from({ length: 5 }, () => ({ active: 0, media: 0, confirmed: 0 }));
  (Array.isArray(sessions) ? sessions : []).forEach(session => {
    const dc = telegramDcNumber(session?.dc);
    if (!dc) return;
    const current = dcs[dc - 1];
    current.active += 1;
    if (session.is_media === true) current.media += 1;
    if (session.telegram_response_seen === true) current.confirmed += 1;
  });
  return dcs;
}

function failureGateIndex(stage) {
  const value = Number(stage);
  return Number.isInteger(value) && value >= 1 && value <= 5 ? value - 1 : null;
}

function normalizeCooldowns(snapshot) {
  if (!Array.isArray(snapshot?.route_cooldowns)) return [];
  return snapshot.route_cooldowns.flatMap(cooldown => {
    const remainingMs = Number(cooldown?.remaining_ms);
    const lane = transportLane(cooldown?.transport);
    if (lane < 0 || !Number.isFinite(remainingMs) || remainingMs <= 0) return [];
    const dc = telegramDcNumber(cooldown.dc);
    return [{ dc, isMedia: cooldown.is_media === true,
      transport: cooldown.transport, remainingMs,
      failureStage: Number(cooldown.failure_stage) || 0 }];
  });
}

function applyCooldowns(lanes, cooldowns) {
  cooldowns.forEach(cooldown => {
    const lane = lanes[transportLane(cooldown.transport)];
    if (!lane) return;
    const newestCooldown = cooldown.remainingMs >= (lane.cooldownRemainingMs || 0);
    lane.cooldownCount = (lane.cooldownCount || 0) + 1;
    lane.cooldownRemainingMs = Math.max(lane.cooldownRemainingMs || 0, cooldown.remainingMs);
    lane.cooldownDcNumbers = [...new Set([...(lane.cooldownDcNumbers || []), cooldown.dc].filter(Number.isInteger))];
    if (newestCooldown) lane.failureStage = cooldown.failureStage || lane.failureStage || 0;
    if (lane.status === "idle") lane.status = "cooldown";
  });
  return lanes;
}

function bezier(start, control1, control2, end, progress) {
  const inverse = 1 - progress;
  const weights = [inverse ** 3, 3 * inverse ** 2 * progress, 3 * inverse * progress ** 2, progress ** 3];
  return [0, 1].map(axis => start[axis] * weights[0] + control1[axis] * weights[1]
    + control2[axis] * weights[2] + end[axis] * weights[3]);
}

function makeLanePath(y) {
  const points = [];
  for (let index = 1; index <= 22; index += 1) {
    points.push(bezier(ROUTE_HUB, [360, 210], [380, y], [440, y], index / 22));
  }
  points.push([620, y]);
  for (let index = 1; index <= 22; index += 1) {
    points.push(bezier([620, y], [680, y], [670, 210], TELEGRAM_HUB, index / 22));
  }
  return makePath(points);
}

function makePath(points) {
  const cumulative = [0];
  for (let index = 1; index < points.length; index += 1) {
    cumulative.push(cumulative[index - 1]
      + Math.hypot(points[index][0] - points[index - 1][0], points[index][1] - points[index - 1][1]));
  }
  return { points, cumulative, length: cumulative[cumulative.length - 1] };
}

function fractionAtX(path, targetX) {
  for (let index = 1; index < path.points.length; index += 1) {
    const left = path.points[index - 1], right = path.points[index];
    if (right[0] < targetX) continue;
    const part = (targetX - left[0]) / (right[0] - left[0] || 1);
    return (path.cumulative[index - 1]
      + (path.cumulative[index] - path.cumulative[index - 1]) * part) / path.length;
  }
  return 1;
}

function composeFlowPoints(routePoints, clientToHubPoints, direction) {
  if (direction === "response") {
    return [...routePoints.slice().reverse(), ...clientToHubPoints.slice(0, -1).reverse()];
  }
  if (direction === "request") return [...clientToHubPoints, ...routePoints.slice(1)];
  return routePoints;
}

function pointAt(path, fraction) {
  const distance = Math.max(0, Math.min(1, fraction)) * path.length;
  let low = 0;
  let high = path.cumulative.length - 1;
  while (high - low > 1) {
    const middle = (low + high) >> 1;
    if (path.cumulative[middle] < distance) low = middle;
    else high = middle;
  }
  const segmentLength = path.cumulative[high] - path.cumulative[low] || 1;
  const progress = (distance - path.cumulative[low]) / segmentLength;
  return [0, 1].map(axis => path.points[low][axis]
    + (path.points[high][axis] - path.points[low][axis]) * progress);
}

function ease(progress) {
  return progress < 0.5 ? 4 * progress ** 3 : 1 - ((-2 * progress + 2) ** 3) / 2;
}

function cssColorToRgb(color, fallback, scope) {
  const probe = document.createElement("span");
  probe.style.color = color;
  probe.setAttribute("aria-hidden", "true");
  probe.style.position = "absolute";
  probe.style.visibility = "hidden";
  (scope && scope.appendChild ? scope : document.body).appendChild(probe);
  const normalized = window.getComputedStyle(probe).color;
  probe.remove();
  const channels = normalized.match(/[\d.]+/g);
  if (!channels || channels.length < 3) return fallback;
  return channels.slice(0, 3).map(value => Number(value));
}

function transportLane(transport) {
  return TRANSPORT_TO_LANE.has(transport) ? TRANSPORT_TO_LANE.get(transport) : -1;
}

function routeState(value) {
  return Object.hasOwn(STATE_LABELS, value) ? value : "idle";
}

function visibleRouteLanes(view) {
  if (!Array.isArray(view?.lanes)) return [];
  return view.lanes.filter(lane => Object.entries(lane.counts || {})
    .some(([state, count]) => VISIBLE_ROUTE_STATES.has(state) && Number(count) > 0)
      || Number(lane.cooldownCount) > 0);
}

function eventState(value) {
  if (value === "first_binary_response") return "selected";
  return routeState(value);
}

function routeDescription(transport, lane) {
  if (transport === "tcp_passthrough") return "Прямой TCP passthrough";
  return ROUTES[lane]?.label || "WSS-транспорт не определён";
}

function latestRouteFailure(snapshot) {
  const stage = Number(snapshot?.last_failure_stage) || 0;
  const successDc = Number(snapshot?.last_success_dc) || 0;
  const failureAge = Number(snapshot?.last_failure_age_ms);
  const successAge = Number(snapshot?.last_success_age_ms);
  if (!stage || !Number.isFinite(failureAge) ||
      (successDc && Number.isFinite(successAge) && failureAge > successAge)) return null;
  const routes = {
    1: [0, "Прямой WSS"],
    2: [1, "Cloudflare Worker"],
    3: [2, "Прокси Cloudflare"],
    4: [3, "Прямой TCP (диагностика)"],
  };
  const stages = {
    1: "DNS",
    2: "TCP",
    3: "TLS",
    4: "WebSocket",
    5: "MTProto",
    6: "Настройка маршрута",
    7: "WSS-маршрут недоступен",
  };
  const route = routes[Number(snapshot?.last_failure_route)] || [-1, "WSS-маршрут"];
  const dc = Number(snapshot?.last_failure_dc) || 0;
  return {
    lane: route[0], route: route[1], stage: stages[stage] || "Ошибка соединения",
    dc: dc ? `DC${dc}` : "DC неизвестен",
  };
}

function hasCurrentRouteFailure(snapshot) {
  return Math.max(0, Number(snapshot?.active_connections) || 0) === 0
    && latestRouteFailure(snapshot) !== null;
}

function selectedLaneFor(session) {
  return session?.selected_transport ? transportLane(session.selected_transport) : -1;
}

function laneStatesForSession(session) {
  const states = ROUTES.map(() => "idle");
  const transports = ROUTES.map(route => route.transport);
  let directLane = transportLane(session.direct_transport);
  let fallbackLane = transportLane(session.fallback_transport);
  if (directLane >= 0) {
    transports[directLane] = session.direct_transport;
    states[directLane] = routeState(session.direct_state);
  }
  if (fallbackLane >= 0) {
    transports[fallbackLane] = session.fallback_transport;
    states[fallbackLane] = routeState(session.fallback_state);
  }
  (session.events || []).forEach(event => {
    const lane = transportLane(event.transport);
    if (lane >= 0) {
      transports[lane] = event.transport;
      states[lane] = eventState(event.state);
    }
  });
  const selectedLane = selectedLaneFor(session);
  if (selectedLane >= 0) {
    transports[selectedLane] = session.selected_transport;
    states[selectedLane] = "selected";
  }
  const connecting = states.map((state, lane) => state === "connecting" ? lane : -1).filter(lane => lane >= 0);
  if (connecting.length > 1) connecting.forEach(lane => { states[lane] = "race"; });
  return { states, transports, connecting: connecting.length > 1, selectedLane };
}

function summarize(snapshot, error) {
  if (error) {
    return {
      state: "unavailable", caption: "Статистика маршрутов недоступна", transportLabel: "Недоступно",
      dcLabel: "DC неизвестен", lanes: ROUTES.map(route => ({ ...route, status: "idle", counts: {} })),
      sessions: [], truncated: false, hedged: [], activeConnections: 0,
      acceptedConnections: 0, mediaSessions: 0, cooldowns: [], cooldownDurationMs: 0,
      dcActivity: telegramDcActivity([]),
    };
  }

  const activeConnections = Math.max(0, Number(snapshot?.active_connections) || 0);
  const sessions = Array.isArray(snapshot?.active_sessions) ? snapshot.active_sessions.slice(0, 64) : [];
  const cooldowns = normalizeCooldowns(snapshot);
  const cooldownDurationMs = Math.max(0, Number(snapshot?.route_cooldown_ms) || 0);
  const emptyLanes = ROUTES.map(route => ({ ...route, status: "idle", counts: {} }));
  if (activeConnections === 0) {
    const failure = latestRouteFailure(snapshot);
    const lanes = applyCooldowns(emptyLanes, cooldowns);
    if (failure) {
      if (failure.lane >= 0) {
        lanes[failure.lane].status = "failed";
        lanes[failure.lane].counts.failed = (lanes[failure.lane].counts.failed || 0) + 1;
        lanes[failure.lane].failureStage = Number(snapshot?.last_failure_stage) || 0;
        lanes[failure.lane].failureAgeMs = Number(snapshot?.last_failure_age_ms) || 0;
      }
      return {
        state: "unavailable",
        caption: `Последняя ошибка: ${failure.stage} · ${failure.dc} · ${failure.route}`,
        transportLabel: "Недоступно", dcLabel: failure.dc, lanes, sessions: [],
        truncated: Boolean(snapshot?.route_sessions_truncated), hedged: [], activeConnections,
        acceptedConnections: Number(snapshot?.accepted_connections) || 0, mediaSessions: 0,
        cooldowns, cooldownDurationMs, dcActivity: telegramDcActivity([]),
      };
    }
    return {
      state: cooldowns.length ? "cooling" : "idle",
      caption: cooldowns.length ? "Нет активных сессий · часть маршрутов на паузе" : "Нет активных соединений",
      transportLabel: cooldowns.length ? "Маршруты на паузе" : "Нет подключений",
      dcLabel: "DC неизвестен", lanes, sessions: [],
      truncated: Boolean(snapshot?.route_sessions_truncated), hedged: [], activeConnections,
      acceptedConnections: Number(snapshot?.accepted_connections) || 0, mediaSessions: 0,
      cooldowns, cooldownDurationMs, dcActivity: telegramDcActivity([]),
    };
  }
  if (!Array.isArray(snapshot?.active_sessions) || !sessions.length) {
    applyCooldowns(emptyLanes, cooldowns);
    return {
      state: "unavailable", caption: "Активные соединения есть, маршрут пока не определён", transportLabel: "Определяется",
      dcLabel: "DC неизвестен", lanes: emptyLanes, sessions: [],
      truncated: Boolean(snapshot?.route_sessions_truncated), hedged: [], activeConnections,
      acceptedConnections: Number(snapshot?.accepted_connections) || 0, mediaSessions: 0,
      cooldowns, cooldownDurationMs, dcActivity: telegramDcActivity([]),
    };
  }

  const counts = ROUTES.map(() => Object.create(null));
  const sessionViews = sessions.map(session => {
    const view = laneStatesForSession(session);
    view.states.forEach((state, lane) => {
      if (state !== "idle") counts[lane][state] = (counts[lane][state] || 0) + 1;
    });
    return { session, ...view };
  });
  const lanes = ROUTES.map((route, index) => {
    const laneCounts = counts[index];
    const status = STATUS_ORDER.find(value => laneCounts[value]) || "idle";
    const transports = [...new Set(sessionViews
      .filter(session => session.states[index] !== "idle")
      .map(session => session.transports[index]).filter(Boolean))];
    const label = transports.length === 1 ? routeDescription(transports[0], index) : route.label;
    return { ...route, label, status, counts: laneCounts };
  });
  applyCooldowns(lanes, cooldowns);
  lanes.forEach(lane => {
    if (lane.cooldownCount) lane.failureAgeMs = Math.max(0, cooldownDurationMs - lane.cooldownRemainingMs);
  });
  sessionViews.forEach(({ session }) => {
    (Array.isArray(session.events) ? session.events : []).forEach(event => {
      if (event.state !== "failed") return;
      const lane = lanes[transportLane(event.transport)];
      const ageMs = Number(event.age_ms);
      if (!lane || !Number.isFinite(ageMs)) return;
      if (!Number.isFinite(lane.failureAgeMs) || ageMs <= lane.failureAgeMs) {
        lane.failureAgeMs = ageMs;
        lane.failureStage = Number(event.failure_stage) || 0;
      }
    });
    const laneIndex = selectedLaneFor(session);
    if (laneIndex < 0 || !session.selected_transport || session.selected_transport.startsWith("tcp_")) return;
    const lane = lanes[laneIndex];
    lane.passedGate = Math.max(lane.passedGate || 0,
      session.stage === "first_wss_binary_response" ? 5
        : session.stage === "upstream_ready" ? 4 : 0);
  });
  const selectedLanes = lanes.filter(lane => lane.counts.selected);
  const connectingLanes = lanes.filter(lane => lane.counts.connecting || lane.counts.race);
  const failedLanes = lanes.filter(lane => lane.counts.failed || lane.counts.cooldown);
  const dcValues = new Set(sessions
    .map(({ dc }) => telegramDcNumber(dc))
    .filter(Number.isInteger));
  const mediaSessions = sessions.filter(session => session.is_media === true).length;
  const dcLabel = dcValues.size === 1 ? `DC${[...dcValues][0]}${mediaSessions ? ` · media ${mediaSessions}` : ""}`
    : dcValues.size > 1 ? `Несколько DC · media ${mediaSessions}` : "DC неизвестен";
  const transportLabel = selectedLanes.length > 1 ? "Несколько маршрутов"
    : selectedLanes.length === 1 ? selectedLanes[0].label
      : connectingLanes.length === 1 ? connectingLanes[0].label
        : connectingLanes.length > 1 ? "Несколько попыток" : failedLanes.length ? "Недоступно" : "Определяется";
  const selectedTransportKeys = new Set(sessionViews.map(({ session }) => session.selected_transport).filter(Boolean));
  const mixedRoutes = selectedTransportKeys.size > 1;
  const hedged = sessionViews.flatMap(view => {
    if (!view.connecting && view.selectedLane < 0) return [];
    const hadTwoAttempts = (view.session.events || []).some((event, eventIndex, events) => event.state === "connecting"
      && events.slice(eventIndex + 1).some(next => next.state === "connecting"
        && transportLane(next.transport) >= 0 && transportLane(next.transport) !== transportLane(event.transport)));
    const cancelled = view.states.map((state, lane) => state === "cancelled" ? lane : -1).filter(lane => lane >= 0);
    return hadTwoAttempts && view.selectedLane >= 0 && cancelled.length
      ? [{ winner: routeDescription(view.session.selected_transport, view.selectedLane),
        losers: cancelled.map(lane => ROUTES[lane].label) }]
      : [];
  });
  const anyConnecting = sessionViews.some(view => view.states.some(state => state === "connecting" || state === "race"));
  const anySelected = selectedLanes.length > 0;
  const allFailed = !anySelected && !anyConnecting && failedLanes.length > 0
    && lanes.every(lane => ["idle", "failed", "cooldown", "cancelled", "skipped"].includes(lane.status));
  const state = anySelected ? (mixedRoutes ? "mixed" : "active")
    : anyConnecting ? (sessionViews.some(view => view.connecting) ? "race" : "searching")
      : allFailed ? "unavailable" : "searching";
  const caption = hedged.length
    ? `Параллельная гонка: победил ${hedged[0].winner}, остальные попытки отменены · ${dcLabel}`
    : mixedRoutes ? `Сессии используют разные маршруты · ${dcLabel}`
      : selectedLanes.length > 1 ? `Активны несколько маршрутов · ${dcLabel}`
        : anySelected ? `Выбран маршрут ${selectedLanes[0].label} · ${dcLabel}`
          : anyConnecting ? (sessionViews.some(view => view.connecting)
            ? `Идёт параллельная гонка маршрутов · ${dcLabel}` : `Прокси устанавливает соединение · ${dcLabel}`)
            : allFailed ? `Для активных соединений маршрут недоступен · ${dcLabel}`
              : `Маршрут определяется · ${dcLabel}`;

  return {
    state, caption, transportLabel, dcLabel, lanes, sessions,
    truncated: Boolean(snapshot.route_sessions_truncated), hedged, activeConnections,
    acceptedConnections: Number(snapshot.accepted_connections) || 0, mediaSessions,
    cooldowns, cooldownDurationMs, dcActivity: telegramDcActivity(sessions),
  };
}

function mountTelegramFlow(canvas) {
  const context = canvas.getContext("2d", { alpha: false });
  if (!context) throw new Error("Canvas 2D недоступен для схемы Telegram");
  const root = canvas.closest(".tg-flow");
  const incomingPath = makePath([CLIENT, ROUTE_HUB]);
  const responsePath = makePath(incomingPath.points.slice().reverse());
  const lanes = ROUTES.map((route, index) => {
    const path = makeLanePath(LANE_Y[index]);
    return {
      ...route, index, path, color: [100, 125, 128], targetColor: [100, 125, 128],
      gateProgress: GATE_X.map(x => fractionAtX(path, x)),
      gatePulses: Array(GATE_NAMES.length).fill(0),
      alpha: 0.22, targetAlpha: 0.22, glow: 0, targetGlow: 0, status: "idle", counts: {}, markerPulse: 0,
    };
  });
  const hub = { angle: 0, pulse: 0, spin: 0 };
  const client = { pulse: 0 };
  const particles = [];
  const trafficParticles = [];
  const sparks = [];
  const ripples = [];
  const ecgBeats = [];
  const cursors = new Map();
  const activeParticles = new Map();
  let currentView = summarize(null, "");
  let processStartedAt = 0;
  let acceptedConnections = null;
  let trafficProcessStartedAt = 0;
  let previousTrafficBytes = null;
  let pixelRatio = 1;
  let scaleX = 1;
  let scaleY = 1;
  let inView = true;
  let destroyed = false;
  let frameId = 0;
  let lastFrame = 0;
  let paletteInitialized = false;
  const motionPreference = window.matchMedia?.("(prefers-reduced-motion: reduce)") || null;
  const darkPreference = window.matchMedia?.("(prefers-color-scheme: dark)") || null;

  const fallbackColors = {
    line: [100, 125, 128],
    text: [230, 237, 240],
    muted: [127, 146, 150],
    accent: [45, 212, 160],
    failure: [239, 91, 91],
    background: [13, 20, 22],
  };
  const palette = { ...fallbackColors, direct: fallbackColors.accent, cloudflare: fallbackColors.muted, tcp: fallbackColors.muted };

  function readColor(name, fallback) {
    const value = window.getComputedStyle(canvas).getPropertyValue(name).trim();
    const scope = canvas.isConnected
      ? canvas.closest(".tg-flow") || canvas.parentElement || document.body
      : document.documentElement;
    return cssColorToRgb(value || `rgb(${fallback.join(",")})`, fallback, scope);
  }

  function refreshPalette() {
    palette.line = readColor("--tg-flow-line", fallbackColors.line);
    palette.text = readColor("--tg-flow-text", fallbackColors.text);
    palette.muted = readColor("--tg-flow-muted", fallbackColors.muted);
    palette.accent = readColor("--tg-flow-accent", fallbackColors.accent);
    palette.failure = readColor("--tg-flow-failure", fallbackColors.failure);
    palette.background = readColor("--tg-flow-background", fallbackColors.background);
    palette.direct = readColor("--tg-flow-direct", fallbackColors.accent);
    palette.cloudflare = readColor("--tg-flow-cloudflare", fallbackColors.muted);
    palette.tcp = readColor("--tg-flow-tcp", fallbackColors.muted);
    lanes.forEach(lane => {
      lane.targetColor = laneColor(lane);
      if (!paletteInitialized || motionPreference?.matches) lane.color = [...lane.targetColor];
    });
    paletteInitialized = true;
  }

  function laneColor(lane) {
    if (lane.status === "failed") return palette.failure;
    if (lane.status === "idle") return palette.line;
    if (lane.status === "cooldown" || lane.status === "cancelled" || lane.status === "skipped") return palette.muted;
    if (lane.status === "selected" && currentView.sessions.some(session =>
      session.selected_transport === lane.transport && session.telegram_response_seen === true))
      return palette.direct;
    if (lane.transport === "tcp_passthrough") return palette.tcp;
    return palette.cloudflare;
  }

  function configureLane(lane, view) {
    const next = view.lanes[lane.index];
    const nextStatus = next?.status || "idle";
    const nextTransport = next?.transport || lane.transport;
    const nextColor = laneColor({ ...lane, status: nextStatus, transport: nextTransport });
    lane.counts = next?.counts || {};
    lane.passedGate = Number(next?.passedGate) || 0;
    lane.failureStage = Number(next?.failureStage) || 0;
    lane.failureAgeMs = Number.isFinite(Number(next?.failureAgeMs)) ? Number(next.failureAgeMs) : null;
    lane.cooldownCount = Number(next?.cooldownCount) || 0;
    lane.cooldownRemainingMs = Number(next?.cooldownRemainingMs) || 0;
    lane.cooldownUpdatedAt = performance.now();
    lane.cooldownDcNumbers = next?.cooldownDcNumbers || [];
    const colorUnchanged = lane.targetColor.every((channel, index) => channel === nextColor[index]);
    if (lane.status === nextStatus && lane.transport === nextTransport && colorUnchanged) return;
    lane.status = nextStatus;
    lane.transport = nextTransport;
    lane.targetColor = nextColor;
    lane.targetAlpha = nextStatus === "idle" ? 0.22
      : nextStatus === "cancelled" || nextStatus === "skipped" ? 0.3 : nextStatus === "selected" ? 0.78 : 0.55;
    const routeActive = ["selected", "connected", "connecting", "race"].includes(nextStatus);
    lane.targetGlow = nextStatus === "selected" ? 0.68 : routeActive ? 0.34 : 0;
    if (nextStatus === "failed") lane.markerPulse = 1;
    if (motionPreference?.matches) {
      lane.color = [...lane.targetColor];
      lane.alpha = lane.targetAlpha;
      lane.glow = lane.targetGlow;
      lane.markerPulse = 0;
    }
  }

function combinedPath(laneIndex, direction, dc) {
    const route = lanes[laneIndex].path.points;
    const dcNumber = telegramDcNumber(dc);
    const pathToDc = dcNumber ? [...route, TELEGRAM_DCS[dcNumber - 1]] : route;
    return makePath(composeFlowPoints(pathToDc, incomingPath.points,
      direction || "route"));
  }

  function addParticle(sessionId, laneIndex, now, options = {}) {
    if (motionPreference?.matches || laneIndex < 0 || particles.length >= MAX_PARTICLES) return null;
  const path = combinedPath(laneIndex, options.direction, options.dc);
  const lane = lanes[laneIndex];
  const dcNumber = telegramDcNumber(options.dc);
  const routeLength = dcNumber
    ? makePath([...lane.path.points, TELEGRAM_DCS[dcNumber - 1]]).length : lane.path.length;
  const gateProgress = lane.gateProgress.map(progress => options.direction === "response"
    ? (routeLength - lane.path.length * progress) / (routeLength + incomingPath.length)
    : lane.path.length * progress / routeLength);
    const particle = {
      sessionId,
      laneIndex,
      path,
      gateProgress,
      fraction: 0,
      startedAt: options.startedAt ?? now,
      duration: options.duration || MOTION.attemptDurationMs,
      stopAt: options.stopAt ?? null,
      kind: options.kind || "attempt",
      fadeAt: 0,
      settleStartedAt: 0,
      settleFrom: 0,
      x: path.points[0][0],
      y: path.points[0][1],
      opacity: 1,
      radius: 2,
      trail: [],
      color: options.kind === "failure" ? palette.failure : lanes[laneIndex].targetColor,
    };
    particles.push(particle);
    if (options.track !== false) activeParticles.set(`${sessionId}:${laneIndex}`, particle);
    return particle;
  }

function launchFailure(sessionId, laneIndex, now, failureStage, dc) {
  fadeAttempt(sessionId, laneIndex, now);
  const lane = lanes[laneIndex];
  lane.failureStage = Number(failureStage) || 0;
  const gate = failureGateIndex(failureStage);
  if (gate !== null) lane.gatePulses[gate] = Math.max(lane.gatePulses[gate], 1);
  const routeProgress = gate === null ? 0.03 : lane.gateProgress[gate];
  const dcNumber = telegramDcNumber(dc);
  const routeLength = dcNumber
    ? makePath([...lane.path.points, TELEGRAM_DCS[dcNumber - 1]]).length : lane.path.length;
  const stopAt = lane.path.length * routeProgress / routeLength;
  addParticle(sessionId, laneIndex, now, {
    startedAt: now, duration: MOTION.failureDurationMs,
    stopAt, kind: "failure", track: false, dc,
  });
  }

  function fadeAttempt(sessionId, laneIndex, now) {
    const particle = activeParticles.get(`${sessionId}:${laneIndex}`);
    if (particle && !particle.fadeAt) particle.fadeAt = now;
  }

  function processEvent(session, event, now) {
    const laneIndex = transportLane(event.transport);
    if (laneIndex < 0) return;
  const eventAge = Number(event.age_ms);
  const eventAt = Number.isFinite(eventAge) && eventAge >= 0 ? now - eventAge : now;
    const state = event.state;
    if (state === "connecting") {
      addParticle(session.id, laneIndex, eventAt, { startedAt: eventAt, dc: session.dc });
      hub.pulse = 0.42;
      hub.spin = 0.18;
    } else if (state === "connected") {
      const particle = activeParticles.get(`${session.id}:${laneIndex}`);
      if (particle) {
        particle.kind = "upstream";
        particle.settleStartedAt = eventAt;
        particle.settleFrom = particle.fraction;
        particle.stopAt = particle.gateProgress[3];
      }
  } else if (state === "selected") {
    fadeAttempt(session.id, laneIndex, eventAt);
    addParticle(session.id, laneIndex, eventAt, { startedAt: eventAt,
      duration: MOTION.winnerDurationMs, kind: "winner", track: false, dc: session.dc });
    hub.pulse = 0.72;
    hub.spin = 0.28;
    } else if (state === "failed") {
    launchFailure(session.id, laneIndex, eventAt, event.failure_stage, session.dc);
    } else if (state === "cancelled") {
    fadeAttempt(session.id, laneIndex, eventAt);
  } else if (state === "cooldown") {
    lanes[laneIndex].markerPulse = 0.7;
    } else if (state === "first_binary_response") {
    addParticle(session.id, laneIndex, eventAt, { direction: "response", startedAt: eventAt,
      kind: "response", duration: MOTION.responseDurationMs, track: false, dc: session.dc });
    hub.pulse = 1;
    hub.spin = 0.3;
    }
  }

  function readEvents(snapshot, view, now) {
    const processTime = Number(snapshot?.process_started_at || 0);
    const accepted = Number(snapshot?.accepted_connections || 0);
    const restarted = processTime && (processStartedAt !== processTime
      || (acceptedConnections != null && accepted < acceptedConnections));
    if (restarted) {
      cursors.clear();
      activeParticles.clear();
      particles.length = 0;
      trafficParticles.length = 0;
      ripples.length = 0;
      ecgBeats.length = 0;
      sparks.length = 0;
    }
    if (processTime) processStartedAt = processTime;
    if (snapshot) acceptedConnections = accepted;
    const liveIds = new Set(view.sessions.map(session => session.id));
    for (const id of cursors.keys()) {
      if (!liveIds.has(id)) {
        cursors.delete(id);
        for (const [key, particle] of activeParticles) {
          if (particle.sessionId === id) {
            particle.fadeAt ||= now;
            activeParticles.delete(key);
          }
        }
      }
    }
    view.sessions.forEach(session => {
      const events = Array.isArray(session.events) ? session.events : [];
      const newest = events.length ? Number(events[events.length - 1].sequence) || 0 : 0;
      const previous = cursors.get(session.id);
      if (previous == null || restarted) {
        cursors.set(session.id, newest);
        return;
      }
      const oldest = events.length ? Number(events[0].sequence) || newest : newest;
      if (previous < oldest - 1) {
        cursors.set(session.id, newest);
        return;
      }
      events.filter(event => Number(event.sequence) > previous)
        .sort((left, right) => left.sequence - right.sequence)
        .forEach(event => processEvent(session, event, now));
      cursors.set(session.id, newest);
    });
  }

  function readTraffic(snapshot, now) {
    if (!snapshot) return;
    const processTime = Number(snapshot.process_started_at) || 0;
    const fromClients = Number(snapshot.bytes_from_clients);
    const fromUpstreams = Number(snapshot.bytes_from_upstreams);
    if (!Number.isFinite(fromClients) || !Number.isFinite(fromUpstreams)) return;
    const restarted = processTime && trafficProcessStartedAt && processTime !== trafficProcessStartedAt;
    if (processTime) trafficProcessStartedAt = processTime;
    if (restarted || previousTrafficBytes === null ||
        fromClients < previousTrafficBytes.fromClients || fromUpstreams < previousTrafficBytes.fromUpstreams) {
      previousTrafficBytes = { fromClients, fromUpstreams };
      trafficParticles.length = 0;
      return;
    }
    const deltas = [
      ["request", fromClients - previousTrafficBytes.fromClients],
      ["response", fromUpstreams - previousTrafficBytes.fromUpstreams],
    ];
    previousTrafficBytes = { fromClients, fromUpstreams };
    deltas.forEach(([direction, bytes]) => {
      if (bytes <= 0 || motionPreference?.matches) return;
      trafficParticles.push({ direction, bytes, startedAt: now, duration: 1250,
        size: 2.5 + Math.min(6, Math.log2(1 + bytes / 128)) });
      if (trafficParticles.length > MAX_PARTICLES) trafficParticles.shift();
    });
  }

  function setLaneTargets(view) {
    lanes.forEach(lane => configureLane(lane, view));
  }

  function resize() {
    if (destroyed) return;
    const rect = canvas.getBoundingClientRect();
    const width = Math.max(1, rect.width);
    const height = Math.max(1, rect.height);
    const nextPixelRatio = Math.min(2.5, Math.max(1, window.devicePixelRatio || 1));
    const ratioChanged = nextPixelRatio !== pixelRatio;
    pixelRatio = nextPixelRatio;
    const backingWidth = Math.round(width * pixelRatio);
    const backingHeight = Math.round(height * pixelRatio);
    const backingStoreChanged = canvas.width !== backingWidth || canvas.height !== backingHeight;
    if (canvas.width !== backingWidth) canvas.width = backingWidth;
    if (canvas.height !== backingHeight) canvas.height = backingHeight;
    scaleX = canvas.width / WIDTH;
    scaleY = canvas.height / HEIGHT;
    const canAnimate = !motionPreference?.matches && inView && !document.hidden;
    if (backingStoreChanged || ratioChanged || !canAnimate) draw();
    if (canAnimate) startLoop();
  }

  function strokePath(path, color, alpha, width, dash = [], glow = 0, dashOffset = 0) {
    context.beginPath();
    context.moveTo(path.points[0][0], path.points[0][1]);
    for (let index = 1; index < path.points.length; index += 1) {
      context.lineTo(path.points[index][0], path.points[index][1]);
    }
    context.setLineDash(dash);
    context.lineDashOffset = dashOffset;
    context.lineWidth = width;
    context.lineCap = "round";
    context.lineJoin = "round";
    context.globalAlpha = alpha;
    context.strokeStyle = color;
    context.shadowColor = color;
    context.shadowBlur = glow * 3;
    context.stroke();
    context.shadowBlur = 0;
    context.globalAlpha = 1;
    context.setLineDash([]);
    context.lineDashOffset = 0;
  }

  function rgb(color, alpha = 1) {
    return `rgba(${color[0] | 0},${color[1] | 0},${color[2] | 0},${alpha})`;
  }

  function drawHexagon(x, y, radius, rotation) {
    context.beginPath();
    for (let index = 0; index < 6; index += 1) {
      const angle = rotation + index * Math.PI / 3;
      context[index ? "lineTo" : "moveTo"](x + radius * Math.cos(angle), y + radius * Math.sin(angle));
    }
    context.closePath();
  }

  function drawNode(x, y, radius, glow) {
    context.save();
    context.translate(x, y);
    context.scale(1, scaleX / scaleY);
    context.beginPath();
    context.arc(0, 0, radius, 0, Math.PI * 2);
    context.fillStyle = rgb(palette.background);
    context.fill();
    context.lineWidth = 2.5;
    context.strokeStyle = rgb(palette.accent, 0.35 + 0.65 * glow);
    context.shadowColor = rgb(palette.accent, 0.9);
    context.shadowBlur = 5 * glow;
    context.stroke();
    context.shadowBlur = 0;
    context.restore();
  }

  function drawText(text, x, y, cssFont, color, cssWidth, cssHeight, align = "center") {
    context.save();
    context.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0);
    context.textAlign = align;
    context.font = cssFont;
    context.fillStyle = color;
    context.fillText(text, x * cssWidth / WIDTH, y * cssHeight / HEIGHT);
    context.restore();
  }

  function drawTelegramDcs(cssWidth, cssHeight) {
    const dcs = currentView.dcActivity || telegramDcActivity([]);
    TELEGRAM_DCS.forEach((position, index) => {
      const activity = dcs[index] || { active: 0, media: 0, confirmed: 0 };
      const active = activity.active > 0;
      const confirmed = activity.confirmed > 0;
      const color = confirmed ? palette.direct : active ? palette.cloudflare : palette.line;
      strokePath(TELEGRAM_DC_PATHS[index], rgb(active ? color : palette.line), active ? 0.55 : 0.24, 1.2);
      const activityLevel = Math.min(1, activity.active / 5);
      drawNode(position[0], position[1], 9 + activityLevel * 3,
        active ? 0.35 + 0.65 * activityLevel : 0);
      context.save();
      context.translate(position[0], position[1]);
      context.scale(1, scaleX / scaleY);
      context.beginPath();
      context.arc(0, 0, 9 + activityLevel * 3, 0, Math.PI * 2);
      context.fillStyle = rgb(color, active ? 0.12 + 0.5 * activityLevel : 0.08);
      context.fill();
      context.lineWidth = 2;
      context.strokeStyle = rgb(color, active ? 0.55 + 0.3 * activityLevel : 0.34);
      context.stroke();
      if (activity.media) {
        context.beginPath();
        context.arc(0, 0, 15 + activityLevel * 3, 0, Math.PI * 2);
        context.setLineDash([2, 3]);
        context.lineWidth = 1.4;
        context.strokeStyle = rgb(palette.accent, 0.85);
        context.stroke();
        context.setLineDash([]);
      }
      context.restore();
      const compact = cssWidth < 600;
      const labelX = compact ? position[0] : position[0] + 24;
      const labelY = compact ? position[1] - 22 : position[1] + 4;
      drawText(`DC${index + 1}`, labelX, labelY,
        compact ? "600 10px system-ui, sans-serif" : "600 11px system-ui, sans-serif",
        rgb(palette.text, active ? 0.9 : 0.55), cssWidth, cssHeight, compact ? "center" : "left");
      if (cssWidth >= 600 && active) {
        const count = activity.media ? `${activity.active} · media ${activity.media}` : String(activity.active);
        drawText(count, position[0] + 24, position[1] + 18,
          "10px system-ui, sans-serif", rgb(palette.muted, 0.88), cssWidth, cssHeight, "left");
      }
    });
    drawNode(TELEGRAM_HUB[0], TELEGRAM_HUB[1], 6, 0.2);
  }

  function drawEcg(now) {
    if (!(currentView.activeConnections > 0 || trafficParticles.length || ecgBeats.length)) return;
    context.beginPath();
    const baseY = ROUTE_HUB[1];
    const startX = CLIENT[0] + 30;
    const endX = ROUTE_HUB[0] - 34;
    context.moveTo(startX, baseY);
    for (let x = startX; x <= endX; x += 3) {
      let offset = 0;
      ecgBeats.forEach(beat => {
        const distance = x - (endX - (now - beat) * 0.17);
        offset += -distance * Math.exp(-distance * distance / 260) * 0.9;
      });
      context.lineTo(x, baseY + Math.max(-34, Math.min(34, offset)));
    }
    context.strokeStyle = rgb(ecgBeats.length ? palette.direct : palette.line,
      ecgBeats.length ? 0.35 + Math.min(0.5, ecgBeats.length * 0.2) : 0.3);
    context.lineWidth = 2.2;
    context.lineJoin = "round";
    context.stroke();
  }

  function draw() {
    if (destroyed || !context || !canvas.width || !canvas.height) return;
    const cssWidth = canvas.width / pixelRatio;
    const cssHeight = canvas.height / pixelRatio;
    const compact = cssWidth < 600;
    context.setTransform(scaleX, 0, 0, scaleY, 0, 0);
    context.globalCompositeOperation = "source-over";
    context.globalAlpha = 1;
    context.fillStyle = rgb(palette.background);
    context.fillRect(0, 0, WIDTH, HEIGHT);

    const now = performance.now();
    if (currentView.activeConnections > 0 || trafficParticles.length)
      strokePath(incomingPath, rgb(palette.line), 0.42, 2.2);
    drawEcg(now);
    const visibleRouteIndices = new Set(visibleRouteLanes(currentView)
      .map(lane => transportLane(lane.transport)));
    lanes.forEach((lane, index) => {
      if (!visibleRouteIndices.has(lane.index)) return;
      const selectedCount = Number(lane.counts.selected) || 0;
      const connectingCount = (Number(lane.counts.connecting) || 0) + (Number(lane.counts.race) || 0);
      const upstreamCount = Number(lane.counts.connected) || 0;
      const failedCount = Number(lane.counts.failed) || 0;
      const selected = selectedCount > 0;
      const connecting = connectingCount > 0;
      const cooling = lane.cooldownCount > 0 && !selected;
      const dash = cooling || failedCount || ["cancelled", "skipped"].includes(lane.status)
        ? [3, 9] : connecting ? [6, 8] : [];
      const color = lane.status === "failed" ? palette.failure : lane.color;
      strokePath(lane.path, rgb(color), selected ? 0.86 : cooling ? 0.4 : connecting ? 0.58 : lane.alpha,
        selected ? 3.4 : 2, dash, lane.glow);
      if (selected && !motionPreference?.matches) {
        const confirmed = currentView.sessions.some(session => session.selected_transport === lane.transport
          && session.telegram_response_seen === true);
        const motionColor = confirmed ? palette.direct : lane.color;
        strokePath(lane.path, rgb(motionColor, 0.58), 1, 1.6, [3, 16], 0,
          -(now / 1000) * (40 + selectedCount * 14));
        if (confirmed) strokePath(lane.path, rgb(palette.direct, 0.36), 1, 1.2, [2, 20], 0,
          (now / 1000) * (50 + selectedCount * 10));
      }
      const label = compact ? ({
        cloudflare_worker: "Worker",
        cloudflare_proxy: "CF proxy",
        tcp_passthrough: "TCP · диагностика",
      }[lane.transport] || lane.label) : lane.label;
      const upper = LANE_Y[index] < ROUTE_HUB[1];
      const labelY = compact ? LANE_Y[index] - 20 : LANE_Y[index] + (upper ? -26 : 36);
      const statusY = compact ? LANE_Y[index] + 24 : LANE_Y[index] + (upper ? -39 : 49);
      const remaining = Math.max(0, lane.cooldownRemainingMs
        - (now - lane.cooldownUpdatedAt));
      const stateLabel = selected ? `активен · ${selectedCount}`
        : connecting ? `${lane.counts.race ? "гонка" : "подключение"} · ${connectingCount}`
          : upstreamCount ? `upstream готов · ${upstreamCount}`
            : lane.cooldownCount ? `пауза · ${Math.ceil(remaining)} мс`
              : failedCount ? `отказ · ${lane.failureStage ? GATE_ACCESSIBLE_NAMES[failureGateIndex(lane.failureStage)] || "маршрут" : "маршрут"}`
                : STATE_LABELS[lane.status] || STATE_LABELS.idle;
      drawText(label, 540, labelY, compact ? "600 11px system-ui, sans-serif" : "600 12px system-ui, sans-serif",
        rgb(palette.text, 0.9), cssWidth, cssHeight);
      drawText(stateLabel, 540, statusY, compact ? "10px system-ui, sans-serif" : "10px system-ui, sans-serif",
        rgb(lane.failureStage ? palette.failure : lane.color, 0.88), cssWidth, cssHeight);
      for (let gate = 0; gate < GATE_NAMES.length; gate += 1) {
        const point = pointAt(lane.path, lane.gateProgress[gate]);
        const failedGate = failureGateIndex(lane.failureStage) === gate;
        const passing = particles.some(particle => particle.laneIndex === lane.index
          && !particle.fadeAt && Math.abs(particle.fraction - particle.gateProgress[gate]) < 0.035);
        const passed = lane.passedGate > gate;
        const gateColor = failedGate ? palette.failure
          : passed ? (lane.passedGate >= GATE_NAMES.length && gate === GATE_NAMES.length - 1
            ? palette.direct : palette.cloudflare)
          : passing ? lane.color : palette.line;
        const pulse = Math.max(lane.gatePulses[gate], passing ? 0.8 : 0);
        context.save();
        context.translate(point[0], point[1]);
        context.scale(1, scaleX / scaleY);
        context.beginPath();
        context.arc(0, 0, 3 + pulse * 2, 0, Math.PI * 2);
        context.fillStyle = rgb(gateColor, failedGate || passed || passing ? 0.95 : 0.38);
        context.shadowColor = rgb(gateColor);
        context.shadowBlur = pulse * 7;
        context.fill();
        context.shadowBlur = 0;
        context.restore();
        if (!compact) drawText(GATE_NAMES[gate], GATE_X[gate], LANE_Y[index] + (upper ? -12 : 19),
          "600 9px system-ui, sans-serif", rgb(palette.muted, 0.35 + pulse * 0.45), cssWidth, cssHeight);
      }
      if (lane.status === "failed" || lane.cooldownCount) {
        const gate = failureGateIndex(lane.failureStage);
        const markerX = gate === null ? 540 : GATE_X[gate];
        const point = pointAt(lane.path, gate === null
          ? fractionAtX(lane.path, markerX) : lane.gateProgress[gate]);
        const cooldownFraction = currentView.cooldownDurationMs > 0
          ? Math.min(1, remaining / currentView.cooldownDurationMs) : 0;
        context.save();
        context.translate(point[0], point[1]);
        context.scale(1, scaleX / scaleY);
        const markerScale = 1 + 0.35 * lane.markerPulse;
        context.scale(markerScale, markerScale);
        context.lineWidth = 2.5;
        context.lineCap = "round";
        context.strokeStyle = rgb(palette.failure, 0.95);
        context.beginPath();
        context.moveTo(-4.5, -4.5); context.lineTo(4.5, 4.5);
        context.moveTo(4.5, -4.5); context.lineTo(-4.5, 4.5);
        context.stroke();
        if (lane.cooldownCount) {
          context.beginPath();
          context.arc(0, 0, 13, -Math.PI / 2, -Math.PI / 2 + Math.PI * 2 * cooldownFraction);
          context.strokeStyle = rgb(palette.failure, 0.88);
          context.lineWidth = 1.8;
          context.stroke();
        }
        context.restore();
      }
    });

    drawTelegramDcs(cssWidth, cssHeight);
    drawNode(CLIENT[0], CLIENT[1], 28, Math.min(1, client.pulse));
    context.strokeStyle = rgb(palette.text, 0.8);
    context.lineWidth = 2;
    context.lineCap = "round";
    context.lineJoin = "round";
    context.strokeRect(CLIENT[0] - 8, CLIENT[1] - 13, 16, 26);
    context.beginPath(); context.moveTo(CLIENT[0] - 3, CLIENT[1] + 8);
    context.lineTo(CLIENT[0] + 3, CLIENT[1] + 8); context.stroke();

    const hubScale = 1 + 0.06 * hub.pulse;
    context.save();
    context.translate(ROUTE_HUB[0], ROUTE_HUB[1]);
    context.scale(hubScale, hubScale * scaleX / scaleY);
    context.beginPath();
    context.arc(0, 0, 60, -Math.PI / 2,
      -Math.PI / 2 + Math.PI * 2 * Math.min(1, currentView.activeConnections / 40));
    context.strokeStyle = rgb(palette.accent, 0.28); context.lineWidth = 2; context.stroke();
    drawHexagon(0, 0, 31, hub.angle);
    context.fillStyle = rgb(palette.background);
    context.fill();
    context.lineWidth = 2.5;
    context.strokeStyle = rgb(palette.accent, 0.95);
    context.shadowColor = rgb(palette.accent, 0.9);
    context.shadowBlur = 4 + 3 * hub.pulse;
    context.stroke();
    context.shadowBlur = 0;
    const orbRadii = [45, 53];
    currentView.sessions.forEach((session, index) => {
      const id = Number(session.id) || index + 1;
      const orbit = index % 2;
      const angle = (id * 2.399963229728653 + now / 1000 * (orbit ? -0.68 : 0.5)) % (Math.PI * 2);
      const state = sessionOrbState(session);
      const color = state === "first_wss_binary_response" ? palette.direct
        : state === "upstream_ready" ? palette.cloudflare
          : state === "routing" ? palette.accent : palette.muted;
      const blink = state === "routing" ? 0.42 + 0.58 * (0.5 + 0.5 * Math.sin(now / 520 + id)) : 1;
      const radius = state === "first_wss_binary_response" ? 2.8 : 2.4;
      const orbitRadius = orbRadii[orbit];
      context.beginPath();
      context.arc(orbitRadius * Math.cos(angle), orbitRadius * Math.sin(angle), radius, 0, Math.PI * 2);
      context.fillStyle = rgb(color, blink);
      context.shadowColor = rgb(color);
      context.shadowBlur = state === "first_wss_binary_response" ? 5 : state === "routing" ? 3 * blink : 0;
      context.fill();
    });
    context.shadowBlur = 0;
    context.beginPath(); context.arc(0, 0, 5, 0, Math.PI * 2);
    context.fillStyle = rgb(palette.text); context.fill();
    context.restore();

    drawText("Клиент", CLIENT[0], CLIENT[1] + 52,
      compact ? "600 10px system-ui, sans-serif" : "600 12px system-ui, sans-serif",
      rgb(palette.text, 0.75), cssWidth, cssHeight);
    drawText("d2o", ROUTE_HUB[0], ROUTE_HUB[1] + 86,
      compact ? "10px system-ui, sans-serif" : "12px system-ui, sans-serif",
      rgb(palette.text, 0.75), cssWidth, cssHeight);

    ripples.forEach(ripple => {
      const progress = ripple.elapsed / (MOTION.rippleDurationMs / 1000);
      const eased = 1 - (1 - progress) ** 3;
      context.beginPath();
      context.arc(ripple.x, ripple.y, 28 + 40 * eased, 0, Math.PI * 2);
      context.strokeStyle = rgb(ripple.color, 0.2 * (1 - progress));
      context.lineWidth = 2;
      context.stroke();
    });
    context.globalCompositeOperation = "lighter";
    trafficParticles.forEach(particle => {
      const progress = Math.min(1, Math.max(0, (now - particle.startedAt) / particle.duration));
      const path = particle.direction === "request" ? incomingPath : responsePath;
      const point = pointAt(path, ease(progress));
      const color = particle.direction === "request" ? palette.accent : palette.direct;
      context.beginPath();
      context.moveTo(point[0] - particle.size, point[1]);
      context.lineTo(point[0] + particle.size, point[1]);
      context.strokeStyle = rgb(color, 0.72 * (1 - progress));
      context.lineWidth = 1.4 + particle.size * 0.45;
      context.lineCap = "round";
      context.shadowColor = rgb(color);
      context.shadowBlur = 4;
      context.stroke();
      context.shadowBlur = 0;
    });
    particles.forEach(particle => {
      if (!visibleRouteIndices.has(particle.laneIndex)) return;
      const color = particle.kind === "failure" ? palette.failure
        : particle.kind === "response" ? palette.direct
          : particle.kind === "upstream" || particle.kind === "upstream_ready"
            ? palette.cloudflare : particle.color;
      const count = particle.kind === "response" ? 8 : 7;
      for (let index = 1; index <= count; index += 1) {
        const fraction = particle.fraction - index * 0.012;
        if (fraction < 0) continue;
        const point = pointAt(particle.path, fraction);
        context.beginPath();
        context.arc(point[0], point[1], 4.2 * (1 - index / (count + 2)), 0, Math.PI * 2);
        context.fillStyle = rgb(color, 0.55 * (1 - index / (count + 1)) * particle.opacity);
        context.fill();
      }
      context.beginPath();
      context.arc(particle.x, particle.y, particle.radius, 0, Math.PI * 2);
      context.fillStyle = rgb(color, 0.95 * particle.opacity);
      context.shadowColor = rgb(color);
      context.shadowBlur = 12;
      context.fill();
      context.shadowBlur = 0;
    });
    sparks.forEach(spark => {
      context.beginPath();
      context.arc(spark.x, spark.y, 1.3, 0, Math.PI * 2);
      context.fillStyle = rgb(palette.failure, 0.35 * (1 - spark.elapsed / spark.duration));
      context.fill();
    });
    context.globalCompositeOperation = "source-over";
    context.globalAlpha = 1;
  }

  function burst(x, y) {
    for (let index = 0; index < 7 && sparks.length < MAX_SPARKS; index += 1) {
      const angle = Math.random() * Math.PI * 2;
      const speed = 20 + Math.random() * 40;
      sparks.push({ x, y, vx: Math.cos(angle) * speed, vy: Math.sin(angle) * speed, elapsed: 0, duration: MOTION.sparkDurationMs / 1000 });
    }
  }

  function updateFrame(now) {
    frameId = 0;
    if (destroyed || !inView || document.hidden || motionPreference?.matches) return;
    const delta = Math.min(0.05, Math.max(0, (now - lastFrame) / 1000));
    lastFrame = now;
    const smoothing = 1 - Math.exp(-delta * 2.6);
    lanes.forEach(lane => {
      for (let channel = 0; channel < 3; channel += 1) {
        lane.color[channel] += (lane.targetColor[channel] - lane.color[channel]) * smoothing;
      }
      lane.alpha += (lane.targetAlpha - lane.alpha) * smoothing;
      lane.glow += (lane.targetGlow - lane.glow) * smoothing;
      lane.markerPulse *= Math.exp(-delta * 2.8);
      lane.gatePulses.forEach((value, index) => { lane.gatePulses[index] = value * Math.exp(-delta * 2.8); });
    });
    hub.pulse *= Math.exp(-delta * 2.2);
    hub.spin *= Math.exp(-delta * 1.6);
    if (currentView.activeConnections > 0) hub.angle += delta * (0.12 + 0.25 * hub.pulse);
    client.pulse *= Math.exp(-delta * 2.2);
    for (let index = particles.length - 1; index >= 0; index -= 1) {
      const particle = particles[index];
      if (particle.fadeAt) {
        const fade = (now - particle.fadeAt) / MOTION.fadeDurationMs;
        if (fade >= 1) {
          particles.splice(index, 1);
          continue;
        }
        particle.opacity = 1 - fade;
        particle.radius = 2 * (1 - 0.5 * fade);
      } else {
        const age = Math.max(0, now - particle.startedAt);
        let progress = Math.min(age / particle.duration, 1);
        let fraction;
        if (particle.kind === "attempt") {
          const start = particle.gateProgress[0] * 0.55;
          const target = particle.gateProgress[3] * 0.92;
          fraction = start + (target - start) * (1 - Math.exp(-age / particle.duration));
          progress = 0;
        } else if (particle.kind === "upstream") {
          progress = Math.min(Math.max(0, now - particle.settleStartedAt) / MOTION.upstreamDurationMs, 1);
          fraction = particle.settleFrom + (particle.stopAt - particle.settleFrom) * ease(progress);
          if (progress >= 1) {
            particle.kind = "upstream_ready";
            fraction = particle.stopAt;
          }
        } else if (particle.kind === "upstream_ready") {
          fraction = particle.stopAt;
          progress = 0;
        } else {
          fraction = particle.stopAt == null ? ease(progress) : Math.min(ease(progress), particle.stopAt);
        }
        particle.fraction = fraction;
        const point = pointAt(particle.path, fraction);
        particle.x = point[0];
        particle.y = point[1];
        particle.opacity = 1;
        if (progress >= 1) {
          if (particle.kind === "failure") {
            burst(particle.x, particle.y);
            lanes[particle.laneIndex].markerPulse = 1;
          } else if (particle.kind === "response") {
            client.pulse = 1;
            ecgBeats.push(now);
            if (ecgBeats.length > MAX_RIPPLES) ecgBeats.shift();
            ripples.push({ x: CLIENT[0], y: CLIENT[1], elapsed: 0, color: palette.direct });
            if (ripples.length > MAX_RIPPLES) ripples.shift();
          }
          if (activeParticles.get(`${particle.sessionId}:${particle.laneIndex}`) === particle) {
            activeParticles.delete(`${particle.sessionId}:${particle.laneIndex}`);
          }
          particles.splice(index, 1);
        }
      }
    }
    for (let index = ecgBeats.length - 1; index >= 0; index -= 1) {
      if (now - ecgBeats[index] >= 1400) ecgBeats.splice(index, 1);
    }
    for (let index = trafficParticles.length - 1; index >= 0; index -= 1) {
      if (now - trafficParticles[index].startedAt >= trafficParticles[index].duration)
        trafficParticles.splice(index, 1);
    }
    for (let index = sparks.length - 1; index >= 0; index -= 1) {
      const spark = sparks[index];
      spark.elapsed += delta;
      spark.x += spark.vx * delta;
      spark.y += spark.vy * delta;
      spark.vx *= 0.94;
      spark.vy *= 0.94;
      if (spark.elapsed >= spark.duration) sparks.splice(index, 1);
    }
    for (let index = ripples.length - 1; index >= 0; index -= 1) {
      ripples[index].elapsed += delta;
      if (ripples[index].elapsed >= MOTION.rippleDurationMs / 1000) ripples.splice(index, 1);
    }
    draw();
    startLoop();
  }

  function startLoop() {
    if (destroyed || frameId || !inView || document.hidden || motionPreference?.matches) return;
    lastFrame = performance.now();
    frameId = window.requestAnimationFrame(updateFrame);
  }

  function stopLoop() {
    if (frameId) window.cancelAnimationFrame(frameId);
    frameId = 0;
  }

  function updateAccessibility(view) {
    const visibleLanes = visibleRouteLanes(view);
    const routeText = visibleLanes.map(lane => {
      const details = Object.entries(lane.counts)
        .map(([state, count]) => `${STATE_LABELS[state] || state}: ${count}`).join(", ")
        || STATE_LABELS[lane.status] || "активный маршрут";
      const gate = failureGateIndex(lane.failureStage);
      const failure = gate === null ? "" : `, отказ на воротах ${GATE_ACCESSIBLE_NAMES[gate]}`;
      const cooldown = lane.cooldownCount
        ? `, пауза ${lane.cooldownCount} маршрута, ещё ${Math.ceil(lane.cooldownRemainingMs)} мс` : "";
      return `${lane.label} — ${details}${failure}${cooldown}`;
    }).join("; ") || "Сейчас нет активных маршрутов";
    const confirmed = view.sessions.some(session => session.telegram_response_seen);
    const connectionText = confirmed
      ? "Ответ Telegram подтверждён" : "Ответ Telegram не подтверждён";
    const raceText = view.hedged.length
      ? ` Параллельная гонка: победитель ${view.hedged[0].winner}; отменены ${view.hedged[0].losers.join(", ")}.` : "";
    const truncationText = view.truncated ? " Показана ограниченная выборка активных сессий." : "";
    canvas.setAttribute("aria-label", `Схема соединений: Клиент → d2o. ${connectionText}. ${routeText}. ${view.caption}.${raceText}${truncationText}`);
    canvas.dataset.state = view.state;
    if (root) root.dataset.state = view.state;
    const caption = root?.querySelector("#tg-flow-caption");
    if (caption && caption.textContent !== view.caption) caption.textContent = view.caption;
  }

  function update(snapshot, error = "") {
    if (destroyed) return null;
    const view = summarize(snapshot, error);
    const now = performance.now();
    readEvents(snapshot, view, now);
    readTraffic(snapshot, now);
    currentView = view;
    setLaneTargets(view);
    updateAccessibility(view);
    if (motionPreference?.matches || !inView || document.hidden) draw();
    else startLoop();
    return view;
  }

  function onMotionPreferenceChange() {
    stopLoop();
    if (motionPreference?.matches) {
      particles.length = 0;
      trafficParticles.length = 0;
      sparks.length = 0;
      ripples.length = 0;
      client.pulse = 0;
      activeParticles.clear();
      lanes.forEach(lane => {
        lane.color = [...lane.targetColor];
        lane.alpha = lane.targetAlpha;
        lane.glow = lane.targetGlow;
        lane.markerPulse = 0;
      });
      draw();
    } else {
      startLoop();
    }
  }

  function onVisibilityChange() {
    if (document.hidden) stopLoop();
    else startLoop();
  }

  function onThemeChange() {
    refreshPalette();
    draw();
  }

  function onIntersection(entries) {
    inView = Boolean(entries[0]?.isIntersecting);
    if (inView) startLoop();
    else stopLoop();
  }

  const resizeObserver = typeof window.ResizeObserver === "function"
    ? new window.ResizeObserver(resize) : null;
  const intersectionObserver = typeof window.IntersectionObserver === "function"
    ? new window.IntersectionObserver(onIntersection, { rootMargin: "80px" }) : null;
  const themeObserver = typeof window.MutationObserver === "function"
    ? new window.MutationObserver(() => { refreshPalette(); draw(); }) : null;
  const motionListener = onMotionPreferenceChange;
  const themeListener = onThemeChange;

  refreshPalette();
  resize();
  resizeObserver?.observe(canvas);
  intersectionObserver?.observe(canvas);
  themeObserver?.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
  window.addEventListener("resize", resize, { passive: true });
  document.addEventListener("visibilitychange", onVisibilityChange);
  motionPreference?.addEventListener("change", motionListener);
  darkPreference?.addEventListener("change", themeListener);
  if (!intersectionObserver) startLoop();

  return {
    update,
    attach() {
      if (destroyed || !canvas.isConnected) return;
      refreshPalette();
      resize();
    },
    destroy() {
      if (destroyed) return;
      destroyed = true;
      stopLoop();
      resizeObserver?.disconnect();
      intersectionObserver?.disconnect();
      themeObserver?.disconnect();
      window.removeEventListener("resize", resize);
      document.removeEventListener("visibilitychange", onVisibilityChange);
      motionPreference?.removeEventListener("change", motionListener);
      darkPreference?.removeEventListener("change", themeListener);
      cursors.clear();
      activeParticles.clear();
      particles.length = 0;
      trafficParticles.length = 0;
      sparks.length = 0;
      ripples.length = 0;
    },
  };
}

global.D2kTelegramFlow = {
  prototypeGeometry: PROTOTYPE_GEOMETRY,
  motionProfile: MOTION,
  mountTelegramFlow,
  summarizeTelegramFlow: summarize,
  composeFlowPoints,
  sessionOrbState,
  telegramDcNumber,
  telegramDcActivity,
  failureGateIndex,
  routeDescription,
  hasCurrentRouteFailure,
  visibleRouteLanes,
};
if (typeof module === "object" && module.exports) module.exports = global.D2kTelegramFlow;
})(typeof window !== "undefined" ? window : globalThis);
