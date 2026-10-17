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

function telegramDcPosition(dc) {
  const number = telegramDcNumber(dc);
  return number === null ? null : PROTOTYPE_GEOMETRY.dcPositions[number - 1];
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

function makePath(points) {
  const cumulative = [0];
  for (let index = 1; index < points.length; index += 1) {
    cumulative.push(cumulative[index - 1]
      + Math.hypot(points[index][0] - points[index - 1][0], points[index][1] - points[index - 1][1]));
  }
  return { points, cumulative, length: cumulative[cumulative.length - 1] };
}

function composeFlowPoints(routePoints, clientToHubPoints, direction) {
  if (direction === "response") {
    return [...routePoints.slice().reverse(), ...clientToHubPoints.slice(0, -1).reverse()];
  }
  if (direction === "request") return [...clientToHubPoints, ...routePoints.slice(1)];
  return routePoints;
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

function collectConfirmedTrafficDeltas(previousBySession, sessions) {
  const live = new Set();
  const deltas = [];
  (Array.isArray(sessions) ? sessions : []).forEach(session => {
    const id = Number(session?.id);
    const fromClients = Number(session?.bytes_from_clients);
    const fromUpstreams = Number(session?.bytes_from_upstreams);
    if (!Number.isSafeInteger(id) || id <= 0 || !Number.isFinite(fromClients) ||
        !Number.isFinite(fromUpstreams) || fromClients < 0 || fromUpstreams < 0) return;
    live.add(id);
    const previous = previousBySession.get(id);
    previousBySession.set(id, { fromClients, fromUpstreams });
    if (!previous || session.telegram_response_seen !== true) return;
    const laneIndex = selectedLaneFor(session);
    const dc = telegramDcNumber(session.dc);
    if (laneIndex < 0 || dc === null) return;
    if (fromClients > previous.fromClients) {
      deltas.push({ id, laneIndex, dc, direction: "request",
        bytes: fromClients - previous.fromClients });
    }
    if (fromUpstreams > previous.fromUpstreams) {
      deltas.push({ id, laneIndex, dc, direction: "response",
        bytes: fromUpstreams - previous.fromUpstreams });
    }
  });
  for (const id of previousBySession.keys()) {
    if (!live.has(id)) previousBySession.delete(id);
  }
  return deltas;
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
  if (error === "stale" && snapshot) {
    const current = summarize(snapshot);
    return { ...current, state: "stale", caption: `Данные маршрутов устарели · ${current.caption}` };
  }
  if (error || !snapshot) {
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
    const confirmed = sessionViews.filter(({ session, selectedLane }) =>
      selectedLane === index && session.telegram_response_seen === true).length;
    return { ...route, label, status, counts: laneCounts, confirmed };
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
  if (!global.D2kTelegramPrototype) throw new Error("Анимация Telegram не загружена");
  return global.D2kTelegramPrototype.mountTelegramFlow(canvas);
}

global.D2kTelegramFlow = {
  prototypeGeometry: PROTOTYPE_GEOMETRY,
  motionProfile: MOTION,
  mountTelegramFlow,
  summarizeTelegramFlow: summarize,
  composeFlowPoints,
  sessionOrbState,
  telegramDcNumber,
  telegramDcPosition,
  telegramDcActivity,
  failureGateIndex,
  collectConfirmedTrafficDeltas,
  routeDescription,
  hasCurrentRouteFailure,
  visibleRouteLanes,
};
if (typeof module === "object" && module.exports) module.exports = global.D2kTelegramFlow;
})(typeof window !== "undefined" ? window : globalThis);
