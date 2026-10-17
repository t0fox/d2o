"use strict";
const assert = require("node:assert/strict");
const flow = require("../internal/web/assets/telegram-flow.js");

const session = (values = {}) => ({
  id: 1,
  dc: null,
  is_media: null,
  stage: "accepted",
  direct_state: "idle",
  direct_transport: null,
  fallback_state: "idle",
  fallback_transport: null,
  selected_transport: null,
  telegram_response_seen: false,
  events: [],
  ...values,
});

const snapshot = (values = {}) => ({
  active_connections: 0,
  accepted_connections: 0,
  active_sessions: [],
  route_sessions_truncated: false,
  ...values,
});

assert.deepEqual(flow.prototypeGeometry, {
  width: 900,
  height: 420,
  client: [70, 210],
  hub: [300, 210],
  collector: [720, 210],
  laneY: [62, 148, 272, 358],
  gateX: [465, 500, 535, 570, 605],
  dcPositions: [[802, 70], [816, 140], [830, 210], [816, 280], [802, 350]],
}, "сцена использует координаты исходного HTML-прототипа");

{
  const previous = new Map();
  const media = session({ id: 91, dc: 4, is_media: true,
    selected_transport: "cloudflare_worker", telegram_response_seen: true,
    bytes_from_clients: 1200, bytes_from_upstreams: 800 });
  assert.deepEqual(flow.collectConfirmedTrafficDeltas(previous, [media]), [],
    "первичный снимок только задаёт базу и не проигрывает накопленный трафик");
  const next = { ...media, bytes_from_clients: 5320, bytes_from_upstreams: 4900 };
  assert.deepEqual(flow.collectConfirmedTrafficDeltas(previous, [next]), [
    { id: 91, laneIndex: 1, dc: 4, direction: "request", bytes: 4120 },
    { id: 91, laneIndex: 1, dc: 4, direction: "response", bytes: 4100 },
  ], "пакеты идут по подтверждённому Cloudflare Worker маршруту DC4 media");
  assert.deepEqual(flow.collectConfirmedTrafficDeltas(previous, [next]), [],
    "повторный poll без новых байтов не рисует пакеты");
  assert.deepEqual(flow.collectConfirmedTrafficDeltas(previous, [
    { ...next, bytes_from_clients: 3, bytes_from_upstreams: 2 },
  ]), [], "сброс счётчиков не выдаётся за новые пакеты");
  const unconfirmed = session({ id: 92, dc: 2, selected_transport: "direct_wss",
    bytes_from_clients: 0, bytes_from_upstreams: 0 });
  flow.collectConfirmedTrafficDeltas(previous, [unconfirmed]);
  assert.deepEqual(flow.collectConfirmedTrafficDeltas(previous, [{ ...unconfirmed,
    bytes_from_clients: 4096, bytes_from_upstreams: 4096 }]), [],
  "неподтверждённая сессия не рисует успешный трафик");
}

{
  const route = [[300, 210], [500, 100], [720, 210]];
  const clientToHub = [[70, 210], [300, 210]];
  assert.deepEqual(flow.composeFlowPoints(route, clientToHub, "request"),
    [[70, 210], [300, 210], [500, 100], [720, 210]],
    "исходная попытка идёт от клиента через d2o к Telegram");
  assert.deepEqual(flow.composeFlowPoints(route, clientToHub, "response"),
    [[720, 210], [500, 100], [300, 210], [70, 210]],
    "подтверждённый ответ Telegram идёт от DC к клиенту");
}

{
  const view = flow.summarizeTelegramFlow(snapshot());
  assert.equal(view.state, "idle");
  assert.equal(view.activeConnections, 0);
  assert.equal(view.acceptedConnections, 0);
}

{
  const view = flow.summarizeTelegramFlow(null);
  assert.equal(view.state, "unavailable");
  assert.match(view.caption, /статистика.*недоступна/i,
    "отсутствующие данные C11 не выглядят как ноль активных соединений");
}

{
  const view = flow.summarizeTelegramFlow(snapshot({ active_connections: 1 }), "stale");
  assert.equal(view.state, "stale");
  assert.equal(view.activeConnections, 1,
    "устаревший снимок сохраняет последнюю цифру и не выдаёт её за текущую");
  assert.match(view.caption, /данные.*устарели/i);
}

{
  assert.equal(flow.sessionOrbState(session({ stage: "accepted" })), "accepted");
  assert.equal(flow.sessionOrbState(session({ stage: "routing" })), "routing");
  assert.equal(flow.sessionOrbState(session({ stage: "upstream_ready" })), "upstream_ready");
  assert.equal(flow.sessionOrbState(session({ stage: "first_wss_binary_response" })),
    "first_wss_binary_response");
  assert.equal(flow.telegramDcNumber(203), 2, "DC203 располагается в узле DC2");
  assert.equal(flow.telegramDcNumber(4), 4);
  assert.equal(flow.telegramDcNumber(null), null);
  assert.deepEqual(flow.telegramDcPosition(203), [816, 140],
    "маршрут DC203 заканчивается в узле DC2");
  assert.deepEqual(flow.telegramDcPosition(4), [816, 280],
    "media DC4 заканчивается в узле DC4");
  assert.equal(flow.telegramDcPosition(null), null,
    "маршрут без DC не приписывается узлу");
  assert.deepEqual(flow.telegramDcActivity([
    session({ dc: 203, is_media: true, telegram_response_seen: true }),
    session({ dc: 2, is_media: false, telegram_response_seen: false }),
    session({ dc: 4, is_media: true, telegram_response_seen: false }),
    session({ dc: 6, is_media: true, telegram_response_seen: true }),
  ]), [
    { active: 0, media: 0, confirmed: 0 },
    { active: 2, media: 1, confirmed: 1 },
    { active: 0, media: 0, confirmed: 0 },
    { active: 1, media: 1, confirmed: 0 },
    { active: 0, media: 0, confirmed: 0 },
  ], "DC-узлы показывают только реальные сессии; DC203 учитывается в DC2");
  assert.deepEqual([1, 2, 3, 4, 5].map(flow.failureGateIndex), [0, 1, 2, 3, 4],
    "ошибки останавливаются на соответствующих воротах DNS/TCP/TLS/WS/MTProto");
  assert.equal(flow.failureGateIndex(6), null, "подготовка маршрута не выдаётся за сетевые ворота");
}

{
  const view = flow.summarizeTelegramFlow(snapshot({
    active_connections: 1,
    active_sessions: [session({ id: 42, dc: 4, is_media: true, stage: "routing" })],
    route_cooldown_ms: 30000,
    route_cooldowns: [{ dc: 4, is_media: true, transport: "cloudflare_proxy",
      remaining_ms: 28750, failure_stage: 3 }],
  }));
  assert.deepEqual(view.cooldowns, [{ dc: 4, isMedia: true, transport: "cloudflare_proxy",
    remainingMs: 28750, failureStage: 3 }]);
  assert.equal(view.lanes[2].cooldownCount, 1);
  assert.ok(flow.visibleRouteLanes(view).some(lane => lane.transport === "cloudflare_proxy"));
}

{
  const sample = snapshot({
    last_failure_dc: 4,
    last_failure_route: 3,
    last_failure_stage: 3,
    last_failure_age_ms: 100,
    last_success_dc: 2,
    last_success_route: 1,
    last_success_age_ms: 1000,
  });
  const view = flow.summarizeTelegramFlow(sample);
  assert.equal(flow.hasCurrentRouteFailure(sample), true);
  assert.equal(view.state, "unavailable");
  assert.equal(view.transportLabel, "Недоступно");
  assert.match(view.caption, /TLS.*DC4.*Прокси Cloudflare/);
  assert.equal(view.lanes[2].counts.failed, 1);
  assert.deepEqual(flow.visibleRouteLanes(view).map(lane => lane.transport), ["cloudflare_proxy"]);
}

{
  const sample = snapshot({
    last_failure_dc: 4,
    last_failure_route: 3,
    last_failure_stage: 3,
    last_failure_age_ms: 1000,
    last_success_dc: 2,
    last_success_route: 1,
    last_success_age_ms: 100,
  });
  const view = flow.summarizeTelegramFlow(sample);
  assert.equal(flow.hasCurrentRouteFailure(sample), false);
  assert.equal(view.state, "idle");
}

{
  const view = flow.summarizeTelegramFlow(snapshot({
    active_connections: 4,
    accepted_connections: 27,
    route_sessions_truncated: true,
    active_sessions: [
      session({ id: 4, dc: 2, is_media: false, stage: "upstream_ready",
        direct_state: "selected", direct_transport: "direct_wss",
        selected_transport: "direct_wss" }),
      session({ id: 5, dc: 2, is_media: true, stage: "first_wss_binary_response",
        direct_state: "selected", direct_transport: "direct_wss",
        selected_transport: "direct_wss", telegram_response_seen: true,
        events: [{ sequence: 4, branch: "direct", transport: "direct_wss",
          state: "first_binary_response" }] }),
      session({ id: 6, dc: 4, is_media: true, stage: "routing",
        fallback_state: "connecting", fallback_transport: "cloudflare_worker",
        events: [{ sequence: 1, branch: "fallback", transport: "cloudflare_worker",
          state: "connecting" }] }),
      session({ id: 7, dc: null, is_media: null, stage: "upstream_ready",
        direct_state: "selected", direct_transport: "tcp_passthrough",
        selected_transport: "tcp_passthrough" }),
    ],
  }));
  assert.equal(view.state, "mixed");
  assert.equal(view.activeConnections, 4);
  assert.equal(view.acceptedConnections, 27);
  assert.equal(view.truncated, true);
  assert.equal(view.mediaSessions, 2);
  assert.match(view.dcLabel, /Несколько DC · media 2/);
  assert.equal(view.lanes[0].counts.selected, 2);
  assert.equal(view.lanes[0].confirmed, 1,
    "маршрут считает только сессии с подтверждённым ответом Telegram");
  assert.equal(view.lanes[3].label, "Прямой TCP passthrough");
  assert.equal(view.lanes[3].counts.selected, 1);
  assert.equal(view.lanes[1].counts.connecting, 1);
  assert.deepEqual(view.lanes.map(lane => lane.transport),
    ["direct_wss", "cloudflare_worker", "cloudflare_proxy", "tcp_passthrough"],
    "на схеме нет удалённого автоматического TCP fallback");
  assert.deepEqual(flow.visibleRouteLanes(view).map(lane => lane.transport),
    ["direct_wss", "cloudflare_worker", "tcp_passthrough"]);
}

{
  const view = flow.summarizeTelegramFlow(snapshot({
    active_connections: 2,
    active_sessions: [
      session({ id: 31, dc: 2, is_media: false, stage: "upstream_ready",
        direct_state: "selected", direct_transport: "direct_wss",
        selected_transport: "direct_wss" }),
      session({ id: 32, dc: null, is_media: null, stage: "upstream_ready",
        direct_state: "selected", direct_transport: "tcp_passthrough",
        selected_transport: "tcp_passthrough" }),
    ],
  }));
  assert.equal(view.dcLabel, "DC2");
  assert.notEqual(view.dcLabel, "Несколько DC");
}

{
  const view = flow.summarizeTelegramFlow(snapshot({
    active_connections: 70,
    accepted_connections: 70,
    active_sessions: Array.from({ length: 64 }, (_, index) => session({ id: index + 1 })),
    route_sessions_truncated: true,
  }));
  assert.equal(view.sessions.length, 64);
  assert.equal(view.activeConnections, 70);
  assert.equal(view.truncated, true);
}

{
  const view = flow.summarizeTelegramFlow(snapshot({ active_connections: 1 }));
  assert.equal(view.state, "unavailable");
  assert.match(view.caption, /маршрут пока не определён/);
}

assert.deepEqual(flow.motionProfile, {
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
}, "реальный поток движется спокойно и ограничивает визуальный шум");
console.log("telegram flow: active sessions and route states match C11 snapshots");
