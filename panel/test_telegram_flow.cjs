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

{
  const route = [[230, 170], [500, 100], [700, 170]];
  const clientToHub = [[60, 170], [230, 170]];
  assert.deepEqual(flow.composeFlowPoints(route, clientToHub, "request"),
    [[60, 170], [230, 170], [500, 100], [700, 170]],
    "исходная попытка идёт от клиента через d2o к Telegram");
  assert.deepEqual(flow.composeFlowPoints(route, clientToHub, "response"),
    [[700, 170], [500, 100], [230, 170], [60, 170]],
    "подтверждённый ответ Telegram идёт от DC к клиенту");
}

{
  assert.deepEqual(flow.connectionDotStates({ activeConnections: 0, sessions: [] }),
    ["idle", "idle", "idle"], "при отсутствии сессий индикаторы d2o погашены");
  assert.deepEqual(flow.connectionDotStates({ activeConnections: 5, sessions: [
    { telegram_response_seen: true }, { telegram_response_seen: false },
  ] }), ["confirmed", "active", "active"],
  "индикаторы учитывают число активных соединений и подтверждённые ответы");
}

{
  const view = flow.summarizeTelegramFlow(snapshot());
  assert.equal(view.state, "idle");
  assert.equal(view.activeConnections, 0);
  assert.equal(view.acceptedConnections, 0);
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
  assert.equal(view.lanes[3].counts.failed, 1);
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
  assert.equal(view.lanes[1].label, "Прямой TCP passthrough");
  assert.equal(view.lanes[1].counts.selected, 1);
  assert.equal(view.lanes[2].counts.connecting, 1);
  assert.deepEqual(flow.visibleRouteLanes(view).map(lane => lane.transport),
    ["direct_wss", "tcp_passthrough", "cloudflare_worker"]);
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

console.log("telegram flow: active sessions and route states match C11 snapshots");
