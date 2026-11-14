import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const source = await readFile(new URL("./worker.js", import.meta.url), "utf8");
const panel = await readFile(new URL("../../internal/web/assets/index.html", import.meta.url), "utf8");
const exact = "/d2o/apiws/5222";
const protocol = "d2o-tcp-5222-v1";
const allowed = { D2O_TG_5222_TARGETS: "149.154.167.91, 2001:b28:f23d:f001::a" };

async function loadWorker(connect, { logs = [], timers = {} } = {}) {
  class MockResponse extends Response {
    constructor(body, options) {
      super(body, { ...options, status: options.status === 101 ? 200 : options.status });
      Object.defineProperty(this, "status", { value: options.status });
      this.webSocket = options.webSocket;
    }
  }
  class MockWebSocket extends EventTarget {
    sent = [];
    readyState = 0;
    closeCalls = [];
    close(code, reason) {
      this.closeCalls.push({ code, reason });
      this.readyState = 3;
    }
    send(value) {
      assert.equal(this.readyState, 1);
      this.sent.push(value);
    }
    accept() {
      assert.equal(this.binaryType, "arraybuffer");
      this.readyState = 1;
    }
  }
  class MockPair {
    constructor() {
      this[1] = new MockWebSocket();
      this[0] = { server: this[1] };
    }
  }
  const sandbox = vm.createContext({
    Response: MockResponse, WebSocketPair: MockPair, URL, TextEncoder,
    Uint8Array, setTimeout, clearTimeout,
    console: { log(record) { logs.push(record); } },
    ...timers,
  });
  const sockets = new vm.SyntheticModule(["connect"], function () {
    this.setExport("connect", connect);
  }, { context: sandbox });
  const worker = new vm.SourceTextModule(source, { context: sandbox });
  await worker.link(specifier => {
    assert.equal(specifier, "cloudflare:sockets");
    return sockets;
  });
  await worker.evaluate();
  return worker.namespace.default;
}

function upgrade(path, query, requestedProtocol) {
  const headers = { Upgrade: "websocket" };
  if (requestedProtocol) headers["Sec-WebSocket-Protocol"] = requestedProtocol;
  return new Request(`https://worker.example${path}?${query}`, { headers });
}

function tcp(opened = Promise.resolve(), write, onPull) {
  let remote;
  let resolveClosed, rejectClosed;
  let readableEnded = false;
  const writes = [];
  const socket = {
    opened, writes, closeCalls: 0,
    closed: new Promise((resolve, reject) => { resolveClosed = resolve; rejectClosed = reject; }),
    readable: new ReadableStream({
      start(controller) { remote = controller; },
      pull: onPull,
      cancel() { readableEnded = true; },
    }, { highWaterMark: 0 }),
    writable: new WritableStream({ write: write ?? (bytes => { writes.push([...bytes]); }) }),
    async close() {
      ++this.closeCalls;
      if (this.isClosed) return;
      this.isClosed = true;
      this.eof();
      resolveClosed();
    },
    eof() {
      if (readableEnded) return;
      readableEnded = true;
      remote.close();
    },
    fail() {
      readableEnded = true;
      remote.error(new Error("TCP reset"));
      rejectClosed(new Error("TCP reset"));
    },
    receive(bytes) { remote.enqueue(bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes)); },
  };
  return socket;
}

const tick = () => new Promise(resolve => setImmediate(resolve));
const deferred = () => Promise.withResolvers();
const wsRequest = () => upgrade("/apiws", "dst=149.154.167.91");

function manualTimers() {
  const pending = new Map();
  return {
    setTimeout(fn, ms) {
      const id = Symbol();
      pending.set(id, { fn, ms });
      return id;
    },
    clearTimeout(id) { pending.delete(id); },
    fire(ms) {
      const timer = [...pending].find(([, entry]) => entry.ms === ms);
      assert.ok(timer, `expected a timer for ${ms} ms`);
      pending.delete(timer[0]);
      timer[1].fn();
    },
    pending,
  };
}

function message(ws, data) {
  ws.dispatchEvent(new MessageEvent("message", { data }));
}

test("the panel serves the same Worker as the release archive", () => {
  const embedded = panel.match(/<script id="tg-worker-source" type="text\/plain">([\s\S]*?)<\/script>/);
  assert.equal(embedded?.[1], source);
});

function peerClose(ws, code = 1000, wasClean = true) {
  ws.readyState = wasClean ? 2 : 3;
  ws.dispatchEvent(Object.assign(new Event("close"), { code, wasClean }));
}

test("Flowseal /apiws opens the requested media DC on 443 and forwards bytes in order", async () => {
  let opened;
  const socket = tcp(new Promise(resolve => { opened = resolve; }));
  const worker = await loadWorker(address => {
    assert.equal(address.hostname, "149.154.167.43");
    assert.equal(address.port, 443);
    return socket;
  });
  let completed = false;
  const pending = worker.fetch(upgrade("/apiws", "dst=::ffff:149.154.167.43&dc=4&media=1&port=5222"))
    .then(result => { completed = true; return result; });
  await tick();
  assert.equal(completed, false);
  opened();
  const response = await pending;
  assert.equal(response.status, 101);
  assert.equal(response.headers.get("Sec-WebSocket-Protocol"), null);
  const ws = response.webSocket.server;
  ws.dispatchEvent(new MessageEvent("message", { data: Uint8Array.of(1, 2).buffer }));
  ws.dispatchEvent(new MessageEvent("message", { data: Uint8Array.of(3, 4).buffer }));
  socket.receive([5, 6]);
  await tick();
  assert.deepEqual(socket.writes, [[1, 2], [3, 4]]);
  assert.deepEqual([...ws.sent[0]], [5, 6]);
  peerClose(ws);
  await tick();
  assert.equal(socket.isClosed, true);
});

test("5222 confirms an allowlisted IPv6 address only after the exact TCP open", async () => {
  let opened;
  const socket = tcp(new Promise(resolve => { opened = resolve; }));
  const worker = await loadWorker(address => {
    assert.equal(address.hostname, "2001:b28:f23d:f001::a");
    assert.equal(address.port, 5222);
    return socket;
  });
  let completed = false;
  const pending = worker.fetch(upgrade(exact, "dst=2001:b28:f23d:f001:0:0:0:a&port=443", protocol), allowed)
    .then(result => { completed = true; return result; });
  await tick();
  assert.equal(completed, false);
  opened();
  const response = await pending;
  assert.equal(response.status, 101);
  assert.equal(response.headers.get("Sec-WebSocket-Protocol"), protocol);
  response.webSocket.server.dispatchEvent(new MessageEvent("message", { data: Uint8Array.of(9).buffer }));
  socket.receive([10]);
  await tick();
  assert.deepEqual(socket.writes, [[9]]);
  assert.deepEqual([...response.webSocket.server.sent[0]], [10]);
  await socket.close();
});

test("5222 refuses missing negotiation and invalid destinations before connecting", async () => {
  const worker = await loadWorker(() => assert.fail("unexpected outbound TCP"));
  assert.equal((await worker.fetch(upgrade(exact, "dst=149.154.167.91"), allowed)).status, 400);
  assert.equal((await worker.fetch(upgrade(exact, "dst=149.154.167.91", protocol))).status, 501);
  for (const query of ["dst=149.154.167.92", "dst=127.0.0.1", "dst=example.com",
    "dst=149.154.167.91%3A443", "dst=149.154.167.91&dst=149.154.167.91"]) {
    assert.equal((await worker.fetch(upgrade(exact, query, protocol), allowed)).status, 403);
  }
  assert.equal((await worker.fetch(upgrade("/apiws", "dst=192.0.2.1"))).status, 403);
  assert.equal((await worker.fetch(upgrade("/apiws/5222", "dst=149.154.167.91"))).status, 404);
});

for (const port of [443, 5222]) {
  test(`a failed TCP ${port} open returns HTTP 502 without upgrade or port fallback`, async () => {
    let attempts = 0;
    const worker = await loadWorker(address => {
      assert.equal(address.hostname, "149.154.167.91");
      assert.equal(address.port, port);
      ++attempts;
      return socket;
    });
    const socket = tcp(Promise.reject(new Error("connection refused")));
    const request = port === 5222
      ? upgrade(exact, "dst=149.154.167.91", protocol)
      : upgrade("/apiws", "dst=149.154.167.91");
    const response = await worker.fetch(request, allowed);
    assert.equal(attempts, 1);
    assert.equal(socket.isClosed, true);
    assert.equal(response.status, 502);
    assert.equal(response.webSocket, undefined);
    assert.equal(response.headers.get("Sec-WebSocket-Protocol"), null);
  });
}

test("a slow TCP receiver bounds pending binary writes and frees both locks on overflow", async () => {
  const write = deferred();
  let started = 0;
  const socket = tcp(undefined, () => { ++started; return write.promise; });
  const logs = [];
  const worker = await loadWorker(() => socket, { logs });
  const response = await worker.fetch(wsRequest(), { D2O_TG_LOG_SESSIONS: "1" });
  const ws = response.webSocket.server;
  for (let i = 0; i < 257; ++i) message(ws, new ArrayBuffer(16 * 1024));
  await tick();
  assert.equal(ws.closeCalls[0]?.code, 1013);
  assert.ok(started <= 1);
  write.resolve();
  await tick();
  assert.equal(socket.closeCalls, 1);
  assert.equal(socket.readable.locked, false);
  assert.equal(socket.writable.locked, false);
  assert.equal(logs.length, 1);
  assert.equal(logs[0].reason, "tcp_queue_full");
  assert.ok(logs[0].tcp_queue_peak <= 4 * 1024 * 1024);
});

test("a socket that reaches EOF before becoming usable cannot upgrade", async () => {
  const socket = tcp();
  socket.eof();
  const worker = await loadWorker(() => socket);
  const response = await worker.fetch(wsRequest());
  assert.equal(response.status, 502);
  assert.equal(response.webSocket, undefined);
  assert.equal(socket.readable.locked, false);
  assert.equal(socket.writable.locked, false);
});

test("TCP EOF preserves queued WebSocket data and releases both stream locks once", async () => {
  const socket = tcp();
  const worker = await loadWorker(() => socket);
  const response = await worker.fetch(wsRequest());
  const ws = response.webSocket.server;
  socket.receive([11, 22]);
  socket.eof();
  await tick();
  assert.deepEqual([...ws.sent[0]], [11, 22]);
  assert.equal(ws.closeCalls[0]?.code, 1000);
  assert.equal(socket.closeCalls, 1);
  assert.equal(socket.readable.locked, false);
  assert.equal(socket.writable.locked, false);
});

test("TCP EOF with an undelivered write reports a failed session", async () => {
  const write = deferred(), logs = [];
  const socket = tcp(undefined, () => write.promise);
  const worker = await loadWorker(() => socket, { logs });
  const ws = (await worker.fetch(wsRequest(), { D2O_TG_LOG_SESSIONS: "1" })).webSocket.server;
  message(ws, new ArrayBuffer(16));
  socket.eof();
  await tick();
  assert.equal(ws.closeCalls[0]?.code, 1011);
  assert.equal(logs[0].reason, "tcp_eof_with_pending_writes");
  assert.equal(logs[0].tcp_pending_bytes, 16);
  assert.equal(socket.readable.locked || socket.writable.locked, false);
  write.reject(new Error("socket closed"));
});

test("TCP open timeout and late open never produce a WebSocket", async () => {
  const timers = manualTimers(), opened = deferred(), logs = [];
  const socket = tcp(opened.promise);
  const worker = await loadWorker(() => socket, { logs, timers });
  const pending = worker.fetch(wsRequest(), { D2O_TG_LOG_SESSIONS: "1" });
  timers.fire(5000);
  const response = await pending;
  assert.equal(response.status, 504);
  assert.equal(response.webSocket, undefined);
  assert.equal(socket.closeCalls, 1);
  opened.resolve();
  await tick();
  assert.equal(timers.pending.size, 0);
  assert.equal(logs.length, 1);
  assert.equal(logs[0].reason, "tcp_open_timeout");
});

test("clean WebSocket close drains ordered pending writes before releasing locks", async () => {
  const first = deferred(), writes = [], logs = [];
  const socket = tcp(undefined, async bytes => {
    writes.push([...bytes]);
    if (writes.length === 1) await first.promise;
  });
  const worker = await loadWorker(() => socket, { logs });
  const request = wsRequest();
  request.headers.set("CF-Ray", "a5a478958bda3aba-AMS");
  request.headers.set("CF-Connecting-IP", "192.0.2.123");
  const response = await worker.fetch(request, { D2O_TG_LOG_SESSIONS: "1" });
  const ws = response.webSocket.server;
  message(ws, Uint8Array.of(7).buffer);
  message(ws, Uint8Array.of(8, 9).buffer);
  peerClose(ws);
  message(ws, Uint8Array.of(10).buffer);
  await tick();
  assert.deepEqual(writes, [[7]]);
  assert.equal(socket.closeCalls, 0);
  first.resolve();
  await tick();
  assert.deepEqual(writes, [[7], [8, 9]]);
  assert.equal(socket.closeCalls, 1);
  assert.equal(socket.readable.locked || socket.writable.locked, false);
  assert.equal(ws.closeCalls.length, 1);
  assert.equal(logs.length, 1);
  assert.equal(logs[0].reason, "ws_peer_close");
  assert.equal(logs[0].bytes_to_tcp, 3);
  assert.equal(logs[0].ray, "a5a478958bda3aba-AMS");
  assert.doesNotMatch(JSON.stringify(logs[0]), /192\.0\.2\.123|149\.154\.167\.91|apiws/);
});

test("a stuck write cannot delay WebSocket close indefinitely", async () => {
  const timers = manualTimers(), write = deferred(), logs = [];
  const socket = tcp(undefined, () => write.promise);
  const worker = await loadWorker(() => socket, { logs, timers });
  const pending = worker.fetch(wsRequest(), { D2O_TG_LOG_SESSIONS: "1" });
  await tick();
  timers.fire(0);
  const ws = (await pending).webSocket.server;
  message(ws, Uint8Array.of(42).buffer);
  peerClose(ws);
  timers.fire(2000);
  assert.equal(ws.closeCalls[0]?.code, 1011);
  assert.equal(socket.closeCalls, 1);
  assert.equal(socket.readable.locked || socket.writable.locked, false);
  write.reject(new Error("late error"));
  await tick();
  assert.equal(logs.length, 1);
  assert.equal(logs[0].reason, "tcp_close_timeout");
  assert.equal(logs[0].tcp_pending_bytes, 1);
  assert.equal(timers.pending.size, 0);
});

for (const expected of ["tcp_error", "ws_peer_disconnected", "ws_send_error", "tcp_write_error"]) {
  test(`interrupted session reports ${expected} and closes once`, async () => {
    const socket = tcp(undefined, () => { throw new Error("write reset"); });
    const logs = [];
    const worker = await loadWorker(() => socket, { logs });
    const ws = (await worker.fetch(wsRequest(), { D2O_TG_LOG_SESSIONS: "1" })).webSocket.server;
    if (expected === "tcp_error") socket.fail();
    else if (expected === "ws_peer_disconnected") peerClose(ws, 1006, false);
    else if (expected === "ws_send_error") {
      ws.send = () => { throw new Error("send reset"); };
      socket.receive([42]);
    } else message(ws, Uint8Array.of(42).buffer);
    await tick();
    ws.dispatchEvent(new Event("error"));
    assert.equal(socket.closeCalls, 1);
    assert.equal(ws.closeCalls.length, 1);
    assert.equal(ws.closeCalls[0].code, 1011);
    assert.equal(socket.readable.locked || socket.writable.locked, false);
    assert.equal(logs.length, 1);
    if (expected === "tcp_error") assert.match(logs[0].reason, /^tcp_(socket|read)_error$/);
    else assert.equal(logs[0].reason, expected);
  });
}

test("parallel long transfers stay byte-exact with independent counters", async () => {
  const block = 128 * 1024;
  const blocks = 256;
  const logs = [];
  const sockets = Array.from({ length: 4 }, (_, session) => {
    let index = 0;
    return tcp(undefined, undefined, async controller => {
      // Hold the first read until all sessions are upgraded.
      await started.promise;
      await tick();
      if (index === blocks) controller.close();
      else controller.enqueue(new Uint8Array(block).fill((session + index++) & 255));
    });
  });
  const started = deferred();
  let index = 0;
  const worker = await loadWorker(() => sockets[index++], { logs });
  const sessions = await Promise.all(sockets.map(() => worker.fetch(wsRequest(), { D2O_TG_LOG_SESSIONS: "1" })));
  const received = sessions.map((response, session) => {
    assert.equal(response.status, 101);
    const ws = response.webSocket.server;
    let bytes = 0;
    const done = deferred();
    ws.send = chunk => {
      assert.ok(chunk.byteLength <= 65536);
      assert.equal(chunk.byteLength, 65536);
      assert.ok(chunk.every(byte => byte === ((session + Math.floor(bytes / block)) & 255)));
      bytes += chunk.byteLength;
    };
    const close = ws.close.bind(ws);
    ws.close = (code, reason) => {
      close(code, reason);
      done.resolve({ code, bytes });
    };
    message(ws, new ArrayBuffer(session + 1));
    return done.promise;
  });
  started.resolve();
  for (const result of await Promise.all(received)) {
    assert.deepEqual(result, { code: 1000, bytes: blocks * block });
  }
  assert.equal(logs.length, 4);
  assert.deepEqual(logs.map(log => log.bytes_to_tcp).sort(), [1, 2, 3, 4]);
  for (const socket of sockets) {
    assert.equal(socket.closeCalls, 1);
    assert.equal(socket.readable.locked || socket.writable.locked, false);
  }
});
