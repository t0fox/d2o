import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const source = await readFile(new URL("./worker.js", import.meta.url), "utf8");
const exact = "/d2o/apiws/5222";
const protocol = "d2o-tcp-5222-v1";
const allowed = { D2O_TG_5222_TARGETS: "149.154.167.91, 2001:b28:f23d:f001::a" };

async function loadWorker(connect) {
  class MockResponse extends Response {
    constructor(body, options) {
      super(body, { ...options, status: options.status === 101 ? 200 : options.status });
      Object.defineProperty(this, "status", { value: options.status });
      this.webSocket = options.webSocket;
    }
  }
  class MockWebSocket extends EventTarget {
    sent = [];
    close() { this.isClosed = true; }
    send(value) { this.sent.push(value); }
    accept() { assert.equal(this.binaryType, "arraybuffer"); }
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

function tcp(opened = Promise.resolve()) {
  let remote;
  const writes = [];
  const socket = {
    opened, writes, closed: Promise.resolve(),
    readable: new ReadableStream({ start(controller) { remote = controller; } }),
    writable: new WritableStream({ write(bytes) { writes.push([...bytes]); } }),
    async close() {
      if (this.isClosed) return;
      this.isClosed = true;
      remote.close();
    },
    receive(bytes) { remote.enqueue(Uint8Array.from(bytes)); },
  };
  return socket;
}

const tick = () => new Promise(resolve => setImmediate(resolve));

test("Flowseal /apiws opens the requested media DC on 443 and forwards bytes in order", async () => {
  let opened;
  const socket = tcp(new Promise(resolve => { opened = resolve; }));
  const worker = await loadWorker(address => {
    assert.equal(address.hostname, "149.154.167.43");
    assert.equal(address.port, 443);
    return socket;
  });
  const response = await worker.fetch(upgrade("/apiws", "dst=::ffff:149.154.167.43&dc=4&media=1&port=5222"));
  assert.equal(response.status, 101);
  assert.equal(response.headers.get("Sec-WebSocket-Protocol"), null);
  opened();
  const ws = response.webSocket.server;
  ws.dispatchEvent(new MessageEvent("message", { data: Uint8Array.of(1, 2).buffer }));
  ws.dispatchEvent(new MessageEvent("message", { data: Uint8Array.of(3, 4).buffer }));
  socket.receive([5, 6]);
  await tick();
  assert.deepEqual(socket.writes, [[1, 2], [3, 4]]);
  assert.deepEqual([...ws.sent[0]], [5, 6]);
  ws.dispatchEvent(new Event("close"));
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

test("a failed TCP 5222 open returns HTTP 502 without upgrade or retry on 443", async () => {
  let attempts = 0;
  const worker = await loadWorker(address => {
    assert.equal(address.port, 5222);
    ++attempts;
    return socket;
  });
  const socket = tcp(Promise.reject(new Error("connection refused")));
  const response = await worker.fetch(upgrade(exact, "dst=149.154.167.91", protocol), allowed);
  assert.equal(attempts, 1);
  assert.equal(socket.isClosed, true);
  assert.equal(response.status, 502);
  assert.equal(response.headers.get("Sec-WebSocket-Protocol"), null);
});
