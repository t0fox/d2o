/*
 * Based on the Cloudflare Worker documented by Flowseal/tg-ws-proxy:
 * https://github.com/Flowseal/tg-ws-proxy/blob/main/docs/EN/CfWorker.md
 *
 * MIT License
 * Copyright (c) 2026 Flowseal
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
import { connect } from "cloudflare:sockets";

const PORT_5222_PATH = "/d2o/apiws/5222";
const PORT_5222_PROTOCOL = "d2o-tcp-5222-v1";

function ipAddress(value) {
  if (typeof value !== "string") return null;
  try {
    if (value.includes(":") && /^[0-9a-f:.]+$/i.test(value)) {
      const ip = new URL(`https://[${value}]/`).hostname.slice(1, -1);
      const mapped = /^::ffff:([0-9a-f]+):([0-9a-f]+)$/.exec(ip);
      if (!mapped) return ip;
      const high = parseInt(mapped[1], 16);
      const low = parseInt(mapped[2], 16);
      return [high >> 8, high & 255, low >> 8, low & 255].join(".");
    }
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)) {
      const ip = new URL(`https://${value}/`).hostname;
      return ip === value ? ip : null;
    }
  } catch {
    return null;
  }
  return null;
}

function ipNumber(ip) {
  if (!ip.includes(":")) {
    return ip.split(".").reduce((number, part) => (number << 8n) | BigInt(part), 0n);
  }
  const [first, second] = ip.split("::");
  const head = first ? first.split(":") : [];
  const tail = second ? second.split(":") : [];
  const groups = second === undefined
    ? head : [...head, ...Array(8 - head.length - tail.length).fill("0"), ...tail];
  return groups.reduce((number, part) => (number << 16n) | BigInt(`0x${part}`), 0n);
}

// Keep in sync with allowed_cidrs in telegram/src/main.c.
const telegramNetworks = [
  ["149.154.160.0", 20], ["91.108.4.0", 22], ["91.108.8.0", 22],
  ["91.108.12.0", 22], ["91.108.16.0", 22], ["91.108.20.0", 22],
  ["91.108.56.0", 22], ["91.105.192.0", 23], ["95.161.64.0", 20],
  ["185.76.151.0", 24], ["2001:67c:4e8::", 48], ["2001:b28:f23c::", 47],
  ["2001:b28:f23f::", 48], ["2a0a:f280:203::", 48],
].map(([ip, prefix]) => {
  const ipv6 = ip.includes(":");
  const shift = BigInt((ipv6 ? 128 : 32) - prefix);
  return { ipv6, shift, network: ipNumber(ip) >> shift };
});

function inTelegramNetwork(hostname) {
  const ipv6 = hostname.includes(":");
  const address = ipNumber(hostname);
  return telegramNetworks.some(entry =>
    entry.ipv6 === ipv6 && (address >> entry.shift) === entry.network);
}

function configuredTargets(value = "") {
  return value.split(",").map(entry => ipAddress(entry.trim())).filter(Boolean);
}

const TCP_OPEN_TIMEOUT_MS = 5000;
const TCP_CLOSE_TIMEOUT_MS = 2000;
const TCP_QUEUE_BYTES = 4 * 1024 * 1024; // Also fits the largest C11 WebSocket frame.
const TCP_QUEUE_MESSAGES = 512;
const WS_CHUNK_BYTES = 64 * 1024;

async function waitForTcp(socket) {
  let timer;
  try {
    return await Promise.race([
      socket.opened.then(() => null, () => "tcp_open_error"),
      socket.closed.then(() => "tcp_early_eof", () => "tcp_open_error"),
      new Promise(resolve => {
        timer = setTimeout(() => resolve("tcp_open_timeout"), TCP_OPEN_TIMEOUT_MS);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function initialRead(firstRead) {
  let timer;
  try {
    return await Promise.race([
      firstRead,
      new Promise(resolve => { timer = setTimeout(resolve, 0); }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

function sessionLogger(request, env, port) {
  if (env.D2O_TG_LOG_SESSIONS !== "1") return () => {};
  const started = Date.now();
  const header = request.headers.get("CF-Ray") ?? "";
  const ray = /^[a-f0-9]{16}(?:-[a-z]{3})?$/i.test(header) ? header : undefined;
  return fields => console.log({
    event: "d2o_tg_session_end", ray, port, duration_ms: Date.now() - started,
    ...fields,
  });
}

function bridge(socket, reader, firstRead, ws, report) {
  ws.binaryType = "arraybuffer";
  const writer = socket.writable.getWriter();
  try {
    ws.accept({ allowHalfOpen: true });
  } catch (error) {
    writer.releaseLock();
    throw error;
  }

  const queue = [];
  let pendingBytes = 0;
  let peakBytes = 0;
  let tcpBytes = 0;
  let wsBytes = 0;
  let writing = false;
  let stopped = false;
  let peerCode;
  let closeTimer;

  // All terminal paths share this teardown. Initiate cancellation before
  // releasing the locks so an outstanding read/write can settle safely.
  function finish(reason, code) {
    if (stopped) return;
    stopped = true;
    clearTimeout(closeTimer);
    queue.length = 0;
    ws.removeEventListener("message", onMessage);
    ws.removeEventListener("close", onClose);
    ws.removeEventListener("error", onError);
    try {
      ws.close(code, reason);
    } catch {
      // The peer or runtime may already have closed the WebSocket.
    }
    void reader.cancel().catch(() => {});
    void writer.abort().catch(() => {});
    reader.releaseLock();
    writer.releaseLock();
    void socket.close().catch(() => {});
    report({
      http: 101, reason, ws_code: code, peer_ws_code: peerCode,
      bytes_to_tcp: tcpBytes, bytes_to_ws: wsBytes, tcp_queue_peak: peakBytes,
      tcp_pending_bytes: pendingBytes,
    });
  }

  async function writeTcp() {
    writing = true;
    try {
      while (!stopped && queue.length) {
        // Keep the in-flight message in the byte and message budgets.
        const bytes = queue[0];
        await writer.write(bytes);
        if (stopped) return;
        queue.shift();
        pendingBytes -= bytes.byteLength;
        tcpBytes += bytes.byteLength;
      }
      if (!stopped && peerCode !== undefined) {
        await writer.close();
        finish("ws_peer_close", 1000);
      }
    } catch {
      finish("tcp_write_error", 1011);
    } finally {
      writing = false;
    }
  }

  function onMessage(event) {
    if (stopped || peerCode !== undefined) return;
    const data = event.data;
    if (typeof data === "string" && data.length > TCP_QUEUE_BYTES - pendingBytes) {
      finish("tcp_queue_full", 1013);
      return;
    }
    const bytes = typeof data === "string" ? new TextEncoder().encode(data) : new Uint8Array(data);
    if (!bytes.byteLength) return;
    if (queue.length >= TCP_QUEUE_MESSAGES || bytes.byteLength > TCP_QUEUE_BYTES - pendingBytes) {
      finish("tcp_queue_full", 1013);
      return;
    }
    pendingBytes += bytes.byteLength;
    peakBytes = Math.max(peakBytes, pendingBytes);
    queue.push(bytes);
    if (!writing) void writeTcp();
  }

  function onClose(event) {
    if (stopped || peerCode !== undefined) return;
    peerCode = event.code;
    if (!event.wasClean || peerCode === 1006) {
      finish("ws_peer_disconnected", 1011);
      return;
    }
    closeTimer = setTimeout(() => finish("tcp_close_timeout", 1011), TCP_CLOSE_TIMEOUT_MS);
    if (!writing) void writeTcp();
  }

  function onError() {
    finish("ws_error", 1011);
  }

  async function readTcp() {
    try {
      let next = firstRead;
      while (!stopped && peerCode === undefined) {
        const { value, done } = await next;
        if (stopped || peerCode !== undefined) return;
        if (done) {
          if (pendingBytes) finish("tcp_eof_with_pending_writes", 1011);
          else finish("tcp_eof", 1000);
          return;
        }
        try {
          if (ws.readyState !== 1) {
            finish("ws_not_open", 1011);
            return;
          }
          for (let offset = 0; offset < value.byteLength; offset += WS_CHUNK_BYTES) {
            const part = value.subarray(offset, offset + WS_CHUNK_BYTES);
            // send() enqueues bytes in the runtime and has no drain signal.
            ws.send(part);
            wsBytes += part.byteLength;
          }
        } catch {
          finish("ws_send_error", 1011);
          return;
        }
        next = reader.read();
      }
    } catch {
      finish("tcp_read_error", 1011);
    }
  }

  ws.addEventListener("message", onMessage);
  ws.addEventListener("close", onClose);
  ws.addEventListener("error", onError);
  // A fulfilled closed promise can race the final readable chunk. Let the
  // reader handle normal EOF after forwarding those bytes.
  void socket.closed.catch(() => finish("tcp_socket_error", 1011));
  void readTcp();
}

export default {
  async fetch(request, env = {}) {
    if (request.method !== "GET" ||
        request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
      return new Response("Expected WebSocket", { status: 426 });
    }
    const url = new URL(request.url);
    const exactPort = url.pathname === PORT_5222_PATH;
    if (!exactPort && url.pathname !== "/apiws") {
      return new Response("Not found", { status: 404 });
    }
    if (exactPort && request.headers.get("Sec-WebSocket-Protocol") !== PORT_5222_PROTOCOL) {
      return new Response("Expected the D2O 5222 WebSocket protocol", { status: 400 });
    }
    const dst = url.searchParams.getAll("dst");
    const hostname = dst.length === 1 ? ipAddress(dst[0]) : null;
    const targets = configuredTargets(exactPort ? env.D2O_TG_5222_TARGETS : env.D2O_TG_443_TARGETS);
    if (exactPort && targets.length === 0) {
      return new Response("Telegram 5222 is disabled", { status: 501 });
    }
    if (!hostname || !(targets.includes(hostname) || (!exactPort && inTelegramNetwork(hostname)))) {
      return new Response("Telegram destination is outside the allowlist", { status: 403 });
    }

    const port = exactPort ? 5222 : 443;
    const report = sessionLogger(request, env, port);
    let socket, reader;
    let failure = "tcp_open_error";
    try {
      socket = connect({ hostname, port });
      failure = await waitForTcp(socket);
      if (failure) throw new Error(failure);

      failure = "tcp_early_read_error";
      reader = socket.readable.getReader();
      const firstRead = reader.read();
      // Observe already settled EOF/errors without waiting for application
      // data: Telegram normally waits for the client to send its handshake.
      const first = await initialRead(firstRead);
      if (first?.done) {
        failure = "tcp_early_eof";
        throw new Error(failure);
      }
      failure = "ws_setup_error";
      const pair = new WebSocketPair();
      const response = new Response(null, {
        status: 101,
        webSocket: pair[0],
        headers: exactPort ? { "Sec-WebSocket-Protocol": PORT_5222_PROTOCOL } : undefined,
      });
      bridge(socket, reader, firstRead, pair[1], report);
      return response;
    } catch {
      if (reader) {
        void reader.cancel().catch(() => {});
        reader.releaseLock();
      }
      if (socket) void socket.close().catch(() => {});
      const status = failure === "tcp_open_timeout" ? 504 : 502;
      report({ http: status, reason: failure });
      return new Response(`Telegram ${port} ${status === 504 ? "connection timed out" : "connection failed"}`,
        { status });
    }
  },
};
