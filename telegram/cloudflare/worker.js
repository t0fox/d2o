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

async function waitForTcp(socket) {
  let timer;
  try {
    await Promise.race([
      socket.opened,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error("TCP open timed out")), 5000);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

function bridge(socket, websocket) {
  const reader = socket.readable.getReader();
  const writer = socket.writable.getWriter();
  let closing = false;
  function close(code, reason) {
    if (closing) return;
    closing = true;
    try {
      websocket.close(code, reason);
    } catch {
      // Newer compatibility dates can close the WebSocket automatically.
    }
    void socket.close().catch(() => {});
  }

  websocket.binaryType = "arraybuffer";
  websocket.accept();
  websocket.addEventListener("message", event => {
    if (closing) return;
    const bytes = typeof event.data === "string"
      ? new TextEncoder().encode(event.data) : new Uint8Array(event.data);
    // WritableStream preserves call order, including back-to-back messages.
    void writer.write(bytes).catch(() => close(1011, "TCP write failed"));
  });
  websocket.addEventListener("close", () => {
    void writer.close().then(
      () => close(1000, "WebSocket closed"),
      () => close(1011, "TCP close failed"),
    );
  });
  websocket.addEventListener("error", () => close(1011, "WebSocket error"));
  void socket.opened.catch(() => close(1011, "TCP open failed"));

  void (async () => {
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        if (value?.byteLength && !closing) websocket.send(value);
      }
      close(1000, "TCP closed");
    } catch {
      close(1011, "TCP read failed");
    } finally {
      reader.releaseLock();
    }
  })();
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

    let socket;
    try {
      socket = connect({ hostname, port: exactPort ? 5222 : 443 });
      void socket.closed.catch(() => {});
      // The legacy upgrade keeps its timing. The exact-port upgrade is proof
      // that the TCP connect has already succeeded on the requested port.
      if (exactPort) await waitForTcp(socket);
      const pair = new WebSocketPair();
      bridge(socket, pair[1]);
      return new Response(null, {
        status: 101,
        webSocket: pair[0],
        headers: exactPort ? { "Sec-WebSocket-Protocol": PORT_5222_PROTOCOL } : undefined,
      });
    } catch {
      if (socket) void socket.close().catch(() => {});
      return new Response(exactPort ? "Telegram 5222 connection failed" : "Telegram 443 connection failed",
        { status: 502 });
    }
  },
};
