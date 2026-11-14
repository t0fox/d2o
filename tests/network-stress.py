"""Local HTTP/3 + TLS media and persistent TCP/UDP tunnel load. Lab only."""
import argparse
import asyncio
from collections import defaultdict
import hashlib
import json
import socket
import ssl
from time import monotonic

from aioquic.asyncio import QuicConnectionProtocol, connect, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration

MEDIA = hashlib.shake_256(b"d2o-media-fixture").digest(128 * 1024)
MEDIA_SHA = hashlib.sha256(MEDIA).digest()
TLS_PORT = 8443
TUNNEL_PORT = 9443


class MediaServer(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)

    def quic_event_received(self, event):
        for msg in self.http.handle_event(event):
            if isinstance(msg, HeadersReceived):
                self.http.send_headers(msg.stream_id, [(b":status", b"200")])
                self.http.send_data(msg.stream_id, MEDIA, end_stream=True)
                self.transmit()


class MediaClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.complete = asyncio.get_running_loop().create_future()
        self.body = hashlib.sha256()
        self.status = None

    def quic_event_received(self, event):
        for msg in self.http.handle_event(event):
            if isinstance(msg, HeadersReceived):
                self.status = dict(msg.headers).get(b":status")
            elif hasattr(msg, "data"):
                self.body.update(msg.data)
            if msg.stream_ended and not self.complete.done():
                self.complete.set_result((self.status, self.body.digest()))

    async def download(self):
        stream = self._quic.get_next_available_stream_id()
        self.http.send_headers(stream, [(b":method", b"GET"), (b":scheme", b"https"),
            (b":authority", b"media.example"), (b":path", b"/segment")], end_stream=True)
        self.transmit()
        status, digest = await self.complete
        if (status, digest) != (b"200", MEDIA_SHA):
            raise ValueError("incomplete HTTP/3 media segment")


async def https_server(reader, writer):
    try:
        await reader.readuntil(b"\r\n\r\n")
        writer.write(f"HTTP/1.1 200 OK\r\nContent-Length: {len(MEDIA)}\r\nConnection: close\r\n\r\n".encode() + MEDIA)
        await writer.drain()
    except (ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        writer.close()


async def tcp_echo(reader, writer):
    try:
        while (packet := await reader.read(4096)):
            writer.write(packet)
            await writer.drain()
    except ConnectionError:
        pass
    finally:
        writer.close()


class UdpEcho(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.transport.sendto(data, addr)


async def server(args):
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(args.cert, args.key)
    config = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
    config.load_cert_chain(args.cert, args.key)
    tcp = await asyncio.start_server(https_server, args.host, TLS_PORT, ssl=tls)
    tunnel_tcp = await asyncio.start_server(tcp_echo, args.host, TUNNEL_PORT)
    tunnel_udp, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        UdpEcho, local_addr=(args.host, TUNNEL_PORT))
    quic = await serve(args.host, TLS_PORT, configuration=config, create_protocol=MediaServer)
    print("READY", flush=True)
    try:
        await asyncio.Event().wait()
    finally:
        tcp.close()
        tunnel_tcp.close()
        tunnel_udp.close()
        quic.close()


async def https_get(address, name, context):
    reader, writer = await asyncio.open_connection(address, TLS_PORT, ssl=context, server_hostname=name)
    try:
        header = b"GET /segment HTTP/1.1\r\nHost: " + name.encode() + b"\r\nConnection: close\r\n\r\n"
        writer.write(header)
        await writer.drain()
        response = await reader.readuntil(b"\r\n\r\n")
        body = await reader.readexactly(len(MEDIA))
        if not response.startswith(b"HTTP/1.1 200 ") or hashlib.sha256(body).digest() != MEDIA_SHA:
            raise ValueError("incomplete HTTPS media segment")
    finally:
        writer.close()


async def h3_get(address, cert):
    config = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN, idle_timeout=4)
    config.server_name = "media.example"
    config.load_verify_locations(cafile=cert)
    async with connect(address, TLS_PORT, configuration=config, create_protocol=MediaClient) as client:
        await client.download()


async def media_loop(deadline, request, stats):
    while monotonic() < deadline:
        try:
            await asyncio.wait_for(request(), timeout=5)
            stats["ok"] += 1
        except (TimeoutError, OSError, ValueError, asyncio.IncompleteReadError):
            stats["errors"] += 1
        await asyncio.sleep(0.025)


async def tunnel_loop(deadline, send_recv, stats, period):
    seq = 0
    while monotonic() < deadline:
        seq += 1
        data = b"\x04\x00\x00\x00" + seq.to_bytes(8, "big") + hashlib.shake_256(
            seq.to_bytes(8, "big")).digest(244)
        started = monotonic()
        try:
            if await asyncio.wait_for(send_recv(data), timeout=1) != data:
                stats["mismatches"] += 1
            else:
                stats["ok"] += 1
                stats["rtt_ms"].append(round((monotonic() - started) * 1000, 3))
        except TimeoutError:
            stats["timeouts"] += 1
        except (ConnectionError, asyncio.IncompleteReadError, OSError):
            stats["disconnects"] += 1
            break
        await asyncio.sleep(max(0, period - (monotonic() - started)))


async def client(args):
    context = ssl.create_default_context(cafile=args.cert)
    media = {name: defaultdict(int) for name in ("https", "h3", "stalled")}
    tunnels = {name: defaultdict(int, rtt_ms=[]) for name in ("tcp", "udp")}
    reader, writer = await asyncio.open_connection(args.host, TUNNEL_PORT)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setblocking(False)
    loop = asyncio.get_running_loop()
    await loop.sock_connect(udp, (args.host, TUNNEL_PORT))

    async def tcp_roundtrip(data):
        writer.write(data)
        await writer.drain()
        return await reader.readexactly(len(data))

    async def udp_roundtrip(data):
        await loop.sock_sendall(udp, data)
        return await loop.sock_recv(udp, len(data) + 1)

    try:
        warmup = monotonic() + 0.5
        await asyncio.gather(tunnel_loop(warmup, tcp_roundtrip, tunnels["tcp"], 0.05),
                             tunnel_loop(warmup, udp_roundtrip, tunnels["udp"], 0.05))
        deadline = monotonic() + args.seconds
        tasks = [
            tunnel_loop(deadline, tcp_roundtrip, tunnels["tcp"], 0.05),
            tunnel_loop(deadline, udp_roundtrip, tunnels["udp"], 0.05),
        ]
        for _ in range(args.concurrency):
            tasks.append(media_loop(deadline, lambda: https_get(args.host, "media.example", context), media["https"]))
            tasks.append(media_loop(deadline, lambda: h3_get(args.host, args.cert), media["h3"]))
        if args.stall_host:
            for _ in range(4):
                tasks.append(media_loop(deadline, lambda: https_get(args.stall_host, "stalled.example", context),
                                        media["stalled"]))
        await asyncio.gather(*tasks)
    finally:
        udp.close()
        writer.close()

    for result in tunnels.values():
        rtts = sorted(result.pop("rtt_ms"))
        result["rtt_p95_ms"] = rtts[int(0.95 * (len(rtts) - 1))] if rtts else None
        result["rtt_max_ms"] = max(rtts, default=None)
    print(json.dumps({"media": media, "tunnel": tunnels}), flush=True)
    for result in tunnels.values():
        if (result.get("ok", 0) < args.seconds * 5
                or any(result.get(k, 0) for k in ("mismatches", "disconnects", "timeouts"))):
            return 1
    return int(not (media["https"]["ok"] and media["h3"]["ok"]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("server", "client"))
    parser.add_argument("host")
    parser.add_argument("cert")
    parser.add_argument("--key")
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--stall-host")
    args = parser.parse_args()
    if args.mode == "server":
        asyncio.run(server(args))
    else:
        raise SystemExit(asyncio.run(client(args)))


if __name__ == "__main__":
    main()
