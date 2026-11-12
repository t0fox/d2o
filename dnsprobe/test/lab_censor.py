#!/usr/bin/env python3
"""Лабораторный цензор для проверки выбора SNI-режима.

9443 — цензор: ClientHello с SNI ровно "api.magicdns.ru" получает RST,
       с "api.magicdns.ru." — пересылается на 9444.
9444 — настоящий TLS/DoH-сервер с сертификатом api.magicdns.ru.
"""
import socket, ssl, struct, threading, sys

CERT = "/tmp/d2k-lab/cert.pem"
KEY = "/tmp/d2k-lab/key.pem"

def dns_reply(query: bytes) -> bytes:
    if len(query) < 12:
        return b""
    # найти конец вопроса
    o = 12
    while o < len(query) and query[o] != 0:
        o += 1 + query[o]
    o += 1 + 4
    q = query[:o]
    resp = bytearray(q)
    resp[2] = 0x81  # QR + RD
    resp[3] = 0x80  # RA
    resp[6:8] = b"\x00\x01"  # ANCOUNT
    resp += b"\xc0\x0c" + b"\x00\x01\x00\x01" + b"\x00\x00\x00\x3c" + b"\x00\x04" + bytes([1,2,3,4])
    return bytes(resp)

def serve_tls(conn):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT, KEY)
        s = ctx.wrap_socket(conn, server_side=True)
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = s.recv(4096)
            if not chunk: return
            data += chunk
        head, _, rest = data.partition(b"\r\n\r\n")
        clen = 0
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                clen = int(line.split(b":",1)[1].strip())
        body = rest
        while len(body) < clen:
            chunk = s.recv(4096)
            if not chunk: break
            body += chunk
        ans = dns_reply(body)
        resp = (b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n"
                b"Content-Length: " + str(len(ans)).encode() + b"\r\nConnection: close\r\n\r\n" + ans)
        s.sendall(resp)
        s.close()
    except Exception as e:
        print("tls err", e, file=sys.stderr)
    finally:
        conn.close()

def tls_listener():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 9444)); srv.listen(8)
    while True:
        c, _ = srv.accept()
        threading.Thread(target=serve_tls, args=(c,), daemon=True).start()

def relay(a, b):
    try:
        while True:
            d = a.recv(4096)
            if not d: break
            b.sendall(d)
    except Exception:
        pass
    finally:
        try: b.shutdown(socket.SHUT_WR)
        except Exception: pass

def censor(conn):
    try:
        conn.settimeout(5)
        data = b""
        while len(data) < 2048:
            chunk = conn.recv(2048 - len(data))
            if not chunk: return
            data += chunk
            if b"api.magicdns.ru" in data:
                break
        if b"api.magicdns.ru." in data:
            up = socket.create_connection(("127.0.0.1", 9444), timeout=5)
            up.sendall(data)
            t1 = threading.Thread(target=relay, args=(conn, up), daemon=True)
            t1.start()
            relay(up, conn)
            up.close()
        else:
            # RST
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            conn.close()
    except Exception as e:
        print("censor err", e, file=sys.stderr)
    finally:
        try: conn.close()
        except Exception: pass

def censor_listener():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 9443)); srv.listen(8)
    while True:
        c, _ = srv.accept()
        threading.Thread(target=censor, args=(c,), daemon=True).start()

if __name__ == "__main__":
    threading.Thread(target=tls_listener, daemon=True).start()
    print("lab ready", flush=True)
    censor_listener()
