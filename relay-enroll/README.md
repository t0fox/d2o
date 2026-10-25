# D2K enrollment on the relay VPS

Both the router runtime and this separate VPS enrollment service are C. The
service enables public self-service installation without
shipping the fleet bootstrap credential in source, artifacts or router config.

`POST https://192.0.2.44.nip.io:9443/register` accepts exactly 120 bytes:
installation ID (16), Ed25519 public key (32), big-endian work nonce (8), and
Ed25519 signature (64). The signed message is `d2k-enroll-v1\0` followed by the
first 56 bytes. Its SHA-256 must start with 18 zero bits. Proofs bind work and
key possession to one identity; replay only repeats the same registration.

The endpoint is intentionally public enrollment, not proof of a purchased or
trusted device. It allows 6 requests per source IP/minute and 120 total/minute,
with bounded request sizes, deadlines and concurrent upstream operations. It
forwards only the fixed ID/public-key JSON to localhost `/register`, signed with
the VPS-owned bootstrap credential. Upstream credentials and responses are
never returned. Existing relay destination allowlists, session limits and
revocation still apply. The Telegram router redirect remains Telegram-only.

## `POST /resolve` (Meta host addresses for the router)

The same service, port 9443 and TLS also answer d2k's own resolver, used by
`files/d2k-instagram-dns.sh` instead of the z2k relay's `/resolve`. Body (at most
2048 bytes, one `Content-Length`, no `Transfer-Encoding`): `{"hosts":["…",…]}`,
at most 32 names, each exactly one of the fixed list:

`instagram.com www.instagram.com graph.instagram.com api.instagram.com i.instagram.com
instagram.c10r.instagram.com static.cdninstagram.com scontent.cdninstagram.com
static.xx.fbcdn.net scontent.xx.fbcdn.net web.whatsapp.com www.whatsapp.com
scontent.whatsapp.net graph.whatsapp.com v.whatsapp.com static.whatsapp.net
mmg.whatsapp.net pps.whatsapp.net`

Any other name, escape, extra key or trailing data → 400; nothing is resolved.
Reply 200 `{"results":{"host":["a.b.c.d",…],…}}`: the union of IPv4 A records from
the VPS's own `getaddrinfo` and from direct UDP queries to 1.1.1.1, 8.8.8.8 and
9.9.9.9 (Meta's GeoDNS answers for each resolver's location, so one source alone
may give only an edge that is dead from the router). The public queries go out
for all names at once and are awaited for at most 1.5 s, only while that still
fits before the deadline; replies must match the query ID and question, and
truncated or malformed ones are ignored; CNAMEs are followed only inside the
answer section. Per name: the VPS answer first, then each resolver in order, at
most 8 distinct, in request order; a name with nothing (or reached after the
~10 s request deadline) gets `[]`. The 12 s alarm after the headers remains the
hard limit. The VPS needs outbound UDP 53 to those three resolvers.
A non-empty answer is cached per name for 10 minutes in memory shared with the
children (one entry per allowlisted name, so the cache is bounded); a request whose
names are all cached costs no DNS and returns at once. Empty answers are not cached.

There is no authentication: the answer is public DNS data for a fixed list, and a
secret embedded in public router code would protect nothing. Protection is the
name allowlist, body limit, the connection limits below and a separate rate
limit — 6 requests per source IP/minute and 600 total/minute — that never shares a
counter with `/register` (6/IP, 120 total). Connections are admitted in separate
pools: at most 16 in the TLS handshake/header phase, then 8 for `/register` and 8
for `/resolve` (a full pool answers 503 with `Retry-After: 30` before any rate
counter is spent), and at most 2 open connections per client address. The
handshake and headers must arrive within 4 s. Counters are per route and live in
memory shared with the forked children; `/health` is not counted. A child that
dies holding the counter lock cannot wedge the service: the lock is taken over
from a dead holder, or after one second. Lookups are bounded (`RES_OPTIONS`
`timeout:2 attempts:1` unless the unit sets its own) and a name is started only
while it can finish before the deadline, so a reply is always sent.
The router still checks Meta ranges and the certificate of every address.

Build with `make` (C11 compiler and OpenSSL development libraries required).
Copy the binary, `d2k-enroll.service` and `install-server.sh` to a private temporary
directory on the existing VPS, then run `sh install-server.sh DIRECTORY` there.
This adds port 9443 and a separate service; it does not restart the shared relay.
Updating an installed service to get `/resolve` is the same command: it replaces
the binary and restarts only `d2k-enroll`.
The installer copies the bootstrap credential locally from the existing root-only
server configuration into `/etc/d2k-enroll/bootstrap.key` (0600). Systemd passes
it with `LoadCredential`. Re-run this script after a fleet secret rotation.
TLS uses the existing ACME PEM and reloads it on handshakes after renewal.

Tests: `make test` (the resolver is replaced by a test double; no network).
An invalid proof must never reach the upstream;
spoofed forwarding headers must not override the real peer address. Router proof
generation is tested by `make -C ../telegram test-enroll`; the clean router install
is the end-to-end acceptance of C proof → HTTPS enrollment → relay authentication.
