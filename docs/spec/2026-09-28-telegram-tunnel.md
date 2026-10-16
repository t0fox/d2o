# Telegram tunnel port — implementation brief

**Goal:** Add the existing z2k Telegram TCP tunnel to d2k as a native C
runtime, installable on the currently supported ARM64 Keenetic target.

**Scope ruling:** “C runtime” means the complete router-side client and its
installation, firewall, supervision, status and user controls. The separately
deployed VPS relay remains Go and its existing wire/API contract is unchanged.
This keeps end-to-end behavior while avoiding an unrelated relay migration.
The adjacent CDN HTTP tunnel on :1444 is not part of this Telegram feature.

## Required behavior

- A separate `/opt/sbin/d2ktg` process listens on TCP :1443, reads
  `SO_ORIGINAL_DST`, rejects self-dials, and tunnels only connections
  redirected for Telegram DC IPv4 ranges. d2kd/NFQUEUE remains independent.
- Use TLS-verified WSS to `/ws`; retain hostname/SNI/certificate verification
  when connecting directly to the IPv4 encoded by the relay's `nip.io` name.
  Ship a trust bundle and use OpenSSL as the C TLS/crypto dependency; the
  ARM64 executable must link statically and run without an Entware library
  install. Pin and record the OpenSSL source revision in the build script.
- Preserve the relay contracts: `/register` HMAC-SHA256; per-install Ed25519
  identity; mux v2 HELLO/HELLO_ACK/AUTHID/INFO with clock correction and
  WINDOW credit; v1 fallback only when v2 is rejected as a protocol version.
  Never fall back after an authentication rejection or disable TLS checks.
- Preserve mux stream behavior: TCP CONNECT/DATA/CLOSE, bounded per-stream
  queues, at most six in-flight CONNECTs, negotiated send credit, half-window
  WINDOW replenishment, read/write idle timeout, ping/pong liveness, jittered
  reconnect, and ordered delivery of queued DATA before CLOSE.
- Preserve local redirect behavior: donor IPv4 Telegram CIDRs in an ipset,
  TCP/443 и TCP/5222 REDIRECT for PREROUTING and OUTPUT to :1443, IPv6 Telegram TCP
  fast-reset, conntrack cleanup, and NDM rule restoration. No UDP/QUIC tunnel.
- Integrate config, independent start/stop/restart supervision, user disable,
  bounded logs, health status and a concise enable/status control in the
  existing panel. Start only when configured and enabled; never expose the
  relay secret in process arguments, logs, or the UI.
- Install/update/uninstall d2ktg and its owned files atomically without
  overwriting an existing user config. Unsupported architectures must fail
  clearly; current D2K install support is ARM64 only.
- Do not modify the z2k donor. Keenetic deployment/field testing requires
  separate approval; the user granted that approval on 2026-09-28 for testing
  service installation and traffic redirection.

## Verification contract

Port the donor's wire/auth/keepalive/flow-control cases as C tests. Add a local
TLS+WebSocket fake relay and echo target to prove v1/v2 handshake, redirect
destination encoding, multiplexed bidirectional data, window/backpressure,
close ordering, reconnect and certificate rejection. Build a static ARM64
artifact and exercise install/update/disable/uninstall in the repository's
local install harness. Field operation remains unclaimed until separately
authorized and demonstrated.

## Panel treatment

Add one compact Telegram status row/card to the approved D2K panel; reuse its
existing type scale, palette, mascot/logo treatment, spacing and control
patterns. Show only “not configured / stopped / connecting / connected” plus
an enable/disable action. No new illustration, dashboard redesign, or
transport jargon.
