# D2K install gate on the relay VPS

A small C service, `d2k-gate`, on `192.0.2.44:9444`. Router installs,
nightly updates and the package managers try it first and fall back to a
direct download when it does not answer: from part of the lines in Russia
GitHub (raw files and releases), Entware and the OpenWrt package server do
not open directly.

It is an allowlisted subset of an HTTP proxy, so curl, BusyBox/uclient wget,
opkg and apk use it without special support (`--proxy` or `http_proxy`):

- `CONNECT host:443` only, to the hosts below. Bytes then pass through
  unchanged: TLS stays between the router and the real server, the router
  checks the server certificate, and the gate can neither read nor change
  the answer.
- `GET`/`HEAD http://host/path` only on port 80, to the same hosts. Entware
  (`bin.entware.net`) is plain HTTP anyway; the OpenWrt installers rewrite
  the official `downloads.openwrt.org` feeds to `http://` for this path,
  where `apk`/`opkg` verify package signatures themselves. The request is
  rebuilt in origin form with `Connection: close`; `Proxy-*` headers are
  dropped.
- Everything else: 400 or 403. The gate is never an open proxy.

Allowed hosts (exact match): `github.com`, `api.github.com`,
`codeload.github.com`, `raw.githubusercontent.com`,
`objects.githubusercontent.com`, `release-assets.githubusercontent.com`,
`bin.entware.net`, `downloads.openwrt.org`.

Limits: 128 connections, 180 new connections per source address per minute,
6000 per minute in total, 15 s for the request head, 10 s to connect
upstream, 120 s idle. Upstream addresses are resolved on the VPS and only
public ones are dialled. One journal line per connection: client, method,
host, bytes each way, duration. The gate holds no secrets.

`uclient-fetch` and `apk` send `GET https://…` to a proxy instead of
`CONNECT`; the gate refuses that on purpose (it would have to decrypt, and the
router-to-VPS leg would carry the answer in clear text). Those tools use the
`http://` feed path above, and the installer fetches GitHub with curl.

D2K never queues traffic to the gate (`files/S99d2k`, `D2K_GATE`): it is
D2K's own channel, not a target. Without that exclusion the datapath read
the TLS hello inside a `CONNECT` tunnel as a flow to "github.com" on the VPS
address and the controller started searching for a bypass of its own update
channel (field, 14.10.2026).

## Build and deploy

```sh
make -C relay-gate test   # unit tests, no network
make -C relay-gate vps    # static x86_64 binary: build/relay-gate/d2k-gate-x86_64
```

Copy the binary (as `d2k-gate`), `d2k-gate.service` and `install-server.sh`
into one directory on the VPS and run `sh install-server.sh <dir>` as root.
The unit runs as `nobody` with a read-only system, no capabilities, 64 MB of
memory and 160 tasks.

Router side: `D2K_GATE` (default `http://192.0.2.44:9444`) in the
environment or in `/opt/d2k/config`; an empty value turns the gate off.
