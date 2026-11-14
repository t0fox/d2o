#!/bin/sh
# Disposable network namespace with a routed/NAT client and separate media server.
# Host: Linux with Docker and nfnetlink_queue loaded. Only private lab traffic.
set -eu

if [ "${1:-}" != --inside ]; then
    ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
    command -v docker >/dev/null 2>&1 || { echo "Docker is required for the routed NFQUEUE lab" >&2; exit 1; }
    WORK=$(mktemp -d /tmp/d2o-network-stress.XXXXXX)
    echo "Network stress evidence: $WORK/evidence"
    mkdir "$WORK/evidence"
    tar -C "$ROOT" -cf - --exclude='*.o' --exclude='.udp-engine' core datapath detect runtime panel files/S99d2k \
        scripts/lab-network-stress.sh tests/network-stress.py | tar -C "$WORK" -xf -
    exec docker run --rm --cap-add=NET_ADMIN --cap-add=NET_RAW --cap-add=SYS_ADMIN \
        --tmpfs /tmp:rw,nosuid,nodev --sysctl net.ipv4.ip_forward=1 --sysctl net.netfilter.nf_conntrack_acct=1 \
        -e D2O_STRESS_SECONDS="${D2O_STRESS_SECONDS:-60}" \
        -v "$WORK:/w" -w /w gcc:14 sh scripts/lab-network-stress.sh --inside
fi

# Prepare tools before disconnecting the container's external interface.
apt-get update -qq
apt-get install -y -qq iproute2 nftables openssl curl python3-aioquic >/dev/null
make -s -C datapath d2kd
make -s -C core d2kc d2kdiag
make -s -C panel d2kpanel
seconds=${D2O_STRESS_SECONDS:-60}
case "$seconds" in ''|*[!0-9]*) exit 2 ;; esac
if [ "$seconds" -lt 20 ] || [ "$seconds" -gt 600 ]; then exit 2; fi

# The lab needs isolated namespace operations. Docker's default mount
# profile may reject 'ip netns add', so create the peer namespace directly.
unshare -n sleep 1800 &
client=$!
unshare -n sleep 1800 &
server=$!
dp='' ctl='' diag='' media='' panel=''
# shellcheck disable=SC2329  # EXIT trap
cleanup() {
    for pid in "$ctl" "$dp" "$diag" "$media" "$panel" "$client" "$server"; do
        [ -z "$pid" ] || kill "$pid" 2>/dev/null || true
    done
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
for pid in "$client" "$server"; do
    own=$(readlink /proc/self/ns/net)
    i=0
    while [ "$(readlink "/proc/$pid/ns/net")" = "$own" ]; do
        i=$((i+1)); [ "$i" -lt 50 ]; sleep 0.05
    done
    kill -0 "$pid"
done
cl() { nsenter -t "$client" -n -- "$@"; }
srv() { nsenter -t "$server" -n -- "$@"; }
ip link set eth0 down
ip link add lan type veth peer name cl
ip link add wan type veth peer name srv
ip link set cl netns "$client"
ip link set srv netns "$server"
ip addr add 10.73.0.1/24 dev lan
ip addr add 10.74.0.1/24 dev wan
ip link set lan up
ip link set wan up
cl ip link set lo up
cl ip addr add 10.73.0.2/24 dev cl
cl ip link set cl up
cl ip route add default via 10.73.0.1
srv ip link set lo up
srv ip addr add 10.74.0.2/24 dev srv
srv ip addr add 10.74.0.3/24 dev srv
srv ip link set srv up
srv ip route add default via 10.74.0.1
ip route replace default via 10.74.0.2 dev wan
printf '%s\n' '10.74.0.2 media.example' '10.74.0.3 stalled.example' >> /etc/hosts
nft -f - <<'NFT'
table ip lab {
    chain nat {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "wan" masquerade
    }
    chain fault {
        type filter hook postrouting priority 10; policy accept;
        # SYN/SYN-ACK pass. Blackhole TCP payload (ClientHello and repeats)
        # to the lab-only stalled endpoint after production NFQUEUE.
        oifname "wan" ip daddr 10.74.0.3 tcp dport 8443 tcp flags & (syn | fin | rst) == 0 ip length > 80 drop
    }
}
NFT
mkdir -p /tmp/d2k-diagnostics /w/evidence/run
chmod 700 /tmp/d2k-diagnostics
touch /tmp/d2k-diagnostics/network-enabled
chmod 600 /tmp/d2k-diagnostics/network-enabled
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
    -subj /CN=media.example -addext subjectAltName=DNS:media.example,DNS:stalled.example \
    -keyout /tmp/lab-key -out /tmp/lab-cert >/dev/null 2>&1
nsenter -t "$server" -n -- python3 tests/network-stress.py server 0.0.0.0 /tmp/lab-cert \
    --key /tmp/lab-key > /w/evidence/server.log 2>&1 &
media=$!
i=0
until grep -q READY /w/evidence/server.log; do
    kill -0 "$media"
    i=$((i+1)); [ "$i" -lt 100 ]; sleep 0.1
done

run=/w/evidence/run
./core/d2kdiag /tmp/absent-telegram.sock "$run" > /w/evidence/diagnostics.log 2>&1 &
diag=$!
echo "$diag" > "$run/d2kdiag.pid"
cl python3 tests/network-stress.py client 10.74.0.2 /tmp/lab-cert --seconds "$seconds" \
    --stall-host 10.74.0.3 > /w/evidence/baseline.json
kill -0 "$diag"
echo 'Baseline completed'

# Load the production nft generator without executing the service entry point.
sed '/^case "\$1" in/,$d' /w/files/S99d2k > /tmp/d2o-stress-functions
# shellcheck disable=SC1091
. /tmp/d2o-stress-functions
D2K_FW=nft
export D2K_FW
nft_ruleset > /w/evidence/production.nft
nft_rst_ruleset > /w/evidence/rst.nft
./datapath/d2kd --mode apply --control /tmp/lab-control --queue "$QUEUE_NUM" \
    --mark "$MARK" --probe-mark "$PROBE_MARK" --udp-reverse-hook --stats 2 \
    > /w/evidence/datapath.log 2>&1 &
dp=$!
echo "$dp" > "$run/d2kd.pid"
i=0
while [ ! -S /tmp/lab-control ]; do
    kill -0 "$dp"
    i=$((i+1)); [ "$i" -lt 100 ]; sleep 0.1
done
nft -f /w/evidence/production.nft
nft -f /w/evidence/rst.nft
./core/d2kc --control /tmp/lab-control --catalog /tmp/lab-catalog --live /tmp/lab-live \
    --mark "$PROBE_MARK" --measure-mark "$MEASURE_MARK" > /w/evidence/controller.log 2>&1 &
ctl=$!
echo "$ctl" > "$run/d2k.pid"
rc=0
cl python3 tests/network-stress.py client 10.74.0.2 /tmp/lab-cert --seconds "$seconds" \
    --stall-host 10.74.0.3 > /w/evidence/with-d2o.json || rc=$?
kill -0 "$dp" "$ctl" "$diag"
./panel/d2kpanel serve --listen 127.0.0.1:18080 >/w/evidence/panel.log 2>&1 &
panel=$!
curl --fail --silent --show-error --retry 5 --retry-connrefused --max-time 10 \
    http://127.0.0.1:18080/api/diagnostics?network-download > /w/evidence/diagnostics.json
cat /w/evidence/baseline.json /w/evidence/with-d2o.json
python3 - /w/evidence/diagnostics.json <<'PY'
import json
import sys

with open(sys.argv[1]) as handle:
    history = json.load(handle)
rows = [dict(zip(history["fields"], row)) for row in history["samples"]]
queues = [dict(zip(history["nfqueue_fields"], row["nfqueue"])) for row in rows if row["nfqueue"]]
controllers = [dict(zip(history["controller_fields"], row["controller"])) for row in rows if row["controller"]]
assert any(row["packets"] > 0 and row["backlog"] is not None for row in queues), "NFQUEUE not exercised"
assert any(row["active"] > 0 or row["classifier_workers_started"] > 0 for row in controllers), "no background search measured"
print("Both NFQUEUE and background search were active")
PY
exit "$rc"
