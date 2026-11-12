#!/bin/sh
# d2k-dns-search-apply.sh — полевой подбор и применение DNS-резолвера.
#
# Запускается на роутере. Сначала d2k-dnsprobe search перебирает манифест,
# затем выбранный победитель применяется через d2k-dns-apply.sh (UCI).
# Без --apply только печатает, что будет применено.
set -eu

SERVICE=
MANIFEST=/tmp/d2k-endpoints.txt
APPLY=0
PROBE=/tmp/d2k-dnsprobe
APPLIER=/tmp/d2k-dns-apply.sh
REPEATS=2

usage() {
    cat >&2 <<'EOF'
d2k-dns-search-apply.sh --service NAME [--manifest FILE] [--repeats N] [--apply]
EOF
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
    --service) SERVICE=${2:-}; shift 2 ;;
    --manifest) MANIFEST=${2:-}; shift 2 ;;
    --repeats) REPEATS=${2:-}; shift 2 ;;
    --apply) APPLY=1; shift ;;
    -h|--help) usage ;;
    *) echo "неизвестный аргумент: $1" >&2; usage ;;
    esac
done
[ -n "$SERVICE" ] || usage
[ -x "$PROBE" ] || { echo "нет $PROBE" >&2; exit 1; }
[ -x "$APPLIER" ] || { echo "нет $APPLIER" >&2; exit 1; }

json=$("$PROBE" search "$MANIFEST" --json --repeats "$REPEATS")
line=$(printf '%s\n' "$json" | grep "\"service\":\"$SERVICE\"" || true)
if [ -z "$line" ]; then
    # C-поиск не умеет DoQ; пробуем его отдельно через dnsproxy, как это
    # делает apply. Это тот же измеряемый вопрос, только другим клиентом.
    mline=$(grep "^$SERVICE|" "$MANIFEST" | head -1 || true)
    dhost=$(printf '%s\n' "$mline" | cut -d'|' -f2)
    if [ -n "$dhost" ] && command -v dnsproxy >/dev/null 2>&1 && command -v dig >/dev/null 2>&1; then
        pkill -f "dnsproxy.*5533" 2>/dev/null || true
        dnsproxy -l 127.0.0.1 -p 5533 -u "quic://$dhost" -b 1.1.1.1 \
            --timeout 8s >/tmp/d2k-dns-doq.log 2>&1 &
        dpid=$!
        sleep 2
        dans=$(dig +time=6 +tries=1 +short A wikipedia.org @127.0.0.1 -p 5533 2>/dev/null | head -1)
        kill "$dpid" 2>/dev/null || true
        wait "$dpid" 2>/dev/null || true
        if [ -n "$dans" ]; then
            echo "winner: service=$SERVICE proto=doq host=$dhost answer=$dans"
            if [ "$APPLY" -eq 1 ]; then
                exec "$APPLIER" --proto doq --host "$dhost" --apply
            else
                "$APPLIER" --proto doq --host "$dhost"
            fi
        fi
    fi
    echo "service=$SERVICE winner=none" >&2
    exit 1
fi

get() {
    printf '%s\n' "$line" | sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p"
}
proto=$(get proto)
host=$(get host)
ip=$(get ip)
path=$(get path)

echo "winner: service=$SERVICE proto=$proto host=$host ip=$ip path=$path"
case "$proto" in
doh)
    if [ "$APPLY" -eq 1 ]; then
        exec "$APPLIER" --proto doh --host "$host" --ip "$ip" --path "${path:-/dns-query}" --apply
    else
        "$APPLIER" --proto doh --host "$host" --ip "$ip" --path "${path:-/dns-query}"
    fi
    ;;
dot)
    if [ "$APPLY" -eq 1 ]; then
        exec "$APPLIER" --proto dot --host "$host" --ip "$ip" --apply
    else
        "$APPLIER" --proto dot --host "$host" --ip "$ip"
    fi
    ;;
plain)
    if [ "$APPLY" -eq 1 ]; then
        exec "$APPLIER" --proto plain --host "$ip" --apply
    else
        "$APPLIER" --proto plain --host "$ip"
    fi
    ;;
*)
    echo "service=$SERVICE: протокол $proto не применяется этим скриптом" >&2
    exit 1
    ;;
esac
