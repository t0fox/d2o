#!/bin/sh
# d2k-dns-apply.sh — применить выбранный DNS-резолвер к dnsmasq через UCI.
#
# Работает только на роутере (OpenWrt): uci, https-dns-proxy, dnsproxy.
# Без --apply печатает команды и ничего не меняет. Перед изменением делает
# резервные копии; --rollback возвращает последнюю.
#
# DoH  -> https-dns-proxy (libcurl, HTTP/2)  -> dnsmasq server=127.0.0.1#5053
# DoT  -> dnsproxy (Go, tls://)              -> dnsmasq server=127.0.0.1#5353
# DoQ  -> dnsproxy (Go, quic://)             -> dnsmasq server=127.0.0.1#5353
# plain-> dnsmasq server=IP
#
# Это НЕ обход SNI-блокировки: внешние прокси не умеют точку в SNI. Для
# MagicDNS на этом ISP TCP 443/853 закрыт по IP, поэтому остаётся plain.
set -eu

PROTO=
HOST=
IP=
PATH_=/dns-query
LISTEN=
APPLY=0
ROLLBACK=0
BACKUP=/etc/d2k/dns-backup

usage() {
    cat >&2 <<'EOF'
d2k-dns-apply.sh --proto doh|dot|doq|plain --host H [--ip IP] [--path P]
                 [--listen N] [--apply] [--rollback]
EOF
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
    --proto) PROTO=${2:-}; shift 2 ;;
    --host) HOST=${2:-}; shift 2 ;;
    --ip) IP=${2:-}; shift 2 ;;
    --path) PATH_=${2:-}; shift 2 ;;
    --listen) LISTEN=${2:-}; shift 2 ;;
    --apply) APPLY=1; shift ;;
    --rollback) ROLLBACK=1; shift ;;
    -h|--help) usage ;;
    *) echo "неизвестный аргумент: $1" >&2; usage ;;
    esac
done

say() { printf '%s\n' "$*"; }
run() {
    if [ "$APPLY" -eq 1 ]; then
        say "+ $*"
        "$@"
    else
        say "  $*"
    fi
}

need() {
    command -v "$1" >/dev/null 2>&1 || { echo "нет $1" >&2; exit 1; }
}

backup() {
    [ "$APPLY" -eq 1 ] || return 0
    mkdir -p "$BACKUP"
    for f in /etc/config/dhcp /etc/config/https-dns-proxy /etc/config/dnsproxy /etc/hosts; do
        [ -f "$f" ] || continue
        cp -f "$f" "$BACKUP/$(basename "$f").last"
    done
    say "резерв: $BACKUP"
}

rollback() {
    need uci
    [ -d "$BACKUP" ] || { echo "нет резерва $BACKUP" >&2; exit 1; }
    /etc/init.d/dnsproxy stop >/dev/null 2>&1 || true
    /etc/init.d/https-dns-proxy stop >/dev/null 2>&1 || true
    for f in dhcp https-dns-proxy dnsproxy hosts; do
        [ -f "$BACKUP/$f.last" ] || continue
        case "$f" in
        hosts) cp -f "$BACKUP/$f.last" /etc/hosts ;;
        *) cp -f "$BACKUP/$f.last" "/etc/config/$f" ;;
        esac
    done
    uci commit dhcp
    uci commit https-dns-proxy 2>/dev/null || true
    uci commit dnsproxy 2>/dev/null || true
    /etc/init.d/https-dns-proxy restart >/dev/null 2>&1 || true
    /etc/init.d/dnsproxy restart >/dev/null 2>&1 || true
    /etc/init.d/dnsmasq restart >/dev/null 2>&1 || true
    say "восстановлено из $BACKUP"
    exit 0
}

[ "$ROLLBACK" -eq 1 ] && rollback
[ -n "$PROTO" ] && [ -n "$HOST" ] || usage
need uci

case "$PROTO" in
doh)
    need https-dns-proxy
    LISTEN=${LISTEN:-5053}
    backup
    if [ "$APPLY" -eq 1 ] && [ -n "$IP" ]; then
        # Прибить имя к измеренному IP: у резолверов бывает несколько A,
        # и первый может быть мёртвым. Блок ограничен маркерами.
        tmp=$(mktemp)
        awk 'BEGIN{skip=0} /^# d2k-dns-begin/{skip=1;next} /^# d2k-dns-end/{skip=0;next} !skip{print}' /etc/hosts > "$tmp"
        printf '# d2k-dns-begin\n%s %s\n# d2k-dns-end\n' "$IP" "$HOST" >> "$tmp"
        cat "$tmp" > /etc/hosts
        rm -f "$tmp"
        say "hosts: $IP $HOST"
    fi
    run uci set "https-dns-proxy.@https-dns-proxy[0].resolver_url=https://$HOST$PATH_"
    run uci set "https-dns-proxy.@https-dns-proxy[0].bootstrap_dns=1.1.1.1,8.8.8.8"
    run uci set "https-dns-proxy.@https-dns-proxy[0].listen_port=$LISTEN"
    run uci set "https-dns-proxy.config.force_dns=0"
    run uci set "https-dns-proxy.config.dnsmasq_config_update="
    run uci commit https-dns-proxy
    run /etc/init.d/https-dns-proxy enable
    run /etc/init.d/https-dns-proxy restart
    UP="127.0.0.1#$LISTEN"
    ;;
dot|doq)
    need dnsproxy
    LISTEN=${LISTEN:-5353}
    backup
    if [ "$APPLY" -eq 1 ] && [ -n "$IP" ]; then
        tmp=$(mktemp)
        awk 'BEGIN{skip=0} /^# d2k-dns-begin/{skip=1;next} /^# d2k-dns-end/{skip=0;next} !skip{print}' /etc/hosts > "$tmp"
        printf '# d2k-dns-begin\n%s %s\n# d2k-dns-end\n' "$IP" "$HOST" >> "$tmp"
        cat "$tmp" > /etc/hosts
        rm -f "$tmp"
        say "hosts: $IP $HOST"
    fi
    run uci set dnsproxy.global.enabled=1
    run uci -q delete dnsproxy.global.listen_addr
    run uci add_list dnsproxy.global.listen_addr=127.0.0.1
    run uci -q delete dnsproxy.global.listen_port
    run uci add_list "dnsproxy.global.listen_port=$LISTEN"
    run uci -q delete dnsproxy.servers.upstream
    if [ "$PROTO" = dot ]; then
        run uci add_list "dnsproxy.servers.upstream=tls://$HOST"
    else
        run uci add_list "dnsproxy.servers.upstream=quic://$HOST"
    fi
    run uci -q delete dnsproxy.servers.bootstrap
    run uci add_list "dnsproxy.servers.bootstrap=1.1.1.1"
    run uci commit dnsproxy
    run /etc/init.d/dnsproxy enable
    run /etc/init.d/dnsproxy restart
    UP="127.0.0.1#$LISTEN"
    ;;
plain)
    backup
    UP=$HOST
    run uci set dhcp.@dnsmasq[0].noresolv=1
    run uci -q delete dhcp.@dnsmasq[0].server
    run uci add_list "dhcp.@dnsmasq[0].server=$HOST"
    run uci commit dhcp
    run /etc/init.d/dnsmasq restart
    ;;
*)
    usage
    ;;
esac

if [ "$PROTO" != plain ]; then
    run uci set dhcp.@dnsmasq[0].noresolv=1
    run uci -q delete dhcp.@dnsmasq[0].server
    run uci add_list "dhcp.@dnsmasq[0].server=$UP"
    run uci commit dhcp
    run /etc/init.d/dnsmasq restart
fi

if [ "$APPLY" -eq 1 ]; then
    sleep 1
    say "проверка: dig wikipedia.org @127.0.0.1 (example.com Smart DNS переписывают)"
    if command -v dig >/dev/null 2>&1; then
        dig +time=5 +tries=1 +short A wikipedia.org @127.0.0.1 2>&1 | head -6
    else
        nslookup wikipedia.org 127.0.0.1 2>&1 | head -8
    fi
else
    say "dry-run: добавьте --apply"
fi
