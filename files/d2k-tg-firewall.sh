#!/bin/sh
# Правила перенаправления TCP-трафика Telegram для IPv4 и IPv6.
set -eu

SET4=d2k_tg_dc
SET6=d2k_tg_dc6
PAIR4=d2k_tg_pair4
PAIR6=d2k_tg_pair6
MANIFEST=${TG_DC_MAP_ENDPOINTS_PATH:-/opt/d2k/state/telegram-dc-endpoints.tsv}
PORT=1443
TCP_PORTS="443 5222"
OUTBOUND_MARK=0x31
OUTBOUND_COMMENT=d2k-tg-outbound
CIDRS4="149.154.160.0/20 91.108.4.0/22 91.108.8.0/22 91.108.12.0/22 91.108.16.0/22 91.108.20.0/22 91.108.56.0/22 91.105.192.0/23 95.161.64.0/20 185.76.151.0/24"
CIDRS6="2001:67c:4e8::/48 2001:b28:f23c::/47 2001:b28:f23f::/48 2a0a:f280:203::/48"

ipt() { iptables -w "$@" 2>/dev/null || iptables "$@" 2>/dev/null; }
ip6t() { ip6tables -w "$@" 2>/dev/null || ip6tables "$@" 2>/dev/null; }

# OpenWrt (25.12 без iptables вовсе): своя таблица nft, тот же выбор, что у
# S99d2k — он экспортирует D2K_FW; удаление зовёт без него, тогда по системе.
FW=${D2K_FW:-}
if [ -z "$FW" ]; then
    if [ -f "${D2K_OPENWRT_RELEASE:-/etc/openwrt_release}" ] && command -v nft >/dev/null 2>&1; then
        FW=nft
    else
        FW=iptables
    fi
fi
NFT_TABLE=d2k_tg

load_pairs() {
    PAIRS=
    [ -e "$MANIFEST" ] || return 0
    [ -f "$MANIFEST" ] || return 1
    PAIRS=$(awk -v allowed="$TCP_PORTS" '
        BEGIN { split(allowed, ports); for (i in ports) valid[ports[i]]=1 }
        NR == 1 {
            if (NF != 3 || $1 != "z2k-tg-dc-options-v1" ||
                $2 !~ /^[0-9]+$/ || $3 !~ /^[0-9]+$/ || $2 < 1 || $3 < 1) exit 1
            header=1; next
        }
        {
            if (NR > 1025 || NF != 2 || !($2 in valid)) { invalid=1; exit 1 }
            if (index($1, ":")) {
                if ($1 !~ /^[[:xdigit:]:]+$/ || $1 ~ /:::/ || length($1) > 39) { invalid=1; exit 1 }
                family=6
            } else {
                if (split($1, octet, ".") != 4) { invalid=1; exit 1 }
                for (i=1; i<=4; i++)
                    if (octet[i] !~ /^[0-9]+$/ || octet[i] > 255) { invalid=1; exit 1 }
                family=4
            }
            print family, $1, $2
        }
        END { if (!header || invalid || NR < 2) exit 1 }
    ' "$MANIFEST") || return 1
}

pair_elements() {
    printf '%s\n' "$PAIRS" | awk -v family="$1" -v separator="$2" '
        $1 == family { if (n++) printf ", "; printf "%s%s%s", $2, separator, $3 }
    '
}

nft_pair_sets() {
    [ -n "$PAIRS" ] || return 0
    for family in 4 6; do
        elements=$(pair_elements "$family" ' . ')
        printf '\tset tg_pair%s { type ipv%s_addr . inet_service;' "$family" "$family"
        [ -z "$elements" ] || printf ' elements = { %s };' "$elements"
        printf ' }\n'
    done
}

nft_list() { printf '%s' "$1" | sed 's/ /, /g'; }
nft_redirects() {
    if [ -n "$PAIRS" ]; then
        printf '\t\tip daddr . tcp dport @tg_pair4 redirect to :%s\n' "$PORT"
        printf '\t\tip6 daddr . tcp dport @tg_pair6 redirect to :%s\n' "$PORT"
    fi
    for port in $TCP_PORTS; do
        printf '\t\tip daddr @tg4 tcp dport %s redirect to :%s\n' "$port" "$PORT"
        printf '\t\tip6 daddr @tg6 tcp dport %s redirect to :%s\n' "$port" "$PORT"
    done
}

# Перехват (LAN — prerouting, сам роутер — output) раньше dstnat fw4.
# Таблица целиком, одной транзакцией.
nft_ruleset() {
    cat <<EOF2
table inet $NFT_TABLE {
	set tg4 { type ipv4_addr; flags interval; elements = { $(nft_list "$CIDRS4") }; }
	set tg6 { type ipv6_addr; flags interval; elements = { $(nft_list "$CIDRS6") }; }
	$(nft_pair_sets)
	chain pre {
		type nat hook prerouting priority dstnat - 1; policy accept;
		$(nft_redirects)
	}
	chain out {
		type nat hook output priority -101; policy accept;
		meta mark $OUTBOUND_MARK return
		$(nft_redirects)
	}
	chain input {
		type filter hook input priority -1; policy accept;
		tcp dport $PORT ct status dnat accept
		tcp dport $PORT drop
	}
}
EOF2
}

nft_installed() {
    listed=$(nft list table inet "$NFT_TABLE" 2>/dev/null) || return 1
    count=8
    if [ -n "$PAIRS" ]; then
        count=12
        for family in 4 6; do
            printf '%s\n' "$listed" | grep -q "set tg_pair$family {" || return 1
            [ "$(printf '%s\n' "$listed" | grep -c "tcp dport @tg_pair$family redirect to :$PORT")" -eq 2 ] || return 1
            actual=$(printf '%s\n' "$listed" | awk -v set="tg_pair$family" '
                $1 == "set" { active=($2 == set); collecting=0 }
                active && /elements =/ { collecting=1; sub(/^.*elements = *[{]/, "") }
                active && collecting {
                    if (index($0,"}")) { sub(/}.*/, ""); collecting=0 }
                    print
                }
            ' | tr ',' '\n' | awk 'NF == 3 { print $1, $2, $3 }' | sort)
            expected=$(printf '%s\n' "$PAIRS" | awk -v family="$family" '$1 == family { print $2, ".", $3 }' | sort)
            [ "$actual" = "$expected" ] || return 1
        done
    fi
    [ "$(printf '%s\n' "$listed" | grep -c "redirect to :$PORT")" -eq "$count" ] || return 1
    printf '%s\n' "$listed" | grep -qF "tcp dport $PORT ct status dnat accept" || return 1
    printf '%s\n' "$listed" | grep -qF "tcp dport $PORT drop" || return 1
    for port in $TCP_PORTS; do
        [ "$(printf '%s\n' "$listed" | grep -cF "tcp dport $port redirect to :$PORT")" -eq 4 ] || return 1
    done
    [ "$(printf '%s\n' "$listed" | grep -c "meta mark $OUTBOUND_MARK return")" -eq 1 ] &&
        [ "$(printf '%s\n' "$listed" | grep -c 'reject with tcp reset')" -eq 0 ]
}

nft_up() {
    f=$(mktemp "${TMPDIR:-/tmp}/d2k-tg-nft.XXXXXX") || return 1
    # Под set -e отказ nft не должен обрывать скрипт до уборки: heal зовёт
    # nft_up последней командой списка ||, где set -e действует.
    rc=0
    if {
        ! nft list table inet "$NFT_TABLE" >/dev/null 2>&1 || echo "delete table inet $NFT_TABLE"
        nft_ruleset
    } > "$f"; then
        nft -f "$f" || rc=$?
    else
        rc=1
    fi
    rm -f "$f"
    return "$rc"
}

ensure_redirects() {
    tg_ipt=$1
    tg_set=$2
    for tg_port in $TCP_PORTS; do
        for tg_chain in PREROUTING OUTPUT; do
            set -- -p tcp --dport "$tg_port" -m set --match-set "$tg_set" dst
            # Keep the exclusion on each OUTPUT rule. A heal can insert a
            # missing rule above the old standalone RETURN.
            if [ "$tg_chain" = OUTPUT ]; then
                set -- "$@" -m mark ! --mark "$OUTBOUND_MARK"
            fi
            set -- "$@" -j REDIRECT --to-port "$PORT"
            "$tg_ipt" -t nat -C "$tg_chain" "$@" ||
                "$tg_ipt" -t nat -I "$tg_chain" 1 "$@" || return 1
            "$tg_ipt" -t nat -C "$tg_chain" "$@" || return 1
        done
        delete_nat_rule "$tg_ipt" OUTPUT -p tcp --dport "$tg_port" \
            -m set --match-set "$tg_set" dst -j REDIRECT --to-port "$PORT" || return 1
    done
    delete_nat_rule "$tg_ipt" OUTPUT -m mark --mark "$OUTBOUND_MARK" \
        -m comment --comment "$OUTBOUND_COMMENT" -j RETURN
}

delete_nat_rule() {
    tg_delete_ipt=$1
    shift
    while "$tg_delete_ipt" -t nat -C "$@"; do
        "$tg_delete_ipt" -t nat -D "$@" || return 1
    done
}

ensure_ipset_pairs() {
    pair_ipt=$1 pair_set=$2 pair_family=$3 pair_version=$4
    wanted=$(printf '%s\n' "$PAIRS" | awk -v version="$pair_version" '
        $1 == version { print $2 ",tcp:" $3 }
    ' | sort)
    if [ -z "$wanted" ]; then
        remove_ipset_pairs "$pair_ipt" "$pair_set"
        return
    fi
    ipset create "$pair_set" hash:ip,port family "$pair_family" -exist 2>/dev/null || return 1
    current=$(ipset save "$pair_set" 2>/dev/null | awk '$1 == "add" { print $3 }' | sort)
    if [ "$wanted" != "$current" ]; then
        temporary="d2k_tg_${pair_version}_$$"
        if ! {
            printf 'create %s hash:ip,port family %s\n' "$temporary" "$pair_family"
            printf '%s\n' "$wanted" | awk -v set="$temporary" '{ print "add", set, $1 }'
            printf 'swap %s %s\n' "$temporary" "$pair_set"
        } | ipset restore; then
            ipset destroy "$temporary" 2>/dev/null || true
            return 1
        fi
        ipset destroy "$temporary" 2>/dev/null || return 1
    fi
    for pair_chain in PREROUTING OUTPUT; do
        set -- -p tcp -m set --match-set "$pair_set" dst,dst
        if [ "$pair_chain" = OUTPUT ]; then set -- "$@" -m mark ! --mark "$OUTBOUND_MARK"; fi
        set -- "$@" -j REDIRECT --to-port "$PORT"
        "$pair_ipt" -t nat -C "$pair_chain" "$@" ||
            "$pair_ipt" -t nat -I "$pair_chain" 1 "$@" || return 1
    done
}

remove_ipset_pairs() {
    delete_nat_rule "$1" PREROUTING -p tcp -m set --match-set "$2" dst,dst \
        -j REDIRECT --to-port "$PORT" || return 1
    delete_nat_rule "$1" OUTPUT -p tcp -m set --match-set "$2" dst,dst \
        -m mark ! --mark "$OUTBOUND_MARK" -j REDIRECT --to-port "$PORT" || return 1
    if command -v ipset >/dev/null 2>&1 && ipset save "$2" 2>/dev/null | grep -q "^create $2 "; then
        ipset destroy "$2" || return 1
    fi
}

ensure4() {
    command -v ipset >/dev/null 2>&1 || return 1
    ipset create "$SET4" hash:net -exist 2>/dev/null || return 1
    for c in $CIDRS4; do ipset add "$SET4" "$c" -exist 2>/dev/null || return 1; done
    ensure_redirects ipt "$SET4" && ensure_ipset_pairs ipt "$PAIR4" inet 4
}

ensure6() {
    command -v ip6tables >/dev/null 2>&1 || return 0
    # Удаляем отказы старой версии до установки новых правил, чтобы IPv6 не
    # оставался заблокированным, если на устройстве нет модуля ip6table_nat.
    for chain in FORWARD OUTPUT; do
        while ip6t -C "$chain" -p tcp -m set --match-set "$SET6" dst -j REJECT --reject-with tcp-reset; do
            ip6t -D "$chain" -p tcp -m set --match-set "$SET6" dst -j REJECT --reject-with tcp-reset || break
        done
    done
    command -v ipset >/dev/null 2>&1 || return 0
    ipset create "$SET6" hash:net family inet6 -exist 2>/dev/null || return 0
    for c in $CIDRS6; do ipset add "$SET6" "$c" -exist 2>/dev/null || return 0; done
    ensure_redirects ip6t "$SET6" && ensure_ipset_pairs ip6t "$PAIR6" inet6 6
}

start() {
    load_pairs || return 1
    if [ "$FW" = nft ]; then
        ipt_stop
        nft_up || return 1
    else
        ensure4 || return 1
        ensure6
    fi
    if command -v conntrack >/dev/null 2>&1; then
        for c in $CIDRS4; do conntrack -D -d "$c" >/dev/null 2>&1 || true; done
        for c in $CIDRS6; do conntrack -D -f ipv6 -d "$c" >/dev/null 2>&1 || true; done
    fi
}

heal() {
    load_pairs || return 1
    if [ "$FW" = nft ]; then
        nft_installed || nft_up
    else
        ensure4 && ensure6
    fi
}

# Снятие iptables-правил — и на Keenetic, и на OpenWrt как остаток установки
# времён Entware. Без iptables здесь нечего делать.
remove_redirects() {
    tg_remove_ipt=$1
    tg_remove_set=$2
    for port in $TCP_PORTS; do
        for chain in PREROUTING OUTPUT; do
            delete_nat_rule "$tg_remove_ipt" "$chain" -p tcp --dport "$port" \
                -m set --match-set "$tg_remove_set" dst -j REDIRECT --to-port "$PORT" || true
        done
        delete_nat_rule "$tg_remove_ipt" OUTPUT -p tcp --dport "$port" \
            -m set --match-set "$tg_remove_set" dst -m mark ! --mark "$OUTBOUND_MARK" \
            -j REDIRECT --to-port "$PORT" || true
    done
    delete_nat_rule "$tg_remove_ipt" OUTPUT -m mark --mark "$OUTBOUND_MARK" \
        -m comment --comment "$OUTBOUND_COMMENT" -j RETURN || true
}

ipt_stop() {
    command -v iptables >/dev/null 2>&1 || return 0
    remove_redirects ipt "$SET4"
    remove_ipset_pairs ipt "$PAIR4" || true
    if command -v ip6tables >/dev/null 2>&1; then
        remove_redirects ip6t "$SET6"
        remove_ipset_pairs ip6t "$PAIR6" || true
        for chain in FORWARD OUTPUT; do
            while ip6t -C "$chain" -p tcp -m set --match-set "$SET6" dst -j REJECT --reject-with tcp-reset; do
                ip6t -D "$chain" -p tcp -m set --match-set "$SET6" dst -j REJECT --reject-with tcp-reset || break
            done
        done
    fi
}

stop() {
    if [ "$FW" = nft ] && nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then
        nft delete table inet "$NFT_TABLE" || return 1
    fi
    ipt_stop
}

case "${1:-}" in
    start) start ;;
    heal) heal ;;
    stop) stop ;;
    *) echo "usage: $0 {start|heal|stop}" >&2; exit 2 ;;
esac
