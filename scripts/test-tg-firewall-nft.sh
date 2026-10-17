#!/bin/sh
# Проверка files/d2k-tg-firewall.sh на OpenWrt без iptables (25.12):
# перенаправления IPv4 и IPv6 находятся в отдельной таблице inet d2k_tg.
# Подмена nft хранит отдельный файл для каждой таблицы, iptables журналирует вызовы.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TGFW=$ROOT/files/d2k-tg-firewall.sh
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "PASS: $*"; }

mkdir -p "$TMP/nftonly" "$TMP/both" "$TMP/nft"
cat > "$TMP/nftonly/nft" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$NFT_STATE/calls"
[ "${STUB_NFT_FAIL:-0}" = 0 ] || exit 1
case "$1 ${2:-}" in
    "-f "*)
        while read -r w1 w2 fam name _; do
            [ "$w1 $w2" = "delete table" ] || continue
            [ -e "$NFT_STATE/${fam}_$name" ] || exit 1
        done < "$2"
        while read -r w1 w2 fam name _; do
            [ "$w1 $w2" = "delete table" ] && rm -f "$NFT_STATE/${fam}_$name"
        done < "$2"
        awk -v dir="$NFT_STATE" '
            /^table / { out = dir "/" $2 "_" $3; printf "" > out }
            out { print >> out }
            /^}/ { out = "" }' "$2" ;;
    "list table") cat "$NFT_STATE/${3}_$4" 2>/dev/null || exit 1 ;;
    "delete table") [ -e "$NFT_STATE/${3}_$4" ] || exit 1; rm -f "$NFT_STATE/${3}_$4" ;;
    *) exit 0 ;;
esac
EOF
chmod +x "$TMP/nftonly/nft"
ln -s "$TMP/nftonly/nft" "$TMP/both/nft"
for t in iptables ip6tables ipset; do
    # shellcheck disable=SC2016  # expanded by the double, not here
    printf '#!/bin/sh\nprintf "%s %%s\\n" "$*" >> "$IPT_LOG"\nexit 1\n' "$t" > "$TMP/both/$t"
    chmod +x "$TMP/both/$t"
done
printf "DISTRIB_ID='OpenWrt'\n" > "$TMP/openwrt_release"

tg() {
    bindir=$1; shift
    env PATH="$bindir:/usr/bin:/bin" NFT_STATE="$TMP/nft" IPT_LOG="$TMP/ipt.log" \
        D2K_OPENWRT_RELEASE="$TMP/openwrt_release" "$@"
}
table() { cat "$TMP/nft/inet_d2k_tg" 2>/dev/null; }

tg "$TMP/nftonly" sh "$TGFW" start || fail "start on nft-only OpenWrt"
r=$(table)
[ -n "$r" ] || fail "table inet d2k_tg not loaded"
want() { printf '%s\n' "$r" | grep -qF -- "$1" || fail "missing: $1"; }
want 'set tg4 { type ipv4_addr; flags interval; elements = { 149.154.160.0/20, 91.108.4.0/22, 91.108.8.0/22, 91.108.12.0/22, 91.108.16.0/22, 91.108.20.0/22, 91.108.56.0/22, 91.105.192.0/23, 95.161.64.0/20, 185.76.151.0/24 }; }'
want 'set tg6 { type ipv6_addr; flags interval; elements = { 2001:67c:4e8::/48, 2001:b28:f23c::/47, 2001:b28:f23f::/48, 2a0a:f280:203::/48 }; }'
want 'type nat hook prerouting priority dstnat - 1; policy accept;'
want 'type nat hook output priority -101; policy accept;'
want 'meta mark 0x31 return'
want 'ip daddr @tg4 tcp dport 443 redirect to :1443'
want 'ip daddr @tg4 tcp dport 5222 redirect to :1443'
want 'ip6 daddr @tg6 tcp dport 443 redirect to :1443'
want 'ip6 daddr @tg6 tcp dport 5222 redirect to :1443'
[ "$(printf '%s\n' "$r" | grep -c 'tcp dport 443 redirect to :1443')" -eq 4 ] || fail "не хватает перенаправлений IPv4/IPv6 для порта 443 в prerouting и output"
[ "$(printf '%s\n' "$r" | grep -c 'tcp dport 5222 redirect to :1443')" -eq 4 ] || fail "не хватает перенаправлений IPv4/IPv6 для порта 5222 в prerouting и output"
[ "$(printf '%s\n' "$r" | grep -c 'redirect to :1443')" -eq 8 ] || fail "не установлены все перенаправления IPv4/IPv6"
[ "$(printf '%s\n' "$r" | grep -c 'reject with tcp reset')" -eq 0 ] || fail "IPv6-трафик Telegram не должен отклоняться"
ok "в inet d2k_tg установлены перенаправления IPv4/IPv6 для LAN и роутера"

: > "$TMP/nft/calls"
tg "$TMP/nftonly" sh "$TGFW" heal || fail "heal with the table in place"
! grep -q '^-f' "$TMP/nft/calls" || fail "heal reloaded a healthy table"
rm -f "$TMP/nft/inet_d2k_tg"
tg "$TMP/nftonly" sh "$TGFW" heal || fail "heal after the table was removed"
[ -n "$(table)" ] || fail "heal did not restore the table"
sed '/redirect/d' "$TMP/nft/inet_d2k_tg" > "$TMP/x" && mv "$TMP/x" "$TMP/nft/inet_d2k_tg"
tg "$TMP/nftonly" sh "$TGFW" heal || fail "heal with a lost rule"
[ "$(table | grep -c 'redirect to :1443')" -eq 8 ] || fail "heal не восстановил перенаправления Telegram IPv4/IPv6"
sed '/meta mark 0x31 return/d' "$TMP/nft/inet_d2k_tg" > "$TMP/x" && mv "$TMP/x" "$TMP/nft/inet_d2k_tg"
tg "$TMP/nftonly" sh "$TGFW" heal || fail "heal with a lost outbound mark exemption"
[ "$(table | grep -c 'meta mark 0x31 return')" -eq 1 ] || fail "heal did not restore the outbound mark exemption"
ok "heal leaves a healthy table alone and restores a lost one"

printf 'table inet fw4 {\n}\n' > "$TMP/nft/inet_fw4"
tg "$TMP/nftonly" sh "$TGFW" stop || fail "stop"
[ -z "$(table)" ] || fail "stop left inet d2k_tg"
[ -e "$TMP/nft/inet_fw4" ] || fail "stop removed a foreign table"
tg "$TMP/nftonly" sh "$TGFW" stop || fail "stop without the table must succeed"
ok "stop removes only inet d2k_tg and is idempotent"

mkdir -p "$TMP/t"
if tg "$TMP/nftonly" STUB_NFT_FAIL=1 TMPDIR="$TMP/t" sh "$TGFW" start 2>/dev/null; then fail "start ignored an nft failure"; fi
# heal под set -e (ревью 07.10): отказ nft не обрывает скрипт до уборки.
if tg "$TMP/nftonly" STUB_NFT_FAIL=1 TMPDIR="$TMP/t" sh "$TGFW" heal 2>/dev/null; then fail "heal ignored an nft failure"; fi
[ -z "$(ls -A "$TMP/t")" ] || fail "a refused load left its temp file: $(ls "$TMP/t")"
ok "a refused nft load fails start and heal and leaves no temp file"

# An Entware-era install had iptables rules: start under nft removes them,
# and stop without D2K_FW (uninstall) removes both kinds.
: > "$TMP/ipt.log"
tg "$TMP/both" sh "$TGFW" start || fail "start with iptables present"
grep -q 'iptables -w -t nat -C PREROUTING -p tcp --dport 443 -m set --match-set d2k_tg_dc dst -j REDIRECT --to-port 1443' "$TMP/ipt.log" \
    || fail "start under nft did not clear the old iptables redirect"
grep -q 'iptables -w -t nat -C PREROUTING -p tcp --dport 5222 -m set --match-set d2k_tg_dc dst -j REDIRECT --to-port 1443' "$TMP/ipt.log" \
    || fail "start under nft did not clear the old Telegram 5222 redirect"
grep -q 'ip6tables -w -t nat -C PREROUTING -p tcp --dport 443 -m set --match-set d2k_tg_dc6 dst -j REDIRECT --to-port 1443' "$TMP/ipt.log" \
    || fail "при nft не удалено старое IPv6-перенаправление"
! grep -q -- ' -I ' "$TMP/ipt.log" || fail "start under nft added iptables rules"
: > "$TMP/ipt.log"
tg "$TMP/both" sh "$TGFW" stop || fail "stop with both"
[ -z "$(table)" ] || fail "stop left the nft table"
grep -q 'ip6tables -w -C FORWARD' "$TMP/ipt.log" || fail "stop did not clear the old IPv6 iptables rules"
ok "Entware-era iptables rules are cleared by start and stop under nft"

# Путь Keenetic/legacy iptables: IPv6 получает перенаправление и исключение
# помеченных исходящих соединений, как IPv4; правил быстрого отказа нет.
mkdir -p "$TMP/iptablesok" "$TMP/iptables-state"
for t in iptables ip6tables; do
    cat > "$TMP/iptablesok/$t" <<'EOF'
#!/bin/sh
tool=${0##*/}
state="$IPT_STATE/$tool"
printf '%s %s\n' "$tool" "$*" >> "$IPT_LOG"
[ "${1:-}" = "-w" ] && shift
table=filter
if [ "${1:-}" = "-t" ]; then table=$2; shift 2; fi
op=$1; shift
case "$op" in
    -C)
        chain=$1; shift
        grep -Fqx -- "$table $chain $*" "$state" 2>/dev/null
        ;;
    -I)
        chain=$1; shift
        [ "${1:-}" = "1" ] && shift
        printf '%s %s %s\n' "$table" "$chain" "$*" >> "$state"
        ;;
    -D)
        chain=$1; shift
        [ -f "$state" ] || exit 1
        grep -Fvx -- "$table $chain $*" "$state" > "$state.tmp" || true
        mv "$state.tmp" "$state"
        ;;
    *) exit 1 ;;
esac
EOF
    chmod +x "$TMP/iptablesok/$t"
done
cat > "$TMP/iptablesok/ipset" <<'EOF'
#!/bin/sh
printf 'ipset %s\n' "$*" >> "$IPT_LOG"
exit 0
EOF
cat > "$TMP/iptablesok/conntrack" <<'EOF'
#!/bin/sh
printf 'conntrack %s\n' "$*" >> "$IPT_LOG"
exit 0
EOF
chmod +x "$TMP/iptablesok/ipset" "$TMP/iptablesok/conntrack"
tg_iptables() {
    env PATH="$TMP/iptablesok:/usr/bin:/bin" IPT_STATE="$TMP/iptables-state" \
        IPT_LOG="$TMP/ipt-ok.log" D2K_OPENWRT_RELEASE="$TMP/no-openwrt" "$@"
}
: > "$TMP/ipt-ok.log"
tg_iptables sh "$TGFW" start || fail "не удалось запустить legacy iptables"
grep -q 'ip6tables -w -t nat -I PREROUTING 1 -p tcp --dport 443 -m set --match-set d2k_tg_dc6 dst -j REDIRECT --to-port 1443' "$TMP/ipt-ok.log" \
    || fail "legacy-правила не перенаправляют IPv6-трафик Telegram"
grep -q 'ip6tables -w -t nat -I OUTPUT 1 -m mark --mark 0x31 -m comment --comment d2k-tg-outbound -j RETURN' "$TMP/ipt-ok.log" \
    || fail "legacy-правила не исключают помеченные IPv6-соединения прокси"
! grep -q -- '-j REJECT' "$TMP/iptables-state/ip6tables" || fail "legacy-правила всё ещё отклоняют IPv6"
[ "$(grep -c 'REDIRECT --to-port 1443' "$TMP/iptables-state/iptables")" -eq 4 ] || fail "не хватает перенаправлений IPv4 для legacy-правил"
[ "$(grep -c 'REDIRECT --to-port 1443' "$TMP/iptables-state/ip6tables")" -eq 4 ] || fail "не хватает перенаправлений IPv6 для legacy-правил"
tg_iptables sh "$TGFW" stop || fail "не удалось остановить legacy iptables"
[ ! -s "$TMP/iptables-state/iptables" ] || fail "после остановки остались перенаправления Telegram IPv4"
[ ! -s "$TMP/iptables-state/ip6tables" ] || fail "после остановки остались перенаправления Telegram IPv6"
ok "legacy iptables перенаправляет IPv4/IPv6 и корректно удаляет правила"

# Keenetic: no openwrt_release — iptables as before, nft never called.
: > "$TMP/nft/calls"
tg "$TMP/both" D2K_OPENWRT_RELEASE="$TMP/none" sh "$TGFW" stop || fail "Keenetic stop"
[ ! -s "$TMP/nft/calls" ] || fail "Keenetic path called nft"
ok "Keenetic keeps the iptables path"

echo "d2k-tg-firewall nftables (stub): all checks passed"
