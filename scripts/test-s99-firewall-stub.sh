#!/bin/sh
# Unit-level check of files/S99d2k firewall bookkeeping with a stateful
# iptables/ip6tables double: IPv4-only start when ip6tables mangle is
# unusable (I4), and removal of leftover d2k-rst: RST-drop rules on stop.
# No Docker, no root, no netfilter: the real-iptables check stays
# scripts/check_firewall.sh (Docker). The double stores rules verbatim
# (minus "-m tcp" and quotes, as iptables -S normalises them) and matches
# -C/-D exactly, which is what these functions rely on.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
S99=$ROOT/files/S99d2k
TMP=$(mktemp -d)
SLEEPER=
HU_OTHER=
cleanup() {
    [ -z "$SLEEPER" ] || kill "$SLEEPER" 2>/dev/null || true
    [ -z "$HU_OTHER" ] || kill "$HU_OTHER" 2>/dev/null || true
    rm -rf "$TMP"
}
trap cleanup EXIT HUP INT TERM
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "PASS: $*"; }

mkdir -p "$TMP/bin" "$TMP/fw" "$TMP/run" "$TMP/proc"
cat > "$TMP/bin/iptables" <<'EOF'
#!/bin/sh
# Stateful double: $FW_STATE/<tool>/<table>/<chain> holds one rule per line.
tool=$(basename "$0")
table=filter
op= chain=
spec=
wait_lock=0
while [ $# -gt 0 ]; do
    case "$1" in
        -w) wait_lock=1; shift ;;
        -n) shift ;;
        -t) table=$2; shift 2 ;;
        -N|-A|-I|-C|-D|-F|-X|-L) op=$1; chain=${2:-}; shift; [ $# -gt 0 ] && shift; break ;;
        -S) op=-S; chain=${2:-}; break ;;
        *) echo "stub: unexpected $1" >&2; exit 2 ;;
    esac
done
[ $# -eq 0 ] || spec=$(printf '%s ' "$@" | sed -e 's/ $//' -e 's/-m tcp //' -e 's/"//g')
# Чужой процесс держит блокировку xtables: настоящий iptables 1.4.21 без -w
# отвечает сразу кодом 4, с -w ждёт её (поле 15.10.2026, Keenetic).
if [ "${NO_ADDRTYPE:-0}" = 1 ]; then
    case " $spec " in *" -m addrtype "*) exit 1 ;; esac
fi
if [ "${STUB_XTABLES_BUSY:-0}" = 1 ] && [ "$wait_lock" = 0 ]; then
    echo "Another app is currently holding the xtables lock. Perhaps you want to use the -w option?" >&2
    exit 4
fi
if [ "$tool" = ip6tables ] && [ "$table" = mangle ] && [ "${STUB_V6_MANGLE_BROKEN:-0}" = 1 ]; then
    echo "ip6tables v1.4.21: can't initialize ip6tables table \`mangle': Table does not exist" >&2
    exit 3
fi
case " $spec " in *" ${STUB_FAIL_MATCH:-@none@} "*) [ "$tool" = "${STUB_FAIL_TOOL:-ip6tables}" ] && [ "$op" = -A ] && exit 1;; esac
dir=$FW_STATE/$tool/$table
mkdir -p "$dir"
for builtin in PREROUTING INPUT FORWARD OUTPUT POSTROUTING; do [ -e "$dir/$builtin" ] || : > "$dir/$builtin"; done
f=$dir/$chain
case "$op" in
    -N) [ ! -e "$f" ] || exit 1; : > "$f"; : > "$f.user" ;;
    -A) [ -e "$f" ] || exit 1; printf '%s\n' "$spec" >> "$f" ;;
    -I) [ -e "$f" ] || exit 1
        case "$chain:$spec" in
            "POSTROUTING:-j D2K_OUT")
                if [ "$tool" = iptables ] && [ -n "${EXPECT_DOH_BEFORE_HOOK:-}" ]; then
                    grep -qF -- "-d $EXPECT_DOH_BEFORE_HOOK --dport 443" "$dir/D2K_OUT" || {
                        echo "DoH was missing when the NFQUEUE hook attached" >&2; exit 1; }
                fi ;;
            D2K_IN:*) if [ -n "${FAIL_DOH_IN:-}" ] && [ "$spec" = "-p udp -s $FAIL_DOH_IN -d 192.0.2.1 --sport 443 -j RETURN" ]; then
                exit 1
            fi ;;
        esac
        { printf '%s\n' "$spec"; cat "$f"; } > "$f.new"; mv "$f.new" "$f" ;;
    -C) [ -e "$f" ] && grep -qxF -- "$spec" "$f" ;;
    -D) [ -e "$f" ] && grep -qxF -- "$spec" "$f" || exit 1
        awk -v s="$spec" '!d && $0==s {d=1; next} {print}' "$f" > "$f.new"; mv "$f.new" "$f" ;;
    -F) [ -e "$f" ] || exit 1; : > "$f" ;;
    -X) [ -e "$f.user" ] && [ ! -s "$f" ] || exit 1; rm -f "$f" "$f.user" ;;
    -L) [ -e "$f" ] ;;
    -S) if [ -n "$chain" ]; then
            [ -e "$f" ] || exit 1; sed "s/^/-A $chain /" "$f"
        else
            for c in "$dir"/*; do case "$c" in *.user|*.new) continue;; esac
                n=$(basename "$c"); [ -e "$c.user" ] && echo "-N $n"; sed "s/^/-A $n /" "$c"; done
        fi ;;
esac
EOF
chmod +x "$TMP/bin/iptables"
ln -s iptables "$TMP/bin/ip6tables"

# shellcheck disable=SC2016  # literal text searched for in S99d2k
CASE_LINE=$(grep -n '^case "$1" in' "$S99" | head -1 | cut -d: -f1)
[ -n "$CASE_LINE" ] || fail "S99d2k layout changed: no 'case \"\$1\" in'"
head -n "$((CASE_LINE - 1))" "$S99" > "$TMP/s99funcs.sh"

# Runs a snippet with the S99d2k functions, the doubles first on PATH and
# runtime paths inside the sandbox.
s99() {
    # shellcheck disable=SC2016  # expanded by the inner shell
    env FW_STATE="$TMP/fw" "$@" sh -c '
        . "$1/s99funcs.sh"
        PATH="$1/bin:$PATH"
        RUN=$1/run; FW_V4ONLY=$RUN/fw-ipv4-only; FW_LOCK=$1/fw.lock; PROC_DIR=$1/proc
        MODE=observe
        shift; eval "$1"' sh "$TMP" "$S99_SNIPPET"
}
rules() { FW_STATE="$TMP/fw" "$TMP/bin/$1" -t "$2" -S 2>/dev/null; }

# --- ЖИВОСТЬ ПОСЛЕ ЗАПУСКА: PID-ФАЙЛ НЕ ЕДИНСТВЕННЫЙ СВИДЕТЕЛЬ -------------
# Поле 13.10.2026, OpenWrt 25.12 (mipsel): служба объявила «контроллер
# завершился сразу после запуска», а журнал контроллера говорит «запущен,
# сокет …» и следом «останавливаюсь» — остановили его мы. Проверялся один раз
# pid-файл чужого start-stop-daemon. Живой процесс обязан быть признан живым.
mkdir -p "$TMP/proc/4242"
echo d2kc > "$TMP/proc/4242/comm"
echo "4242 (d2kc) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 1 0 0" > "$TMP/proc/4242/stat"
echo 99999 > "$TMP/run/d2kc.pid"   # номер мёртвого процесса
# shellcheck disable=SC2016  # $RUN раскрывает ВНУТРЕННЯЯ оболочка, не эта
S99_SNIPPET='wait_running "$RUN/d2kc.pid" d2kc' s99 >/dev/null 2>&1 \
    || fail "живой процесс по имени не признан живым"
[ "$(cat "$TMP/run/d2kc.pid")" = "4242" ] \
    || fail "pid-файл не поправлен на живой номер: $(cat "$TMP/run/d2kc.pid")"
# Процесса нет вовсе — отказ, а не выдумка.
rm -rf "$TMP/proc/4242"
echo 99999 > "$TMP/run/d2kc.pid"
# shellcheck disable=SC2016  # то же: раскрытие во внутренней оболочке
if S99_SNIPPET='wait_running "$RUN/d2kc.pid" d2kc' s99 >/dev/null 2>&1; then
    fail "wait_running признал живым то, чего нет"
fi
ok "живой процесс признаётся живым даже с негодным pid-файлом"

# --- ПРИЧИНА ОТКАЗА ЗАПУСКА — ИЗ ЖУРНАЛА УПАВШЕГО ---------------------------
# Поле 13.10.2026: у пользователя служба сказала «контроллер завершился сразу
# после запуска» и замолчала, хотя причина лежала в его же журнале строкой
# ниже. Диагноз пришлось воспроизводить под QEMU вместо того, чтобы прочитать.
mkdir -p "$TMP/log"
printf 'd2kc: каталога нет — начинаю с пустого\nd2kc: связь с датапатом: No such file or directory\n' \
    > "$TMP/log/d2kc.log"
out=$(S99_SNIPPET='die_with_log "контроллер завершился сразу после запуска" "'"$TMP"'/log/d2kc.log"' \
    s99 2>&1) && fail "die_with_log вернул успех"
printf '%s\n' "$out" | grep -q 'контроллер завершился сразу после запуска' \
    || fail "die_with_log не назвал сам отказ: $out"
printf '%s\n' "$out" | grep -q 'связь с датапатом' \
    || fail "die_with_log не показал причину из журнала: $out"
: > "$TMP/log/empty.log"
out=$(S99_SNIPPET='die_with_log "движок не встал" "'"$TMP"'/log/empty.log"' s99 2>&1) \
    && fail "die_with_log на пустом журнале вернул успех"
printf '%s\n' "$out" | grep -q 'журнал .* пуст' \
    || fail "пустой журнал не назван пустым: $out"
ok "отказ запуска печатает причину из журнала упавшего"

# --- I4: ip6tables mangle unusable → IPv4-only, with a clear warning --------
S99_SNIPPET='fw_up && fw_installed' s99 || fail "baseline fw_up failed"
rules ip6tables mangle | grep -q -- '-N D2K_OUT' || fail "baseline did not set up IPv6"
[ ! -e "$TMP/run/fw-ipv4-only" ] || fail "IPv4-only marker without a reason"
S99_SNIPPET='fw_down' s99
rm -rf "$TMP/fw"; mkdir -p "$TMP/fw"

out=$(S99_SNIPPET='fw_up && fw_installed && echo INSTALLED' s99 STUB_V6_MANGLE_BROKEN=1 2>&1) \
    || { echo "$out" >&2; fail "fw_up refused to start without ip6tables mangle"; }
printf '%s\n' "$out" | grep -q 'только по IPv4' || fail "no clear IPv4-only warning: $out"
printf '%s\n' "$out" | grep -q INSTALLED || fail "fw_installed rejects the IPv4-only state"
[ -e "$TMP/run/fw-ipv4-only" ] || fail "IPv4-only state is not recorded"
rules iptables mangle | grep -q -- '-A POSTROUTING -j D2K_OUT' || fail "IPv4 rules missing in IPv4-only mode"
rules iptables mangle | grep -q -- '--queue-bypass' || fail "IPv4 queue rules missing in IPv4-only mode"
# The heal watchdog still notices an IPv4 rule removed by NDM.
FW_STATE="$TMP/fw" "$TMP/bin/iptables" -t mangle -D FORWARD -j D2K_IN
if S99_SNIPPET='fw_installed' s99 STUB_V6_MANGLE_BROKEN=1; then fail "IPv4-only fw_installed missed a removed IPv4 jump"; fi
S99_SNIPPET='fw_down' s99 STUB_V6_MANGLE_BROKEN=1
[ ! -e "$TMP/run/fw-ipv4-only" ] || fail "fw_down kept the IPv4-only marker"
[ -z "$(rules iptables mangle | grep D2K || true)" ] || fail "fw_down left IPv4 rules in IPv4-only mode"
if S99_SNIPPET='fw_installed' s99 STUB_V6_MANGLE_BROKEN=1; then fail "fw_installed true after fw_down"; fi
ok "without ip6tables mangle the service runs IPv4-only and says so"

# --- ICMP time-exceeded на свои фальшивки (поле 04.10.2026, icmp-rua.pcap) --
# В очередь — только TTL-истечение в пути (11/0, ICMPv6 3/0), только в
# ответной цепочке, с --queue-bypass; потеря правила видна сторожу; fw_down
# снимает его вместе с цепочкой.
rm -rf "$TMP/fw"; mkdir -p "$TMP/fw"
S99_SNIPPET='fw_up && fw_installed' s99 || fail "fw_up with the ICMP rule failed"
for tool in iptables ip6tables; do
    rules "$tool" mangle | grep -qx -- '-A D2K_IN -p tcp -m conntrack --ctdir REPLY -m multiport --sports 80 -m connbytes --connbytes 9: --connbytes-dir reply --connbytes-mode packets -j NFQUEUE --queue-num 2000 --queue-bypass' || fail "$tool: late HTTP replies are invisible"
done
rules iptables mangle | grep -qx -- '-A D2K_IN -p icmp --icmp-type 11/0 -j NFQUEUE --queue-num 2000 --queue-bypass' \
    || fail "IPv4 time-exceeded is not queued in D2K_IN"
rules ip6tables mangle | grep -qx -- '-A D2K_IN -p ipv6-icmp --icmpv6-type 3/0 -j NFQUEUE --queue-num 2000 --queue-bypass' \
    || fail "ICMPv6 time-exceeded is not queued in D2K_IN"
[ "$(rules iptables mangle | grep -c icmp)" -eq 1 ] || fail "IPv4: more than the one time-exceeded ICMP rule"
[ "$(rules ip6tables mangle | grep -c icmp)" -eq 1 ] || fail "IPv6: more than the one time-exceeded ICMP rule"
! rules iptables mangle | grep -- '-A D2K_OUT' | grep -q icmp || fail "ICMP rule leaked into D2K_OUT"
for tool in iptables ip6tables; do
    if [ "$tool" = iptables ]; then
        FW_STATE="$TMP/fw" "$TMP/bin/$tool" -t mangle -D D2K_IN -p icmp --icmp-type 11/0 \
            -j NFQUEUE --queue-num 2000 --queue-bypass
    else
        FW_STATE="$TMP/fw" "$TMP/bin/$tool" -t mangle -D D2K_IN -p ipv6-icmp --icmpv6-type 3/0 \
            -j NFQUEUE --queue-num 2000 --queue-bypass
    fi
    if S99_SNIPPET='fw_installed' s99; then fail "$tool: a lost ICMP rule went unnoticed"; fi
    S99_SNIPPET='fw_up' s99 || fail "$tool: fw_up did not restore the ICMP rule"
    S99_SNIPPET='fw_installed' s99 || fail "$tool: restored rules not recognised"
done
S99_SNIPPET='fw_down' s99
! rules iptables mangle | grep -q icmp || fail "fw_down left the IPv4 ICMP rule"
! rules ip6tables mangle | grep -q icmp || fail "fw_down left the IPv6 ICMP rule"
ok "time-exceeded ICMP is queued with bypass in both families and removed on stop"

# --- Проброс портов (issue #23, Keenetic) ------------------------------------
# Соединение С WAN на проброшенный порт идёт по conntrack в направлении
# ORIGINAL и проходит POSTROUTING: правило D2K_OUT «--ctdir ORIGINAL» брало
# его как исходящее из LAN, и проброс на NAS переставал работать. Такие
# соединения несут признак DNAT в обоих направлениях. Исключение — в обеих
# цепочках, раньше любого правила очереди; сторож замечает его пропажу.
rm -rf "$TMP/fw"; mkdir -p "$TMP/fw"
S99_SNIPPET='fw_up && fw_installed' s99 || fail "fw_up with the DNAT exclusion failed"
for tool in iptables ip6tables; do
    for ch in D2K_OUT D2K_IN; do
        rules "$tool" mangle | grep -- "-A $ch " | awk -v ch="$ch" '
            $0 == "-A " ch " -m conntrack --ctstate DNAT -j RETURN" { if (!q) seen = 1 }
            /NFQUEUE/ { q = 1 }
            END { exit !seen }' \
            || fail "$tool $ch: no DNAT RETURN before the first queue rule (port forwards get queued)"
    done
    FW_STATE="$TMP/fw" "$TMP/bin/$tool" -t mangle -D D2K_OUT -m conntrack --ctstate DNAT -j RETURN
    if S99_SNIPPET='fw_installed' s99; then fail "$tool: a lost DNAT exclusion went unnoticed"; fi
    S99_SNIPPET='fw_up' s99 || fail "$tool: fw_up did not restore the DNAT exclusion"
done
S99_SNIPPET='fw_down' s99
ok "port-forwarded (DNAT) connections never enter the queue, in both directions"

# --- Проводник установки на VPS — канал самого D2K, не цель ------------------
# Поле 14.10.2026: туннель CONNECT к 192.0.2.44:9444 датапат принял за
# поток к «github.com», и контроллер начал искать обход своему же каналу.
# RETURN в обе стороны, раньше очереди, только IPv4; сторож замечает пропажу;
# пустой D2K_GATE исключение снимает.
export D2K_GATE=http://192.0.2.44:9444
rm -rf "$TMP/fw"; mkdir -p "$TMP/fw"
S99_SNIPPET='fw_up && fw_installed' s99 || fail "fw_up with the gate exclusion failed"
for spec in "D2K_OUT -p tcp -d 192.0.2.44 --dport 9444 -j RETURN" \
            "D2K_IN -p tcp -s 192.0.2.44 --sport 9444 -j RETURN"; do
    ch=${spec%% *}
    rules iptables mangle | grep -- "-A $ch " | awk -v want="-A $spec" '
        $0 == want { if (!q) seen = 1 }
        /NFQUEUE/ { q = 1 }
        END { exit !seen }' || fail "iptables $ch: no gate RETURN before the first queue rule"
done
if rules ip6tables mangle | grep -q '192.0.2.44'; then fail "ip6tables must not carry an IPv4 gate rule"; fi
FW_STATE="$TMP/fw" "$TMP/bin/iptables" -t mangle -D D2K_OUT -p tcp -d 192.0.2.44 --dport 9444 -j RETURN
if S99_SNIPPET='fw_installed' s99; then fail "a lost gate exclusion went unnoticed"; fi
S99_SNIPPET='fw_up' s99 || fail "fw_up did not restore the gate exclusion"
S99_SNIPPET='fw_down' s99
rm -rf "$TMP/fw"; mkdir -p "$TMP/fw"
S99_SNIPPET='fw_up && fw_installed' s99 D2K_GATE= || fail "fw_up without a gate failed"
if rules iptables mangle | grep -q '9444'; then fail "empty D2K_GATE must leave no gate rule"; fi
S99_SNIPPET='fw_down' s99 D2K_GATE=
unset D2K_GATE
ok "explicit user proxy gate is excluded"

# --- DNS роутера — не цель (поле 15.10.2026) ---------------------------------
# Keenetic резолвит через DoH (https-dns-proxy → geohide.ru:443). Поток к нему
# шёл через очередь D2K как обычный TLS; прокси при всплесках падал «too
# many». DNS роутера, какой ни заведён (DoH, DoT, обычный на нестандартном
# порту), исключается по адресу и порту из `ndmc show dns-proxy`: RETURN в
# обе стороны, раньше очереди, TCP и UDP. Адреса DoH сверяются на каждом
# круге сторожа; неразрешившееся имя прежних правил не снимает.
cat > "$TMP/bin/ndmc" <<'NDMC'
#!/bin/sh
[ ! -f "$NDMC_FAIL" ] || { echo 'command temporarily unavailable'; exit 0; }
if [ "${NDMC_NO_ANNOTATIONS:-0}" = 1 ]; then
    case "$2" in
        'show dns-proxy') echo 'dns_server = 127.0.0.1:40508 .' ;;
        'show running-config')
            printf 'dns-proxy
    https upstream "https://doh.test/dns-query" dnsm
!
'
            ;;
        *) exit 1 ;;
    esac
    exit
fi
printf '\033[K\n     proxy-status: \n              proxy-name: System\n\n'
printf 'timeout = 7000\n'
printf 'dns_server = 127.0.0.1:40508 . # https://doh.test/dns-query@dnsm\n'
printf 'dns_server = 127.0.0.1:40500 . # 9.9.9.9:853@dns.quad9.net\n'
printf 'dns_server = 192.0.2.53:5353 .\n'
printf 'static_a = my.keenetic.net 198.51.100.11 1\n'
NDMC
cat > "$TMP/bin/nslookup" <<'NSL'
#!/bin/sh
[ "$1" = doh.test ] || exit 1
case "$2" in
    127.0.0.1)
        if [ -f "$NSL_FAIL" ]; then
            if [ "${NSL_HANG:-0}" = 1 ]; then
                : > "$NSL_LOOKUP_STARTED"
                exec sleep 15
            fi
            exit 1
        fi ;;

    8.8.8.8|1.1.1.1)
        [ -s "$NSL_BOOTSTRAP" ] || exit 1
        printf 'Server: %s
Address: %s:53

Name: doh.test
' "$2" "$2"
        sed 's/^/Address: /' "$NSL_BOOTSTRAP"
        exit 0 ;;
    *) exit 1 ;;
esac
printf 'Server:    127.0.0.1\nAddress 1: 127.0.0.1 localhost\n\nName:      doh.test\n'
i=1; for a in $(cat "$NSL_ADDRS"); do printf 'Address %d: %s\n' $i "$a"; i=$((i+1)); done
NSL
chmod +x "$TMP/bin/ndmc" "$TMP/bin/nslookup"
printf '198.51.100.7\n2001:db8::7\n' > "$TMP/nsl-addrs"
dns_before_queue() { # <tool> <chain> <spec>
    rules "$1" mangle | grep -- "-A $2 " | awk -v want="-A $2 $3" '
        $0 == want { if (!q) seen = 1 }
        /NFQUEUE/ { q = 1 }
        END { exit !seen }'
}
rm -rf "$TMP/fw" "$TMP/run/dns-excl"; mkdir -p "$TMP/fw"
mkdir -p "$TMP/proc/net"
cat > "$TMP/proc/net/fib_trie" <<'ROUTES'
Local:
    |-- 192.0.2.1
       /32 host LOCAL
    |-- 192.0.2.80
       /32 link UNICAST
    |-- 127.0.0.1
       /32 host LOCAL
ROUTES
printf '20010db8000000000000000000000001 01 80 00 80 wan
' > "$TMP/proc/net/if_inet6"
export NO_ADDRTYPE=1
export NSL_ADDRS="$TMP/nsl-addrs" NSL_FAIL="$TMP/nsl-fail" NSL_BOOTSTRAP="$TMP/nsl-bootstrap" NDMC_FAIL="$TMP/ndmc-fail"
S99_SNIPPET='fw_up && fw_installed' s99 EXPECT_DOH_BEFORE_HOOK=198.51.100.7 \
    || fail "fw_up with router DNS exclusions failed"
for want in "iptables 198.51.100.7 443" "ip6tables 2001:db8::7 443" "iptables 9.9.9.9 853" \
            "iptables 192.0.2.53 5353"; do
    # Разбиение по словам намеренное: «инструмент адрес порт» в одной строке.
    # shellcheck disable=SC2086
    set -- $want
    router=192.0.2.1
    [ "$1" != ip6tables ] || router=2001:0db8:0000:0000:0000:0000:0000:0001
    for pr in tcp udp; do
        dns_before_queue "$1" D2K_OUT "-p $pr -s $router -d $2 --dport $3 -j RETURN" \
            || fail "$1: no $pr RETURN to router DNS $2:$3 before the queue"
        dns_before_queue "$1" D2K_IN "-p $pr -s $2 -d $router --sport $3 -j RETURN" \
            || fail "$1: no $pr RETURN from router DNS $2:$3 before the queue"
    done
done
if rules iptables mangle | grep -q '127.0.0.1 --dport 40508\|198.51.100.11'; then
    fail "local proxy port or static_a records must not become exclusions"
fi
# DoH сменил адрес — старое снято, новое стоит.
printf '198.51.100.8\n' > "$TMP/nsl-addrs"
S99_SNIPPET='dns_excl_sync' s99
dns_before_queue iptables D2K_OUT "-p tcp -s 192.0.2.1 -d 198.51.100.8 --dport 443 -j RETURN" \
    || fail "a new DoH address was not excluded"
if rules iptables mangle | grep -q '198.51.100.7'; then fail "a stale DoH address stayed excluded"; fi
if rules ip6tables mangle | grep -q '2001:db8::7'; then fail "a stale IPv6 DoH address stayed excluded"; fi
# Имя сейчас не разрешилось — прежнее исключение остаётся.
: > "$TMP/nsl-fail"
S99_SNIPPET='dns_excl_sync' s99
dns_before_queue iptables D2K_OUT "-p tcp -s 192.0.2.1 -d 198.51.100.8 --dport 443 -j RETURN" \
    || fail "a failed lookup removed the DoH exclusion"
rm -f "$TMP/nsl-fail"
# The router's recursive DoH is still down after the upstream's IP rotated.
# An independent bootstrap lookup can resolve the new edge.
: > "$TMP/nsl-fail"
printf '198.51.100.9
2001:db8::9
' > "$TMP/nsl-bootstrap"
S99_SNIPPET='dns_excl_sync' s99 NSL_HANG=1 NSL_LOOKUP_STARTED="$TMP/nsl-started" &
refresh=$!
attempt=0
while [ ! -f "$TMP/nsl-started" ] && [ "$attempt" -lt 50 ]; do
    sleep 0.1
    attempt=$((attempt + 1))
done
[ -f "$TMP/nsl-started" ] || fail "timeout fixture did not start"
[ ! -d "$TMP/fw.lock" ] || fail "DoH timeout held the firewall operation lock"
wait "$refresh" || fail "bootstrap refresh did not recover from the timeout"
grep -qx 'doh.test 198.51.100.9 443' "$TMP/run/dns-excl" \
    || fail "rotated DoH IPv4 address was not discovered with local DNS down"
grep -qx 'doh.test 2001:db8::9 443' "$TMP/run/dns-excl" \
    || fail "rotated DoH IPv6 address was not discovered with local DNS down"
! grep -q '198.51.100.8' "$TMP/run/dns-excl" || fail "bootstrap retained the superseded address"
rm -f "$TMP/nsl-fail" "$TMP/nsl-bootstrap"
# Сброс извне снёс исключение — круг сторожа его возвращает.
FW_STATE="$TMP/fw" "$TMP/bin/iptables" -t mangle -D D2K_OUT -p tcp -s 192.0.2.1 -d 9.9.9.9 --dport 853 -j RETURN
S99_SNIPPET='dns_excl_sync' s99
dns_before_queue iptables D2K_OUT "-p tcp -s 192.0.2.1 -d 9.9.9.9 --dport 853 -j RETURN" \
    || fail "the watchdog round did not restore a lost DNS exclusion"
# Execute the real watchdog with the same test firewall in each process.
cat > "$TMP/heal-init" <<'INIT'
#!/bin/sh
. "$TEST_DIR/s99funcs.sh"
PATH="$TEST_DIR/bin:$PATH"
RUN=$TEST_DIR/run; FW_V4ONLY=$RUN/fw-ipv4-only; FW_LOCK=$TEST_DIR/fw.lock; PROC_DIR=$TEST_DIR/proc
case "$1" in
    status)
        echo 'датапат: работает'
        if fw_installed; then echo 'правила: стоят'; fi ;;
    ppe-ensure) exit 0 ;;
    reapply) fw_up ;;
    dns-ensure) dns_excl_sync ;;
esac
INIT
chmod +x "$TMP/heal-init"
heal_round() {
    env FW_STATE="$TMP/fw" TEST_DIR="$TMP" INIT_SCRIPT="$TMP/heal-init" \
        HEAL_LOCK="$TMP/heal.lock" HEAL_LAST="$TMP/heal.last" MIN_INTERVAL=0 \
        "$@" sh "$ROOT/files/d2k-fw-heal.sh"
}

# Lose NDM and the whole firewall during the DNS outage. The rebuilt hooks
# must use the cached addresses even before the first successful discovery.
: > "$TMP/ndmc-fail"
S99_SNIPPET='fw_down' s99
heal_round EXPECT_DOH_BEFORE_HOOK=198.51.100.8 || fail "watchdog failed to rebuild the firewall from cache"
dns_before_queue iptables D2K_OUT '-p tcp -s 192.0.2.1 -d 198.51.100.8 --dport 443 -j RETURN' \
    || fail "watchdog lost the cached DoH route when NDM was unavailable"
rules iptables mangle > "$TMP/fw-before-heal"
heal_round || fail "restarted watchdog failed"
rules iptables mangle > "$TMP/fw-after-heal"
cmp -s "$TMP/fw-before-heal" "$TMP/fw-after-heal" || fail "restarted watchdog changed healthy rules"
rm -f "$TMP/ndmc-fail"

# Heal rebuilds using the old IP and then discovers the rotated IP in the
# same run, even though the local resolver is still timing out.
: > "$TMP/nsl-fail"
printf '198.51.100.9\n2001:db8::9\n' > "$TMP/nsl-bootstrap"
S99_SNIPPET='fw_down' s99
heal_round EXPECT_DOH_BEFORE_HOOK=198.51.100.8 || fail "watchdog failed during DoH rotation"
dns_before_queue ip6tables D2K_IN '-p udp -s 2001:db8::9 -d 2001:0db8:0000:0000:0000:0000:0000:0001 --sport 443 -j RETURN' \
    || fail "watchdog rebuild did not also refresh the rotated IPv6 address"
rm -f "$TMP/nsl-fail" "$TMP/nsl-bootstrap"

# Changing endpoints never drops working exclusions before all replacements
# have been added, even if one of the four firewall updates fails.
printf '198.51.100.10\n2001:db8::10\n' > "$TMP/nsl-addrs"
if S99_SNIPPET='dns_excl_sync' s99 FAIL_DOH_IN=198.51.100.10; then
    fail "partial DoH rule update reported success"
fi
dns_before_queue iptables D2K_OUT '-p tcp -s 192.0.2.1 -d 198.51.100.9 --dport 443 -j RETURN' \
    || fail "failed DoH rotation dropped the previous edge"
heal_round || fail "watchdog failed to retry a partial DoH rule update"
dns_before_queue iptables D2K_IN '-p udp -s 198.51.100.10 -d 192.0.2.1 --sport 443 -j RETURN' \
    || fail "failed DoH reply rule was not repaired"
! rules iptables mangle | grep -q '198.51.100.9' || fail "the superseded edge survived a successful retry"

# Some NDM versions omit the explanatory comment from the DNS proxy status.
printf '198.51.100.12\n' > "$TMP/nsl-addrs"
heal_round NDMC_NO_ANNOTATIONS=1 || fail "watchdog failed with unannotated NDM output"
grep -qx 'doh.test 198.51.100.12 443' "$TMP/run/dns-excl" \
    || fail "configured DoH URL was not discovered from running-config"
if rules iptables mangle | awk '
    /--[ds]port 443 -j RETURN/ && !(/ -s / && / -d /) { found = 1 }
    END { exit !found }'; then
    fail "an address-only bypass would exclude forwarded HTTPS to the same address"
fi
! rules iptables mangle | grep -q '192.0.2.80' || fail "a LAN peer was treated as a router address"

# WAN renew changes the local tuple as well as the remote one.
sed 's/192\.0\.2\.1$/192.0.2.2/' "$TMP/proc/net/fib_trie" > "$TMP/proc/net/fib_trie.new"
mv "$TMP/proc/net/fib_trie.new" "$TMP/proc/net/fib_trie"
heal_round NDMC_NO_ANNOTATIONS=1
dns_before_queue iptables D2K_OUT '-p tcp -s 192.0.2.2 -d 198.51.100.12 --dport 443 -j RETURN' \
    || fail "the new WAN IP did not get its DoH exception"
! rules iptables mangle | grep -q '192\.0\.2\.1 ' || fail "the old WAN IP still has a DoH exception"
S99_SNIPPET='fw_down' s99
rm -f "$TMP/bin/ndmc" "$TMP/bin/nslookup" "$TMP/run/dns-excl" "$TMP/run/dns-excl-rules" "$TMP/run/dns-excl-rules.check"
unset NSL_ADDRS NSL_FAIL NSL_BOOTSTRAP NDMC_FAIL NO_ADDRTYPE
ok "router-only DNS exceptions work without addrtype and survive address rotation, outages and firewall rebuilds"

# A working ip6tables whose rule fails half-way is still a real error: both
# families roll back, as before.
rm -rf "$TMP/fw"; mkdir -p "$TMP/fw"
if S99_SNIPPET='fw_up' s99 STUB_FAIL_MATCH=connbytes STUB_FAIL_TOOL=ip6tables >/dev/null 2>&1; then
    fail "a failing IPv6 rule was taken for a missing IPv6 table"
fi
[ -z "$(rules iptables mangle | grep D2K || true)$(rules ip6tables mangle | grep D2K || true)" ] \
    || fail "partial IPv6 failure did not roll back both families"
[ ! -e "$TMP/run/fw-ipv4-only" ] || fail "partial IPv6 failure set IPv4-only"
ok "a partial IPv6 failure still rolls back both families"

# Прошивка без xt_addrtype (поле 03.10.2026, Keenetic mipsel 3.4_kn: «No
# chain/target/match by that name», служба не запускалась): исключения
# ставятся явными адресами, служба стартует и проверка правил её принимает.
rm -rf "$TMP/fw"; mkdir -p "$TMP/fw"
out=$(S99_SNIPPET='fw_up && fw_installed && echo INSTALLED' s99 STUB_FAIL_MATCH=addrtype STUB_FAIL_TOOL=iptables 2>&1) \
    || { echo "$out" >&2; fail "fw_up refused to start without xt_addrtype"; }
printf '%s\n' "$out" | grep -q INSTALLED || { echo "$out" >&2; fail "rules without xt_addrtype not accepted as installed"; }
printf '%s\n' "$out" | grep -q "нет xt_addrtype" || fail "missing xt_addrtype not reported"
rules iptables mangle | grep -qx -- "-A D2K_OUT -d 255.255.255.255 -j RETURN" || fail "explicit broadcast RETURN missing"
! rules iptables mangle | grep -q addrtype || fail "addrtype rule present although unsupported"
ok "without xt_addrtype the service starts with explicit broadcast exclusions"

# --- Блокировка xtables занята чужим процессом (поле 15.10.2026) -------------
# Сразу после запуска Telegram и разгрузка PPE работают с iptables
# одновременно со сторожем. iptables без -w на занятой блокировке отвечает
# кодом 4 (на роутере 18 из 300 проверок): fw_installed принимал это за
# пропажу правил, сторож звал reapply, тот падал на том же и снимал всё —
# установка 15.10 оставила роутер без единого правила на 55 с.
S99_SNIPPET='fw_up && fw_installed' s99 STUB_XTABLES_BUSY=1 \
    || fail "busy xtables lock: fw_up/fw_installed must wait for it, not fail"
S99_SNIPPET='fw_down' s99 STUB_XTABLES_BUSY=1
for tool in iptables ip6tables; do
    if rules "$tool" mangle | grep -q 'NFQUEUE'; then fail "$tool: fw_down left queue rules under a busy lock"; fi
done
ok "a busy xtables lock is waited for, not mistaken for missing rules"

# Модули ядра лежат файлами в прошивке, но не загружены (Keenetic: modprobe из
# Entware ищет в /opt/lib/modules) — служба загружает их сама через insmod.
# Уже доступные (в /proc/net/ip_tables_matches) не трогаются.
mkdir -p "$TMP/mods/9.9-test" "$TMP/proc/net"
for m in xt_addrtype xt_comment xt_conntrack nf_conntrack_netlink xt_mark; do : > "$TMP/mods/9.9-test/$m.ko"; done
mkdir -p "$TMP/sysmod/xt_mark"   # встроен в ядро: есть в /sys/module, нет в lsmod
printf 'multiport\nconnbytes\nmark\nconnmark\n' > "$TMP/proc/net/ip_tables_matches"
printf 'NFQUEUE\nCONNMARK\n' > "$TMP/proc/net/ip_tables_targets"
cat > "$TMP/bin/uname" <<'EOF2'
#!/bin/sh
echo 9.9-test
EOF2
cat > "$TMP/bin/modprobe" <<'EOF2'
#!/bin/sh
exit 1
EOF2
cat > "$TMP/bin/insmod" <<'EOF2'
#!/bin/sh
echo "$1" >> "$INSMOD_LOG"
EOF2
cat > "$TMP/bin/lsmod" <<'EOF2'
#!/bin/sh
exit 0
EOF2
chmod +x "$TMP/bin/uname" "$TMP/bin/modprobe" "$TMP/bin/insmod" "$TMP/bin/lsmod"
: > "$TMP/insmod.log"
out=$(S99_SNIPPET='load_modules' s99 D2K_MODULES_DIR="$TMP/mods" D2K_SYS_MODULE_DIR="$TMP/sysmod" INSMOD_LOG="$TMP/insmod.log" 2>&1) || { echo "$out" >&2; fail "load_modules failed"; }
for m in xt_addrtype xt_comment xt_conntrack nf_conntrack_netlink; do
    grep -q "/$m.ko$" "$TMP/insmod.log" || fail "$m not loaded from the firmware tree"
done
! grep -q "multiport\|connbytes\|NFQUEUE\|xt_mark" "$TMP/insmod.log" || fail "an already available module was reloaded"
printf '%s\n' "$out" | grep -q "загружен модуль ядра xt_addrtype" || fail "module load not reported"
rm -f "$TMP/bin/uname" "$TMP/bin/modprobe" "$TMP/bin/insmod" "$TMP/bin/lsmod"
ok "kernel modules present as files are loaded by the service itself"

# --- Leftover d2k-rst: rules (filter OUTPUT, both families) ------------------
rm -rf "$TMP/fw"; mkdir -p "$TMP/fw"
sleep 300 >/dev/null 2>&1 & SLEEPER=$!
dead=999990
while kill -0 "$dead" 2>/dev/null; do dead=$((dead + 1)); done
mkdir -p "$TMP/proc/$$" "$TMP/proc/$SLEEPER"
printf 'd2k-detect\n' > "$TMP/proc/$$/comm"     # a live d2k process
printf 'sshd\n' > "$TMP/proc/$SLEEPER/comm"      # a live foreign process
for tool in iptables ip6tables; do
    t() { FW_STATE="$TMP/fw" "$TMP/bin/$tool" -w "$@"; }
    t -A OUTPUT -p tcp -m tcp --sport 40750 --tcp-flags RST RST -m comment --comment "d2k-rst:$dead" -j DROP
    t -A OUTPUT -p tcp -m tcp --sport 40751 --tcp-flags RST RST -m comment --comment "d2k-rst:$$" -j DROP
    t -A OUTPUT -p tcp -m tcp --sport 40752 --tcp-flags RST RST -m comment --comment "d2k-rst:$SLEEPER" -j DROP
    t -A OUTPUT -p tcp -m tcp --sport 40753 --tcp-flags RST RST -m comment --comment "other:$dead" -j DROP
    t -A OUTPUT -p tcp -m tcp --sport 22 --tcp-flags RST RST -m comment --comment "d2k-rst:$dead" -j DROP
    t -A OUTPUT -p tcp -m tcp --sport 40754 --tcp-flags RST RST -m comment --comment "d2k-rst:$dead" -j ACCEPT
done
# engine stop: only rules whose owner is gone (a live search keeps its own).
S99_SNIPPET='rst_rules_down dead' s99
for tool in iptables ip6tables; do
    r=$(rules "$tool" filter)
    ! printf '%s\n' "$r" | grep -q -- "--sport 40750 " || fail "$tool: rule of a dead owner survived engine stop"
    printf '%s\n' "$r" | grep -q -- "--sport 40751 " || fail "$tool: engine stop removed a live d2k process's rule"
done
# service stop / uninstall: every d2k-owned rule goes; foreign ones stay.
S99_SNIPPET='rst_rules_down all' s99
for tool in iptables ip6tables; do
    r=$(rules "$tool" filter)
    ! printf '%s\n' "$r" | grep -q -- "--sport 40751 " || fail "$tool: rule of a live d2k process survived service stop"
    printf '%s\n' "$r" | grep -q -- "--sport 40752 " || fail "$tool: rule owned by a non-d2k process was removed"
    printf '%s\n' "$r" | grep -q -- "--sport 40753 " || fail "$tool: rule with a foreign comment was removed"
    printf '%s\n' "$r" | grep -q -- "--sport 22 " || fail "$tool: rule outside the d2k port range was removed"
    printf '%s\n' "$r" | grep -q -- "--sport 40754 " || fail "$tool: rule with another target was removed"
done
grep -q 'rst_rules_down dead' "$S99" || fail "engine_stop does not clean dead-owner RST rules"
grep -q 'rst_rules_down all' "$S99" || fail "stop does not clean d2k RST rules"
ok "stop removes leftover d2k-rst: rules in both families and nothing else"

# --- Миграция с прокси d2khttp (задача 51) ------------------------------------
rm -rf "$TMP/fw"; mkdir -p "$TMP/fw"
v4() { FW_STATE="$TMP/fw" "$TMP/bin/iptables" -w "$@"; }
v4 -t nat -N D2K_HTTP
v4 -t nat -A D2K_HTTP -p tcp --dport 80 -j REDIRECT --to-ports 18080
v4 -t nat -I PREROUTING -j D2K_HTTP
v4 -t mangle -N D2K_HTTP_MARK
v4 -t mangle -A D2K_HTTP_MARK -m mark --mark 0x30 -j CONNMARK --save-mark
v4 -t mangle -I OUTPUT -j D2K_HTTP_MARK
v4 -t nat -A PREROUTING -j FOREIGN_NAT
S99_SNIPPET='fw_up && fw_installed' s99 || fail "fw_up over the old d2khttp rules failed"
! rules iptables nat | grep -q D2K_HTTP || fail "old nat D2K_HTTP survived fw_up"
! rules iptables mangle | grep -q D2K_HTTP_MARK || fail "old D2K_HTTP_MARK survived fw_up"
rules iptables nat | grep -qx -- '-A PREROUTING -j FOREIGN_NAT' || fail "migration removed a foreign nat rule"
! rules iptables mangle | grep -q 18080 || fail "the :18080 proxy exclusion is still installed"
! rules iptables nat | grep -q REDIRECT || fail "a port-80 REDIRECT is still installed"
S99_SNIPPET='fw_down' s99
ok "fw_up removes the old d2khttp nat/mangle rules and adds none"

# Старый pid-файл d2khttp: гасится только процесс с именем d2khttp (ревью M3).
sleep 300 >/dev/null 2>&1 & HU_OTHER=$!
mkdir -p "$TMP/proc/$HU_OTHER"
printf 'sshd\n' > "$TMP/proc/$HU_OTHER/comm"
printf '%s\n' "$HU_OTHER" > "$TMP/run/d2k-http.pid"
# shellcheck disable=SC2016  # раскрывает S99d2k, не этот скрипт
if S99_SNIPPET='HU_PID=$RUN/d2k-http.pid; legacy_http_present' s99; then
    kill "$HU_OTHER"; fail "a reused pid of a foreign process counted as d2khttp"
fi
# shellcheck disable=SC2016  # раскрывает S99d2k, не этот скрипт
S99_SNIPPET='HU_PID=$RUN/d2k-http.pid; legacy_http_stop' s99
kill -0 "$HU_OTHER" 2>/dev/null || fail "legacy cleanup killed a foreign process by a stale pid"
[ ! -e "$TMP/run/d2k-http.pid" ] || fail "stale d2khttp pid file kept"
printf 'd2khttp\n' > "$TMP/proc/$HU_OTHER/comm"
printf '%s\n' "$HU_OTHER" > "$TMP/run/d2k-http.pid"
# shellcheck disable=SC2016  # раскрывает S99d2k, не этот скрипт
S99_SNIPPET='HU_PID=$RUN/d2k-http.pid; legacy_http_present' s99 || fail "a live d2khttp not seen"
# shellcheck disable=SC2016  # раскрывает S99d2k, не этот скрипт
S99_SNIPPET='HU_PID=$RUN/d2k-http.pid; legacy_http_stop' s99
i=0; while kill -0 "$HU_OTHER" 2>/dev/null && [ $i -lt 30 ]; do sleep 0.1; i=$((i + 1)); done
if kill -0 "$HU_OTHER" 2>/dev/null; then kill "$HU_OTHER"; fail "a live d2khttp was not stopped"; fi
ok "legacy d2khttp cleanup checks the process name, not the pid alone"

# --- Только политика Keenetic (задача 59) -------------------------------------
# Заглушка ndmc повторяет вывод роутера владельца 14.10.2026: управляющий
# символ в начале, внутреннее имя Policy0 и описание «VPN политика» с
# двоеточием в конце. Имя принимается в обоих видах; неизвестное — none и
# предупреждение; без KEENETIC_POLICY ключа нет.
printf '%s\n' '#!/bin/sh' "printf '\033[K\n           policy, name = Policy0, description = VPN политика: \n                 mark: ffffaaa\n               table4: 4096\n           policy, name = Policy1, description = D2K: \n                 mark: ffffaab\n           policy, name = D2Ktest: \n                 mark: ffffaac\n'" > "$TMP/bin/ndmc"
chmod +x "$TMP/bin/ndmc"
# shellcheck disable=SC2016  # expanded by the inner shell
[ "$(S99_SNIPPET='policy_args 2>/dev/null' s99 KEENETIC_POLICY=Policy0)" = "--only-mark 0xffffaaa/0xffffffff" ] \
    || fail "policy by internal name: wrong datapath key"
[ "$(S99_SNIPPET='policy_args 2>/dev/null' s99 KEENETIC_POLICY='VPN политика')" = "--only-mark 0xffffaaa/0xffffffff" ] \
    || fail "policy by its web-interface description: wrong datapath key"
[ "$(S99_SNIPPET='policy_args 2>/dev/null' s99 KEENETIC_POLICY=D2K)" = "--only-mark 0xffffaab/0xffffffff" ] \
    || fail "second policy: wrong mark"
[ "$(S99_SNIPPET='policy_args 2>/dev/null' s99 KEENETIC_POLICY=D2Ktest)" = "--only-mark 0xffffaac/0xffffffff" ] \
    || fail "a policy without a description (name ends with a colon) must be found"
[ "$(S99_SNIPPET='policy_args 2>/dev/null' s99 KEENETIC_POLICY=Нет)" = "--only-mark none" ] \
    || fail "unknown policy must serve no device"
S99_SNIPPET='policy_args 2>&1 >/dev/null' s99 KEENETIC_POLICY=Нет | grep -q 'не найдена' \
    || fail "unknown policy must be reported"
[ -z "$(S99_SNIPPET='policy_args 2>/dev/null' s99)" ] || fail "no KEENETIC_POLICY: no key"
rm -f "$TMP/bin/ndmc"
ok "KEENETIC_POLICY: the policy mark from ndmc goes to the datapath; unknown — none"

echo "S99d2k firewall (stub): all checks passed"
