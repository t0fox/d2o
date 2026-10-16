#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
WATCHDOG=$ROOT/files/d2k-tg-watchdog.sh
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
mkdir -p "$TMP/d2k/state"

fail() {
    printf 'watchdog test: %s\n' "$1" >&2
    exit 1
}

if grep -q 'core.telegram.org' "$WATCHDOG" || grep -q 'curl' "$WATCHDOG"; then
    fail "локальный watchdog всё ещё зависит от внешнего HTTPS"
fi

cat > "$TMP/firewall" <<'SH'
#!/bin/sh
printf '%s\n' "$1" >> "$WATCHDOG_FIREWALL_CALLS"
SH
cat > "$TMP/init" <<'SH'
#!/bin/sh
printf '%s\n' "$*" >> "$WATCHDOG_INIT_CALLS"
SH
chmod +x "$TMP/firewall" "$TMP/init"
cp "$TMP/firewall" "$TMP/d2k/d2k-tg-firewall.sh"
chmod +x "$TMP/d2k/d2k-tg-firewall.sh"
export WATCHDOG_FIREWALL_CALLS="$TMP/firewall-calls"
export WATCHDOG_INIT_CALLS="$TMP/init-calls"

pid=$$
start_ticks=$(awk '{ sub(/^.*\) /, ""); print $20 }' "/proc/$pid/stat")
heartbeat_ms=$(awk '{ printf "%.0f", $1 * 1000 }' /proc/uptime)
boot_id=$(cat /proc/sys/kernel/random/boot_id)
printf 'D2KH1 %s %s %s %s test 20 - 0 1 1\n' \
    "$pid" "$start_ticks" "$heartbeat_ms" "$boot_id" > "$TMP/health"

set +e
timeout 2 env \
    TG_WATCHDOG_DIR="$TMP/d2k" \
    TG_WATCHDOG_INIT="$TMP/init" \
    TG_WATCHDOG_HEALTH="$TMP/health" \
    TG_WATCHDOG_INTERVAL=1 \
    TG_WATCHDOG_FAILURE_LIMIT=1 \
    WATCHDOG_FIREWALL_CALLS="$WATCHDOG_FIREWALL_CALLS" \
    WATCHDOG_INIT_CALLS="$WATCHDOG_INIT_CALLS" \
    sh "$WATCHDOG" >/dev/null 2>&1
rc=$?
set -e
[ "$rc" -eq 124 ] || fail "watchdog завершился с кодом $rc вместо работы в цикле"
[ ! -s "$WATCHDOG_INIT_CALLS" ] || fail "свежий local heartbeat вызвал перезапуск"
[ -s "$WATCHDOG_FIREWALL_CALLS" ] || fail "watchdog перестал восстанавливать firewall"

rm -f "$WATCHDOG_INIT_CALLS" "$WATCHDOG_FIREWALL_CALLS"
mkdir -p "$TMP/stale/state"
set +e
timeout 3 env \
    TG_WATCHDOG_DIR="$TMP/stale" \
    TG_WATCHDOG_INIT="$TMP/init" \
    TG_WATCHDOG_HEALTH="$TMP/missing-health" \
    TG_WATCHDOG_STATE="$TMP/stale/failures" \
    TG_WATCHDOG_RESTARTS="$TMP/stale/restarts" \
    TG_WATCHDOG_LIMITED="$TMP/stale/limited" \
    TG_WATCHDOG_INTERVAL=1 \
    TG_WATCHDOG_FAILURE_LIMIT=1 \
    TG_WATCHDOG_RESTART_WINDOW=900 \
    TG_WATCHDOG_MAX_RESTARTS=1 \
    TG_WATCHDOG_BACKOFF_BASE=1 \
    TG_WATCHDOG_BACKOFF_MAX=1 \
    WATCHDOG_FIREWALL_CALLS="$WATCHDOG_FIREWALL_CALLS" \
    WATCHDOG_INIT_CALLS="$WATCHDOG_INIT_CALLS" \
    sh "$WATCHDOG" >/dev/null 2>&1
rc=$?
set -e
[ "$rc" -eq 124 ] || fail "watchdog завершился с кодом $rc вместо работы в цикле"
[ "$(wc -l < "$WATCHDOG_INIT_CALLS")" -eq 1 ] ||
    fail "лимит рестартов не остановил повторные попытки"
printf 'Тесты Telegram watchdog: ок\n'
