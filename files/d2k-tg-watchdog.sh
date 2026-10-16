#!/bin/sh
# Сторож проверяет локальную готовность d2ktg, а не доступность внешнего сайта.
set -u
umask 077
PATH=/opt/sbin:/opt/bin:/opt/usr/sbin:/opt/usr/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

DIR=${TG_WATCHDOG_DIR-/opt/d2k}
INIT=${TG_WATCHDOG_INIT-/opt/etc/init.d/S99d2k}
HEALTH=${TG_WATCHDOG_HEALTH-/tmp/d2k/d2ktg.health}
STATE=${TG_WATCHDOG_STATE-$DIR/state/telegram-health.failures}
RESTARTS=${TG_WATCHDOG_RESTARTS-$DIR/state/telegram-health.restarts}
LIMITED=${TG_WATCHDOG_LIMITED-$DIR/state/telegram-health.restart-limited}

positive_setting() {
    case "$1" in
        ''|*[!0-9]*|0) printf '%s\n' "$2" ;;
        *) printf '%s\n' "$1" ;;
    esac
}

bounded_setting() {
    value=$(positive_setting "$1" "$2")
    [ "$value" -le "$3" ] || value=$3
    printf '%s\n' "$value"
}

is_uint() {
    case "$1" in ''|*[!0-9]*) return 1 ;; esac
}

INTERVAL=$(bounded_setting "${TG_WATCHDOG_INTERVAL-60}" 60 3600)
MAX_HEALTH_AGE_MS=$(bounded_setting "${TG_WATCHDOG_MAX_HEALTH_AGE_MS-15000}" 15000 300000)
FAILURE_LIMIT=$(bounded_setting "${TG_WATCHDOG_FAILURE_LIMIT-3}" 3 10)
RESTART_WINDOW=$(bounded_setting "${TG_WATCHDOG_RESTART_WINDOW-900}" 900 86400)
MAX_RESTARTS=$(bounded_setting "${TG_WATCHDOG_MAX_RESTARTS-3}" 3 10)
BACKOFF_BASE=$(bounded_setting "${TG_WATCHDOG_BACKOFF_BASE-60}" 60 3600)
BACKOFF_MAX=$(bounded_setting "${TG_WATCHDOG_BACKOFF_MAX-300}" 300 3600)
[ "$BACKOFF_MAX" -ge "$BACKOFF_BASE" ] || BACKOFF_MAX=$BACKOFF_BASE

watchdog_log() {
    if command -v logger >/dev/null 2>&1; then
        logger -t d2k-tg-watchdog "$1" 2>/dev/null || true
    fi
}

health_is_fresh() {
    [ -r "$HEALTH" ] || return 1
    IFS=' ' read -r magic pid start_ticks heartbeat_ms boot_id _release_id wire _peer _connected ready _external < "$HEALTH" || return 1
    [ "$magic" = D2KH1 ] && [ "$ready" = 1 ] || return 1
    is_uint "$pid" && [ "$pid" -gt 1 ] || return 1
    is_uint "$start_ticks" && is_uint "$heartbeat_ms" || return 1
    is_uint "$wire" || return 1
    kill -0 "$pid" 2>/dev/null || return 1
    current_start=$(awk '{ sub(/^.*\) /, ""); if (NF >= 20) print $20 }' "/proc/$pid/stat" 2>/dev/null) || return 1
    [ "$current_start" = "$start_ticks" ] || return 1
    current_boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null) || return 1
    [ "$current_boot_id" = "$boot_id" ] || return 1
    awk -v heartbeat="$heartbeat_ms" -v max_age="$MAX_HEALTH_AGE_MS" '
        BEGIN {
            if ((getline line < "/proc/uptime") <= 0) exit 1
            split(line, values)
            age = values[1] * 1000 - heartbeat
            exit !(age >= 0 && age <= max_age)
        }
    ' || return 1
    return 0
}

reserve_restart_slot() {
    now=$(date +%s 2>/dev/null) || return 1
    is_uint "$now" || return 1
    mkdir -p "$(dirname "$RESTARTS")" || return 1
    temporary=$RESTARTS.tmp.$$
    : > "$temporary" || return 1
    recent=0
    if [ -r "$RESTARTS" ]; then
        while IFS= read -r stamp; do
            is_uint "$stamp" || continue
            age=$((now - stamp))
            if [ "$age" -ge 0 ] && [ "$age" -lt "$RESTART_WINDOW" ]; then
                printf '%s\n' "$stamp" >> "$temporary" || {
                    rm -f "$temporary"
                    return 1
                }
                recent=$((recent + 1))
            fi
        done < "$RESTARTS"
    fi
    if [ "$recent" -ge "$MAX_RESTARTS" ]; then
        mv -f "$temporary" "$RESTARTS" || {
            rm -f "$temporary"
            return 1
        }
        RESTART_COUNT=$recent
        return 2
    fi
    printf '%s\n' "$now" >> "$temporary" || {
        rm -f "$temporary"
        return 1
    }
    mv -f "$temporary" "$RESTARTS" || {
        rm -f "$temporary"
        return 1
    }
    RESTART_COUNT=$((recent + 1))
    return 0
}

failures=0
if [ -r "$STATE" ]; then
    read -r failures < "$STATE" || failures=0
    is_uint "$failures" || failures=0
fi
mkdir -p "$(dirname "$STATE")" 2>/dev/null || true

while :; do
    if [ -x "$DIR/d2k-tg-firewall.sh" ]; then
        "$DIR/d2k-tg-firewall.sh" heal >/dev/null 2>&1 || true
    fi
    if health_is_fresh; then
        failures=0
        rm -f "$STATE" "$LIMITED"
    else
        [ "$failures" -ge "$FAILURE_LIMIT" ] || failures=$((failures + 1))
        printf '%s\n' "$failures" > "$STATE"
        if [ "$failures" -ge "$FAILURE_LIMIT" ]; then
            reserve_restart_slot
            slot_status=$?
            if [ "$slot_status" -eq 0 ]; then
                watchdog_log "heartbeat d2ktg устарел; перезапуск $RESTART_COUNT/$MAX_RESTARTS"
                "$INIT" telegram-restart >/dev/null 2>&1 ||
                    watchdog_log "команда перезапуска d2ktg завершилась ошибкой"
                failures=0
                rm -f "$STATE"
                backoff=$BACKOFF_BASE
                step=1
                while [ "$step" -lt "$RESTART_COUNT" ] &&
                      [ "$backoff" -lt "$BACKOFF_MAX" ]; do
                    backoff=$((backoff * 2))
                    [ "$backoff" -le "$BACKOFF_MAX" ] ||
                        backoff=$BACKOFF_MAX
                    step=$((step + 1))
                done
                sleep "$backoff"
                continue
            elif [ "$slot_status" -eq 2 ] && [ ! -e "$LIMITED" ]; then
                watchdog_log "достигнут лимит перезапусков d2ktg; новые попытки отложены"
                : > "$LIMITED"
            fi
        fi
    fi
    sleep "$INTERVAL"
done
