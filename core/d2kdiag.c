#define _POSIX_C_SOURCE 200809L
#include "diag_transport.h"
#include "../telegram/include/tg_stats_socket.h"
#include "../runtime/d2k_runtime.h"
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <time.h>

static volatile sig_atomic_t stopping;
static void stop(int sig) { (void)sig; stopping = 1; }

typedef union {
    d2k_diag_header header;
    tg_diag_snapshot telegram;
    d2k_diag_counts_message counts;
    d2k_diag_event_message event;
} diag_message;

static int64_t now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int snapshot_valid(const tg_diag_snapshot *tg) {
    const tg_epoll_proxy_stats *s = &tg->stats;
    if (s->active_sessions_count > TG_EPOLL_MAX_ACTIVE_ROUTE_SESSIONS ||
        s->route_cooldowns_count > TG_EPOLL_MAX_ROUTE_COOLDOWNS ||
        s->route_health_count > TG_EPOLL_MAX_ROUTE_STATS ||
        s->problem_sessions_count > TG_EPOLL_MAX_PROBLEM_SESSIONS) return 0;
    for (size_t i = 0; i < s->active_sessions_count; ++i)
        if (s->active_sessions[i].event_count > TG_EPOLL_MAX_ROUTE_EVENTS) return 0;
    return memchr(tg->map.last_refresh_result, '\0', sizeof(tg->map.last_refresh_result)) != NULL;
}

static void record_event(d2k_diag *diag, d2k_diag_event_message *m) {
    m->target[sizeof(m->target)-1] = m->protocol[sizeof(m->protocol)-1] = 0;
    m->outcome[sizeof(m->outcome)-1] = m->reason[sizeof(m->reason)-1] = 0;
    m->ip[sizeof(m->ip)-1] = m->path[sizeof(m->path)-1] = m->kind[sizeof(m->kind)-1] = 0;
    d2k_diag_event event = {
        .id=m->id, .elapsed_ms=m->elapsed_ms, .queue_ms=m->queue_ms, .probe_units=m->probe_units,
        .family=m->family, .trigger=m->trigger, .shape=m->shape, .target=m->target,
        .protocol=m->protocol, .outcome=m->outcome, .reason=m->reason, .ip=m->ip,
        .path=m->path, .kind=m->kind
    };
    d2k_diag_record(diag, &event);
}

static FILE *begin_write(const char *path) {
    if (unlink(path) && errno != ENOENT) return NULL;
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return NULL;
    FILE *file = fdopen(fd, "w");
    if (!file) { close(fd); unlink(path); }
    return file;
}

static void finish_write(FILE *file, const char *tmp, const char *path, int ok) {
    long size = ftell(file);
    if (fclose(file) != 0) ok = 0;
    if (!ok || size <= 0 || (unsigned long)size > D2K_DIAG_REPORT_MAX ||
        rename(tmp, path) != 0) unlink(tmp);
}

static int self_check(void) { return sizeof(diag_message) <= 65536 ? 0 : -1; }

int main(int argc, char **argv) {
    int offline = d2k_runtime_offline(argc, argv, "d2kdiag", self_check);
    if (offline >= 0) return offline;
    if (argc != 1 || d2k_diag_dir(D2K_DIAG_DIR, 1) != 0) return 1;
    const struct rlimit memory = {16u * 1024u * 1024u, 16u * 1024u * 1024u};
    if (setrlimit(RLIMIT_AS, &memory) != 0) return 1;
    if (setpriority(PRIO_PROCESS, 0, 15) != 0) return 1;
    int lock = open(D2K_DIAG_DIR "/collector.lock", O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_RDWR, 0600);
    struct flock exclusive = {.l_type = F_WRLCK, .l_whence = SEEK_SET};
    if (lock < 0 || fcntl(lock, F_SETLK, &exclusive) != 0) return 1;
    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    struct sockaddr_un address;
    if (fd < 0 || d2k_diag_address(&address, D2K_DIAG_INPUT) != 0) return 1;
    umask(0077);
    if (unlink(D2K_DIAG_INPUT) && errno != ENOENT) return 1;
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) != 0) return 1;
    struct sigaction sa = {.sa_handler = stop};
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    d2k_diag *general = d2k_diag_new();
    d2k_diag_telegram *telegram = NULL;
    tg_diag_snapshot latest = {0};
    d2k_diag_counts_message controller = {0};
    static char json[D2K_DIAG_TG_JSON_MAX + 1];
    int general_on = 0, telegram_on = 0, live = 0, live_dirty = 0;
    int64_t tg_at = -10000, controller_at = -10000, next = 0, report_due = 0;
    unlink(D2K_DIAG_LIVE);
    if (!general) return 1;
    d2k_diag_set_enabled(general, 0);
    while (!stopping) {
        int64_t now = now_ms();
        if (now >= next) {
            next = now + 1000;
            int g = d2k_diag_enabled(D2K_DIAG_DIR);
            int t = d2k_diag_telegram_enabled(D2K_DIAG_DIR);
            if (g != general_on) {
                d2k_diag_free(general);
                general = d2k_diag_new();
                if (!general) break;
                d2k_diag_set_enabled(general, g);
                general_on = g;
                report_due = 0;
            }
            if (t != telegram_on) {
                d2k_diag_telegram_free(telegram);
                telegram = t ? d2k_diag_telegram_new() : NULL;
                if (t && !telegram) break;
                telegram_on = t;
                report_due = 0;
            }
            if (now - tg_at <= 3500 && live_dirty) {
                size_t length = tg_stats_encode(&latest, 0, json, sizeof(json));
                FILE *file = length ? begin_write(D2K_DIAG_LIVE ".new") : NULL;
                if (file) finish_write(file, D2K_DIAG_LIVE ".new", D2K_DIAG_LIVE,
                                       fwrite(json, 1, length, file) == length);
                live = length != 0;
                live_dirty = 0;
            } else if (live && now - tg_at > 3500) {
                unlink(D2K_DIAG_LIVE);
                live = 0;
                if (telegram) report_due = 0;
            }
            if ((g || t) && now >= report_due) {
                report_due = now + 60000;
                if (g && now - controller_at <= 3500) {
                    d2k_diag_set_controller(general, controller.header.pid, controller.memory);
                    d2k_diag_set_madvise(general, &controller.madvise);
                    d2k_diag_sample(general, now, &controller.counts, "/proc", "/opt/d2k/run");
                }
                if (telegram) {
                    size_t n = live ? tg_stats_encode(&latest, 1, json, sizeof(json)) : 0;
                    if (!n || d2k_diag_telegram_record(telegram, now, json, n) < 0)
                        d2k_diag_telegram_error(telegram, live ? EPROTO : ENOTCONN);
                }
                FILE *file = begin_write(D2K_DIAG_DIR "/report.new");
                if (file) {
                    int ok = d2k_diag_write_combined(general, telegram, file) == 0;
                    ok = ok && g == d2k_diag_enabled(D2K_DIAG_DIR) &&
                         t == d2k_diag_telegram_enabled(D2K_DIAG_DIR);
                    finish_write(file, D2K_DIAG_DIR "/report.new", D2K_DIAG_DIR "/report.json", ok);
                }
            } else if (!g && !t) unlink(D2K_DIAG_DIR "/report.json");
        }
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        int wait = (int)(next - now_ms());
        if (poll(&pfd, 1, wait > 0 ? wait : 0) <= 0) continue;
        for (int i = 0; i < 16; ++i) {
            diag_message message;
            ssize_t n = recv(fd, &message, sizeof(message), MSG_DONTWAIT | MSG_TRUNC);
            if (n < (ssize_t)sizeof(message.header)) break;
            if (message.header.version != D2K_DIAG_IPC_VERSION ||
                message.header.pid <= 0 || message.header.pid > INT_MAX) continue;
            switch (message.header.kind) {
            case D2K_DIAG_IPC_TELEGRAM:
                if (n == (ssize_t)sizeof(message.telegram) && snapshot_valid(&message.telegram)) {
                    if (telegram_on && now - tg_at > 3500) report_due = 0;
                    latest = message.telegram;
                    tg_at = now;
                    live_dirty = 1;
                }
                break;
            case D2K_DIAG_IPC_COUNTS:
                if (n == (ssize_t)sizeof(message.counts)) {
                    controller = message.counts;
                    controller.counts.worker_oldest_type[sizeof(controller.counts.worker_oldest_type)-1] = 0;
                    controller_at = now;
                }
                break;
            case D2K_DIAG_IPC_LIMIT:
                if (general_on && n == (ssize_t)sizeof(message.counts))
                    d2k_diag_record_limit(general, message.counts.monotonic_ms, &message.counts.counts);
                break;
            case D2K_DIAG_IPC_EVENT:
                if (general_on && n == (ssize_t)sizeof(message.event)) record_event(general, &message.event);
                break;
            }
        }
    }
    d2k_diag_free(general);
    d2k_diag_telegram_free(telegram);
    unlink(D2K_DIAG_INPUT);
    unlink(D2K_DIAG_LIVE);
    close(fd);
    close(lock);
    return stopping ? 0 : 1;
}
