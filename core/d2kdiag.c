#define _GNU_SOURCE
#include "diag_transport.h"
#include "network_diag.h"
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
    d2k_diag_counts_message counts;
    d2k_diag_event_message event;
    d2k_network_controller_message net_controller;
    d2k_network_datapath_message net_datapath;
} diag_message;

static int64_t now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* The restored proxy serves the original JSON protocol. Only the collector waits for it. */
static size_t read_telegram(const char *path, char *json, size_t cap, long *pid) {
    struct sockaddr_un address;
    if (d2k_diag_address(&address, path) != 0) return 0;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return 0;
    size_t used = 0;
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) goto done;
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0 &&
        errno != EINPROGRESS) goto done;
    struct ucred peer;
    socklen_t peer_size = sizeof(peer);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &peer_size) != 0 ||
        peer_size != sizeof(peer) || peer.pid <= 0 || peer.uid != geteuid()) goto done;
    *pid = peer.pid;
    int64_t deadline = now_ms() + 1250;
    while (used < cap && !stopping) {
        int64_t wait = deadline - now_ms();
        if (wait <= 0) break;
        struct pollfd poller = {.fd = fd, .events = POLLIN};
        if (poll(&poller, 1, (int)wait) <= 0) break;
        ssize_t n = read(fd, json + used, cap - used);
        if (n <= 0) break;
        used += (size_t)n;
        if (json[used - 1] == '\n') break;
    }
done:
    close(fd);
    if (used < 3 || json[0] != '{' || json[used - 2] != '}' || json[used - 1] != '\n')
        return 0;
    return used;
}

static size_t telegram_sample(char *json, size_t len, size_t cap, long pid) {
    FILE *tail = fmemopen(json + len - 2, cap - len + 2, "w");
    if (!tail) return 0;
    d2k_diag_telegram_proc(tail, "/proc", pid);
    fputs("}\n", tail);
    long added = ftell(tail);
    if (fclose(tail) != 0 || added <= 0 || (size_t)added >= cap - len + 2) return 0;
    return len - 2 + (size_t)added;
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

static void report_network(FILE *file, const void *history) {
    fputs(",\"network_history\":", file);
    d2k_network_history_write(file, history);
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
    if (argc > 3 || d2k_diag_dir(D2K_DIAG_DIR, 1) != 0) return 1;
    const char *stats_path = argc >= 2 ? argv[1] : "/opt/d2k/state/telegram.stats.sock";
    const char *run_path = argc >= 3 ? argv[2] : "/opt/d2k/run";
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
    d2k_diag_counts_message controller = {0};
    d2k_network_history *network = NULL;
    d2k_network_controller_message net_controller = {0};
    d2k_network_datapath_message net_datapath = {0};
    static char json[D2K_DIAG_TG_JSON_MAX + 1];
    int general_on = 0, telegram_on = 0, live = 0;
    int64_t controller_at = -10000, next = 0, report_due = 0;
    unlink(D2K_DIAG_LIVE);
    if (!general) return 1;
    d2k_diag_set_enabled(general, 0);
    while (!stopping) {
        int64_t now = now_ms();
        if (now >= next) {
            next = now + D2K_NET_DIAG_INTERVAL_MS;
            int g = d2k_diag_enabled(D2K_DIAG_DIR);
            int t = d2k_diag_telegram_enabled(D2K_DIAG_DIR);
            if (g != general_on) {
                d2k_diag_free(general);
                general = d2k_diag_new();
                if (!general) break;
                d2k_diag_set_enabled(general, g);
                general_on = g;
                free(network);
                network = g ? d2k_network_history_new() : NULL;
                net_controller = (d2k_network_controller_message){0};
                net_datapath = (d2k_network_datapath_message){0};
                report_due = 0;
            }
            if (t != telegram_on) {
                d2k_diag_telegram_free(telegram);
                telegram = t ? d2k_diag_telegram_new() : NULL;
                if (t && !telegram) break;
                telegram_on = t;
                report_due = 0;
            }
            long pid = 0;
            size_t length = read_telegram(stats_path, json, sizeof(json), &pid);
            if (length) {
                FILE *file = begin_write(D2K_DIAG_LIVE ".new");
                if (file) finish_write(file, D2K_DIAG_LIVE ".new", D2K_DIAG_LIVE,
                    fwrite(json, 1, length - 2, file) == length - 2 &&
                    fprintf(file, ",\"process_id\":%ld}\n", pid) > 0);
                if (!live && telegram) report_due = 0;
            } else if (live) {
                unlink(D2K_DIAG_LIVE);
                if (telegram) report_due = 0;
            }
            live = length != 0;
            if (g) d2k_network_history_sample(network, (uint64_t)now, &net_controller,
                                               &net_datapath, "/proc", "/sys", run_path);
            if ((g || t) && now >= report_due) {
                report_due = now + 60000;
                if (g && now - controller_at <= 3500) {
                    d2k_diag_set_controller(general, controller.header.pid, controller.memory);
                    d2k_diag_set_madvise(general, &controller.madvise);
                    d2k_diag_sample(general, now, &controller.counts, "/proc", run_path);
                }
                if (telegram) {
                    if (length) length = telegram_sample(json, length, sizeof(json), pid);
                    if (!length || d2k_diag_telegram_record(telegram, now, json, length) < 0)
                        d2k_diag_telegram_error(telegram, live ? EPROTO : ENOTCONN);
                }
                FILE *file = begin_write(D2K_DIAG_DIR "/report.new");
                if (file) {
                    int ok = d2k_diag_write_extended(general, telegram, file,
                        g ? report_network : NULL, network) == 0;
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
            case D2K_DIAG_IPC_COUNTS:
                if (n == (ssize_t)sizeof(message.counts)) {
                    controller = message.counts;
                    controller.counts.worker_oldest_type[sizeof(controller.counts.worker_oldest_type)-1] = 0;
                    controller_at = now_ms();
                }
                break;
            case D2K_DIAG_IPC_LIMIT:
                if (general_on && n == (ssize_t)sizeof(message.counts))
                    d2k_diag_record_limit(general, message.counts.monotonic_ms, &message.counts.counts);
                break;
            case D2K_DIAG_IPC_NETWORK_CONTROLLER:
                if (general_on && n == (ssize_t)sizeof(message.net_controller))
                    net_controller = message.net_controller;
                break;
            case D2K_DIAG_IPC_NETWORK_DATAPATH:
                if (general_on && n == (ssize_t)sizeof(message.net_datapath))
                    net_datapath = message.net_datapath;
                break;
            case D2K_DIAG_IPC_EVENT:
                if (general_on && n == (ssize_t)sizeof(message.event)) record_event(general, &message.event);
                break;
            }
        }
    }
    free(network);
    d2k_diag_free(general);
    d2k_diag_telegram_free(telegram);
    unlink(D2K_DIAG_INPUT);
    unlink(D2K_DIAG_LIVE);
    close(fd);
    close(lock);
    return stopping ? 0 : 1;
}
