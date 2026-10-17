#define _POSIX_C_SOURCE 200809L
#include "tg_stats_socket.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static const char *route_stage_name(uint8_t stage) {
    switch (stage) {
    case TG_ROUTE_SESSION_STAGE_ROUTING: return "routing";
    case TG_ROUTE_SESSION_STAGE_UPSTREAM_READY: return "upstream_ready";
    case TG_ROUTE_SESSION_STAGE_FIRST_WSS_BINARY_RESPONSE:
        return "first_wss_binary_response";
    default: return "accepted";
    }
}

static const char *route_state_name(uint8_t state) {
    static const char *const names[] = {
        "idle", "connecting", "connected", "selected", "cooldown",
        "failed", "cancelled", "skipped", "first_binary_response"
    };
    return state < sizeof(names) / sizeof(names[0]) ? names[state] : "idle";
}

static const char *route_transport_name(uint8_t transport) {
    switch (transport) {
    case TG_ROUTE_SESSION_TRANSPORT_DIRECT_WSS: return "direct_wss";
    case TG_ROUTE_SESSION_TRANSPORT_CLOUDFLARE_WORKER: return "cloudflare_worker";
    case TG_ROUTE_SESSION_TRANSPORT_CLOUDFLARE_PROXY: return "cloudflare_proxy";
    case TG_ROUTE_SESSION_TRANSPORT_TCP_FALLBACK: return "tcp_fallback";
    case TG_ROUTE_SESSION_TRANSPORT_TCP_PASSTHROUGH: return "tcp_passthrough";
    default: return NULL;
    }
}

static int stats_append(char *buffer, size_t capacity, size_t *used,
                        const char *format, ...) {
    if (*used >= capacity) return -1;
    va_list args;
    va_start(args, format);
    int count = vsnprintf(buffer + *used, capacity - *used, format, args);
    va_end(args);
    if (count < 0 || (size_t)count >= capacity - *used) return -1;
    *used += (size_t)count;
    return 0;
}

static int append_active_sessions(char *buffer, size_t capacity, size_t *used,
                                  const tg_epoll_proxy_stats *stats) {
    if (stats_append(buffer, capacity, used,
        "\"process_started_at\":%" PRIu64 ",\"accepted_connections\":%" PRIu64
        ",\"active_sessions\":[", stats->process_started_at,
        stats->accepted_connections) != 0)
        return -1;
    for (size_t i = 0; i < stats->active_sessions_count; ++i) {
        const tg_active_route_session *session = &stats->active_sessions[i];
        const char *direct = route_transport_name(session->direct_transport);
        const char *fallback = route_transport_name(session->fallback_transport);
        const char *selected = route_transport_name(session->selected_transport);
        int rc = session->has_dc
            ? stats_append(buffer, capacity, used,
                "%s{\"id\":%" PRIu64 ",\"dc\":%u", i ? "," : "",
                session->id, session->dc)
            : stats_append(buffer, capacity, used,
                "%s{\"id\":%" PRIu64 ",\"dc\":null", i ? "," : "",
                session->id);
        if (rc != 0 || stats_append(buffer, capacity, used,
            ",\"is_media\":%s,\"stage\":\"%s\",\"direct_state\":\"%s\","
            "\"direct_transport\":%s%s%s,\"fallback_state\":\"%s\","
            "\"fallback_transport\":%s%s%s,\"selected_transport\":%s%s%s,"
            "\"telegram_response_seen\":%s,\"bytes_from_clients\":%" PRIu64
            ",\"bytes_from_upstreams\":%" PRIu64 ",\"events\":[",
            session->has_media ? (session->is_media ? "true" : "false") : "null",
            route_stage_name(session->stage), route_state_name(session->direct_state),
            direct ? "\"" : "null", direct ? direct : "", direct ? "\"" : "",
            route_state_name(session->fallback_state),
            fallback ? "\"" : "null", fallback ? fallback : "", fallback ? "\"" : "",
            selected ? "\"" : "null", selected ? selected : "", selected ? "\"" : "",
            session->telegram_response_seen ? "true" : "false",
            session->bytes_from_clients, session->bytes_from_upstreams) != 0)
            return -1;
        for (size_t j = 0; j < session->event_count; ++j) {
            const tg_route_session_event *event = &session->events[j];
            const char *transport = route_transport_name(event->transport);
            if (!transport || stats_append(buffer, capacity, used,
            "%s{\"sequence\":%" PRIu64 ",\"age_ms\":%" PRIu64
            ",\"failure_stage\":%u,\"branch\":\"%s\","
            "\"transport\":\"%s\",\"state\":\"%s\"}",
                j ? "," : "", event->sequence,
            stats->monotonic_time_ms >= event->timestamp_ms
                ? stats->monotonic_time_ms - event->timestamp_ms : 0,
            (unsigned)event->failure_stage,
                event->branch ? "fallback" : "direct", transport,
                route_state_name(event->state)) != 0)
                return -1;
        }
        if (stats_append(buffer, capacity, used, "]}") != 0) return -1;
    }
    if (stats_append(buffer, capacity, used,
        "],\"route_sessions_truncated\":%s,\"route_cooldown_ms\":%u"
        ",\"route_cooldowns\":[",
        stats->route_sessions_truncated ? "true" : "false",
        stats->route_cooldown_ms) != 0)
        return -1;
    for (size_t i = 0; i < stats->route_cooldowns_count; ++i) {
        const tg_route_cooldown *cooldown = &stats->route_cooldowns[i];
        const char *transport = route_transport_name(cooldown->transport);
        if (!transport || stats_append(buffer, capacity, used,
            "%s{\"dc\":%u,\"is_media\":%s,\"transport\":\"%s\","
            "\"remaining_ms\":%" PRIu64 ",\"failure_stage\":%u}",
            i ? "," : "", cooldown->dc,
            cooldown->is_media ? "true" : "false", transport,
            cooldown->remaining_ms, (unsigned)cooldown->failure_stage) != 0)
            return -1;
    }
    return stats_append(buffer, capacity, used,
        "],\"route_cooldowns_truncated\":%s,",
        stats->route_cooldowns_truncated ? "true" : "false");
}

static int set_socket_flags(int fd) {
    int status_flags = fcntl(fd, F_GETFL, 0);
    int descriptor_flags = fcntl(fd, F_GETFD, 0);
    if (status_flags < 0 || descriptor_flags < 0 ||
        fcntl(fd, F_SETFL, status_flags | O_NONBLOCK) != 0 ||
        fcntl(fd, F_SETFD, descriptor_flags | FD_CLOEXEC) != 0)
        return -1;
    return 0;
}

static int remove_stale_socket(const char *path) {
    struct stat current;
    if (lstat(path, &current) != 0) return errno == ENOENT ? 0 : -1;
    if (!S_ISSOCK(current.st_mode) || current.st_uid != geteuid()) {
        errno = EEXIST;
        return -1;
    }

    int probe = socket(AF_UNIX, SOCK_STREAM, 0);
    if (probe < 0) return -1;
    if (set_socket_flags(probe) != 0) {
        close(probe);
        return -1;
    }
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, strlen(path) + 1);
    int rc = connect(probe, (struct sockaddr *)&address, sizeof(address));
    int saved_errno = errno;
    close(probe);
    if (rc == 0 || (saved_errno != ECONNREFUSED && saved_errno != ENOENT)) {
        errno = EADDRINUSE;
        return -1;
    }
    if (unlink(path) != 0 && errno != ENOENT) return -1;
    return 0;
}

int tg_stats_socket_open(tg_stats_socket *server, const char *path) {
    if (!server || !path || !*path) {
        errno = EINVAL;
        return -1;
    }
    memset(server, 0, sizeof(*server));
    server->fd = -1;
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    size_t path_len = strlen(path);
    if (path_len >= sizeof(address.sun_path) || path_len >= sizeof(server->path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, path_len + 1);
    if (remove_stale_socket(path) != 0) return -1;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (set_socket_flags(fd) != 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    mode_t previous_mask = umask(0077);
    int bind_rc = bind(fd, (struct sockaddr *)&address, sizeof(address));
    int bind_errno = errno;
    (void)umask(previous_mask);
    if (bind_rc != 0 || listen(fd, 8) != 0) {
        int saved_errno = bind_rc != 0 ? bind_errno : errno;
        close(fd);
        if (bind_rc == 0) unlink(path);
        errno = saved_errno;
        return -1;
    }
    struct stat created = {0}, secured = {0};
    int setup_error = 0;
    if (lstat(path, &created) != 0) setup_error = errno;
    else if (!S_ISSOCK(created.st_mode) || created.st_uid != geteuid())
        setup_error = EPERM;
    else if (chmod(path, 0600) != 0) setup_error = errno;
    else if (lstat(path, &secured) != 0) setup_error = errno;
    else if (!S_ISSOCK(secured.st_mode) || secured.st_uid != geteuid() ||
             secured.st_dev != created.st_dev || secured.st_ino != created.st_ino)
        setup_error = ESTALE;
    if (setup_error) {
        close(fd);
        struct stat current;
        if (created.st_ino && lstat(path, &current) == 0 &&
            S_ISSOCK(current.st_mode) && current.st_dev == created.st_dev &&
            current.st_ino == created.st_ino)
            unlink(path);
        errno = setup_error;
        return -1;
    }
    server->fd = fd;
    memcpy(server->path, path, path_len + 1);
    server->device = secured.st_dev;
    server->inode = secured.st_ino;
    return 0;
}

int tg_stats_socket_serve(tg_stats_socket *server,
                          const tg_epoll_proxy *proxy) {
    if (!server || server->fd < 0 || !proxy) {
        errno = EINVAL;
        return -1;
    }
    for (;;) {
        int client = accept(server->fd, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            return -1;
        }
        if (set_socket_flags(client) != 0) {
            close(client);
            continue;
        }
        tg_epoll_proxy_stats stats;
        char response[131072];
        int n = tg_epoll_proxy_get_stats(proxy, &stats);
        size_t used = 0;
        int length = n == 0 ? snprintf(response, sizeof(response),
            "{\"active_connections\":%zu,", stats.active_connections) : -1;
        if (length > 0 && (size_t)length < sizeof(response)) {
            used = (size_t)length;
            if (append_active_sessions(response, sizeof(response), &used,
                                       &stats) == 0 &&
                stats_append(response, sizeof(response), &used,
                    "\"max_connections\":%zu,\"active_wss_connections\":%zu"
                    ",\"max_wss_connections\":%zu"
                    ",\"buffer_bytes_current\":%zu"
                    ",\"buffer_bytes_peak\":%zu"
                    ",\"buffer_bytes_limit\":%zu"
                    ",\"connections_started\":%" PRIu64
                    ",\"bytes_from_clients\":%" PRIu64
                    ",\"bytes_from_upstreams\":%" PRIu64
                    ",\"wss_attempts\":%" PRIu64 ",\"wss_failures\":%" PRIu64
                    ",\"wss_responses\":%" PRIu64
                    ",\"cf_wss_responses\":%" PRIu64
                    ",\"last_success_dc\":%u,\"last_success_route\":%u"
                    ",\"last_success_latency_ms\":%" PRIu64
                    ",\"last_success_age_ms\":%" PRIu64
                    ",\"last_failure_dc\":%u,\"last_failure_route\":%u"
                    ",\"last_failure_stage\":%u,\"last_failure_age_ms\":%" PRIu64
                    ",\"client_response_latency_total\":%" PRIu64
                    ",\"client_response_latency_samples\":%zu"
                    ",\"client_response_latency_last_us\":%" PRIu64
                    ",\"client_response_latency_p50_us\":%" PRIu64
                    ",\"client_response_latency_p95_us\":%" PRIu64
                    "}\n",
                    stats.max_connections, stats.active_wss_connections,
                    stats.max_wss_connections, stats.buffer_bytes_current,
                    stats.buffer_bytes_peak, stats.buffer_bytes_limit,
                    stats.connections_started,
                    stats.bytes_from_clients, stats.bytes_from_upstreams,
                    stats.wss_attempts, stats.wss_failures, stats.wss_responses,
                    stats.cf_wss_responses, stats.last_success_dc,
                    stats.last_success_route, stats.last_success_latency_ms,
                    stats.last_success_age_ms, stats.last_failure_dc,
                    stats.last_failure_route, stats.last_failure_stage,
                    stats.last_failure_age_ms,
                    stats.client_response_latency_total,
                    stats.client_response_latency_samples,
                    stats.client_response_latency_last_us,
                    stats.client_response_latency_p50_us,
                    stats.client_response_latency_p95_us) == 0)
                length = (int)used;
            else
                length = -1;
        } else {
            length = -1;
        }
        if (length > 0 && (size_t)length == used) {
            size_t sent = 0;
            while (sent < (size_t)length) {
                ssize_t written = send(client, response + sent,
                                       (size_t)length - sent, MSG_NOSIGNAL);
                if (written > 0) {
                    sent += (size_t)written;
                    continue;
                }
                if (written < 0 && errno == EINTR) continue;
                break;
            }
        }
        close(client);
    }
}

void tg_stats_socket_close(tg_stats_socket *server) {
    if (!server) return;
    if (server->fd >= 0) close(server->fd);
    if (server->path[0]) {
        struct stat current;
        if (lstat(server->path, &current) == 0 && S_ISSOCK(current.st_mode) &&
            current.st_uid == geteuid() && current.st_dev == server->device &&
            current.st_ino == server->inode)
            (void)unlink(server->path);
    }
    memset(server, 0, sizeof(*server));
    server->fd = -1;
}
