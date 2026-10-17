#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "tg_epoll_proxy.h"

#include "tg_limits.h"
#include "tg_route_plan.h"
#include "tg_route_dns.h"
#include "tg_mtproto_splitter.h"
#include "tg_tls.h"
#include "tg_ws.h"

#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/epoll.h>
#include <netinet/in.h>

#define TG_EPOLL_MAX_EVENTS 128
#define TG_EPOLL_IO_CHUNK 16384u
#define TG_EPOLL_MAX_LISTEN_PORTS 16u
#define TG_ROUTE_HEALTH_MAX 256u
#define TG_HEDGE_DELAY_DEFAULT_MS 125u
#define TG_ROUTE_DNS_WAIT_TIMEOUT_MS 20000u
#define TG_ROUTE_DNS_RETRY_MS 50u
#ifndef TG_ROUTE_HEALTH_COOLDOWN_MS
#define TG_ROUTE_HEALTH_COOLDOWN_MS 30000u
#endif

enum { WSS_NONE, WSS_TLS, WSS_UPGRADE_WRITE, WSS_UPGRADE_READ, WSS_READY };

typedef struct {
    uint8_t *data;
    size_t cap;
    size_t head;
    size_t len;
} byte_queue;

typedef struct proxy_connection proxy_connection;

typedef struct {
    tg_route_kind kind;
    uint32_t dc_id;
    int is_media;
    char hostname[TG_CF_DOMAIN_LEN];
    tg_listener_destination original;
    uint64_t cooldown_until_ms;
    uint64_t last_success_ms;
    uint64_t last_failure_ms;
    uint64_t latency_ms;
    uint32_t last_failure_stage;
    uint64_t attempts;
    uint64_t failures;
    uint64_t responses;
    uint64_t cf_responses;
    int used;
} route_health;

typedef struct {
    int kind;
    proxy_connection *connection;
    int side;
    int fd;
    int registered;
} socket_watch;

struct proxy_connection {
    proxy_connection *next;
    proxy_connection *retired_next;
    proxy_connection *hedge_parent;
    proxy_connection *hedges[2];
    struct tg_epoll_proxy *server;
    socket_watch client_watch;
    socket_watch upstream_watch;
    int client_fd;
    int upstream_fd;
    SSL *upstream_ssl;
    tg_ws_pump ws_pump;
    tg_ws_upgrade_state ws_upgrade;
    tg_mtproto_ctr client_decrypt;
    tg_mtproto_ctr client_encrypt;
    tg_mtproto_ctr server_decrypt;
    tg_mtproto_splitter splitter;
    tg_mtproto_proto wss_proto;
    tg_route_plan route_plan;
    char tls_hostname[TG_CF_DOMAIN_LEN];
    char wss_path[512];
    tg_route_kind route_kind;
    int wss_phase;
    int ws_pump_ready;
    int splitter_ready;
    int direct_wss;
    int packet_framing;
    int wss_subprotocol;
    uint32_t route_dc_id;
    int route_is_media;
    int route_tcp_only;
    int route_session_tracked;
    tg_active_route_session route_session;
    size_t route_index;
    size_t route_dns_step_index;
    uint64_t route_dns_retry_at_ms;
    uint64_t route_dns_deadline_ms;
    int route_dns_pending;
    int route_dns_peer_fin;
    int route_dns_event_active;
    int route_health_index;
    int route_response_seen;
    uint8_t response_header[4];
    size_t response_header_len;
    size_t response_header_needed;
    int response_header_ack;
    uint8_t response_prefix[40];
    size_t response_packet_len;
    size_t response_packet_seen;
    size_t response_prefix_len;
    int response_packet_padded;
    uint64_t route_started_ms;
    uint64_t hedge_due_ms;
    size_t hedge_payload_offset;
    uint32_t tls_want;
    uint64_t wss_deadline_ms;
    int closed;
    int promoted;
    int route_racing;
    int handshake_done;
    int connecting;
    int client_eof;
    int upstream_eof;
    int client_shutdown;
    int upstream_shutdown;
    uint8_t handshake[TG_MTPROTO_HANDSHAKE_LEN];
    size_t handshake_len;
    uint64_t handshake_deadline_ms;
    uint64_t last_activity_ms;
    tg_listener_destination original;
    tg_listener_destination upstream_target;
    byte_queue to_upstream;
    byte_queue to_client;
};

struct tg_epoll_proxy {
    int epoll_fd;
    int listener_fd;
    socket_watch listener_watch;
    tg_epoll_proxy_config config;
    tg_route_dns *route_dns;
    uint16_t listen_ports[TG_EPOLL_MAX_LISTEN_PORTS];
    size_t max_connections;
    size_t active_connections;
    size_t tracked_sessions;
    size_t max_wss_connections;
    size_t active_wss_connections;
    uint64_t connections_started;
    uint64_t process_started_at;
    uint64_t bytes_from_clients;
    uint64_t bytes_from_upstreams;
    uint64_t last_success_ms;
    uint64_t last_success_latency_ms;
    uint64_t last_failure_ms;
    uint32_t last_success_dc;
    uint32_t last_success_route;
    uint32_t last_failure_dc;
    uint32_t last_failure_route;
    uint32_t last_failure_stage;
    route_health route_health[TG_ROUTE_HEALTH_MAX];
    proxy_connection *connections;
    proxy_connection *retired;
};

static int queue_wss_packet(void *opaque, const uint8_t *packet,
                            size_t packet_len);
static int process_client_payload(proxy_connection *connection,
                                  uint8_t *buffer, size_t length);
static int hedge_flush_buffered_payload(proxy_connection *connection);
static int hedge_candidate_flush_buffered_payload(
    proxy_connection *candidate);
static void hedge_cancel_candidates(proxy_connection *connection);
static int hedge_promote_candidate(proxy_connection *candidate);
static void advance_half_closes(proxy_connection *connection);

static uint64_t monotonic_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    return (uint64_t)now.tv_sec * 1000u + (uint64_t)now.tv_nsec / 1000000u;
}

static void add_bytes(uint64_t *total, size_t amount) {
    if (amount > UINT64_MAX - *total) *total = UINT64_MAX;
    else *total += (uint64_t)amount;
}

static void add_u64(uint64_t *total, uint64_t amount) {
    if (amount > UINT64_MAX - *total) *total = UINT64_MAX;
    else *total += amount;
}

static proxy_connection *route_session_owner(proxy_connection *connection) {
    return connection && connection->hedge_parent
        ? connection->hedge_parent : connection;
}

static uint8_t route_session_transport_for(const proxy_connection *connection,
                                           tg_route_kind kind) {
    if (kind == TG_ROUTE_DIRECT_WSS)
        return TG_ROUTE_SESSION_TRANSPORT_DIRECT_WSS;
    if (kind == TG_ROUTE_CF_WORKER)
        return TG_ROUTE_SESSION_TRANSPORT_CLOUDFLARE_WORKER;
    if (kind == TG_ROUTE_CF_PROXY)
        return TG_ROUTE_SESSION_TRANSPORT_CLOUDFLARE_PROXY;
    if (kind == TG_ROUTE_DIRECT_TCP)
        return connection->route_tcp_only
            ? TG_ROUTE_SESSION_TRANSPORT_TCP_PASSTHROUGH
            : TG_ROUTE_SESSION_TRANSPORT_TCP_FALLBACK;
    return TG_ROUTE_SESSION_TRANSPORT_NONE;
}

static void route_session_append(tg_active_route_session *session,
                                 uint8_t branch, uint8_t transport,
                                 uint8_t state) {
    if (session->event_count == TG_EPOLL_MAX_ROUTE_EVENTS) {
        memmove(&session->events[0], &session->events[1],
                (TG_EPOLL_MAX_ROUTE_EVENTS - 1u) * sizeof(session->events[0]));
        --session->event_count;
    }
    tg_route_session_event *event = &session->events[session->event_count++];
    event->sequence = session->next_event_sequence++;
    event->branch = branch;
    event->transport = transport;
    event->state = state;
}

static void route_session_event(proxy_connection *connection,
                                tg_route_kind kind, uint8_t state) {
    proxy_connection *owner = route_session_owner(connection);
    if (!owner || !owner->route_session_tracked) return;
    tg_active_route_session *session = &owner->route_session;
    uint8_t transport = route_session_transport_for(connection, kind);
    if (transport == TG_ROUTE_SESSION_TRANSPORT_NONE) return;
    uint8_t branch = transport == TG_ROUTE_SESSION_TRANSPORT_DIRECT_WSS ||
        transport == TG_ROUTE_SESSION_TRANSPORT_TCP_PASSTHROUGH ? 0u : 1u;
    session->stage = TG_ROUTE_SESSION_STAGE_ROUTING;
    if (!branch) {
        session->direct_state = state;
        session->direct_transport = transport;
    } else {
        session->fallback_state = state;
        session->fallback_transport = transport;
    }
    route_session_append(session, branch, transport, state);
}

static void route_session_selected(proxy_connection *connection,
                                   tg_route_kind kind) {
    proxy_connection *owner = route_session_owner(connection);
    if (!owner || !owner->route_session_tracked) return;
    tg_active_route_session *session = &owner->route_session;
    uint8_t transport = route_session_transport_for(connection, kind);
    if (transport == TG_ROUTE_SESSION_TRANSPORT_NONE) return;
    uint8_t branch = transport == TG_ROUTE_SESSION_TRANSPORT_DIRECT_WSS ||
        transport == TG_ROUTE_SESSION_TRANSPORT_TCP_PASSTHROUGH ? 0u : 1u;
    uint8_t *losing_state = branch ? &session->direct_state
                                   : &session->fallback_state;
    uint8_t losing_transport = branch ? session->direct_transport
                                      : session->fallback_transport;
    if (*losing_state == TG_ROUTE_SESSION_CONNECTED && losing_transport) {
        *losing_state = TG_ROUTE_SESSION_CANCELLED;
        route_session_append(session, branch ? 0u : 1u, losing_transport,
                             TG_ROUTE_SESSION_CANCELLED);
    }
    session->selected_transport = transport;
    session->telegram_response_seen = 0;
    route_session_event(connection, kind, TG_ROUTE_SESSION_SELECTED);
    session->stage = TG_ROUTE_SESSION_STAGE_UPSTREAM_READY;
}

static void route_session_first_response(proxy_connection *connection) {
    proxy_connection *owner = route_session_owner(connection);
    if (!owner || !owner->route_session_tracked ||
        owner->route_session.telegram_response_seen) return;
    tg_active_route_session *session = &owner->route_session;
    tg_route_kind kind = connection->route_kind;
    if (session->selected_transport == TG_ROUTE_SESSION_TRANSPORT_NONE)
        route_session_selected(connection, kind);
    session->telegram_response_seen = 1;
    route_session_event(connection, kind,
                        TG_ROUTE_SESSION_FIRST_BINARY_RESPONSE);
    session->stage = TG_ROUTE_SESSION_STAGE_FIRST_WSS_BINARY_RESPONSE;
}

static uint32_t read_le32(const uint8_t *data) {
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
           ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

static uint64_t read_le64(const uint8_t *data) {
    return (uint64_t)read_le32(data) |
           ((uint64_t)read_le32(data + 4) << 32);
}

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 ? 0 : -1;
}

static int default_original_destination(void *context, int fd,
                                        tg_listener_destination *out) {
    (void)context;
    return tg_listener_get_original_dst_any(fd, out);
}

static int queue_append(byte_queue *queue, const uint8_t *data, size_t len) {
    if (len > queue->cap - queue->len) return -1;
    if (queue->head + queue->len + len > queue->cap && queue->head) {
        memmove(queue->data, queue->data + queue->head, queue->len);
        queue->head = 0;
    }
    memcpy(queue->data + queue->head + queue->len, data, len);
    queue->len += len;
    return 0;
}

static int queue_append_grow(byte_queue *queue, const uint8_t *data, size_t len,
                             size_t max_capacity) {
    if (queue->len > max_capacity || len > max_capacity - queue->len)
        return -1;
    if (queue->head + queue->len + len > queue->cap && queue->head) {
        memmove(queue->data, queue->data + queue->head, queue->len);
        queue->head = 0;
    }
    size_t need = queue->len + len;
    if (need > queue->cap) {
        size_t cap = queue->cap ? queue->cap : 256u;
        while (cap < need) {
            if (cap > max_capacity / 2u) {
                cap = max_capacity;
                break;
            }
            cap *= 2u;
        }
        if (cap < need) return -1;
        uint8_t *grown = realloc(queue->data, cap);
        if (!grown) return -1;
        queue->data = grown;
        queue->cap = cap;
    }
    if (len) memcpy(queue->data + queue->head + queue->len, data, len);
    queue->len += len;
    return 0;
}

static int queue_flush(int fd, byte_queue *queue, uint64_t *last_activity) {
    while (queue->len) {
        ssize_t n = send(fd, queue->data + queue->head, queue->len,
                         MSG_NOSIGNAL);
        if (n > 0) {
            queue->head += (size_t)n;
            queue->len -= (size_t)n;
            if (!queue->len) queue->head = 0;
            *last_activity = monotonic_ms();
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
        return -1;
    }
    return 0;
}

static uint32_t client_events(const proxy_connection *connection) {
    uint32_t events = 0;
    int upstream_ready = !connection->route_dns_pending &&
        (!connection->direct_wss || connection->wss_phase == WSS_READY);
    int wss_backpressure = connection->ws_pump_ready &&
                           connection->ws_pump.tx_memory_bytes != 0;
    int queue_has_room = connection->to_upstream.len <
                         connection->to_upstream.cap;
    if ((!connection->route_dns_pending || !connection->route_dns_peer_fin) &&
        (!connection->route_racing || queue_has_room)) events |= EPOLLRDHUP;
    if (!connection->client_eof && upstream_ready && !wss_backpressure &&
        (!connection->route_racing || queue_has_room) &&
        (!connection->handshake_done ||
         queue_has_room))
        events |= EPOLLIN;
    if (connection->to_client.len) events |= EPOLLOUT;
    return events;
}

static uint32_t upstream_events(const proxy_connection *connection) {
    uint32_t events = EPOLLRDHUP;
    if (connection->connecting) return events | EPOLLOUT;
    if (connection->direct_wss) {
        if (connection->wss_phase == WSS_READY && connection->ws_pump_ready) {
            short want = tg_ws_pump_events(&connection->ws_pump);
            if (want & POLLIN) events |= EPOLLIN;
            if (want & POLLOUT) events |= EPOLLOUT;
        } else {
            events |= connection->tls_want;
        }
        return events;
    }
    if (!connection->upstream_eof &&
        connection->to_client.len < connection->to_client.cap)
        events |= EPOLLIN;
    if (connection->to_upstream.len) events |= EPOLLOUT;
    return events;
}

static int watch_update(tg_epoll_proxy *server, socket_watch *watch,
                        uint32_t events) {
    struct epoll_event event;
    memset(&event, 0, sizeof(event));
    event.events = events;
    event.data.ptr = watch;
    int operation = watch->registered ? EPOLL_CTL_MOD : EPOLL_CTL_ADD;
    if (epoll_ctl(server->epoll_fd, operation, watch->fd, &event) == 0) {
        watch->registered = 1;
        return 0;
    }
    if (operation == EPOLL_CTL_MOD && errno == ENOENT &&
        epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, watch->fd, &event) == 0) {
        watch->registered = 1;
        return 0;
    }
    return -1;
}

static void watch_remove(tg_epoll_proxy *server, socket_watch *watch) {
    if (watch->registered) {
        (void)epoll_ctl(server->epoll_fd, EPOLL_CTL_DEL, watch->fd, NULL);
        watch->registered = 0;
    }
}

static void connection_close(proxy_connection *connection) {
    if (!connection || connection->closed) return;
    tg_epoll_proxy *server = connection->server;
    connection->closed = 1;
    hedge_cancel_candidates(connection);
    if (connection->direct_wss && server->active_wss_connections)
        --server->active_wss_connections;
    watch_remove(server, &connection->client_watch);
    watch_remove(server, &connection->upstream_watch);
    if (connection->upstream_ssl) SSL_free(connection->upstream_ssl);
    if (connection->client_fd >= 0) close(connection->client_fd);
    if (connection->upstream_fd >= 0) close(connection->upstream_fd);
    if (connection->ws_pump_ready) tg_ws_pump_destroy(&connection->ws_pump);
    if (connection->splitter_ready)
        tg_mtproto_splitter_destroy(&connection->splitter);
    tg_mtproto_ctr_destroy(&connection->client_decrypt);
    tg_mtproto_ctr_destroy(&connection->client_encrypt);
    tg_mtproto_ctr_destroy(&connection->server_decrypt);
    connection->client_fd = connection->upstream_fd = -1;
    proxy_connection **link = &server->connections;
    while (*link && *link != connection) link = &(*link)->next;
    if (*link == connection) *link = connection->next;
    if (server->active_connections) --server->active_connections;
    if (connection->route_session_tracked && server->tracked_sessions)
        --server->tracked_sessions;
    connection->retired_next = server->retired;
    server->retired = connection;
}

static void collect_retired(tg_epoll_proxy *server) {
    while (server->retired) {
        proxy_connection *connection = server->retired;
        server->retired = connection->retired_next;
        free(connection->to_upstream.data);
        free(connection->to_client.data);
        free(connection);
    }
}

static int route_health_key_matches(const route_health *health,
                                    const proxy_connection *connection) {
    const tg_listener_destination *a = &health->original;
    const tg_listener_destination *b = &connection->original;
    size_t address_len = a->family == AF_INET ? 4u : 16u;
    return health->used && health->kind == connection->route_kind &&
        health->dc_id == connection->route_dc_id &&
        health->is_media == connection->route_is_media &&
        strcmp(health->hostname, connection->tls_hostname) == 0 &&
        a->family == b->family && a->port == b->port &&
        (a->family == AF_INET || a->family == AF_INET6) &&
        memcmp(a->address, b->address, address_len) == 0;
}

static int route_health_in_use(const tg_epoll_proxy *server, size_t index) {
    for (const proxy_connection *connection = server->connections; connection;
         connection = connection->next) {
        if (!connection->closed && connection->route_health_index == (int)index)
            return 1;
        for (size_t i = 0; i < 2; ++i)
            if (connection->hedges[i] &&
                connection->hedges[i]->route_health_index == (int)index)
                return 1;
    }
    return 0;
}

static int route_health_get(tg_epoll_proxy *server,
                            const proxy_connection *connection, int create) {
    size_t empty = TG_ROUTE_HEALTH_MAX, oldest = TG_ROUTE_HEALTH_MAX;
    uint64_t oldest_time = UINT64_MAX;
    uint64_t now = monotonic_ms();
    for (size_t i = 0; i < TG_ROUTE_HEALTH_MAX; ++i) {
        route_health *health = &server->route_health[i];
        if (route_health_key_matches(health, connection)) return (int)i;
        if (!health->used && empty == TG_ROUTE_HEALTH_MAX) empty = i;
        if (health->used && !route_health_in_use(server, i) &&
            health->cooldown_until_ms <= now &&
            health->last_success_ms < oldest_time) {
            oldest = i;
            oldest_time = health->last_success_ms;
        }
    }
    if (!create) return -1;
    size_t index = empty != TG_ROUTE_HEALTH_MAX ? empty : oldest;
    if (index == TG_ROUTE_HEALTH_MAX) return -1;
    route_health *health = &server->route_health[index];
    memset(health, 0, sizeof(*health));
    health->kind = connection->route_kind;
    health->dc_id = connection->route_dc_id;
    health->is_media = connection->route_is_media;
    memcpy(health->hostname, connection->tls_hostname,
           strlen(connection->tls_hostname) + 1u);
    health->original = connection->original;
    health->used = 1;
    return (int)index;
}

static void route_health_failed(proxy_connection *connection) {
    if (!connection || connection->route_health_index < 0) return;
    route_health *health = &connection->server->route_health[
        (size_t)connection->route_health_index];
    if (!health->used) return;
    if (health->failures != UINT64_MAX) ++health->failures;
    uint64_t now = monotonic_ms();
    health->cooldown_until_ms = now + TG_ROUTE_HEALTH_COOLDOWN_MS;
    health->last_failure_ms = now;
    if (connection->connecting || connection->wss_phase == WSS_NONE) {
        health->last_failure_stage = TG_EPOLL_FAILURE_TCP;
    } else if (connection->wss_phase == WSS_TLS) {
        health->last_failure_stage = TG_EPOLL_FAILURE_TLS;
    } else if (connection->wss_phase == WSS_UPGRADE_WRITE ||
               connection->wss_phase == WSS_UPGRADE_READ) {
        health->last_failure_stage = TG_EPOLL_FAILURE_WEBSOCKET;
    } else if (connection->wss_phase == WSS_READY) {
        health->last_failure_stage = TG_EPOLL_FAILURE_MTPROTO;
    } else {
        health->last_failure_stage = TG_EPOLL_FAILURE_SETUP;
    }
    tg_epoll_proxy *server = connection->server;
    if (now >= server->last_failure_ms) {
        server->last_failure_ms = now;
        server->last_failure_dc = health->dc_id;
        server->last_failure_route = (uint32_t)health->kind;
        server->last_failure_stage = health->last_failure_stage;
    }
}

static size_t route_worker_count(const tg_epoll_proxy *server);
static const char *route_worker_domain(const tg_epoll_proxy *server,
                                       size_t index);
static size_t route_cf_domain_count(const tg_epoll_proxy *server);
static int route_cf_domain(const tg_epoll_proxy *server, size_t index,
                           char domain[TG_CF_DOMAIN_LEN]);

static int route_health_preferred_step(const tg_epoll_proxy *server,
                                       const proxy_connection *connection,
                                       tg_route_step *out) {
    uint64_t now = monotonic_ms();
    const tg_listener_destination *target = &connection->original;
    size_t address_len = target->family == AF_INET ? 4u : 16u;
    const route_health *best = NULL;
    for (size_t i = 0; i < TG_ROUTE_HEALTH_MAX; ++i) {
        const route_health *health = &server->route_health[i];
        if (!health->used ||
            health->kind == TG_ROUTE_DIRECT_TCP ||
            health->dc_id != connection->route_dc_id ||
            health->is_media != connection->route_is_media ||
            !health->last_success_ms || now < health->last_success_ms ||
            now - health->last_success_ms > 120000u ||
            health->original.family != target->family ||
            health->original.port != target->port ||
            memcmp(health->original.address, target->address, address_len) != 0)
            continue;
        if (!best || health->latency_ms < best->latency_ms) best = health;
    }
    if (!best) return 0;
    out->kind = best->kind;
    out->index = 0;
    if (best->kind == TG_ROUTE_DIRECT_WSS) {
        char primary[TG_CF_DOMAIN_LEN], alternate[TG_CF_DOMAIN_LEN];
        uint32_t dc = tg_route_websocket_dc(connection->route_dc_id);
        int a = snprintf(primary, sizeof(primary),
                         "kws%u.web.telegram.org", dc);
        int b = snprintf(alternate, sizeof(alternate),
                         "kws%u-1.web.telegram.org", dc);
        if (a <= 0 || b <= 0 || (size_t)a >= sizeof(primary) ||
            (size_t)b >= sizeof(alternate)) return 0;
        if (strcmp(best->hostname, primary) == 0) out->index = 0;
        else if (strcmp(best->hostname, alternate) == 0) out->index = 1;
        else return 0;
        return 1;
    }
    if (best->kind == TG_ROUTE_CF_WORKER) {
        for (size_t i = 0; i < route_worker_count(server); ++i)
            if (strcmp(best->hostname, route_worker_domain(server, i)) == 0) {
                out->index = (uint8_t)i;
                return 1;
            }
        return 0;
    }
    if (best->kind == TG_ROUTE_CF_PROXY) {
        for (size_t i = 0; i < route_cf_domain_count(server); ++i) {
            char domain[TG_CF_DOMAIN_LEN];
            if (route_cf_domain(server, i, domain) != 0) continue;
            for (unsigned variant = 0; variant <=
                    (unsigned)connection->route_is_media; ++variant) {
                char hostname[TG_CF_DOMAIN_LEN];
                if (tg_route_cf_proxy_hostname(connection->route_dc_id,
                        (int)variant, domain, hostname, sizeof(hostname)) == 0 &&
                    strcmp(best->hostname, hostname) == 0) {
                    out->index = (uint8_t)(2u * i + variant);
                    return 1;
                }
            }
        }
    }
    return 0;
}

static void route_plan_prioritize(tg_route_plan *plan,
                                  const tg_route_step *preferred) {
    for (size_t i = 0; i < plan->count; ++i) {
        if (plan->steps[i].kind != preferred->kind ||
            plan->steps[i].index != preferred->index) continue;
        if (i) {
            tg_route_step selected = plan->steps[i];
            memmove(&plan->steps[1], &plan->steps[0],
                    i * sizeof(plan->steps[0]));
            plan->steps[0] = selected;
        }
        return;
    }
}

static int target_sockaddr(const tg_listener_destination *target,
                           struct sockaddr_storage *address,
                           socklen_t *length) {
    memset(address, 0, sizeof(*address));
    if (!target || !target->port) return -1;
    if (target->family == AF_INET) {
        struct sockaddr_in *v4 = (struct sockaddr_in *)address;
        v4->sin_family = AF_INET;
        v4->sin_port = htons(target->port);
        memcpy(&v4->sin_addr, target->address, sizeof(v4->sin_addr));
        *length = sizeof(*v4);
        return 0;
    }
    if (target->family == AF_INET6) {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)address;
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons(target->port);
        memcpy(&v6->sin6_addr, target->address, sizeof(v6->sin6_addr));
        *length = sizeof(*v6);
        return 0;
    }
    return -1;
}

static int ipv4_public(const uint8_t ip[4]) {
    return ip[0] != 0 && ip[0] != 10 && ip[0] != 127 && ip[0] < 224 &&
           !(ip[0] == 100 && (ip[1] & 0xc0u) == 0x40u) &&
           !(ip[0] == 169 && ip[1] == 254) &&
           !(ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) &&
           !(ip[0] == 192 && ip[1] == 168) &&
           !(ip[0] == 192 && ip[1] == 0 && ip[2] == 0) &&
           !(ip[0] == 192 && ip[1] == 0 && ip[2] == 2) &&
           !(ip[0] == 192 && ip[1] == 88 && ip[2] == 99) &&
           !(ip[0] == 198 && (ip[1] == 18 || ip[1] == 19)) &&
           !(ip[0] == 198 && ip[1] == 51 && ip[2] == 100) &&
           !(ip[0] == 203 && ip[1] == 0 && ip[2] == 113);
}

static int public_route_target(const tg_listener_destination *target) {
    if (!target) return 0;
    if (target->family == AF_INET) return ipv4_public(target->address);
    if (target->family != AF_INET6) return 0;
    static const uint8_t mapped_prefix[12] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff
    };
    if (memcmp(target->address, mapped_prefix, sizeof(mapped_prefix)) == 0)
        return ipv4_public(target->address + 12);
    static const uint8_t zero[16] = {0};
    return (target->address[0] & 0xe0u) == 0x20u &&
           memcmp(target->address, zero, sizeof(zero)) != 0 &&
           !(memcmp(target->address, zero, 15) == 0 && target->address[15] == 1) &&
           (target->address[0] & 0xfeu) != 0xfcu &&
           target->address[0] != 0xffu &&
           !(target->address[0] == 0xfeu &&
             (target->address[1] & 0xc0u) == 0x80u) &&
           !(target->address[0] == 0x20u && target->address[1] == 0x01u &&
             target->address[2] <= 0x01u) &&
           !(target->address[0] == 0x20u && target->address[1] == 0x02u) &&
           !(target->address[0] == 0x20u && target->address[1] == 0x01u &&
             target->address[2] == 0x0du && target->address[3] == 0xb8u);
}

static int resolve_route_domain(tg_epoll_proxy *server, const char *domain,
                                tg_listener_destination *out) {
    int rc = server->config.resolve_domain
        ? server->config.resolve_domain(server->config.route_context, domain, out)
        : tg_route_dns_resolve_status(server->route_dns, domain, out);
    if (rc == 1) return 1;
    if (rc != 0 || target_sockaddr(out, &(struct sockaddr_storage){0},
                                   &(socklen_t){0}) != 0) return -1;
    return server->config.resolve_domain || public_route_target(out) ? 0 : -1;
}

static size_t route_worker_count(const tg_epoll_proxy *server) {
    return server->config.routing_config
        ? server->config.routing_config->cf_worker_domain_count : 0;
}

static const char *route_worker_domain(const tg_epoll_proxy *server,
                                       size_t index) {
    return server->config.routing_config &&
           index < server->config.routing_config->cf_worker_domain_count
        ? server->config.routing_config->cf_worker_domains[index] : NULL;
}

static size_t route_cf_domain_count(const tg_epoll_proxy *server) {
    if (server->config.cf_domain_pool)
        return tg_cf_domain_pool_count(server->config.cf_domain_pool);
    return server->config.routing_config
        ? server->config.routing_config->cf_proxy_domain_count : 0;
}

static int route_cf_domain(const tg_epoll_proxy *server, size_t index,
                           char domain[TG_CF_DOMAIN_LEN]) {
    if (server->config.cf_domain_pool)
        return tg_cf_domain_pool_copy_at(server->config.cf_domain_pool, index,
                                         domain);
    if (!server->config.routing_config ||
        index >= server->config.routing_config->cf_proxy_domain_count)
        return -1;
    memcpy(domain, server->config.routing_config->cf_proxy_domains[index],
           TG_CF_DOMAIN_LEN);
    return 0;
}

static int set_direct_hostname(proxy_connection *connection, unsigned variant) {
    uint32_t dc = tg_route_websocket_dc(connection->route_dc_id);
    if (dc < 1 || dc > 5 || variant > 1) return -1;
    int n = variant
        ? snprintf(connection->tls_hostname, sizeof(connection->tls_hostname),
                   "kws%u-1.web.telegram.org", dc)
        : snprintf(connection->tls_hostname, sizeof(connection->tls_hostname),
                   "kws%u.web.telegram.org", dc);
    return n > 0 && (size_t)n < sizeof(connection->tls_hostname) ? 0 : -1;
}

static int set_worker_path(proxy_connection *connection) {
    char address[INET6_ADDRSTRLEN];
    if (!inet_ntop(connection->original.family, connection->original.address,
                   address, sizeof(address))) return -1;
    int n = snprintf(connection->wss_path, sizeof(connection->wss_path),
                     "/apiws?dst=%s&dc=%u&media=%u", address,
                     connection->route_dc_id,
                     (unsigned)connection->route_is_media);
    return n > 0 && (size_t)n < sizeof(connection->wss_path) ? 0 : -1;
}

static int prepare_wss_tls(proxy_connection *connection) {
    tg_epoll_proxy *server = connection->server;
    if (!server->config.tls_context || !connection->tls_hostname[0]) return -1;
    connection->upstream_ssl = tg_tls_prepare_client_fd(
        server->config.tls_context, connection->upstream_fd,
        connection->tls_hostname, connection->tls_hostname);
    if (!connection->upstream_ssl) return -1;
    connection->wss_phase = WSS_TLS;
    connection->tls_want = EPOLLOUT;
    connection->wss_deadline_ms = monotonic_ms() +
                                  server->config.handshake_timeout_ms;
    return 0;
}

static int begin_upstream(proxy_connection *connection,
                          const tg_listener_destination *target) {
    tg_epoll_proxy *server = connection->server;
    struct sockaddr_storage address;
    socklen_t length;
    if (target_sockaddr(target, &address, &length) != 0) return -1;
    if (server->config.enforce_self_dial &&
        tg_listener_is_self_dial_addr(target, server->listen_ports,
                                      server->config.listen_port_count))
        return -1;

    int fd = socket(target->family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    if (server->config.require_socket_mark) {
#ifdef SO_MARK
        uint32_t mark = server->config.socket_mark;
        if (!mark || setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0) {
            close(fd);
            return -1;
        }
#else
        close(fd);
        errno = ENOTSUP;
        return -1;
#endif
    }
    connection->upstream_fd = fd;
    int rc = connect(fd, (struct sockaddr *)&address, length);
    if (rc != 0 && errno != EINPROGRESS) {
        close(fd);
        connection->upstream_fd = -1;
        return -1;
    }
    connection->connecting = rc != 0;
    if (!connection->connecting && connection->direct_wss &&
        prepare_wss_tls(connection) != 0) {
        close(fd);
        connection->upstream_fd = -1;
        return -1;
    }
    connection->upstream_watch = (socket_watch){
        .kind = 2, .connection = connection, .side = 1, .fd = fd
    };
    if (watch_update(server, &connection->upstream_watch,
                     upstream_events(connection)) != 0) {
        if (connection->upstream_ssl) {
            SSL_free(connection->upstream_ssl);
            connection->upstream_ssl = NULL;
        }
        close(fd);
        connection->upstream_fd = -1;
        return -1;
    }
    return 0;
}

static void clear_wss_state(proxy_connection *connection) {
    if (connection->upstream_ssl) {
        SSL_free(connection->upstream_ssl);
        connection->upstream_ssl = NULL;
    }
    if (connection->ws_pump_ready) {
        tg_ws_pump_destroy(&connection->ws_pump);
        connection->ws_pump_ready = 0;
    }
    if (connection->splitter_ready) {
        tg_mtproto_splitter_destroy(&connection->splitter);
        connection->splitter_ready = 0;
    }
    tg_mtproto_ctr_destroy(&connection->client_decrypt);
    tg_mtproto_ctr_destroy(&connection->client_encrypt);
    tg_mtproto_ctr_destroy(&connection->server_decrypt);
    connection->response_header_len = 0;
    connection->response_header_needed = 0;
    connection->response_header_ack = 0;
    connection->response_packet_len = 0;
    connection->response_packet_seen = 0;
    connection->response_prefix_len = 0;
    connection->response_packet_padded = 0;
    connection->wss_phase = WSS_NONE;
    connection->tls_want = 0;
    connection->wss_deadline_ms = 0;
}

static void clear_route_attempt(proxy_connection *connection, int failed) {
    tg_epoll_proxy *server = connection->server;
    if (failed) {
        route_session_event(connection, connection->route_kind,
                            TG_ROUTE_SESSION_FAILED);
        route_health_failed(connection);
    } else if (connection->direct_wss) {
        proxy_connection *owner = route_session_owner(connection);
        if (!owner->route_session_tracked) goto route_attempt_cleared;
        uint8_t transport = route_session_transport_for(connection,
                                                        connection->route_kind);
        uint8_t branch = transport == TG_ROUTE_SESSION_TRANSPORT_DIRECT_WSS ||
            transport == TG_ROUTE_SESSION_TRANSPORT_TCP_PASSTHROUGH ? 0u : 1u;
        uint8_t state = branch ? owner->route_session.fallback_state
                               : owner->route_session.direct_state;
        if (state == TG_ROUTE_SESSION_CONNECTING ||
            state == TG_ROUTE_SESSION_CONNECTED)
            route_session_event(connection, connection->route_kind,
                                TG_ROUTE_SESSION_CANCELLED);
    }
route_attempt_cleared:
    if (connection->direct_wss && server->active_wss_connections)
        --server->active_wss_connections;
    watch_remove(server, &connection->upstream_watch);
    clear_wss_state(connection);
    if (connection->upstream_fd >= 0) close(connection->upstream_fd);
    connection->upstream_fd = -1;
    connection->connecting = 0;
    connection->direct_wss = 0;
    connection->route_health_index = -1;
    connection->route_response_seen = 0;
    connection->route_started_ms = 0;
}

static void hedge_retire_candidate(proxy_connection *candidate, int failed) {
    if (!candidate || candidate->closed) return;
    proxy_connection *parent = candidate->hedge_parent;
    if (parent) {
        for (size_t i = 0; i < 2; ++i)
            if (parent->hedges[i] == candidate) parent->hedges[i] = NULL;
    }
    clear_route_attempt(candidate, failed);
    candidate->hedge_parent = NULL;
    candidate->closed = 1;
    candidate->retired_next = candidate->server->retired;
    candidate->server->retired = candidate;
}

static void hedge_cancel_candidates(proxy_connection *connection) {
    if (!connection) return;
    for (size_t i = 0; i < 2; ++i) {
        proxy_connection *candidate = connection->hedges[i];
        if (candidate) hedge_retire_candidate(candidate, 0);
        connection->hedges[i] = NULL;
    }
    connection->hedge_due_ms = 0;
    connection->route_racing = 0;
}

static int setup_route_attempt(proxy_connection *connection,
                               const tg_route_step *step,
                               tg_listener_destination *target) {
    tg_epoll_proxy *server = connection->server;
    connection->route_kind = step->kind;
    connection->packet_framing = 1;
    connection->wss_subprotocol = 1;
    memcpy(connection->wss_path, "/apiws", sizeof("/apiws"));
    if (step->kind == TG_ROUTE_DIRECT_WSS) {
        *target = connection->upstream_target;
        return set_direct_hostname(connection, step->index);
    }
    if (step->kind == TG_ROUTE_CF_WORKER || step->kind == TG_ROUTE_CF_PROXY) {
        char domain_copy[TG_CF_DOMAIN_LEN];
        char hostname[TG_CF_DOMAIN_LEN];
        const char *domain;
        if (step->kind == TG_ROUTE_CF_WORKER) {
            domain = route_worker_domain(server, step->index);
        } else {
            if (route_cf_domain(server, step->index / 2u,
                                domain_copy) != 0 ||
                tg_route_cf_proxy_hostname(connection->route_dc_id,
                    step->index % 2u, domain_copy, hostname,
                    sizeof(hostname)) != 0)
                return -1;
            domain = hostname;
        }
        if (!domain) return -1;
        int resolve_status = resolve_route_domain(server, domain, target);
        if (resolve_status != 0) return resolve_status;
        if (strlen(domain) >= sizeof(connection->tls_hostname)) return -1;
        memcpy(connection->tls_hostname, domain, strlen(domain) + 1u);
        if (step->kind == TG_ROUTE_CF_WORKER) {
            connection->packet_framing = 0;
            connection->wss_subprotocol = 0;
            return set_worker_path(connection);
        }
        return 0;
    }
    return -1;
}

static int start_next_route(proxy_connection *connection) {
    if (!connection || connection->closed ||
        connection->wss_phase == WSS_READY) return -1;
    tg_epoll_proxy *server = connection->server;
    while (connection->route_index < connection->route_plan.count) {
        size_t step_index = connection->route_index;
        tg_route_step step =
            connection->route_plan.steps[connection->route_index++];
        connection->route_kind = step.kind;
        int retrying_dns = connection->route_dns_event_active &&
            connection->route_dns_step_index == step_index;
        if (!retrying_dns)
            route_session_event(connection, step.kind,
                                TG_ROUTE_SESSION_CONNECTING);
        if (step.kind == TG_ROUTE_DIRECT_TCP) {
            connection->route_dns_event_active = 0;
            connection->route_dns_pending = 0;
            if (connection->to_upstream.len != 0 ||
                queue_append(&connection->to_upstream, connection->handshake,
                             sizeof(connection->handshake)) != 0)
                return -1;
            if (begin_upstream(connection,
                               &connection->upstream_target) == 0) {
                if (!connection->connecting)
                    route_session_event(connection, step.kind,
                                        TG_ROUTE_SESSION_CONNECTED);
                return 0;
            }
            route_session_event(connection, step.kind,
                                TG_ROUTE_SESSION_FAILED);
            continue;
        }
        if (!server->config.enable_direct_wss ||
            server->active_wss_connections >= server->max_wss_connections) {
            route_session_event(connection, step.kind,
                                TG_ROUTE_SESSION_SKIPPED);
            continue;
        }
        tg_listener_destination target;
        memset(&target, 0, sizeof(target));
        int setup_status = setup_route_attempt(connection, &step, &target);
        if (setup_status == 1) {
            uint64_t now = monotonic_ms();
            if (!retrying_dns) {
                connection->route_dns_step_index = step_index;
                connection->route_dns_deadline_ms =
                    now + TG_ROUTE_DNS_WAIT_TIMEOUT_MS;
                connection->route_dns_peer_fin = 0;
                connection->route_dns_event_active = 1;
            }
            connection->route_dns_pending = 1;
            connection->route_dns_retry_at_ms = now + TG_ROUTE_DNS_RETRY_MS;
            return 0;
        }
        connection->route_dns_pending = 0;
        connection->route_dns_retry_at_ms = 0;
        connection->route_dns_deadline_ms = 0;
        connection->route_dns_event_active = 0;
        if (setup_status != 0 ||
            (server->config.enforce_self_dial &&
             tg_listener_is_self_dial_addr(&target, server->listen_ports,
                                           server->config.listen_port_count))) {
            route_session_event(connection, step.kind,
                                TG_ROUTE_SESSION_FAILED);
            continue;
        }
        int health_index = route_health_get(server, connection, 1);
        if (health_index >= 0) {
            route_health *health = &server->route_health[health_index];
            if (health->cooldown_until_ms > monotonic_ms()) {
                route_session_event(connection, step.kind,
                                    TG_ROUTE_SESSION_COOLDOWN);
                continue;
            }
            connection->route_health_index = health_index;
            connection->route_response_seen = 0;
            connection->route_started_ms = monotonic_ms();
            if (health->attempts != UINT64_MAX) ++health->attempts;
        }
        connection->direct_wss = 1;
        connection->wss_phase = WSS_NONE;
        ++server->active_wss_connections;
        if (begin_upstream(connection, &target) == 0) {
            if (!connection->connecting)
                route_session_event(connection, step.kind,
                                    TG_ROUTE_SESSION_CONNECTED);
            connection->wss_deadline_ms = monotonic_ms() +
                server->config.handshake_timeout_ms;
            return 0;
        }
        clear_route_attempt(connection, 1);
    }
    return -1;
}

static int advance_route(proxy_connection *connection) {
    if (!connection || connection->closed || !connection->direct_wss ||
        connection->wss_phase == WSS_READY) return -1;
    clear_route_attempt(connection, 1);
    return start_next_route(connection);
}

static size_t hedge_candidate_count(const proxy_connection *connection) {
    return (connection->hedges[0] != NULL) +
           (connection->hedges[1] != NULL);
}

static size_t hedge_connection_count(const tg_epoll_proxy *server) {
    size_t count = 0;
    for (const proxy_connection *connection = server->connections; connection;
         connection = connection->next)
        if (connection->route_racing) ++count;
    return count;
}

static int hedge_launch_next(proxy_connection *parent) {
    tg_epoll_proxy *server = parent->server;
    if (server->active_wss_connections >= server->max_wss_connections)
        return 0;
    while (parent->route_index < parent->route_plan.count) {
        tg_route_step step = parent->route_plan.steps[parent->route_index];
        if (step.kind == TG_ROUTE_DIRECT_TCP) return 0;
        ++parent->route_index;
        if (!server->config.enable_direct_wss) continue;

        proxy_connection *candidate = calloc(1, sizeof(*candidate));
        if (!candidate) return 0;
        candidate->server = server;
        candidate->hedge_parent = parent;
        candidate->client_fd = -1;
        candidate->upstream_fd = -1;
        candidate->route_health_index = -1;
        candidate->original = parent->original;
        candidate->upstream_target = parent->upstream_target;
        candidate->route_dc_id = parent->route_dc_id;
        candidate->route_is_media = parent->route_is_media;
        candidate->route_tcp_only = parent->route_tcp_only;
        candidate->wss_proto = parent->wss_proto;
        memcpy(candidate->handshake, parent->handshake,
               sizeof(candidate->handshake));
        int setup_status = setup_route_attempt(candidate, &step,
                                &candidate->upstream_target);
        if (setup_status == 1) {
            --parent->route_index;
            free(candidate);
            return 0;
        }
        if (setup_status != 0 ||
            (server->config.enforce_self_dial &&
             tg_listener_is_self_dial_addr(&candidate->upstream_target,
                                           server->listen_ports,
                                           server->config.listen_port_count))) {
            route_session_event(parent, step.kind,
                                TG_ROUTE_SESSION_FAILED);
            free(candidate);
            continue;
        }
        int slot = parent->hedges[0] ? (parent->hedges[1] ? -1 : 1) : 0;
        if (slot < 0) {
            free(candidate);
            return 0;
        }
        int health_index = route_health_get(server, candidate, 1);
        if (health_index >= 0) {
            route_health *health = &server->route_health[health_index];
            if (health->cooldown_until_ms > monotonic_ms()) {
                route_session_event(parent, step.kind,
                                    TG_ROUTE_SESSION_COOLDOWN);
                free(candidate);
                continue;
            }
            candidate->route_health_index = health_index;
            candidate->route_started_ms = monotonic_ms();
            if (health->attempts != UINT64_MAX) ++health->attempts;
        }
        candidate->direct_wss = 1;
        candidate->wss_phase = WSS_NONE;
        parent->hedges[slot] = candidate;
        ++server->active_wss_connections;
        if (begin_upstream(candidate, &candidate->upstream_target) == 0) {
            route_session_event(candidate, step.kind,
                                TG_ROUTE_SESSION_CONNECTING);
            if (!candidate->connecting)
                route_session_event(candidate, step.kind,
                                    TG_ROUTE_SESSION_CONNECTED);
            candidate->wss_deadline_ms = monotonic_ms() +
                server->config.handshake_timeout_ms;
            return 1;
        }
        route_session_event(candidate, step.kind, TG_ROUTE_SESSION_CONNECTING);
        route_session_event(candidate, step.kind, TG_ROUTE_SESSION_FAILED);
        hedge_retire_candidate(candidate, 1);
    }
    return 0;
}

static int hedge_fill(proxy_connection *parent, int fill_second_slot) {
    size_t current = hedge_candidate_count(parent);
    size_t wanted = current ? (fill_second_slot ? 2u : current) : 1u;
    while (current < wanted) {
        int started = hedge_launch_next(parent);
        if (started < 0) return -1;
        if (!started) break;
        ++current;
    }
    if (!current) {
        parent->route_racing = 0;
        parent->hedge_due_ms = 0;
        return start_next_route(parent);
    }
    if (current < 2 && parent->route_index < parent->route_plan.count &&
        parent->route_plan.steps[parent->route_index].kind != TG_ROUTE_DIRECT_TCP &&
        parent->server->active_wss_connections <
            parent->server->max_wss_connections) {
        uint32_t delay = parent->server->config.routing_config
            ? parent->server->config.routing_config->ws_hedge_delay_ms
            : TG_HEDGE_DELAY_DEFAULT_MS;
        parent->hedge_due_ms = monotonic_ms() + delay;
    }
    else
        parent->hedge_due_ms = 0;
    return 0;
}

static void hedge_fail_candidate(proxy_connection *candidate) {
    proxy_connection *parent = candidate ? candidate->hedge_parent : NULL;
    hedge_retire_candidate(candidate, 1);
    if (parent && !parent->closed && hedge_fill(parent, 1) != 0)
        connection_close(parent);
}

static void connection_update(proxy_connection *connection) {
    if (!connection || connection->closed) return;
    tg_epoll_proxy *server = connection->server;
    if (connection->client_fd >= 0 &&
        watch_update(server, &connection->client_watch,
                     client_events(connection)) != 0) {
        connection_close(connection);
        return;
    }
    if (connection->upstream_fd >= 0 &&
        watch_update(server, &connection->upstream_watch,
                     upstream_events(connection)) != 0) {
        connection_close(connection);
    }
}

static int hedge_promote_candidate(proxy_connection *candidate) {
    proxy_connection *parent = candidate->hedge_parent;
    if (!parent || parent->closed) return -1;
    if (hedge_candidate_flush_buffered_payload(candidate) != 0 ||
        candidate->hedge_payload_offset != parent->to_upstream.len) {
        return -1;
    }
    if (candidate->to_client.len &&
        queue_append_grow(&parent->to_client,
                          candidate->to_client.data + candidate->to_client.head,
                          candidate->to_client.len,
                          TG_MTPROTO_MAX_PACKET) != 0) {
        return -1;
    }
    tg_epoll_proxy *server = parent->server;
    for (size_t i = 0; i < 2; ++i)
        if (parent->hedges[i] == candidate) parent->hedges[i] = NULL;
    candidate->hedge_parent = NULL;
    watch_remove(server, &candidate->upstream_watch);

    parent->upstream_fd = candidate->upstream_fd;
    parent->upstream_ssl = candidate->upstream_ssl;
    parent->ws_pump = candidate->ws_pump;
    parent->ws_upgrade = candidate->ws_upgrade;
    parent->client_decrypt = candidate->client_decrypt;
    parent->client_encrypt = candidate->client_encrypt;
    parent->server_decrypt = candidate->server_decrypt;
    parent->splitter = candidate->splitter;
    parent->route_kind = candidate->route_kind;
    parent->wss_phase = candidate->wss_phase;
    parent->ws_pump_ready = candidate->ws_pump_ready;
    parent->splitter_ready = candidate->splitter_ready;
    parent->direct_wss = 1;
    parent->packet_framing = candidate->packet_framing;
    parent->wss_subprotocol = candidate->wss_subprotocol;
    parent->route_health_index = candidate->route_health_index;
    parent->route_response_seen = candidate->route_response_seen;
    memcpy(parent->response_header, candidate->response_header,
           sizeof(parent->response_header));
    parent->response_header_len = candidate->response_header_len;
    parent->response_header_needed = candidate->response_header_needed;
    parent->response_header_ack = candidate->response_header_ack;
    memcpy(parent->response_prefix, candidate->response_prefix,
           sizeof(parent->response_prefix));
    parent->response_packet_len = candidate->response_packet_len;
    parent->response_packet_seen = candidate->response_packet_seen;
    parent->response_prefix_len = candidate->response_prefix_len;
    parent->response_packet_padded = candidate->response_packet_padded;
    parent->route_started_ms = candidate->route_started_ms;
    parent->tls_want = candidate->tls_want;
    parent->upstream_eof = candidate->upstream_eof;
    parent->wss_deadline_ms = 0;
    memcpy(parent->tls_hostname, candidate->tls_hostname,
           sizeof(parent->tls_hostname));
    memcpy(parent->wss_path, candidate->wss_path, sizeof(parent->wss_path));
    parent->upstream_watch = (socket_watch){
        .kind = 2, .connection = parent, .side = 1,
        .fd = parent->upstream_fd
    };
    parent->to_upstream.head = 0;
    parent->to_upstream.len = 0;
    parent->route_racing = 0;
    parent->hedge_due_ms = 0;

    candidate->upstream_fd = -1;
    candidate->upstream_ssl = NULL;
    candidate->route_health_index = -1;
    candidate->direct_wss = 0;
    candidate->ws_pump_ready = 0;
    candidate->splitter_ready = 0;
    memset(&candidate->ws_pump, 0, sizeof(candidate->ws_pump));
    memset(&candidate->splitter, 0, sizeof(candidate->splitter));
    memset(&candidate->client_decrypt, 0, sizeof(candidate->client_decrypt));
    memset(&candidate->client_encrypt, 0, sizeof(candidate->client_encrypt));
    memset(&candidate->server_decrypt, 0, sizeof(candidate->server_decrypt));
    candidate->closed = 1;
    candidate->promoted = 1;
    candidate->retired_next = server->retired;
    server->retired = candidate;

    hedge_cancel_candidates(parent);
    if (watch_update(server, &parent->upstream_watch,
                     upstream_events(parent)) != 0) {
        connection_close(parent);
        return 0;
    }
    advance_half_closes(parent);
    connection_update(parent);
    return 0;
}

static void advance_half_closes(proxy_connection *connection) {
    if (!connection || connection->closed) return;
    if (connection->direct_wss && connection->client_eof &&
        !connection->upstream_shutdown && connection->wss_phase == WSS_READY) {
        int split_rc = connection->packet_framing
            ? tg_mtproto_splitter_flush(&connection->splitter,
                                        queue_wss_packet, connection)
            : TG_MTPROTO_SPLIT_OK;
        if (split_rc != TG_MTPROTO_SPLIT_OK ||
            tg_ws_pump_queue_close(&connection->ws_pump) != 0) {
            connection_close(connection);
            return;
        }
        connection->upstream_shutdown = 1;
    }
    if (!connection->connecting && connection->upstream_fd >= 0 &&
        !connection->direct_wss &&
        connection->client_eof && !connection->upstream_shutdown &&
        connection->to_upstream.len == 0) {
        (void)shutdown(connection->upstream_fd, SHUT_WR);
        connection->upstream_shutdown = 1;
    }
    if (connection->client_fd >= 0 && connection->upstream_eof &&
        !connection->client_shutdown && connection->to_client.len == 0) {
        (void)shutdown(connection->client_fd, SHUT_WR);
        connection->client_shutdown = 1;
    }
    if (connection->client_eof && connection->upstream_eof &&
        connection->to_upstream.len == 0 && connection->to_client.len == 0)
        connection_close(connection);
}

static int route_after_handshake(proxy_connection *connection) {
    tg_epoll_proxy *server = connection->server;
    tg_epoll_route_selection selection = {0};
    int validated = server->config.select_route != NULL;
    if (validated) {
        if (server->config.select_route(server->config.context,
                                        &connection->original,
                                        connection->handshake, &selection) != 0)
            return -1;
    } else {
        /* Compatibility for the existing synthetic test fixture. */
        if (server->config.select_target(server->config.context,
                                         &connection->original,
                                         connection->handshake,
                                         &selection.upstream) != 0)
            return -1;
        tg_mtproto_init parsed;
        if (tg_mtproto_parse_obfuscated2(connection->handshake,
                                        &parsed) == 0) {
            selection.dc_id = parsed.dc_id;
            selection.is_media = parsed.is_media;
            selection.proto = parsed.proto;
        }
    }
    tg_listener_destination *upstream = &selection.upstream;
    if (target_sockaddr(upstream, &(struct sockaddr_storage){0},
                        &(socklen_t){0}) != 0 ||
        (server->config.enforce_self_dial &&
         tg_listener_is_self_dial_addr(upstream, server->listen_ports,
                                       server->config.listen_port_count)))
        return -1;
    connection->upstream_target = *upstream;
    connection->direct_wss = 0;
    size_t worker_count = 0, cf_count = 0;
    tg_ws_routing_policy policy = TG_WS_ROUTING_ADAPTIVE;
    tg_route_step preferred = {0};
    int have_preferred = 0;
    connection->route_dc_id = selection.dc_id;
    connection->route_is_media = selection.is_media;
    connection->route_tcp_only = selection.tcp_only;
    connection->wss_proto = selection.proto;
    if (connection->route_session_tracked) {
        connection->route_session.stage = TG_ROUTE_SESSION_STAGE_ROUTING;
        if (selection.dc_id) {
            connection->route_session.dc = selection.dc_id;
            connection->route_session.has_dc = 1;
            connection->route_session.is_media = selection.is_media != 0;
            connection->route_session.has_media = 1;
        }
    }
    if (selection.dc_id != 0 && !selection.tcp_only) {
        worker_count = route_worker_count(server);
        cf_count = route_cf_domain_count(server);
        if (server->config.routing_config)
            policy = server->config.routing_config->ws_routing;
    }
    have_preferred = route_health_preferred_step(server, connection,
                                                  &preferred);
    int prefer_cf = policy == TG_WS_ROUTING_ADAPTIVE && have_preferred &&
        (preferred.kind == TG_ROUTE_CF_WORKER ||
         preferred.kind == TG_ROUTE_CF_PROXY);
    if (tg_route_plan_build(selection.tcp_only ? 0 : connection->route_dc_id,
                            connection->route_is_media, policy, prefer_cf,
                            worker_count, cf_count,
                            &connection->route_plan) != 0)
        return -1;
    if (policy == TG_WS_ROUTING_ADAPTIVE && have_preferred)
        route_plan_prioritize(&connection->route_plan, &preferred);
    uint32_t hedge_limit = server->config.routing_config
        ? server->config.routing_config->ws_hedge_limit : 0;
    if (policy == TG_WS_ROUTING_HEDGED && hedge_limit > 0 &&
        hedge_connection_count(server) < hedge_limit) {
        connection->route_racing = 1;
        connection->handshake_done = 1;
        return hedge_fill(connection, 0);
    }
    if (start_next_route(connection) != 0) return -1;
    connection->handshake_done = 1;
    return 0;
}

static int receive_client(proxy_connection *connection) {
    uint8_t buffer[TG_EPOLL_IO_CHUNK];
    for (;;) {
        if (connection->route_dns_pending) return 0;
        if (connection->direct_wss &&
            (connection->wss_phase != WSS_READY ||
             connection->ws_pump.tx_memory_bytes != 0))
            return 0;
        size_t capacity = sizeof(buffer);
        if (!connection->handshake_done) {
            capacity = sizeof(connection->handshake) - connection->handshake_len;
            if (!capacity) return -1;
        } else {
            size_t free_bytes = connection->to_upstream.cap -
                                connection->to_upstream.len;
            if (!free_bytes) return 0;
            if (capacity > free_bytes) capacity = free_bytes;
        }
        ssize_t n = recv(connection->client_fd, buffer, capacity, 0);
        if (n > 0) {
            add_bytes(&connection->server->bytes_from_clients, (size_t)n);
            connection->last_activity_ms = monotonic_ms();
            if (!connection->handshake_done) {
                memcpy(connection->handshake + connection->handshake_len,
                       buffer, (size_t)n);
                connection->handshake_len += (size_t)n;
                if (connection->handshake_len == sizeof(connection->handshake) &&
                    route_after_handshake(connection) != 0)
                    return -1;
                if (connection->route_dns_pending) return 0;
            } else if (connection->route_racing) {
                if (queue_append(&connection->to_upstream, buffer,
                                 (size_t)n) != 0)
                    return -1;
                for (size_t i = 0; i < 2; ++i) {
                    proxy_connection *candidate = connection->hedges[i];
                    if (!candidate || candidate->wss_phase != WSS_READY)
                        continue;
                    int flush_rc = hedge_candidate_flush_buffered_payload(candidate);
                    int watch_rc = flush_rc == 0
                        ? watch_update(connection->server,
                                       &candidate->upstream_watch,
                                       upstream_events(candidate)) : 0;
                    if (flush_rc != 0 || watch_rc != 0) {
                        hedge_fail_candidate(candidate);
                        if (connection->closed) return -1;
                    }
                }
            } else if (process_client_payload(connection, buffer,
                                              (size_t)n) != 0) {
                return -1;
            }
            continue;
        }
        if (n == 0) {
            if (!connection->handshake_done) return -1;
            if (connection->direct_wss &&
                connection->wss_phase != WSS_READY) {
                clear_route_attempt(connection, 0);
                if (start_next_route(connection) != 0) return -1;
            }
            connection->client_eof = 1;
            advance_half_closes(connection);
            return 0;
        }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return -1;
    }
}

static int receive_upstream(proxy_connection *connection) {
    uint8_t buffer[TG_EPOLL_IO_CHUNK];
    for (;;) {
        size_t free_bytes = connection->to_client.cap - connection->to_client.len;
        if (!free_bytes) return 0;
        size_t capacity = free_bytes < sizeof(buffer) ? free_bytes : sizeof(buffer);
        ssize_t n = recv(connection->upstream_fd, buffer, capacity, 0);
        if (n > 0) {
            add_bytes(&connection->server->bytes_from_upstreams, (size_t)n);
            connection->last_activity_ms = monotonic_ms();
            if (queue_append(&connection->to_client, buffer, (size_t)n) != 0)
                return -1;
            continue;
        }
        if (n == 0) {
            connection->upstream_eof = 1;
            advance_half_closes(connection);
            return 0;
        }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return -1;
    }
}

static int socket_error(int fd) {
    int error = 0;
    socklen_t length = sizeof(error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) != 0) return errno;
    return error;
}

static int queue_wss_packet(void *opaque, const uint8_t *packet,
                            size_t packet_len) {
    proxy_connection *connection = opaque;
    return tg_ws_pump_queue_binary(&connection->ws_pump, packet, packet_len);
}

static int process_client_payload(proxy_connection *connection,
                                  uint8_t *buffer, size_t length) {
    if (connection->direct_wss) {
        if (connection->packet_framing) {
            if (tg_mtproto_ctr_xor(&connection->client_decrypt, buffer,
                                   length) != 0 ||
                tg_mtproto_splitter_feed(&connection->splitter,
                                         &connection->client_encrypt,
                                         buffer, length, queue_wss_packet,
                                         connection) != TG_MTPROTO_SPLIT_OK)
                return -1;
            return 0;
        }
        return tg_ws_pump_queue_binary(&connection->ws_pump, buffer, length);
    }
    return queue_append(&connection->to_upstream, buffer, length);
}

static int hedge_flush_buffered_payload(proxy_connection *connection) {
    uint8_t buffer[TG_EPOLL_IO_CHUNK];
    while (connection->to_upstream.len) {
        size_t length = connection->to_upstream.len;
        if (length > sizeof(buffer)) length = sizeof(buffer);
        memcpy(buffer, connection->to_upstream.data +
                        connection->to_upstream.head, length);
        connection->to_upstream.head += length;
        connection->to_upstream.len -= length;
        if (!connection->to_upstream.len) connection->to_upstream.head = 0;
        if (process_client_payload(connection, buffer, length) != 0) return -1;
    }
    return 0;
}

static int hedge_candidate_flush_buffered_payload(
    proxy_connection *candidate) {
    proxy_connection *parent = candidate ? candidate->hedge_parent : NULL;
    uint8_t buffer[TG_EPOLL_IO_CHUNK];
    if (!parent || candidate->wss_phase != WSS_READY ||
        candidate->hedge_payload_offset > parent->to_upstream.len)
        return -1;
    while (candidate->hedge_payload_offset < parent->to_upstream.len) {
        size_t length = parent->to_upstream.len -
                        candidate->hedge_payload_offset;
        if (length > sizeof(buffer)) length = sizeof(buffer);
        memcpy(buffer, parent->to_upstream.data + parent->to_upstream.head +
                        candidate->hedge_payload_offset, length);
        if (process_client_payload(candidate, buffer, length) != 0) return -1;
        candidate->hedge_payload_offset += length;
    }
    return 0;
}

static int response_packet_valid(const proxy_connection *connection) {
    if (connection->response_packet_padded &&
        connection->response_packet_len >= 8u &&
        connection->response_packet_len <= 16u &&
        connection->response_prefix_len >= 8u &&
        read_le32(connection->response_prefix) == UINT32_MAX)
        return 2;
    if (connection->response_prefix_len < 20) return 0;
    if (read_le64(connection->response_prefix) == 0) {
        if (connection->response_prefix_len < 20 ||
            connection->response_packet_len < 24)
            return 0;
        uint64_t message_id = read_le64(connection->response_prefix + 8);
        uint32_t message_len = read_le32(connection->response_prefix + 16);
        if (!message_id || (message_id >> 63) || (message_id & 3u) != 1u ||
            message_len < 4 ||
            (size_t)message_len > connection->response_packet_len - 20u)
            return 0;
        size_t padding = connection->response_packet_len - 20u - message_len;
        return connection->response_packet_padded ? padding <= 15u
                                                  : padding == 0;
    }
    if (connection->response_prefix_len < 40 ||
        connection->response_packet_len < 40)
        return 0;
    size_t encrypted_len = connection->response_packet_len - 24u;
    return connection->response_packet_padded || (encrypted_len & 15u) == 0;
}

static int observe_mtproto_response(proxy_connection *connection,
                                    const uint8_t *payload,
                                    size_t payload_len) {
    uint8_t decoded[TG_EPOLL_IO_CHUNK];
    size_t offset = 0;
    int response_seen = 0;
    int result = -1;
    if (!connection || !connection->server_decrypt.ctx ||
        (payload_len && !payload))
        goto cleanup;
    while (offset < payload_len) {
        if (!connection->response_packet_len) {
            if (connection->response_header_needed == 0) {
                uint8_t byte = payload[offset++];
                if (tg_mtproto_ctr_xor(&connection->server_decrypt,
                                       &byte, 1) != 0)
                    goto cleanup;
                connection->response_header[0] = byte;
                connection->response_header_len = 1;
                connection->response_header_ack = 0;
                if (connection->wss_proto == TG_MTPROTO_ABRIDGED &&
                    (byte & 0x80u)) {
                    connection->response_header_ack = 1;
                    connection->response_header_needed = 4u;
                } else {
                    connection->response_header_needed =
                        connection->wss_proto == TG_MTPROTO_ABRIDGED &&
                        byte == 0x7fu ? 4u : 1u;
                }
            }
            while (connection->response_header_len <
                       connection->response_header_needed &&
                   offset < payload_len) {
                uint8_t byte = payload[offset++];
                if (tg_mtproto_ctr_xor(&connection->server_decrypt,
                                       &byte, 1) != 0)
                    goto cleanup;
                connection->response_header[
                    connection->response_header_len++] = byte;
            }
            if (connection->response_header_len <
                connection->response_header_needed)
                break;
            if (connection->response_header_ack) {
                connection->response_header_len = 0;
                connection->response_header_needed = 0;
                connection->response_header_ack = 0;
                continue;
            }
            uint32_t packet_len;
            connection->response_packet_padded = 0;
            if (connection->wss_proto == TG_MTPROTO_ABRIDGED) {
                uint32_t words = connection->response_header_needed == 1
                    ? connection->response_header[0]
                    : (uint32_t)connection->response_header[1] |
                      ((uint32_t)connection->response_header[2] << 8) |
                      ((uint32_t)connection->response_header[3] << 16);
                if (!words || words > TG_MTPROTO_MAX_PACKET / 4u) goto cleanup;
                packet_len = words * 4u;
            } else {
                uint32_t raw_len = read_le32(connection->response_header);
                if (connection->wss_proto == TG_MTPROTO_INTERMEDIATE &&
                    (raw_len & UINT32_C(0x80000000))) {
                    connection->response_header_len = 0;
                    connection->response_header_needed = 4u;
                    continue;
                }
                connection->response_packet_padded =
                    connection->wss_proto == TG_MTPROTO_PADDED_INTERMEDIATE;
                packet_len = raw_len & UINT32_C(0x7fffffff);
                if (packet_len < 8u ||
                    packet_len > TG_MTPROTO_MAX_PACKET)
                    goto cleanup;
            }
            connection->response_packet_len = packet_len;
            connection->response_packet_seen = 0;
            connection->response_prefix_len = 0;
        }
        size_t remaining = connection->response_packet_len -
                           connection->response_packet_seen;
        size_t amount = payload_len - offset;
        if (amount > sizeof(decoded)) amount = sizeof(decoded);
        if (amount > remaining) amount = remaining;
        memcpy(decoded, payload + offset, amount);
        if (tg_mtproto_ctr_xor(&connection->server_decrypt, decoded,
                               amount) != 0)
            goto cleanup;
        size_t prefix_space = sizeof(connection->response_prefix) -
                              connection->response_prefix_len;
        size_t prefix_copy = amount < prefix_space ? amount : prefix_space;
        if (prefix_copy) {
            memcpy(connection->response_prefix +
                       connection->response_prefix_len,
                   decoded, prefix_copy);
            connection->response_prefix_len += prefix_copy;
        }
        connection->response_packet_seen += amount;
        offset += amount;
        if (connection->response_packet_seen ==
            connection->response_packet_len) {
            int packet_status = response_packet_valid(connection);
            if (packet_status <= 0) goto cleanup;
            if (packet_status == 1) response_seen = 1;
            connection->response_packet_len = 0;
            connection->response_packet_seen = 0;
            connection->response_prefix_len = 0;
            connection->response_header_len = 0;
            connection->response_header_needed =
                connection->wss_proto == TG_MTPROTO_ABRIDGED ? 0u : 4u;
            connection->response_header_ack = 0;
        }
    }
    result = response_seen;
cleanup:
    OPENSSL_cleanse(decoded, sizeof(decoded));
    return result;
}

static int queue_wss_response(void *opaque, const uint8_t *payload,
                              size_t payload_len) {
    proxy_connection *connection = opaque;
    int response = observe_mtproto_response(connection, payload, payload_len);
    if (response < 0) return -1;
    if (response > 0 && !connection->route_response_seen) {
        connection->route_response_seen = 1;
        route_session_first_response(connection);
        if (connection->route_health_index >= 0) {
            route_health *health = &connection->server->route_health[
                (size_t)connection->route_health_index];
            uint64_t now = monotonic_ms();
            health->cooldown_until_ms = 0;
            health->last_success_ms = now;
            health->latency_ms = now >= connection->route_started_ms
                ? now - connection->route_started_ms : 0;
            if (now >= connection->server->last_success_ms) {
                connection->server->last_success_ms = now;
                connection->server->last_success_dc = health->dc_id;
                connection->server->last_success_route =
                    (uint32_t)health->kind;
                connection->server->last_success_latency_ms =
                    health->latency_ms;
            }
            if (health->responses != UINT64_MAX) ++health->responses;
            if ((health->kind == TG_ROUTE_CF_WORKER ||
                 health->kind == TG_ROUTE_CF_PROXY) &&
                health->cf_responses != UINT64_MAX)
                ++health->cf_responses;
        }
    }
    if (queue_append_grow(&connection->to_client, payload, payload_len,
                          TG_MTPROTO_MAX_PACKET) != 0)
        return -1;
    add_bytes(&connection->server->bytes_from_upstreams, payload_len);
    connection->last_activity_ms = monotonic_ms();
    return 0;
}

static int establish_wss_stream(proxy_connection *connection) {
    if (connection->wss_proto < TG_MTPROTO_ABRIDGED ||
        connection->wss_proto > TG_MTPROTO_PADDED_INTERMEDIATE ||
        tg_mtproto_direct_server_stream_cipher(connection->handshake,
                                                &connection->server_decrypt) != 0)
        return -1;
    connection->response_header_needed =
        connection->wss_proto == TG_MTPROTO_ABRIDGED ? 0u : 4u;
    if (tg_ws_pump_init(&connection->ws_pump, connection->upstream_ssl) != 0)
        return -1;
    connection->ws_pump_ready = 1;
    if (connection->packet_framing) {
        if (tg_mtproto_direct_stream_ciphers(connection->handshake,
                                             &connection->client_decrypt,
                                             &connection->client_encrypt) != 0)
            return -1;
        if (tg_mtproto_splitter_init(&connection->splitter,
                                     connection->wss_proto) !=
            TG_MTPROTO_SPLIT_OK)
            return -1;
        connection->splitter_ready = 1;
    }
    if (tg_ws_pump_queue_binary(&connection->ws_pump,
                                connection->handshake,
                                sizeof(connection->handshake)) != 0)
        return -1;
    connection->wss_phase = WSS_READY;
    route_session_event(connection, connection->route_kind,
                        TG_ROUTE_SESSION_CONNECTED);
    if (!connection->hedge_parent)
        route_session_selected(connection, connection->route_kind);
    connection->wss_deadline_ms = 0;
    connection->last_activity_ms = monotonic_ms();
    return 0;
}

static int set_tls_want(proxy_connection *connection, int result) {
    int error = SSL_get_error(connection->upstream_ssl, result);
    if (error == SSL_ERROR_WANT_READ) {
        connection->tls_want = EPOLLIN;
        return 0;
    }
    if (error == SSL_ERROR_WANT_WRITE) {
        connection->tls_want = EPOLLOUT;
        return 0;
    }
    return -1;
}

static int progress_wss(proxy_connection *connection, uint32_t events) {
    for (size_t step = 0;
         step < TG_WS_UPGRADE_MAX_HEADER + sizeof(connection->ws_upgrade.request);
         ++step) {
        if (connection->wss_phase == WSS_TLS) {
            if (!(events & connection->tls_want)) return 0;
            int rc = SSL_do_handshake(connection->upstream_ssl);
            if (rc != 1) return set_tls_want(connection, rc);
            if (SSL_get_verify_result(connection->upstream_ssl) != X509_V_OK ||
                tg_ws_upgrade_start_ex(&connection->ws_upgrade,
                    connection->tls_hostname, connection->wss_path,
                    connection->wss_subprotocol ? "binary" : NULL,
                    "https://web.telegram.org",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/131.0.0.0 Safari/537.36") != 0)
                return -1;
            connection->wss_phase = WSS_UPGRADE_WRITE;
            connection->tls_want = EPOLLOUT;
            continue;
        }
        if (connection->wss_phase == WSS_UPGRADE_WRITE) {
            if (!(events & connection->tls_want)) return 0;
            size_t pending_len = 0, written = 0;
            const uint8_t *pending = tg_ws_upgrade_pending(
                &connection->ws_upgrade, &pending_len);
            if (!pending || pending_len == 0) {
                connection->wss_phase = WSS_UPGRADE_READ;
                connection->tls_want = EPOLLIN;
                continue;
            }
            int rc = SSL_write_ex(connection->upstream_ssl, pending,
                                  pending_len, &written);
            if (rc != 1) return set_tls_want(connection, rc);
            if (!written || tg_ws_upgrade_advance(&connection->ws_upgrade,
                                                  written) != 0)
                return -1;
            continue;
        }
        if (connection->wss_phase == WSS_UPGRADE_READ) {
            if (!(events & connection->tls_want)) return 0;
            uint8_t byte;
            size_t received = 0, consumed = 0;
            int rc = SSL_read_ex(connection->upstream_ssl, &byte, 1, &received);
            if (rc != 1) {
                if (SSL_get_error(connection->upstream_ssl, rc) ==
                    SSL_ERROR_ZERO_RETURN)
                    return -1;
                return set_tls_want(connection, rc);
            }
            if (received != 1) return -1;
            rc = tg_ws_upgrade_feed(&connection->ws_upgrade, &byte, 1,
                                    &consumed);
            if (rc < 0 || consumed != 1) {
                return -1;
            }
            if (rc == 1) {
                if (establish_wss_stream(connection) != 0) return -1;
                if (connection->hedge_parent) {
                    if (hedge_candidate_flush_buffered_payload(connection) != 0) {
                        return -1;
                    }
                } else if (hedge_flush_buffered_payload(connection) != 0) {
                    return -1;
                }
                continue;
            }
            if (SSL_pending(connection->upstream_ssl) > 0 ||
                SSL_has_pending(connection->upstream_ssl))
                continue;
            connection->tls_want = EPOLLIN;
            return 0;
        }
        if (connection->wss_phase == WSS_READY) {
            short revents = 0;
            if (events & EPOLLIN) revents |= POLLIN;
            if (events & EPOLLOUT) revents |= POLLOUT;
            if (events & EPOLLERR) revents |= POLLERR;
            if (events & (EPOLLHUP | EPOLLRDHUP)) revents |= POLLHUP;
            int pump_rc = tg_ws_pump_process(&connection->ws_pump, revents,
                                             queue_wss_response, connection);
            if (pump_rc != 0) {
                return -1;
            }
            if (connection->hedge_parent && connection->route_response_seen) {
                if (connection->ws_pump.closed)
                    connection->upstream_eof = 1;
                return hedge_promote_candidate(connection);
            }
            if (connection->ws_pump.closed) {
                if (connection->hedge_parent) {
                    hedge_fail_candidate(connection);
                    return 0;
                }
                if (!connection->route_response_seen)
                    route_health_failed(connection);
                connection->upstream_eof = 1;
                advance_half_closes(connection);
            }
            return 0;
        }
        return -1;
    }
    return 0;
}

static void handle_pending_dns_client_event(proxy_connection *connection,
                                           uint32_t events) {
    if (!connection || connection->closed || !connection->route_dns_pending)
        return;
    if (events & (EPOLLERR | EPOLLHUP)) {
        connection_close(connection);
        return;
    }
    if ((events & EPOLLRDHUP) && !connection->route_dns_peer_fin) {
        uint8_t byte;
        ssize_t n = recv(connection->client_fd, &byte, sizeof(byte),
                         MSG_PEEK | MSG_DONTWAIT);
        if (n == 0) {
            connection_close(connection);
            return;
        }
        if (n > 0) {
            connection->route_dns_peer_fin = 1;
        } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            connection_close(connection);
            return;
        }
    }
    connection_update(connection);
}

static void client_event(proxy_connection *connection, uint32_t events) {
    if (!connection || connection->closed) return;
    if ((events & EPOLLERR) && socket_error(connection->client_fd)) {
        connection_close(connection);
        return;
    }
    if (connection->route_dns_pending) {
        handle_pending_dns_client_event(connection, events);
        return;
    }
    if (events & (EPOLLIN | EPOLLRDHUP | EPOLLHUP)) {
        if (receive_client(connection) != 0) {
            connection_close(connection);
            return;
        }
    }
    if (connection->closed) return;
    if (connection->route_dns_pending) {
        handle_pending_dns_client_event(connection, events);
        return;
    }
    if ((events & EPOLLOUT) &&
        queue_flush(connection->client_fd, &connection->to_client,
                    &connection->last_activity_ms) != 0) {
        connection_close(connection);
        return;
    }
    advance_half_closes(connection);
    connection_update(connection);
}

static void upstream_event(proxy_connection *connection, uint32_t events) {
    if (!connection || connection->closed) return;
    if (connection->connecting &&
        (events & (EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLRDHUP))) {
        int error = socket_error(connection->upstream_fd);
        if (error) {
            if (connection->hedge_parent) {
                hedge_fail_candidate(connection);
                return;
            }
            if (connection->direct_wss &&
                advance_route(connection) == 0) {
                connection_update(connection);
                return;
            }
            if (!connection->direct_wss)
                route_session_event(connection, connection->route_kind,
                                    TG_ROUTE_SESSION_FAILED);
            connection_close(connection);
            return;
        }
        connection->connecting = 0;
        if (!connection->direct_wss)
            route_session_event(connection, connection->route_kind,
                                TG_ROUTE_SESSION_CONNECTED);
        if (connection->direct_wss && prepare_wss_tls(connection) != 0) {
            if (connection->hedge_parent) {
                hedge_fail_candidate(connection);
                return;
            }
            if (advance_route(connection) == 0) {
                connection_update(connection);
                return;
            }
            connection_close(connection);
            return;
        }
    }
    if (connection->direct_wss) {
        int failed = (events & EPOLLERR) &&
                     socket_error(connection->upstream_fd) != 0;
        if ((events & (EPOLLHUP | EPOLLRDHUP)) &&
            connection->wss_phase != WSS_READY)
            failed = 1;
        if (!failed && progress_wss(connection, events) != 0) failed = 1;
        if (failed) {
            if (connection->hedge_parent) {
                hedge_fail_candidate(connection);
                return;
            }
            if (connection->wss_phase != WSS_READY &&
                advance_route(connection) == 0) {
                connection_update(connection);
                return;
            }
            if (connection->wss_phase == WSS_READY &&
                !connection->route_response_seen)
                route_health_failed(connection);
            connection_close(connection);
            return;
        }
        if (connection->closed) return;
        advance_half_closes(connection);
        connection_update(connection);
        return;
    }
    if ((events & EPOLLERR) && socket_error(connection->upstream_fd)) {
        route_session_event(connection, connection->route_kind,
                            TG_ROUTE_SESSION_FAILED);
        connection_close(connection);
        return;
    }
    if (!connection->connecting && (events & (EPOLLIN | EPOLLRDHUP | EPOLLHUP))) {
        if (receive_upstream(connection) != 0) {
            connection_close(connection);
            return;
        }
    }
    if (connection->closed) return;
    if (!connection->connecting && (events & EPOLLOUT) &&
        queue_flush(connection->upstream_fd, &connection->to_upstream,
                    &connection->last_activity_ms) != 0) {
        route_session_event(connection, connection->route_kind,
                            TG_ROUTE_SESSION_FAILED);
        connection_close(connection);
        return;
    }
    if (!connection->connecting && !connection->direct_wss &&
        connection->to_upstream.len == 0 &&
        connection->route_kind == TG_ROUTE_DIRECT_TCP &&
        connection->route_session_tracked) {
        proxy_connection *owner = route_session_owner(connection);
        uint8_t transport = route_session_transport_for(connection,
            connection->route_kind);
        uint8_t branch = transport ==
            TG_ROUTE_SESSION_TRANSPORT_TCP_PASSTHROUGH ? 0u : 1u;
        uint8_t state = branch ? owner->route_session.fallback_state
                               : owner->route_session.direct_state;
        if (state == TG_ROUTE_SESSION_CONNECTED)
            route_session_selected(connection, connection->route_kind);
    }
    advance_half_closes(connection);
    connection_update(connection);
}

static void accept_clients(tg_epoll_proxy *server) {
    for (;;) {
        int fd = accept4(server->listener_fd, NULL, NULL,
                         SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EINTR) continue;
            return;
        }
        if (server->active_connections >= server->max_connections) {
            close(fd);
            continue;
        }
        tg_listener_destination original;
        memset(&original, 0, sizeof(original));
        if (server->config.original_destination(server->config.context, fd,
                                                &original) != 0 ||
            !original.port ||
            (server->config.enforce_self_dial &&
             tg_listener_is_self_dial_addr(&original, server->listen_ports,
                                           server->config.listen_port_count))) {
            close(fd);
            continue;
        }
        proxy_connection *connection = calloc(1, sizeof(*connection));
        if (!connection) {
            close(fd);
            continue;
        }
        connection->to_upstream.data = malloc(server->config.queue_bytes);
        connection->to_client.data = malloc(server->config.queue_bytes);
        if (!connection->to_upstream.data || !connection->to_client.data) {
            close(fd);
            free(connection->to_upstream.data);
            free(connection->to_client.data);
            free(connection);
            continue;
        }
        connection->server = server;
        connection->client_fd = fd;
        connection->upstream_fd = -1;
        connection->route_health_index = -1;
        connection->original = original;
        connection->to_upstream.cap = server->config.queue_bytes;
        connection->to_client.cap = server->config.queue_bytes;
        connection->handshake_deadline_ms = monotonic_ms() +
                                            server->config.handshake_timeout_ms;
        connection->last_activity_ms = monotonic_ms();
        connection->client_watch = (socket_watch){
            .kind = 1, .connection = connection, .side = 0, .fd = fd
        };
        connection->next = server->connections;
        server->connections = connection;
        ++server->active_connections;
        if (server->connections_started != UINT64_MAX)
            ++server->connections_started;
        if (server->tracked_sessions < TG_EPOLL_MAX_ACTIVE_ROUTE_SESSIONS) {
            connection->route_session_tracked = 1;
            connection->route_session.id = server->connections_started;
            connection->route_session.stage = TG_ROUTE_SESSION_STAGE_ACCEPTED;
            connection->route_session.direct_state = TG_ROUTE_SESSION_IDLE;
            connection->route_session.fallback_state = TG_ROUTE_SESSION_IDLE;
            connection->route_session.next_event_sequence = 1;
            ++server->tracked_sessions;
        }
        if (watch_update(server, &connection->client_watch,
                         client_events(connection)) != 0)
            connection_close(connection);
    }
}

static int timeout_until_expiry(tg_epoll_proxy *server, int timeout_ms) {
    uint64_t now = monotonic_ms(), nearest = UINT64_MAX;
    for (proxy_connection *connection = server->connections; connection;
         connection = connection->next) {
        uint64_t expires = connection->route_dns_pending
            ? connection->route_dns_retry_at_ms
            : connection->direct_wss && connection->wss_phase != WSS_READY
                ? connection->wss_deadline_ms
                : connection->handshake_done
                    ? connection->last_activity_ms +
                      server->config.idle_timeout_ms
                    : connection->handshake_deadline_ms;
        if (connection->route_dns_pending &&
            connection->route_dns_deadline_ms < expires)
            expires = connection->route_dns_deadline_ms;
        if (expires < nearest) nearest = expires;
        if (connection->hedge_due_ms && connection->hedge_due_ms < nearest)
            nearest = connection->hedge_due_ms;
        for (size_t i = 0; i < 2; ++i) {
            const proxy_connection *candidate = connection->hedges[i];
            if (candidate) {
                uint64_t expires = candidate->wss_phase != WSS_READY
                    ? candidate->wss_deadline_ms
                    : candidate->last_activity_ms +
                      server->config.idle_timeout_ms;
                if (expires < nearest) nearest = expires;
            }
        }
    }
    if (nearest == UINT64_MAX) return timeout_ms;
    uint64_t remaining = nearest > now ? nearest - now : 0;
    if (timeout_ms < 0 || remaining < (uint64_t)timeout_ms)
        return remaining > INT32_MAX ? INT32_MAX : (int)remaining;
    return timeout_ms;
}

static void expire_connections(tg_epoll_proxy *server) {
    uint64_t now = monotonic_ms();
    proxy_connection *connection = server->connections;
    while (connection) {
        proxy_connection *next = connection->next;
        for (size_t i = 0; i < 2 && !connection->closed; ++i) {
            proxy_connection *candidate = connection->hedges[i];
            if (candidate) {
                uint64_t expires = candidate->wss_phase != WSS_READY
                    ? candidate->wss_deadline_ms
                    : candidate->last_activity_ms +
                      server->config.idle_timeout_ms;
                if (now >= expires) {
                    hedge_fail_candidate(candidate);
                    break;
                }
            }
        }
        if (!connection->closed && connection->route_racing &&
            connection->hedge_due_ms && now >= connection->hedge_due_ms) {
            connection->hedge_due_ms = 0;
            if (hedge_fill(connection, 1) != 0)
                connection_close(connection);
        }
        if (connection->closed) {
            connection = next;
            continue;
        }
        if (connection->route_dns_pending) {
            if (now >= connection->route_dns_deadline_ms) {
                connection->route_dns_pending = 0;
                connection->route_dns_retry_at_ms = 0;
                connection->route_dns_event_active = 0;
                connection->route_index =
                    connection->route_dns_step_index + 1u;
                route_session_event(connection, connection->route_kind,
                                    TG_ROUTE_SESSION_FAILED);
            } else if (now >= connection->route_dns_retry_at_ms) {
                connection->route_dns_pending = 0;
                connection->route_dns_retry_at_ms = 0;
                connection->route_index = connection->route_dns_step_index;
            } else {
                connection = next;
                continue;
            }
            if (start_next_route(connection) == 0)
                connection_update(connection);
            else
                connection_close(connection);
            connection = next;
            continue;
        }
        int expired = connection->direct_wss &&
                      connection->wss_phase != WSS_READY
            ? now >= connection->wss_deadline_ms
            : connection->handshake_done
                ? now >= connection->last_activity_ms + server->config.idle_timeout_ms
                : now >= connection->handshake_deadline_ms;
        if (expired && connection->direct_wss &&
            connection->wss_phase != WSS_READY &&
            advance_route(connection) == 0) {
            connection_update(connection);
        } else if (expired) {
            if (connection->direct_wss && !connection->route_response_seen)
                route_health_failed(connection);
            connection_close(connection);
        }
        connection = next;
    }
}

tg_epoll_proxy *tg_epoll_proxy_create(const tg_epoll_proxy_config *config) {
    if (!config || config->listener_fd < 0 ||
        (!config->select_target && !config->select_route) ||
        config->queue_bytes < 1024 || config->queue_bytes > 1024u * 1024u ||
        !config->memory_budget_bytes || !config->configured_max_connections ||
        !config->handshake_timeout_ms || !config->idle_timeout_ms ||
        config->listen_port_count > TG_EPOLL_MAX_LISTEN_PORTS ||
        (config->listen_port_count && !config->listen_ports) ||
        (config->require_socket_mark && !config->socket_mark) ||
        (config->enable_direct_wss && !config->tls_context)) {
        errno = EINVAL;
        return NULL;
    }
    size_t per_connection = sizeof(proxy_connection);
    if (config->queue_bytes > (SIZE_MAX - per_connection) / 2) {
        errno = EOVERFLOW;
        return NULL;
    }
    per_connection += config->queue_bytes * 2;
    size_t max_connections = tg_limits_auto_max_connections(
        tg_limits_soft_nofile(), config->memory_budget_bytes, per_connection,
        0, config->configured_max_connections);
    if (!max_connections) {
        errno = ENOMEM;
        return NULL;
    }
    tg_epoll_proxy *server = calloc(1, sizeof(*server));
    if (!server) return NULL;
    server->epoll_fd = -1;
    server->listener_fd = config->listener_fd;
    server->config = *config;
    server->max_connections = max_connections;
    time_t started = time(NULL);
    server->process_started_at = started > 0 ? (uint64_t)started : 0;
    if (config->enable_direct_wss) {
        size_t base_reservation;
        /* Буфер сборки фрагментированного WebSocket-сообщения. */
        size_t wss_extra = 4u * (size_t)TG_MTPROTO_MAX_PACKET +
                          TG_WS_MAX_MESSAGE;
        if (max_connections > SIZE_MAX / per_connection) {
            free(server);
            errno = EOVERFLOW;
            return NULL;
        }
        base_reservation = max_connections * per_connection;
        if (base_reservation < config->memory_budget_bytes && wss_extra) {
            server->max_wss_connections =
                (config->memory_budget_bytes - base_reservation) / wss_extra;
            if (server->max_wss_connections > max_connections)
                server->max_wss_connections = max_connections;
        }
    }
    if (config->listen_port_count)
        memcpy(server->listen_ports, config->listen_ports,
               config->listen_port_count * sizeof(server->listen_ports[0]));
    if (!server->config.original_destination)
        server->config.original_destination = default_original_destination;
    if (config->enable_direct_wss && !config->resolve_domain &&
        (route_worker_count(server) || route_cf_domain_count(server))) {
        server->route_dns = tg_route_dns_create(config->tls_context,
                                                 config->socket_mark,
                                                 config->cf_domain_pool,
                                                 NULL, NULL);
        if (server->route_dns) {
            for (size_t i = 0; i < route_worker_count(server); ++i)
                (void)tg_route_dns_prefetch(server->route_dns,
                                            route_worker_domain(server, i));
            if (config->cf_domain_pool)
                tg_route_dns_prefetch_cf_pool(server->route_dns,
                                               config->cf_domain_pool);
        }
    }
    if (set_nonblocking(server->listener_fd) != 0) goto fail;
    server->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (server->epoll_fd < 0) goto fail;
    server->listener_watch = (socket_watch){
        .kind = 0, .fd = server->listener_fd
    };
    if (watch_update(server, &server->listener_watch, EPOLLIN) != 0) goto fail;
    return server;
fail:
    if (server->epoll_fd >= 0) close(server->epoll_fd);
    tg_route_dns_destroy(server->route_dns);
    free(server);
    return NULL;
}

int tg_epoll_proxy_step(tg_epoll_proxy *server, int timeout_ms) {
    if (!server || timeout_ms < -1) {
        errno = EINVAL;
        return -1;
    }
    struct epoll_event events[TG_EPOLL_MAX_EVENTS];
    int count = epoll_wait(server->epoll_fd, events, TG_EPOLL_MAX_EVENTS,
                           timeout_until_expiry(server, timeout_ms));
    if (count < 0 && errno != EINTR) return -1;
    if (count > 0) {
        for (int i = 0; i < count; ++i) {
            socket_watch *watch = events[i].data.ptr;
            if (!watch) continue;
            if (watch->kind == 0) {
                accept_clients(server);
            } else if (watch->connection && watch->side == 0) {
                client_event(watch->connection, events[i].events);
            } else if (watch->connection) {
                upstream_event(watch->connection, events[i].events);
            }
        }
    }
    expire_connections(server);
    collect_retired(server);
    return count < 0 ? 0 : count;
}

void tg_epoll_proxy_destroy(tg_epoll_proxy *server) {
    if (!server) return;
    while (server->connections) connection_close(server->connections);
    collect_retired(server);
    if (server->epoll_fd >= 0) close(server->epoll_fd);
    tg_route_dns_destroy(server->route_dns);
    free(server);
}

size_t tg_epoll_proxy_active_connections(const tg_epoll_proxy *server) {
    return server ? server->active_connections : 0;
}

size_t tg_epoll_proxy_max_connections(const tg_epoll_proxy *server) {
    return server ? server->max_connections : 0;
}

int tg_epoll_proxy_get_stats(const tg_epoll_proxy *server,
                             tg_epoll_proxy_stats *out) {
    if (!server || !out) {
        errno = EINVAL;
        return -1;
    }
    memset(out, 0, sizeof(*out));
    out->active_connections = server->active_connections;
    out->process_started_at = server->process_started_at;
    out->accepted_connections = server->connections_started;
    for (const proxy_connection *connection = server->connections; connection;
         connection = connection->next) {
        if (!connection->route_session_tracked ||
            out->active_sessions_count >= TG_EPOLL_MAX_ACTIVE_ROUTE_SESSIONS)
            continue;
        size_t at = out->active_sessions_count++;
        out->active_sessions[at] = connection->route_session;
    }
    for (size_t i = 1; i < out->active_sessions_count; ++i) {
        tg_active_route_session value = out->active_sessions[i];
        size_t j = i;
        while (j && out->active_sessions[j - 1].id > value.id) {
            out->active_sessions[j] = out->active_sessions[j - 1];
            --j;
        }
        out->active_sessions[j] = value;
    }
    out->route_sessions_truncated =
        server->active_connections > out->active_sessions_count;
    out->max_connections = server->max_connections;
    out->connections_started = server->connections_started;
    out->bytes_from_clients = server->bytes_from_clients;
    out->bytes_from_upstreams = server->bytes_from_upstreams;
    out->wss_attempts = out->wss_failures = out->wss_responses =
        out->cf_wss_responses = 0;
    out->last_success_dc = server->last_success_dc;
    out->last_success_route = server->last_success_route;
    out->last_success_latency_ms = server->last_success_latency_ms;
    uint64_t now = monotonic_ms();
    out->last_success_age_ms = server->last_success_ms &&
        now >= server->last_success_ms ? now - server->last_success_ms : 0;
    out->last_failure_dc = server->last_failure_dc;
    out->last_failure_route = server->last_failure_route;
    out->last_failure_stage = server->last_failure_stage;
    out->last_failure_age_ms = server->last_failure_ms &&
        now >= server->last_failure_ms ? now - server->last_failure_ms : 0;
    for (size_t i = 0; i < TG_ROUTE_HEALTH_MAX; ++i) {
        const route_health *health = &server->route_health[i];
        if (!health->used) continue;
        add_u64(&out->wss_attempts, health->attempts);
        add_u64(&out->wss_failures, health->failures);
        add_u64(&out->wss_responses, health->responses);
        add_u64(&out->cf_wss_responses, health->cf_responses);
    }
    return 0;
}

#else

struct tg_epoll_proxy { int unavailable; };

tg_epoll_proxy *tg_epoll_proxy_create(const tg_epoll_proxy_config *config) {
    (void)config;
    errno = ENOTSUP;
    return NULL;
}
int tg_epoll_proxy_step(tg_epoll_proxy *server, int timeout_ms) {
    (void)server;
    (void)timeout_ms;
    errno = ENOTSUP;
    return -1;
}
void tg_epoll_proxy_destroy(tg_epoll_proxy *server) { free(server); }
size_t tg_epoll_proxy_active_connections(const tg_epoll_proxy *server) {
    (void)server;
    return 0;
}
size_t tg_epoll_proxy_max_connections(const tg_epoll_proxy *server) {
    (void)server;
    return 0;
}
int tg_epoll_proxy_get_stats(const tg_epoll_proxy *server,
                             tg_epoll_proxy_stats *out) {
    (void)server;
    (void)out;
    errno = ENOTSUP;
    return -1;
}

#endif
