#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "tg_epoll_proxy.h"

#include "tg_limits.h"
#include "tg_route_plan.h"
#include "tg_route_dns.h"
#include "tg_mtproto_splitter.h"
#include "tg_tls.h"
#include "tg_ws.h"
#include "tg_memory_budget.h"

#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
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
#include <netinet/tcp.h>

#define TG_EPOLL_MAX_EVENTS 128
#define TG_EPOLL_IO_CHUNK 16384u
#define TG_EPOLL_MAX_LISTEN_PORTS 16u
#define TG_ROUTE_HEALTH_MAX 256u
#define TG_CLIENT_LATENCY_SAMPLE_COUNT 128u
#define TG_HEDGE_DELAY_DEFAULT_MS 125u
#define TG_HEDGE_CANDIDATES 4u
#define TG_ROUTE_DNS_WAIT_TIMEOUT_MS 20000u
#define TG_ROUTE_DNS_RETRY_MS 50u
#define TG_WS_PING_INTERVAL_MS 30000u
#define TG_EPOLL_RUNTIME_RESERVE_PER_CONNECTION (256u * 1024u)
#ifndef TG_ROUTE_HEALTH_COOLDOWN_MS
#define TG_ROUTE_HEALTH_COOLDOWN_MS 30000u
#endif

#ifdef TG_EPOLL_TESTING
static uint64_t ws_ping_interval_ms = TG_WS_PING_INTERVAL_MS;
void tg_epoll_proxy_test_set_ping_interval_ms(uint64_t interval_ms) {
    ws_ping_interval_ms = interval_ms ? interval_ms : 1u;
}
#else
#define ws_ping_interval_ms TG_WS_PING_INTERVAL_MS
#endif

enum { WSS_NONE, WSS_TLS, WSS_UPGRADE_WRITE, WSS_UPGRADE_READ, WSS_READY };

typedef struct {
    uint8_t *data;
    size_t cap;
    size_t head;
    size_t len;
    size_t dynamic_bytes;
} byte_queue;

typedef struct proxy_connection proxy_connection;

typedef struct {
    tg_route_kind kind;
    uint8_t transport;
    uint32_t dc_id;
    uint16_t upstream_port;
    int is_media;
    char hostname[TG_CF_DOMAIN_LEN];
    tg_listener_destination original;
    uint64_t cooldown_until_ms;
    uint64_t next_probe_ms;
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
    proxy_connection *hedges[TG_HEDGE_CANDIDATES];
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
    int wss_close_queued;
    uint32_t route_dc_id;
    int route_is_media;
    int route_tcp_only;
    int direct_recovery_probe;
    int route_session_tracked;
    int route_failure_recorded;
    uint8_t route_failure_stage;
    tg_active_route_session route_session;
    size_t route_index;
    uint8_t hedge_step_index;
    size_t route_dns_step_index;
    uint64_t route_dns_retry_at_ms;
    uint64_t route_dns_deadline_ms;
    int route_dns_pending;
    int route_dns_peer_fin;
    int route_dns_event_active;
    int route_health_index;
    int route_data_seen;
    int route_response_seen;
    int from_worker_pool;
    int response_observer_disabled;
    int wss_replay_disabled;
    int wss_client_payload_started;
    size_t wss_forwarded_offset;
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
    uint64_t accepted_at_us;
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
    uint64_t next_ping_ms;
    uint64_t wss_read_paused_at_ms;
    uint64_t upstream_connect_deadline_ms;
    tg_listener_destination original;
    tg_listener_destination upstream_target;
    byte_queue to_upstream;
    byte_queue to_client;
};

#define TG_WORKER_5222_SUBPROTOCOL "d2o-tcp-5222-v1"
#define TG_WORKER_POOL_MAX 12u
#define TG_WORKER_POOL_SLOTS 12u
#define TG_WORKER_POOL_MAX_AGE_MS 80000u
#define TG_WORKER_POOL_CONNECT_TIMEOUT_MS 5000u

typedef struct {
    int fd;
    SSL *ssl;
    uint32_t dc_id;
    int is_media;
    uint64_t created_ms;
    char hostname[TG_CF_DOMAIN_LEN];
    char path[512];
} worker_pool_entry;

typedef struct {
    struct tg_epoll_proxy *server;
    pthread_mutex_t lock;
    pthread_cond_t wake;
    pthread_t thread;
    int started;
    int stopping;
    size_t count;
    size_t capacity;
    worker_pool_entry entries[TG_WORKER_POOL_MAX];
    SSL_CTX *tls_context;
    uint32_t socket_mark;
    int require_socket_mark;
    char domain[TG_CF_DOMAIN_LEN];
    uint32_t dcs[TG_WORKER_POOL_SLOTS];
    int media[TG_WORKER_POOL_SLOTS];
    char paths[TG_WORKER_POOL_SLOTS][512];
    uint64_t host_retry_at;
    unsigned host_failures;
    uint64_t retry_at[TG_WORKER_POOL_SLOTS];
    unsigned failures[TG_WORKER_POOL_SLOTS];
    size_t dc_count;
} worker_pool;

typedef struct {
    char domain[TG_CF_DOMAIN_LEN];
    uint64_t until_ms;
    unsigned failures;
} cf_rate_limit;

struct tg_epoll_proxy {
    int epoll_fd;
    int listener_fd;
    socket_watch listener_watch;
    socket_watch stats_watch;
    uint64_t accept_retry_at_ms;
    unsigned accept_errors;
    unsigned accept_rebinds;
    tg_epoll_proxy_config config;
    tg_route_dns *route_dns;
    cf_rate_limit cf_rate_limits[TG_CF_POOL_MAX];
    size_t worker_balance_offset;
    size_t cf_balance_offset;
    worker_pool *worker_pool;
    uint16_t listen_ports[TG_EPOLL_MAX_LISTEN_PORTS];
    size_t max_connections;
    size_t memory_headroom_bytes;
    size_t memory_ceiling_bytes;
    size_t active_connections;
    size_t tracked_sessions;
    size_t max_wss_connections;
    size_t active_wss_connections;
    tg_memory_budget buffer_budget;
    uint64_t connections_started;
    uint64_t accept_limit_rejections;
    uint64_t accept_fd_exhaustion;
    uint64_t allocation_failures;
    uint64_t wss_read_pauses;
    uint64_t wss_read_resumes;
    uint64_t wss_paused_timeouts;
    uint64_t http_403;
    uint64_t http_501;
    uint64_t http_502;
    uint32_t last_http_status;
    uint64_t failure_by_stage[TG_EPOLL_FAILURE_STAGE_COUNT];
    tg_problem_session problem_sessions[TG_EPOLL_MAX_PROBLEM_SESSIONS];
    uint64_t problem_session_total;
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
    uint64_t client_response_latency[TG_CLIENT_LATENCY_SAMPLE_COUNT];
    size_t client_response_latency_count;
    size_t client_response_latency_next;
    uint64_t client_response_latency_total;
    uint64_t worker_pool_hits;
    uint64_t worker_pool_misses;
    uint64_t worker_pool_responses;
    route_health route_health[TG_ROUTE_HEALTH_MAX];
    proxy_connection *connections;
    proxy_connection *retired;
};

static int queue_wss_packet(void *opaque, const uint8_t *packet,
                            size_t packet_len);
static int process_client_payload(proxy_connection *connection,
                                  uint8_t *buffer, size_t length);
static int queue_wss_replay_payload(proxy_connection *connection,
                                    uint8_t *buffer, size_t length);
static void clear_wss_replay(proxy_connection *connection);
static int flush_wss_replay(proxy_connection *connection);
static int hedge_candidate_flush_buffered_payload(
    proxy_connection *candidate);
static void hedge_cancel_candidates(proxy_connection *connection);
static int hedge_promote_candidate(proxy_connection *candidate);
static void advance_half_closes(proxy_connection *connection);
static int progress_wss(proxy_connection *connection, uint32_t events);
static int establish_wss_stream(proxy_connection *connection);

static uint64_t monotonic_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    return (uint64_t)now.tv_sec * 1000u + (uint64_t)now.tv_nsec / 1000000u;
}

static uint64_t monotonic_us(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    return (uint64_t)now.tv_sec * UINT64_C(1000000) +
           (uint64_t)now.tv_nsec / 1000u;
}

static void record_client_response_latency(tg_epoll_proxy *server,
                                          const proxy_connection *connection) {
    if (!server || !connection || !connection->accepted_at_us) return;
    uint64_t now = monotonic_us();
    if (now < connection->accepted_at_us) return;
    server->client_response_latency[server->client_response_latency_next] =
        now - connection->accepted_at_us;
    server->client_response_latency_next =
        (server->client_response_latency_next + 1u) %
        TG_CLIENT_LATENCY_SAMPLE_COUNT;
    if (server->client_response_latency_count <
        TG_CLIENT_LATENCY_SAMPLE_COUNT)
        ++server->client_response_latency_count;
    if (server->client_response_latency_total != UINT64_MAX)
        ++server->client_response_latency_total;
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

static void route_session_add_bytes(proxy_connection *connection,
                                    int from_client, size_t amount) {
    proxy_connection *owner = route_session_owner(connection);
    if (!owner || !owner->route_session_tracked) return;
    if (amount) owner->route_session.no_progress_ms = monotonic_ms();
    uint64_t *total = from_client
        ? &owner->route_session.bytes_from_clients
        : &owner->route_session.bytes_from_upstreams;
    add_bytes(total, amount);
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

static uint8_t route_session_branch(const proxy_connection *connection,
                                    uint8_t transport) {
    if (connection->server->config.cloudflare_only)
        return transport == TG_ROUTE_SESSION_TRANSPORT_CLOUDFLARE_PROXY ? 0u : 1u;
    return transport == TG_ROUTE_SESSION_TRANSPORT_DIRECT_WSS ||
           transport == TG_ROUTE_SESSION_TRANSPORT_TCP_PASSTHROUGH ? 0u : 1u;
}

static void route_session_append(tg_active_route_session *session,
                                 uint8_t branch, uint8_t transport,
                                 uint8_t state, uint8_t failure_stage) {
    if (session->event_count == TG_EPOLL_MAX_ROUTE_EVENTS) {
        memmove(&session->events[0], &session->events[1],
                (TG_EPOLL_MAX_ROUTE_EVENTS - 1u) * sizeof(session->events[0]));
        --session->event_count;
    }
    tg_route_session_event *event = &session->events[session->event_count++];
    event->sequence = session->next_event_sequence++;
    event->timestamp_ms = monotonic_ms();
    event->branch = branch;
    event->transport = transport;
    event->state = state;
    event->failure_stage = failure_stage;
}

static void route_session_event(proxy_connection *connection,
                                tg_route_kind kind, uint8_t state) {
    proxy_connection *owner = route_session_owner(connection);
    if (!owner || !owner->route_session_tracked) return;
    tg_active_route_session *session = &owner->route_session;
    uint8_t transport = route_session_transport_for(connection, kind);
    if (transport == TG_ROUTE_SESSION_TRANSPORT_NONE) return;
    uint8_t branch = route_session_branch(connection, transport);
    session->stage = TG_ROUTE_SESSION_STAGE_ROUTING;
    if (!branch) {
        session->direct_state = state;
        session->direct_transport = transport;
    } else {
        session->fallback_state = state;
        session->fallback_transport = transport;
    }
    route_session_append(session, branch, transport, state,
        state == TG_ROUTE_SESSION_FAILED ? connection->route_failure_stage : 0);
}

static void route_session_selected(proxy_connection *connection,
                                   tg_route_kind kind) {
    proxy_connection *owner = route_session_owner(connection);
    if (!owner || !owner->route_session_tracked) return;
    tg_active_route_session *session = &owner->route_session;
    uint8_t transport = route_session_transport_for(connection, kind);
    if (transport == TG_ROUTE_SESSION_TRANSPORT_NONE) return;
    uint8_t branch = route_session_branch(connection, transport);
    uint8_t *losing_state = branch ? &session->direct_state
                                   : &session->fallback_state;
    uint8_t losing_transport = branch ? session->direct_transport
                                      : session->fallback_transport;
    if (*losing_state == TG_ROUTE_SESSION_CONNECTED && losing_transport) {
        *losing_state = TG_ROUTE_SESSION_CANCELLED;
        route_session_append(session, branch ? 0u : 1u, losing_transport,
                                 TG_ROUTE_SESSION_CANCELLED, 0);
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
    uint64_t now = monotonic_ms();
    if (session->started_ms && now >= session->started_ms)
        session->first_response_latency_ms = now - session->started_ms;
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

static void set_tcp_nodelay(int fd) {
    int enabled = 1;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled));
}

static void set_tcp_quickack(int fd) {
#ifdef TCP_QUICKACK
    int enabled = 1;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &enabled, sizeof(enabled));
#else
    (void)fd;
#endif
}

static int default_original_destination(void *context, int fd,
                                        tg_listener_destination *out) {
    (void)context;
    return tg_listener_get_original_dst_any(fd, out);
}

static uint64_t buffer_failures(const tg_epoll_proxy *server) {
    const tg_memory_budget *budget = &server->buffer_budget;
    return budget->rejections + budget->allocation_failures + budget->size_rejections;
}

static int queue_append_grow(proxy_connection *connection, byte_queue *queue,
                             const uint8_t *data, size_t len,
                             size_t max_capacity) {
    tg_memory_budget *budget = &connection->server->buffer_budget;
    if (queue->len > max_capacity || len > max_capacity - queue->len) {
        ++budget->size_rejections;
        return -1;
    }
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
        size_t growth = cap - queue->cap;
        if (tg_memory_budget_reserve(budget, growth) != 0)
            return -1;
        uint8_t *grown = realloc(queue->data, cap);
        if (!grown) {
            ++budget->allocation_failures;
            tg_memory_budget_release(budget, growth);
            return -1;
        }
        queue->data = grown;
        queue->cap = cap;
        queue->dynamic_bytes += growth;
    }
    if (len) memcpy(queue->data + queue->head + queue->len, data, len);
    queue->len += len;
    return 0;
}

static int queue_prepend(byte_queue *queue, const uint8_t *data, size_t len,
                         size_t max_capacity, tg_memory_budget *budget) {
    if (!queue || (len && !data) || len > SIZE_MAX - queue->len)
        return -1;
    size_t needed = queue->len + len;
    if (needed > max_capacity) {
        if (budget) ++budget->size_rejections;
        return -1;
    }
    if (needed > queue->cap) {
        size_t growth = needed - queue->cap;
        if (budget && tg_memory_budget_reserve(budget, growth) != 0)
            return -1;
        uint8_t *grown = realloc(queue->data, needed);
        if (!grown) {
            if (budget) ++budget->allocation_failures;
            tg_memory_budget_release(budget, growth);
            return -1;
        }
        queue->data = grown;
        queue->cap = needed;
        queue->dynamic_bytes += growth;
    }
    if (queue->head >= len) {
        queue->head -= len;
        if (len) memcpy(queue->data + queue->head, data, len);
    } else {
        memmove(queue->data + len, queue->data + queue->head, queue->len);
        queue->head = 0;
        if (len) memcpy(queue->data, data, len);
    }
    queue->len = needed;
    return 0;
}

static void queue_release(proxy_connection *connection, byte_queue *queue) {
    if (!queue) return;
    tg_memory_budget *budget = connection && connection->server
        ? &connection->server->buffer_budget : NULL;
    free(queue->data);
    tg_memory_budget_release(budget, queue->dynamic_bytes);
    queue->data = NULL;
    queue->cap = 0;
    queue->head = 0;
    queue->len = 0;
    queue->dynamic_bytes = 0;
}

static int queue_flush(int fd, byte_queue *queue, uint64_t *last_activity,
                       proxy_connection *connection) {
    while (queue->len) {
        ssize_t n = send(fd, queue->data + queue->head, queue->len,
                         MSG_NOSIGNAL);
        if (n > 0) {
            queue->head += (size_t)n;
            queue->len -= (size_t)n;
            if (!queue->len) {
                queue->head = 0;
                queue_release(connection, queue);
            }
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
        (!connection->direct_wss ||
         (connection->wss_phase == WSS_READY && !connection->upstream_eof));
    int wss_backpressure = connection->ws_pump_ready &&
                           connection->ws_pump.tx_memory_bytes != 0;
    int queue_has_room = connection->to_upstream.len <
                         connection->server->config.queue_bytes;
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
            if (!want && connection->ws_pump.read_paused) return 0;
            if (want & POLLIN) events |= EPOLLIN;
            if (want & POLLOUT) events |= EPOLLOUT;
        } else {
            events |= connection->tls_want;
        }
        return events;
    }
    if (!connection->upstream_eof &&
        connection->to_client.len < connection->server->config.queue_bytes)
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

static void wss_close_best_effort(proxy_connection *connection) {
    if (!connection) return;
    if (connection->ws_pump_ready && connection->wss_phase == WSS_READY &&
        !connection->wss_close_queued && !connection->ws_pump.failed &&
        !connection->ws_pump.closed) {
        connection->wss_close_queued = 1;
        if (tg_ws_pump_queue_close(&connection->ws_pump) == 0)
            (void)tg_ws_pump_process(&connection->ws_pump, POLLOUT, NULL, NULL);
    }
    if (connection->upstream_ssl) (void)SSL_shutdown(connection->upstream_ssl);
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
    wss_close_best_effort(connection);
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
    connection->upstream_connect_deadline_ms = 0;
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
        tg_memory_budget_release(&server->buffer_budget,
                                connection->to_upstream.dynamic_bytes);
        tg_memory_budget_release(&server->buffer_budget,
                                connection->to_client.dynamic_bytes);
        free(connection->to_upstream.data);
        free(connection->to_client.data);
        free(connection);
    }
}

static int route_health_key_matches(const route_health *health,
                                    const proxy_connection *connection) {
    const tg_listener_destination *a = &health->original;
    const tg_listener_destination *b = &connection->original;
    if (!health->used || health->kind != connection->route_kind ||
        health->dc_id != connection->route_dc_id ||
        health->is_media != connection->route_is_media ||
        (health->kind != TG_ROUTE_DIRECT_TCP &&
         strcmp(health->hostname, connection->tls_hostname) != 0) ||
        a->port != b->port ||
        (a->family != AF_INET && a->family != AF_INET6) ||
        (b->family != AF_INET && b->family != AF_INET6))
        return 0;
    if (a->family != b->family) return 0;
    size_t address_len = a->family == AF_INET ? 4u : 16u;
    return memcmp(a->address, b->address, address_len) == 0;
}

static int route_health_in_use(const tg_epoll_proxy *server, size_t index) {
    for (const proxy_connection *connection = server->connections; connection;
         connection = connection->next) {
        if (!connection->closed && connection->route_health_index == (int)index)
            return 1;
        for (size_t i = 0; i < TG_HEDGE_CANDIDATES; ++i)
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
    health->transport = route_session_transport_for(connection,
                                                     connection->route_kind);
    health->dc_id = connection->route_dc_id;
    health->is_media = connection->route_is_media;
    memcpy(health->hostname, connection->tls_hostname,
           strlen(connection->tls_hostname) + 1u);
    health->original = connection->original;
    health->used = 1;
    return (int)index;
}

static route_health *ip_health(proxy_connection *connection, int create) {
    tg_route_kind kind = connection->route_kind;
    connection->route_kind = TG_ROUTE_DIRECT_TCP;
    int index = route_health_get(connection->server, connection, create);
    connection->route_kind = kind;
    return index < 0 ? NULL : &connection->server->route_health[index];
}

static void mark_ip_failure(proxy_connection *connection) {
    const tg_config *routing = connection->server->config.routing_config;
    if (!routing || !routing->ip_fail_cooldown_secs ||
        connection->route_tcp_only) return;
    route_health *health = ip_health(connection, 1);
    if (health) health->cooldown_until_ms = monotonic_ms() +
        routing->ip_fail_cooldown_secs * UINT64_C(1000);
}

static uint64_t wss_timeout_ms(const proxy_connection *connection) {
    const tg_epoll_proxy_config *config = &connection->server->config;
    const tg_config *routing = config->routing_config;
    if (routing && connection->direct_recovery_probe)
        return routing->ws_fail_probe_timeout_secs * UINT64_C(1000);
    uint32_t seconds = !routing ? 0 : connection->route_kind == TG_ROUTE_DIRECT_WSS
        ? routing->ws_connect_timeout_secs : routing->cf_connect_timeout_secs;
    return seconds ? seconds * UINT64_C(1000) : config->handshake_timeout_ms;
}

static cf_rate_limit *cf_domain_rate_limit(tg_epoll_proxy *server,
                                          const char *domain, int create) {
    cf_rate_limit *oldest = &server->cf_rate_limits[0];
    for (size_t i = 0; i < TG_CF_POOL_MAX; ++i) {
        cf_rate_limit *entry = &server->cf_rate_limits[i];
        if (strcmp(entry->domain, domain) == 0) return entry;
        if (entry->until_ms < oldest->until_ms) oldest = entry;
    }
    if (!create) return NULL;
    memset(oldest, 0, sizeof(*oldest));
    memcpy(oldest->domain, domain, strlen(domain) + 1);
    return oldest;
}

static void cf_proxy_mark_rate_limited(proxy_connection *connection) {
    const char *domain = strchr(connection->tls_hostname, '.');
    if (!domain || !domain[1]) return;
    cf_rate_limit *entry = cf_domain_rate_limit(connection->server, domain + 1, 1);
    static const uint64_t backoff_ms[] = {45000, 90000, 180000, 300000};
    entry->until_ms = monotonic_ms() + backoff_ms[entry->failures];
    if (entry->failures < 3) ++entry->failures;
}

static uint64_t route_cooldown_ms(const proxy_connection *connection,
                                  uint32_t stage) {
    const tg_config *routing = connection->server->config.routing_config;
    uint32_t seconds = 0;
    unsigned status = stage == TG_EPOLL_FAILURE_WEBSOCKET
        ? connection->ws_upgrade.http_status : 0;
    if (connection->route_kind == TG_ROUTE_CF_PROXY && status == 503)
        return 15000;
    if (!routing) return TG_ROUTE_HEALTH_COOLDOWN_MS;
    if (connection->route_kind == TG_ROUTE_DIRECT_WSS)
        seconds = status >= 300 && status < 400
            ? routing->ws_redirect_cooldown_secs : routing->ws_fail_cooldown_secs;
    else
        seconds = routing->cf_fail_cooldown_secs;
    return seconds ? seconds * UINT64_C(1000) : TG_ROUTE_HEALTH_COOLDOWN_MS;
}

static void route_failure_record(proxy_connection *connection,
                                 tg_route_kind kind, uint32_t stage) {
    if (!connection) return;
    connection->route_failure_stage = (uint8_t)stage;
    uint64_t now = monotonic_ms();
    tg_epoll_proxy *server = connection->server;
    if (stage < TG_EPOLL_FAILURE_STAGE_COUNT &&
        server->failure_by_stage[stage] != UINT64_MAX)
        ++server->failure_by_stage[stage];
    uint32_t http_status = stage == TG_EPOLL_FAILURE_WEBSOCKET
        ? connection->ws_upgrade.http_status : 0;
    if (http_status) {
        server->last_http_status = http_status;
        if (http_status == 403 && server->http_403 != UINT64_MAX)
            ++server->http_403;
        else if (http_status == 501 && server->http_501 != UINT64_MAX)
            ++server->http_501;
        else if (http_status == 502 && server->http_502 != UINT64_MAX)
            ++server->http_502;
    }
    uint64_t sequence = server->problem_session_total;
    if (server->problem_session_total != UINT64_MAX)
        ++server->problem_session_total;
    tg_problem_session *problem = &server->problem_sessions[
        sequence % TG_EPOLL_MAX_PROBLEM_SESSIONS];
    memset(problem, 0, sizeof(*problem));
    problem->sequence = sequence == UINT64_MAX ? UINT64_MAX : sequence + 1u;
    problem->dc = connection->route_dc_id;
    problem->client_port = connection->original.port;
    problem->upstream_port = connection->upstream_target.port;
    problem->http_status = (uint16_t)http_status;
    problem->is_media = (uint8_t)(connection->route_is_media != 0);
    problem->transport = route_session_transport_for(connection, kind);
    problem->failure_stage = (uint8_t)stage;
    proxy_connection *owner = route_session_owner(connection);
    if (owner) {
        problem->session_id = owner->route_session.id;
        problem->bytes_from_clients = owner->route_session.bytes_from_clients;
        problem->bytes_from_upstreams = owner->route_session.bytes_from_upstreams;
    }
    uint64_t accepted_ms = connection->accepted_at_us / 1000u;
    problem->age_ms = now >= accepted_ms ? now - accepted_ms : 0;
    if (now >= server->last_failure_ms) {
        server->last_failure_ms = now;
        server->last_failure_dc = connection->route_dc_id;
        server->last_failure_route = (uint32_t)kind;
        server->last_failure_stage = stage;
    }
    connection->route_failure_recorded = 1;
}

static void route_health_cooldown_at(proxy_connection *connection,
                                     uint32_t stage) {
    if (!connection) return;
    if (connection->route_health_index >= 0) {
        route_health *health = &connection->server->route_health[
            (size_t)connection->route_health_index];
        if (health->used) {
            uint64_t now = monotonic_ms();
            health->cooldown_until_ms = now + route_cooldown_ms(connection, stage);
            health->last_failure_ms = now;
            health->last_failure_stage = stage;
        }
    }
    if (connection->route_kind == TG_ROUTE_CF_PROXY &&
        stage == TG_EPOLL_FAILURE_WEBSOCKET && connection->ws_upgrade.http_status == 429)
        cf_proxy_mark_rate_limited(connection);
    route_failure_record(connection, connection->route_kind, stage);
}

static void route_health_failed_at(proxy_connection *connection,
                                   uint32_t stage) {
    if (!connection) return;
    if (connection->route_health_index >= 0) {
        route_health *health = &connection->server->route_health[
            (size_t)connection->route_health_index];
        if (health->used && health->failures != UINT64_MAX)
            ++health->failures;
    }
    route_health_cooldown_at(connection, stage);
}

static void route_health_failed(proxy_connection *connection) {
    if (!connection) return;
    uint32_t stage;
    if (connection->connecting || connection->wss_phase == WSS_NONE) {
        stage = TG_EPOLL_FAILURE_TCP;
    } else if (connection->wss_phase == WSS_TLS) {
        stage = TG_EPOLL_FAILURE_TLS;
    } else if (connection->wss_phase == WSS_UPGRADE_WRITE ||
               connection->wss_phase == WSS_UPGRADE_READ) {
        stage = connection->ws_upgrade.failed &&
            connection->route_kind == TG_ROUTE_CF_WORKER &&
            connection->original.port == 5222
            ? TG_EPOLL_FAILURE_WORKER_PORT : TG_EPOLL_FAILURE_WEBSOCKET;
    } else if (connection->wss_phase == WSS_READY) {
        stage = TG_EPOLL_FAILURE_MTPROTO;
    } else {
        stage = TG_EPOLL_FAILURE_SETUP;
    }
    route_health_failed_at(connection, stage);
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
    if (target->family != AF_INET && target->family != AF_INET6) return 0;
    size_t address_len = target->family == AF_INET ? 4u : 16u;
    const route_health *best = NULL;
    int proxy_first = server->config.cloudflare_only && !connection->route_tcp_only &&
        (!server->config.routing_config ||
         server->config.routing_config->route_only != TG_ROUTE_ONLY_WORKER) &&
        route_cf_domain_count(server) > 0;
    for (size_t i = 0; i < TG_ROUTE_HEALTH_MAX; ++i) {
        const route_health *health = &server->route_health[i];
        if (!health->used ||
            health->kind == TG_ROUTE_DIRECT_TCP ||
            (proxy_first && health->kind != TG_ROUTE_CF_PROXY) ||
            health->dc_id != connection->route_dc_id ||
            health->is_media != connection->route_is_media ||
            !health->last_success_ms || now < health->last_success_ms ||
            health->original.port != target->port ||
            health->cooldown_until_ms > now ||
            health->last_failure_ms > health->last_success_ms ||
            (health->kind == TG_ROUTE_CF_WORKER &&
             (health->original.family != target->family ||
              memcmp(health->original.address, target->address,
                     address_len) != 0)))
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

static int route_plan_keep_only(tg_route_plan *plan, tg_route_only only) {
    tg_route_kind wanted;
    switch (only) {
    case TG_ROUTE_ONLY_DIRECT: wanted = TG_ROUTE_DIRECT_WSS; break;
    case TG_ROUTE_ONLY_WORKER: wanted = TG_ROUTE_CF_WORKER; break;
    case TG_ROUTE_ONLY_CF_PROXY: wanted = TG_ROUTE_CF_PROXY; break;
    case TG_ROUTE_ONLY_TCP: wanted = TG_ROUTE_DIRECT_TCP; break;
    default: return 0;
    }
    size_t kept = 0;
    for (size_t i = 0; i < plan->count; ++i)
        if (plan->steps[i].kind == wanted) plan->steps[kept++] = plan->steps[i];
    plan->count = kept;
    return kept ? 0 : -1;
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

static const struct {
    uint32_t dc;
    const char *address;
} worker_warm_targets[] = {
    {1, "149.154.175.50"}, {2, "149.154.167.51"},
    {3, "149.154.175.100"}, {4, "149.154.167.91"},
    {5, "149.154.171.5"}, {203, "91.105.192.100"},
};

static int format_worker_path(const char *address, uint16_t port,
                              uint32_t dc, int is_media, char *path, size_t path_size) {
    if (port != 443 && port != 5222) return -1;
    int n = snprintf(path, path_size, "%s?dst=%s&dc=%u&media=%d",
                     port == 5222 ? "/d2o/apiws/5222" : "/apiws",
                     address, dc, is_media ? 1 : 0);
    return n > 0 && (size_t)n < path_size ? 0 : -1;
}

static int worker_requires_5222(const proxy_connection *connection) {
    return connection->route_kind == TG_ROUTE_CF_WORKER &&
           connection->original.port == 5222;
}

static int set_worker_path(proxy_connection *connection) {
    char address[INET6_ADDRSTRLEN];
    const tg_listener_destination *original = &connection->original;
    if (!inet_ntop(original->family, original->address, address, sizeof(address)))
        return -1;
    return format_worker_path(address, original->port, connection->route_dc_id,
                              connection->route_is_media, connection->wss_path,
                              sizeof(connection->wss_path));
}

static void worker_pool_entry_close(worker_pool_entry *entry) {
    if (!entry) return;
    if (entry->ssl) SSL_free(entry->ssl);
    if (entry->fd >= 0) close(entry->fd);
    entry->ssl = NULL;
    entry->fd = -1;
}

static int worker_pool_entry_alive(const worker_pool_entry *entry) {
    if (!entry || entry->fd < 0 || !entry->ssl) return 0;
    if (SSL_pending(entry->ssl) > 0) return 0;
    struct pollfd ready = { .fd = entry->fd, .events = POLLIN };
    int rc = poll(&ready, 1, 0);
    if (rc < 0) return 0;
    if (ready.revents & (POLLERR | POLLHUP | POLLNVAL)) return 0;
    if (!(ready.revents & POLLIN)) return 1;
    uint8_t byte;
    int peek = SSL_peek(entry->ssl, &byte, 1);
    if (peek > 0) return 0;
    int error = SSL_get_error(entry->ssl, peek);
    return error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE;
}

static int worker_pool_connect_host(worker_pool *pool, SSL **out_ssl) {
    const char *domain = pool->domain;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *result = NULL;
    if (getaddrinfo(domain, "443", &hints, &result) != 0) {
        fprintf(stderr, "worker pool: DNS %s failed\n", domain);
        return -1;
    }
    int fd = -1;
    unsigned tls_failures = 0;
    for (struct addrinfo *it = result; it; it = it->ai_next) {
        fd = socket(it->ai_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) continue;
        if (pool->require_socket_mark) {
#ifdef SO_MARK
            int mark = (int)pool->socket_mark;
            if (!mark || setsockopt(fd, SOL_SOCKET, SO_MARK, &mark,
                                    sizeof(mark)) != 0) {
                close(fd); fd = -1; continue;
            }
#else
            close(fd); fd = -1; continue;
#endif
        }
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
            close(fd); fd = -1; continue;
        }
        int rc = connect(fd, it->ai_addr, it->ai_addrlen);
        if (rc != 0 && errno != EINPROGRESS) { close(fd); fd = -1; continue; }
        if (rc != 0) {
            struct pollfd ready = { .fd = fd, .events = POLLOUT };
            rc = poll(&ready, 1, TG_WORKER_POOL_CONNECT_TIMEOUT_MS);
            if (rc <= 0 || (ready.revents & (POLLERR | POLLHUP | POLLNVAL))) {
                close(fd); fd = -1; continue;
            }
            int error = 0;
            socklen_t error_len = sizeof(error);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_len) != 0 ||
                error != 0) {
                close(fd); fd = -1; continue;
            }
        }
        if (fcntl(fd, F_SETFL, flags) != 0) { close(fd); fd = -1; continue; }
        struct timeval timeout = { .tv_sec = 8 };
        (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        *out_ssl = tg_tls_connect_fd_sni(pool->tls_context, fd, domain, domain);
        if (*out_ssl) break;
        close(fd);
        fd = -1;
        if (++tls_failures == 2) break;
    }
    if (fd < 0)
        fprintf(stderr, "worker pool: %s %s failed\n",
                tls_failures ? "TLS" : "TCP", domain);
    freeaddrinfo(result);
    return fd;
}

typedef enum {
    WORKER_POOL_CONNECTED,
    WORKER_POOL_HOST_FAILED,
    WORKER_POOL_PATH_FAILED
} worker_pool_connect_result;

static worker_pool_connect_result worker_pool_connect(
    worker_pool *pool, uint32_t dc, int is_media, worker_pool_entry *out) {
    const char *path = NULL;
    for (size_t i = 0; i < pool->dc_count; ++i)
        if (pool->dcs[i] == dc && pool->media[i] == is_media)
            path = pool->paths[i];
    if (!path) return WORKER_POOL_PATH_FAILED;
    SSL *ssl = NULL;
    int fd = worker_pool_connect_host(pool, &ssl);
    if (fd < 0) return WORKER_POOL_HOST_FAILED;
    if (tg_ws_upgrade(ssl, pool->domain, path) != 0) {
        fprintf(stderr, "worker pool: WS %s%s failed\n", pool->domain, path);
        SSL_free(ssl);
        close(fd);
        return WORKER_POOL_PATH_FAILED;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        fprintf(stderr, "worker pool: nonblocking %s failed\n", pool->domain);
        SSL_free(ssl);
        close(fd);
        return WORKER_POOL_PATH_FAILED;
    }
    memset(out, 0, sizeof(*out));
    out->fd = fd;
    out->ssl = ssl;
    out->dc_id = dc;
    out->is_media = is_media;
    out->created_ms = monotonic_ms();
    snprintf(out->hostname, sizeof(out->hostname), "%s", pool->domain);
    snprintf(out->path, sizeof(out->path), "%s", path);
    return WORKER_POOL_CONNECTED;
}

static uint64_t worker_pool_retry_delay(unsigned *failures) {
    if (*failures < 7u) ++*failures;
    uint64_t delay = UINT64_C(1000) << (*failures - 1u);
    return delay > 60000u ? 60000u : delay;
}

static void *worker_pool_thread(void *opaque) {
    worker_pool *pool = opaque;
    for (;;) {
        worker_pool_entry stale[TG_WORKER_POOL_MAX];
        size_t stale_count = 0;
        uint32_t missing = 0;
        int missing_media = 0;
        size_t missing_index = 0;
        int have_missing = 0;
        pthread_mutex_lock(&pool->lock);
        if (pool->stopping) { pthread_mutex_unlock(&pool->lock); break; }
        uint64_t now = monotonic_ms();
        for (size_t i = 0; i < pool->count;) {
            if (now - pool->entries[i].created_ms >=
                TG_WORKER_POOL_MAX_AGE_MS ||
                !worker_pool_entry_alive(&pool->entries[i])) {
                stale[stale_count++] = pool->entries[i];
                pool->entries[i] = pool->entries[--pool->count];
            } else {
                ++i;
            }
        }
        for (size_t i = 0; now >= pool->host_retry_at && pool->count < pool->capacity &&
                         i < pool->dc_count && !have_missing; ++i) {
            int found = 0;
            for (size_t j = 0; j < pool->count; ++j)
                if (pool->entries[j].dc_id == pool->dcs[i] &&
                    pool->entries[j].is_media == pool->media[i]) {
                    found = 1; break;
                }
            if (!found && now >= pool->retry_at[i]) {
                missing = pool->dcs[i];
                missing_media = pool->media[i];
                missing_index = i;
                have_missing = 1;
            }
        }
        if (!have_missing) {
            struct timespec wake_at;
            clock_gettime(CLOCK_REALTIME, &wake_at);
            wake_at.tv_sec += 1;
            (void)pthread_cond_timedwait(&pool->wake, &pool->lock, &wake_at);
            pthread_mutex_unlock(&pool->lock);
        } else {
            pthread_mutex_unlock(&pool->lock);
        }
        for (size_t i = 0; i < stale_count; ++i)
            worker_pool_entry_close(&stale[i]);
        if (!have_missing) continue;
        worker_pool_entry entry;
        worker_pool_connect_result status =
            worker_pool_connect(pool, missing, missing_media, &entry);
        if (status != WORKER_POOL_CONNECTED) {
            pthread_mutex_lock(&pool->lock);
            if (!pool->stopping) {
                uint64_t now = monotonic_ms();
                if (status == WORKER_POOL_HOST_FAILED) {
                    pool->host_retry_at = now +
                        worker_pool_retry_delay(&pool->host_failures);
                } else {
                    pool->host_failures = 0;
                    pool->host_retry_at = 0;
                    pool->retry_at[missing_index] = now +
                        worker_pool_retry_delay(&pool->failures[missing_index]);
                }
                struct timespec retry_at;
                clock_gettime(CLOCK_REALTIME, &retry_at);
                retry_at.tv_sec += 1;
                (void)pthread_cond_timedwait(&pool->wake, &pool->lock,
                                             &retry_at);
            }
            pthread_mutex_unlock(&pool->lock);
            continue;
        }
        pthread_mutex_lock(&pool->lock);
        pool->host_failures = 0;
        pool->host_retry_at = 0;
        pool->failures[missing_index] = 0;
        pool->retry_at[missing_index] = 0;
        if (pool->stopping || pool->count >= pool->capacity) {
            pthread_mutex_unlock(&pool->lock);
            worker_pool_entry_close(&entry);
            continue;
        }
        pool->entries[pool->count++] = entry;
        pthread_mutex_unlock(&pool->lock);
    }
    pthread_mutex_lock(&pool->lock);
    for (size_t i = 0; i < pool->count; ++i)
        worker_pool_entry_close(&pool->entries[i]);
    pool->count = 0;
    pthread_mutex_unlock(&pool->lock);
    return NULL;
}

static worker_pool *worker_pool_start(const tg_epoll_proxy_config *config,
                                      size_t capacity) {
    if (!capacity || !config || !config->routing_config || !config->tls_context ||
        !config->enable_direct_wss || config->resolve_domain ||
        !config->routing_config->cf_worker_domain_count)
        return NULL;
    tg_route_only only = config->routing_config->route_only;
    if (only != TG_ROUTE_ONLY_AUTO && only != TG_ROUTE_ONLY_WORKER)
        return NULL;
    worker_pool *pool = calloc(1, sizeof(*pool));
    if (!pool) return NULL;
    pool->capacity = capacity < TG_WORKER_POOL_MAX ? capacity : TG_WORKER_POOL_MAX;
    pool->tls_context = config->tls_context;
    pool->socket_mark = config->socket_mark;
    pool->require_socket_mark = config->require_socket_mark;
    snprintf(pool->domain, sizeof(pool->domain), "%s",
             config->routing_config->cf_worker_domains[0]);
    if (!pool->domain[0]) { free(pool); return NULL; }
    for (size_t i = 0; i < sizeof(worker_warm_targets) / sizeof(worker_warm_targets[0]); ++i) {
        for (int is_media = 0; is_media <= 1; ++is_media) {
            char path[512];
            if (format_worker_path(worker_warm_targets[i].address, 443,
                                   worker_warm_targets[i].dc, is_media,
                                   path, sizeof(path)) != 0)
                continue;
            pool->dcs[pool->dc_count] = worker_warm_targets[i].dc;
            pool->media[pool->dc_count] = is_media;
            memcpy(pool->paths[pool->dc_count], path, strlen(path) + 1u);
            ++pool->dc_count;
        }
    }
    if (!pool->dc_count) { free(pool); return NULL; }
    if (pthread_mutex_init(&pool->lock, NULL) != 0) {
        free(pool);
        return NULL;
    }
    if (pthread_cond_init(&pool->wake, NULL) != 0) {
        pthread_mutex_destroy(&pool->lock);
        free(pool);
        return NULL;
    }
    pool->stopping = 0;
    pool->started = pthread_create(&pool->thread, NULL, worker_pool_thread,
                                   pool) == 0 ? 1 : 0;
    if (!pool->started) {
        pthread_cond_destroy(&pool->wake);
        pthread_mutex_destroy(&pool->lock);
        free(pool);
        return NULL;
    }
    return pool;
}

static int worker_pool_take(worker_pool *pool, const char *hostname,
                            const char *path, worker_pool_entry *out) {
    if (!pool || !out) return 0;
    worker_pool_entry stale[TG_WORKER_POOL_MAX];
    size_t stale_count = 0;
    int found = 0;
    pthread_mutex_lock(&pool->lock);
    uint64_t now = monotonic_ms();
    for (size_t i = 0; i < pool->count;) {
        /* The upgrade already opened a specific Telegram destination. The
         * full path includes its address, port, DC and media class. */
        if (strcmp(pool->entries[i].hostname, hostname) != 0 ||
            strcmp(pool->entries[i].path, path) != 0) { ++i; continue; }
        if (now - pool->entries[i].created_ms >= TG_WORKER_POOL_MAX_AGE_MS ||
            !worker_pool_entry_alive(&pool->entries[i])) {
            stale[stale_count++] = pool->entries[i];
            pool->entries[i] = pool->entries[--pool->count];
            continue;
        }
        *out = pool->entries[i];
        pool->entries[i] = pool->entries[--pool->count];
        (void)pthread_cond_signal(&pool->wake);
        found = 1;
        break;
    }
    pthread_mutex_unlock(&pool->lock);
    for (size_t i = 0; i < stale_count; ++i)
        worker_pool_entry_close(&stale[i]);
    return found;
}

#ifdef TG_EPOLL_TESTING
int tg_epoll_proxy_test_worker_pool_take(int fd, SSL *ssl,
                                      const char *hostname, const char *path) {
    worker_pool pool = {.count = 1};
    if (pthread_mutex_init(&pool.lock, NULL) != 0) return -1;
    if (pthread_cond_init(&pool.wake, NULL) != 0) {
        pthread_mutex_destroy(&pool.lock);
        return -1;
    }
    pool.entries[0] = (worker_pool_entry){
        .fd = fd, .ssl = ssl, .created_ms = monotonic_ms(),
        .hostname = "worker.test", .path = "/apiws?dst=149.154.167.51&dc=2&media=1",
    };
    worker_pool_entry entry;
    int found = worker_pool_take(&pool, hostname, path, &entry);
    pthread_cond_destroy(&pool.wake);
    pthread_mutex_destroy(&pool.lock);
    return found;
}
#endif

static void worker_pool_stop(worker_pool *pool) {
    if (!pool) return;
    pthread_mutex_lock(&pool->lock);
    pool->stopping = 1;
    (void)pthread_cond_signal(&pool->wake);
    pthread_mutex_unlock(&pool->lock);
    if (pool->started) (void)pthread_join(pool->thread, NULL);
    pthread_mutex_lock(&pool->lock);
    for (size_t i = 0; i < pool->count; ++i)
        worker_pool_entry_close(&pool->entries[i]);
    pool->count = 0;
    pthread_mutex_unlock(&pool->lock);
    pthread_cond_destroy(&pool->wake);
    pthread_mutex_destroy(&pool->lock);
    free(pool);
}

static int attach_pooled_worker(proxy_connection *connection,
                                worker_pool_entry *entry) {
    if (!connection || !entry || entry->fd < 0 || !entry->ssl) return -1;
    tg_epoll_proxy *server = connection->server;
    connection->upstream_fd = entry->fd;
    connection->upstream_ssl = entry->ssl;
    entry->fd = -1;
    entry->ssl = NULL;
    connection->direct_wss = 1;
    connection->from_worker_pool = 1;
    connection->packet_framing = 0;
    connection->wss_subprotocol = 0;
    connection->connecting = 0;
    connection->upstream_connect_deadline_ms = 0;
    snprintf(connection->tls_hostname, sizeof(connection->tls_hostname),
             "%s", entry->hostname);
    snprintf(connection->wss_path, sizeof(connection->wss_path),
             "%s", entry->path);
    /* The pooled TLS/WS handshake is already complete; run the same
       post-upgrade setup as a cold worker so the MTProto cipher, splitter and
       replay state are initialized before the first response arrives. */
    if (establish_wss_stream(connection) != 0) return -1;
    connection->upstream_watch = (socket_watch){
        .kind = 2, .connection = connection, .side = 1,
        .fd = connection->upstream_fd
    };
    if (watch_update(server, &connection->upstream_watch,
                     upstream_events(connection)) != 0)
        return -1;
    return 0;
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
    connection->wss_deadline_ms = monotonic_ms() + wss_timeout_ms(connection);
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
    set_tcp_nodelay(fd);
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
    uint64_t timeout_ms = connection->direct_wss ? wss_timeout_ms(connection)
        : server->config.handshake_timeout_ms;
    if (connection->route_kind == TG_ROUTE_DIRECT_TCP &&
        server->config.routing_config &&
        server->config.routing_config->tcp_fallback_timeout_secs)
        timeout_ms = server->config.routing_config->tcp_fallback_timeout_secs * 1000u;
    connection->upstream_connect_deadline_ms = connection->connecting
        ? monotonic_ms() + timeout_ms : 0;
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
    connection->ws_upgrade.http_status = 0;
    connection->tls_want = 0;
    connection->wss_deadline_ms = 0;
    connection->next_ping_ms = 0;
    connection->wss_read_paused_at_ms = 0;
    connection->wss_close_queued = 0;
}

static void clear_route_attempt(proxy_connection *connection, int failed) {
    tg_epoll_proxy *server = connection->server;
    if (failed) {
        route_health_failed(connection);
        route_session_event(connection, connection->route_kind,
                            TG_ROUTE_SESSION_FAILED);
    } else if (connection->direct_wss) {
        proxy_connection *owner = route_session_owner(connection);
        if (!owner->route_session_tracked) goto route_attempt_cleared;
        uint8_t transport = route_session_transport_for(connection,
                                                        connection->route_kind);
        uint8_t branch = route_session_branch(connection, transport);
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
    wss_close_best_effort(connection);
    watch_remove(server, &connection->upstream_watch);
    clear_wss_state(connection);
    if (connection->upstream_fd >= 0) close(connection->upstream_fd);
    connection->upstream_fd = -1;
    connection->connecting = 0;
    connection->upstream_eof = 0;
    connection->upstream_shutdown = 0;
    connection->upstream_connect_deadline_ms = 0;
    connection->direct_wss = 0;
    connection->from_worker_pool = 0;
    connection->route_health_index = -1;
    connection->route_data_seen = 0;
    connection->route_response_seen = 0;
    connection->response_observer_disabled = 0;
    connection->wss_forwarded_offset = 0;
    connection->route_started_ms = 0;
}

static void hedge_retire_candidate(proxy_connection *candidate, int failed) {
    if (!candidate || candidate->closed) return;
    proxy_connection *parent = candidate->hedge_parent;
    if (parent) {
        for (size_t i = 0; i < TG_HEDGE_CANDIDATES; ++i)
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
    for (size_t i = 0; i < TG_HEDGE_CANDIDATES; ++i) {
        proxy_connection *candidate = connection->hedges[i];
        if (candidate) hedge_retire_candidate(candidate, 0);
        connection->hedges[i] = NULL;
    }
    connection->hedge_due_ms = 0;
    connection->route_racing = 0;
}

static int setup_route_attempt(proxy_connection *connection,
                               const tg_route_step *step,
                               tg_listener_destination *target,
                               int *dns_failure, int *cooldown) {
    tg_epoll_proxy *server = connection->server;
    if (dns_failure) *dns_failure = 0;
    if (cooldown) *cooldown = 0;
    connection->route_kind = step->kind;
    connection->packet_framing = 1;
    connection->wss_subprotocol = 1;
    memcpy(connection->wss_path, "/apiws", sizeof("/apiws"));
    connection->direct_recovery_probe = 0;
    if (step->kind == TG_ROUTE_DIRECT_WSS) {
        route_health *ip = ip_health(connection, 0);
        uint64_t now = monotonic_ms();
        if (ip && ip->cooldown_until_ms > now) {
            const tg_config *routing = server->config.routing_config;
            if (!connection->hedge_parent || !routing ||
                routing->ws_routing != TG_WS_ROUTING_ADAPTIVE ||
                !routing->ws_fail_probe_timeout_secs || now < ip->next_probe_ms) {
                if (cooldown) *cooldown = 1;
                return 2;
            }
            connection->direct_recovery_probe = 1;
            ip->next_probe_ms = now + routing->ws_fail_probe_timeout_secs * UINT64_C(1000);
        }
        *target = connection->upstream_target;
        if (server->config.direct_wss_port)
            target->port = server->config.direct_wss_port;
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
            cf_rate_limit *limit = cf_domain_rate_limit(server, domain_copy, 0);
            if (limit && limit->until_ms > monotonic_ms()) {
                if (cooldown) *cooldown = 1;
                return 2;
            }
            domain = hostname;
        }
        if (!domain) return -1;
        if (strlen(domain) >= sizeof(connection->tls_hostname)) return -1;
        memcpy(connection->tls_hostname, domain, strlen(domain) + 1u);
        int health_index = route_health_get(server, connection, 0);
        if (health_index >= 0 &&
            server->route_health[health_index].cooldown_until_ms >
                monotonic_ms()) {
            if (cooldown) *cooldown = 1;
            return 2;
        }
        int resolve_status = resolve_route_domain(server, domain, target);
        if (resolve_status < 0 && dns_failure) *dns_failure = 1;
        if (resolve_status != 0) return resolve_status;
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
            route_health *ip = ip_health(connection, 0);
            if (!connection->route_tcp_only && ip &&
                ip->cooldown_until_ms > monotonic_ms()) {
                route_session_event(connection, step.kind, TG_ROUTE_SESSION_COOLDOWN);
                continue;
            }
            connection->route_dns_event_active = 0;
            connection->route_dns_pending = 0;
            if ((connection->wss_replay_disabled &&
                 connection->wss_client_payload_started) ||
                queue_prepend(&connection->to_upstream,
                              connection->handshake,
                              sizeof(connection->handshake),
                              server->config.queue_bytes,
                              &server->buffer_budget) != 0)
                return -1;
            connection->wss_replay_disabled = 1;
            if (begin_upstream(connection,
                               &connection->upstream_target) == 0) {
                if (!connection->connecting)
                    route_session_event(connection, step.kind,
                                        TG_ROUTE_SESSION_CONNECTED);
                return 0;
            }
            mark_ip_failure(connection);
            route_failure_record(connection, step.kind, TG_EPOLL_FAILURE_TCP);
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
        int dns_failure = 0, route_cooldown = 0;
        int setup_status = setup_route_attempt(connection, &step, &target,
                                               &dns_failure, &route_cooldown);
        if (route_cooldown) {
            route_session_event(connection, step.kind,
                                TG_ROUTE_SESSION_COOLDOWN);
            continue;
        }
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
            if (dns_failure) {
                connection->route_health_index =
                    route_health_get(server, connection, 1);
                if (connection->route_health_index >= 0)
                    route_health_cooldown_at(connection,
                                             TG_EPOLL_FAILURE_DNS);
                else
                    route_failure_record(connection, step.kind,
                                         TG_EPOLL_FAILURE_DNS);
                connection->route_health_index = -1;
            } else {
                route_failure_record(connection, step.kind,
                    step.kind == TG_ROUTE_DIRECT_WSS
                        ? TG_EPOLL_FAILURE_SETUP : TG_EPOLL_FAILURE_DNS);
            }
            route_session_event(connection, step.kind,
                                TG_ROUTE_SESSION_FAILED);
            continue;
        }
        connection->route_data_seen = 0;
        connection->route_response_seen = 0;
        connection->response_observer_disabled = 0;
        int health_index = route_health_get(server, connection, 1);
        if (health_index >= 0) {
            route_health *health = &server->route_health[health_index];
            health->upstream_port = target.port;
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
        if (step.kind == TG_ROUTE_CF_WORKER && step.index == 0 &&
            !connection->route_tcp_only && server->worker_pool) {
            worker_pool_entry pooled;
            if (worker_pool_take(server->worker_pool, connection->tls_hostname,
                                 connection->wss_path, &pooled)) {
                ++server->worker_pool_hits;
                connection->direct_wss = 1;
                ++server->active_wss_connections;
                uint64_t local_failures = buffer_failures(server);
                if (attach_pooled_worker(connection, &pooled) == 0)
                    return 0;
                if (buffer_failures(server) != local_failures) return -1;
                clear_route_attempt(connection, 1);
                continue;
            }
            ++server->worker_pool_misses;
        }
        connection->direct_wss = 1;
        connection->wss_phase = WSS_NONE;
        ++server->active_wss_connections;
        if (begin_upstream(connection, &target) == 0) {
            if (!connection->connecting)
                route_session_event(connection, step.kind,
                                    TG_ROUTE_SESSION_CONNECTED);
            connection->wss_deadline_ms = monotonic_ms() + wss_timeout_ms(connection);
            return 0;
        }
        clear_route_attempt(connection, 1);
    }
    if (!connection->route_failure_recorded)
        route_failure_record(connection, TG_ROUTE_NONE,
                             TG_EPOLL_FAILURE_ROUTE_UNAVAILABLE);
    return -1;
}

static int advance_route(proxy_connection *connection) {
    if (!connection || connection->closed || !connection->direct_wss ||
        connection->route_data_seen ||
        (connection->wss_replay_disabled &&
         connection->wss_client_payload_started)) return -1;
    clear_route_attempt(connection, 1);
    return start_next_route(connection);
}

static size_t hedge_candidate_count(const proxy_connection *connection) {
    size_t count = 0;
    for (size_t i = 0; i < TG_HEDGE_CANDIDATES; ++i)
        if (connection->hedges[i]) ++count;
    return count;
}

static size_t hedge_connection_count(const tg_epoll_proxy *server) {
    size_t count = 0;
    for (const proxy_connection *connection = server->connections; connection;
         connection = connection->next)
        if (connection->route_racing) ++count;
    return count;
}

static size_t hedge_worker_index(const proxy_connection *parent) {
    for (size_t i = parent->route_index; i < parent->route_plan.count; ++i)
        if (parent->route_plan.steps[i].kind == TG_ROUTE_CF_WORKER) return i;
    return parent->route_plan.count;
}

static size_t hedge_next_index(const proxy_connection *parent) {
    size_t direct = 0, worker = 0, cf = 0, cf_index = 0;
    for (size_t i = 0; i < TG_HEDGE_CANDIDATES; ++i) {
        const proxy_connection *candidate = parent->hedges[i];
        if (!candidate) continue;
        if (candidate->route_kind == TG_ROUTE_DIRECT_WSS) ++direct;
        else if (candidate->route_kind == TG_ROUTE_CF_WORKER) ++worker;
        else if (candidate->route_kind == TG_ROUTE_CF_PROXY) {
            ++cf;
            cf_index = candidate->hedge_step_index / 2u;
        }
    }
    if (parent->server->config.cloudflare_only && cf && !worker) {
        size_t index = hedge_worker_index(parent);
        if (index < parent->route_plan.count) return index;
    }
    size_t next_direct = parent->route_plan.count;
    size_t next_cf = parent->route_plan.count;
    for (size_t i = parent->route_index; i < parent->route_plan.count; ++i) {
        tg_route_step step = parent->route_plan.steps[i];
        if (step.kind == TG_ROUTE_DIRECT_TCP) break;
        if (step.kind == TG_ROUTE_DIRECT_WSS) {
            if (direct < 2 && next_direct == parent->route_plan.count) next_direct = i;
        } else if ((!worker || parent->server->config.cloudflare_only) &&
                   next_cf == parent->route_plan.count) {
            if ((step.kind == TG_ROUTE_CF_WORKER && !cf && !worker) ||
                (step.kind == TG_ROUTE_CF_PROXY && cf < 2 &&
                 (!cf || cf_index != step.index / 2u)))
                next_cf = i;
        }
    }
    /* Give an unopened branch its first candidate before racing alternatives. */
    if (direct && !worker && !cf && next_cf < parent->route_plan.count)
        return next_cf;
    if (!direct && (worker || cf) && next_direct < parent->route_plan.count)
        return next_direct;
    return next_direct < next_cf ? next_direct : next_cf;
}

static int hedge_launch_next(proxy_connection *parent) {
    tg_epoll_proxy *server = parent->server;
    if (server->active_wss_connections >= server->max_wss_connections)
        return 0;
    size_t worker_after_pending_proxy = parent->route_plan.count;
    while (parent->route_index < parent->route_plan.count) {
        size_t index = worker_after_pending_proxy < parent->route_plan.count
            ? worker_after_pending_proxy : hedge_next_index(parent);
        worker_after_pending_proxy = parent->route_plan.count;
        if (index == parent->route_plan.count) return 0;
        tg_route_step step = parent->route_plan.steps[index];
        if (step.kind == TG_ROUTE_DIRECT_TCP) return 0;
        if (index > parent->route_index) {
            memmove(&parent->route_plan.steps[parent->route_index + 1],
                    &parent->route_plan.steps[parent->route_index],
                    (index - parent->route_index) * sizeof(step));
            parent->route_plan.steps[parent->route_index] = step;
        }
        ++parent->route_index;
        if (!server->config.enable_direct_wss) continue;

        proxy_connection *candidate = calloc(1, sizeof(*candidate));
        if (!candidate) {
            ++server->allocation_failures;
            return 0;
        }
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
        candidate->hedge_step_index = step.index;
        candidate->wss_proto = parent->wss_proto;
        memcpy(candidate->handshake, parent->handshake,
               sizeof(candidate->handshake));
        int dns_failure = 0, route_cooldown = 0;
        int setup_status = setup_route_attempt(candidate, &step,
            &candidate->upstream_target, &dns_failure, &route_cooldown);
        if (setup_status == 1) {
            --parent->route_index;
            free(candidate);
            if (server->config.cloudflare_only && !hedge_candidate_count(parent) &&
                step.kind == TG_ROUTE_CF_PROXY) {
                size_t worker = hedge_worker_index(parent);
                if (worker < parent->route_plan.count) {
                    /* Try a ready Worker while the primary resolves. */
                    worker_after_pending_proxy = worker;
                    continue;
                }
            }
            if (server->config.cloudflare_only && step.kind == TG_ROUTE_CF_WORKER &&
                index > parent->route_index) {
                memmove(&parent->route_plan.steps[parent->route_index],
                        &parent->route_plan.steps[parent->route_index + 1],
                        (index - parent->route_index) * sizeof(step));
                parent->route_plan.steps[index] = step;
            }
            return 0;
        }
        if (route_cooldown) {
            route_session_event(parent, step.kind,
                                TG_ROUTE_SESSION_COOLDOWN);
            free(candidate);
            continue;
        }
        if (setup_status != 0 ||
            (server->config.enforce_self_dial &&
             tg_listener_is_self_dial_addr(&candidate->upstream_target,
                                           server->listen_ports,
                                           server->config.listen_port_count))) {
            if (dns_failure) {
                candidate->route_health_index =
                    route_health_get(server, candidate, 1);
                if (candidate->route_health_index >= 0)
                    route_health_cooldown_at(candidate,
                                             TG_EPOLL_FAILURE_DNS);
                else
                    route_failure_record(candidate, step.kind,
                                         TG_EPOLL_FAILURE_DNS);
            } else {
                route_failure_record(candidate, step.kind,
                                     TG_EPOLL_FAILURE_SETUP);
            }
            route_session_event(candidate, step.kind,
                                TG_ROUTE_SESSION_FAILED);
            free(candidate);
            continue;
        }
        size_t slot = 0;
        while (slot < TG_HEDGE_CANDIDATES && parent->hedges[slot]) ++slot;
        if (slot == TG_HEDGE_CANDIDATES) {
            free(candidate);
            return 0;
        }
        int health_index = route_health_get(server, candidate, 1);
        if (health_index >= 0) {
            route_health *health = &server->route_health[health_index];
            if (health->cooldown_until_ms > monotonic_ms() &&
                !candidate->direct_recovery_probe) {
                route_session_event(parent, step.kind,
                                    TG_ROUTE_SESSION_COOLDOWN);
                free(candidate);
                continue;
            }
            health->upstream_port = candidate->upstream_target.port;
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
            candidate->wss_deadline_ms = monotonic_ms() + wss_timeout_ms(candidate);
            return 1;
        }
        route_session_event(candidate, step.kind, TG_ROUTE_SESSION_CONNECTING);
        route_failure_record(candidate, step.kind, TG_EPOLL_FAILURE_TCP);
        route_session_event(candidate, step.kind, TG_ROUTE_SESSION_FAILED);
        hedge_retire_candidate(candidate, 1);
    }
    return 0;
}

static int hedge_fill(proxy_connection *parent, int fill_second_slot) {
    size_t current = hedge_candidate_count(parent);
    size_t wanted = current;
    if (!current || (fill_second_slot && current < TG_HEDGE_CANDIDATES)) ++wanted;
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
    size_t next_index = hedge_next_index(parent);
    if (current < TG_HEDGE_CANDIDATES && next_index < parent->route_plan.count &&
        parent->route_plan.steps[next_index].kind != TG_ROUTE_DIRECT_TCP &&
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
    if (connection->upstream_fd >= 0) {
        uint32_t events = connection->upstream_eof ? 0 : upstream_events(connection);
        if (!events) {
            watch_remove(server, &connection->upstream_watch);
        } else if (watch_update(server, &connection->upstream_watch, events) != 0) {
            connection_close(connection);
        }
    }
}

static int hedge_promote_candidate(proxy_connection *candidate) {
    proxy_connection *parent = candidate->hedge_parent;
    if (!parent || parent->closed) return -1;
    int flush_rc = hedge_candidate_flush_buffered_payload(candidate);
    if (flush_rc != 0 ||
        candidate->hedge_payload_offset != parent->to_upstream.len) {
        return -1;
    }
    if (candidate->to_client.len &&
        queue_append_grow(parent, &parent->to_client,
                          candidate->to_client.data + candidate->to_client.head,
                          candidate->to_client.len,
                          TG_MTPROTO_MAX_PACKET) != 0) {
        return -1;
    }
    tg_epoll_proxy *server = parent->server;
    for (size_t i = 0; i < TG_HEDGE_CANDIDATES; ++i)
        if (parent->hedges[i] == candidate) parent->hedges[i] = NULL;
    candidate->hedge_parent = NULL;
    watch_remove(server, &candidate->upstream_watch);

    parent->upstream_fd = candidate->upstream_fd;
    parent->upstream_ssl = candidate->upstream_ssl;
    parent->ws_pump = candidate->ws_pump;
    parent->wss_read_paused_at_ms = candidate->wss_read_paused_at_ms;
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
    parent->route_data_seen = candidate->route_data_seen;
    parent->route_response_seen = candidate->route_response_seen;
    if (parent->route_tcp_only) parent->response_observer_disabled = 1;
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
    parent->wss_deadline_ms = candidate->wss_deadline_ms;
    memcpy(parent->tls_hostname, candidate->tls_hostname,
           sizeof(parent->tls_hostname));
    memcpy(parent->wss_path, candidate->wss_path, sizeof(parent->wss_path));
    parent->upstream_watch = (socket_watch){
        .kind = 2, .connection = parent, .side = 1,
        .fd = parent->upstream_fd
    };
    parent->wss_forwarded_offset = candidate->hedge_payload_offset;
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
    int progress_rc = progress_wss(parent, EPOLLOUT);
    if (progress_rc != 0) {
        connection_close(parent);
        return 0;
    }
    advance_half_closes(parent);
    connection_update(parent);
    return 0;
}

static void advance_half_closes(proxy_connection *connection) {
    if (!connection || connection->closed) return;
    if (connection->direct_wss && connection->upstream_eof)
        connection->next_ping_ms = 0;
    if (connection->direct_wss && !connection->upstream_eof &&
        connection->client_eof && !connection->upstream_shutdown && connection->wss_phase == WSS_READY) {
        int split_rc = connection->packet_framing
            ? tg_mtproto_splitter_flush(&connection->splitter,
                                        queue_wss_packet, connection)
            : TG_MTPROTO_SPLIT_OK;
        if (split_rc != TG_MTPROTO_SPLIT_OK ||
            (!connection->wss_close_queued &&
             tg_ws_pump_queue_close(&connection->ws_pump) != 0)) {
            connection_close(connection);
            return;
        }
        connection->wss_close_queued = 1;
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
        if (connection->direct_wss) connection->last_activity_ms = monotonic_ms();
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
    connection->route_failure_recorded = 0;
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
    const tg_config *routing = server->config.routing_config;
    tg_route_only route_only = routing ? routing->route_only : TG_ROUTE_ONLY_AUTO;
    if (routing) policy = routing->ws_routing;
    have_preferred = route_health_preferred_step(server, connection, &preferred);
    if (server->config.cloudflare_only) {
        if (selection.tcp_only) {
            /* Production's transparent selector has already checked the DC
             * map or Telegram CIDRs and the original destination port. */
            if (validated && (connection->original.port == 443 ||
                              connection->original.port == 5222))
                worker_count = route_worker_count(server);
        } else if (selection.dc_id) {
            worker_count = route_worker_count(server);
            cf_count = route_cf_domain_count(server);
        }
        if (tg_route_plan_build_cloudflare(connection->route_is_media,
                worker_count, cf_count, &connection->route_plan) != 0)
            return -1;
    } else {
        if (selection.dc_id && !selection.tcp_only) {
            worker_count = route_worker_count(server);
            cf_count = route_cf_domain_count(server);
        }
        int allow_tcp = selection.tcp_only || route_only == TG_ROUTE_ONLY_TCP ||
            (routing && (routing->tcp_fallback_timeout_secs ||
                         routing->diagnostic_direct_tcp));
        int prefer_cf = policy == TG_WS_ROUTING_ADAPTIVE && have_preferred &&
            preferred.kind == TG_ROUTE_CF_PROXY;
        if (tg_route_plan_build(selection.tcp_only ? 0 : connection->route_dc_id,
                connection->route_is_media, policy, prefer_cf,
                worker_count, cf_count, allow_tcp, &connection->route_plan) != 0)
            return -1;
    }
    if (routing && routing->cf_balance) {
        size_t worker_offset = worker_count
            ? server->worker_balance_offset++ % worker_count : 0;
        size_t cf_offset = cf_count ? server->cf_balance_offset++ % cf_count : 0;
        for (size_t i = 0; i < connection->route_plan.count; ++i) {
            tg_route_step *step = &connection->route_plan.steps[i];
            if (step->kind == TG_ROUTE_CF_WORKER)
                step->index = (uint8_t)((step->index + worker_offset) % worker_count);
            else if (step->kind == TG_ROUTE_CF_PROXY)
                step->index = (uint8_t)(2u * ((step->index / 2u + cf_offset) % cf_count) +
                    step->index % 2u);
        }
    }
    if (route_only != TG_ROUTE_ONLY_AUTO &&
        route_plan_keep_only(&connection->route_plan, route_only) != 0) {
        route_failure_record(connection, TG_ROUTE_NONE,
                             TG_EPOLL_FAILURE_ROUTE_UNAVAILABLE);
        return -1;
    }
    if (!connection->route_plan.count) {
        route_failure_record(connection, TG_ROUTE_NONE,
                             TG_EPOLL_FAILURE_ROUTE_UNAVAILABLE);
        return -1;
    }
    if (policy == TG_WS_ROUTING_ADAPTIVE && have_preferred)
        route_plan_prioritize(&connection->route_plan, &preferred);
    uint32_t hedge_limit = server->config.routing_config
        ? server->config.routing_config->ws_hedge_limit : 0;
    int adaptive_hedge = policy == TG_WS_ROUTING_ADAPTIVE &&
        route_only == TG_ROUTE_ONLY_AUTO && !have_preferred &&
        connection->route_plan.count > 1;
    if ((policy == TG_WS_ROUTING_HEDGED || adaptive_hedge) && hedge_limit > 0 &&
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
            size_t queue_limit = connection->server->config.queue_bytes;
            size_t free_bytes = connection->to_upstream.len < queue_limit
                ? queue_limit - connection->to_upstream.len : 0;
            if (!free_bytes && connection->direct_wss &&
                !connection->route_racing &&
                !connection->route_data_seen &&
                !connection->wss_replay_disabled) {
                connection->wss_replay_disabled = 1;
                clear_wss_replay(connection);
                free_bytes = queue_limit;
            }
            if (!free_bytes) return 0;
            if (capacity > free_bytes) capacity = free_bytes;
        }
        if (connection->direct_wss && !connection->route_response_seen)
            set_tcp_quickack(connection->client_fd);
        ssize_t n = recv(connection->client_fd, buffer, capacity, 0);
        if (n > 0) {
            add_bytes(&connection->server->bytes_from_clients, (size_t)n);
            route_session_add_bytes(connection, 1, (size_t)n);
            connection->last_activity_ms = monotonic_ms();
            if (!connection->handshake_done) {
                memcpy(connection->handshake + connection->handshake_len,
                       buffer, (size_t)n);
                connection->handshake_len += (size_t)n;
                if (connection->handshake_len == sizeof(connection->handshake) &&
                    route_after_handshake(connection) != 0) {
                    if (!connection->route_failure_recorded)
                        route_failure_record(connection, connection->route_kind,
                                             TG_EPOLL_FAILURE_SETUP);
                    return -1;
                }
                if (connection->route_dns_pending) return 0;
            } else if (connection->route_racing) {
                if (queue_append_grow(connection, &connection->to_upstream,
                                     buffer, (size_t)n,
                                     connection->server->config.queue_bytes) != 0)
                    return -1;
                connection->wss_client_payload_started = 1;
                for (size_t i = 0; i < TG_HEDGE_CANDIDATES; ++i) {
                    proxy_connection *candidate = connection->hedges[i];
                    if (!candidate || candidate->wss_phase != WSS_READY)
                        continue;
                    if (hedge_promote_candidate(candidate) != 0) {
                        hedge_fail_candidate(candidate);
                        if (connection->closed) return -1;
                    }
                    break;
                }
            } else if (connection->direct_wss
                           ? queue_wss_replay_payload(connection, buffer,
                                                      (size_t)n) != 0
                           : process_client_payload(connection, buffer,
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
        size_t queue_limit = connection->server->config.queue_bytes;
        size_t free_bytes = connection->to_client.len < queue_limit
            ? queue_limit - connection->to_client.len : 0;
        if (!free_bytes) return 0;
        size_t capacity = free_bytes < sizeof(buffer) ? free_bytes : sizeof(buffer);
        ssize_t n = recv(connection->upstream_fd, buffer, capacity, 0);
        if (n > 0) {
            add_bytes(&connection->server->bytes_from_upstreams, (size_t)n);
            route_session_add_bytes(connection, 0, (size_t)n);
            connection->last_activity_ms = monotonic_ms();
            if (queue_append_grow(connection, &connection->to_client,
                                  buffer, (size_t)n, queue_limit) != 0)
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
    return tg_ws_pump_queue_mtproto_payload(&connection->ws_pump, packet,
                                            packet_len);
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
        return tg_ws_pump_queue_mtproto_payload(&connection->ws_pump, buffer,
                                                length);
    }
    return queue_append_grow(connection, &connection->to_upstream, buffer,
                             length,
                             connection->server->config.queue_bytes);
}

static void clear_wss_replay(proxy_connection *connection) {
    queue_release(connection, &connection->to_upstream);
    connection->wss_forwarded_offset = 0;
}

static void disable_wss_replay_after_payload_write(
    proxy_connection *connection) {
    if (!connection || !connection->direct_wss ||
        !connection->ws_pump.mtproto_payload_write_attempted ||
        connection->wss_replay_disabled)
        return;
    connection->wss_replay_disabled = 1;
    clear_wss_replay(connection);
}

static int queue_wss_replay_payload(proxy_connection *connection,
                                    uint8_t *buffer, size_t length) {
    connection->wss_client_payload_started = 1;
    if (!connection->wss_replay_disabled &&
        !connection->route_data_seen) {
        if (queue_append_grow(connection, &connection->to_upstream, buffer,
                              length,
                              connection->server->config.queue_bytes) == 0) {
            if (process_client_payload(connection, buffer, length) != 0)
                return -1;
            connection->wss_forwarded_offset += length;
            return 0;
        }
        connection->wss_replay_disabled = 1;
        clear_wss_replay(connection);
    }
    return process_client_payload(connection, buffer, length);
}

static int flush_wss_replay(proxy_connection *connection) {
    if (!connection || !connection->direct_wss ||
        connection->wss_phase != WSS_READY ||
        connection->wss_replay_disabled || connection->route_data_seen)
        return 0;
    uint8_t buffer[TG_EPOLL_IO_CHUNK];
    while (connection->wss_forwarded_offset < connection->to_upstream.len) {
        size_t length = connection->to_upstream.len -
                        connection->wss_forwarded_offset;
        if (length > sizeof(buffer)) length = sizeof(buffer);
        memcpy(buffer, connection->to_upstream.data +
                        connection->to_upstream.head +
                        connection->wss_forwarded_offset, length);
        if (process_client_payload(connection, buffer, length) != 0)
            return -1;
        connection->wss_forwarded_offset += length;
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
    int response = 0;
    if (payload_len && !connection->route_data_seen) {
        connection->route_data_seen = 1;
        connection->wss_replay_disabled = 1;
        clear_wss_replay(connection);
    }
    if (!connection->response_observer_disabled) {
        response = observe_mtproto_response(connection, payload, payload_len);
        if (response < 0) connection->response_observer_disabled = 1;
    }
    if (response > 0 && !connection->route_response_seen) {
        connection->route_response_seen = 1;
        if (connection->from_worker_pool &&
            connection->server->worker_pool_responses != UINT64_MAX)
            ++connection->server->worker_pool_responses;
        record_client_response_latency(connection->server, connection);
        route_session_first_response(connection);
        if (connection->route_kind == TG_ROUTE_CF_PROXY) {
            const char *domain = strchr(connection->tls_hostname, '.');
            cf_rate_limit *limit = domain
                ? cf_domain_rate_limit(connection->server, domain + 1, 0) : NULL;
            if (limit) memset(limit, 0, sizeof(*limit));
        }
        if (connection->route_health_index >= 0) {
            route_health *health = &connection->server->route_health[
                (size_t)connection->route_health_index];
            uint64_t now = monotonic_ms();
            health->cooldown_until_ms = 0;
            uint64_t latency_ms = now >= connection->route_started_ms
                ? now - connection->route_started_ms : 0;
            if (health->last_success_ms && now - health->last_success_ms <= 120000)
                latency_ms = (health->latency_ms * 3 + latency_ms) / 4;
            health->last_success_ms = now;
            health->latency_ms = latency_ms;
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
    if (queue_append_grow(connection, &connection->to_client,
                          payload, payload_len,
                          TG_MTPROTO_MAX_PACKET) != 0)
        return -1;
    add_bytes(&connection->server->bytes_from_upstreams, payload_len);
    route_session_add_bytes(connection, 0, payload_len);
    connection->last_activity_ms = monotonic_ms();
    if (connection->to_client.len < connection->server->config.queue_bytes)
        return 0;
    connection->wss_read_paused_at_ms = connection->last_activity_ms;
    ++connection->server->wss_read_pauses;
    return 1;
}

static int establish_wss_stream(proxy_connection *connection) {
    if (connection->route_tcp_only) {
        connection->response_observer_disabled = 1;
    } else if (connection->wss_proto < TG_MTPROTO_ABRIDGED ||
               connection->wss_proto > TG_MTPROTO_PADDED_INTERMEDIATE ||
               tg_mtproto_direct_server_stream_cipher(connection->handshake,
                   &connection->server_decrypt) != 0) {
        return -1;
    }
    connection->response_header_needed =
        connection->wss_proto == TG_MTPROTO_ABRIDGED ? 0u : 4u;
    if (tg_ws_pump_init_accounted(&connection->ws_pump,
                                 connection->upstream_ssl,
                                 &connection->server->buffer_budget) != 0)
        return -1;
    connection->ws_pump_ready = 1;
    if (connection->packet_framing) {
        if (tg_mtproto_direct_stream_ciphers(connection->handshake,
                                             &connection->client_decrypt,
                                             &connection->client_encrypt) != 0)
            return -1;
        if (tg_mtproto_splitter_init_accounted(&connection->splitter,
                                     connection->wss_proto,
                                     &connection->server->buffer_budget) !=
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
    connection->wss_deadline_ms = monotonic_ms() +
        connection->server->config.handshake_timeout_ms;
    connection->last_activity_ms = monotonic_ms();
    connection->next_ping_ms = connection->last_activity_ms +
                               ws_ping_interval_ms;
    if (flush_wss_replay(connection) != 0) return -1;
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
                    worker_requires_5222(connection) ? TG_WORKER_5222_SUBPROTOCOL :
                    connection->wss_subprotocol ? "binary" : NULL,
                    connection->route_kind == TG_ROUTE_CF_WORKER
                        ? NULL : "https://web.telegram.org",
                    connection->route_kind == TG_ROUTE_CF_WORKER
                        ? NULL : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
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
            if (!connection->route_response_seen)
                set_tcp_quickack(connection->upstream_fd);
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
                    proxy_connection *parent = connection->hedge_parent;
                    if (parent->to_upstream.len >
                        connection->hedge_payload_offset)
                        return hedge_promote_candidate(connection);
                } else if (flush_wss_replay(connection) != 0) {
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
            if (events & (EPOLLIN | EPOLLRDHUP | EPOLLHUP))
                revents |= POLLIN;
            if (events & EPOLLOUT) revents |= POLLOUT;
            if ((events & EPOLLERR) && !(events & (EPOLLIN | EPOLLRDHUP |
                                                    EPOLLHUP)))
                revents |= POLLERR;
            if (events & (EPOLLHUP | EPOLLRDHUP)) revents |= POLLHUP;
            if (!connection->route_response_seen)
                set_tcp_quickack(connection->upstream_fd);
            uint64_t local_failures = buffer_failures(connection->server);
            int pump_rc = tg_ws_pump_process(&connection->ws_pump, revents,
                                             queue_wss_response, connection);
            disable_wss_replay_after_payload_write(connection);
            if (pump_rc != 0) {
                if (buffer_failures(connection->server) != local_failures) return -1;
                if (connection->route_data_seen) {
                    if (!connection->route_response_seen && !connection->route_tcp_only)
                        route_health_failed(connection);
                    connection->upstream_eof = 1;
                    advance_half_closes(connection);
                    return 0;
                }
                if (!connection->hedge_parent &&
                    advance_route(connection) == 0)
                    return 0;
                return -1;
            }
            if (connection->hedge_parent && connection->route_data_seen) {
                if (connection->ws_pump.closed)
                    connection->upstream_eof = 1;
                return hedge_promote_candidate(connection);
            }
            if (connection->ws_pump.closed) {
                if (connection->hedge_parent) {
                    hedge_fail_candidate(connection);
                    return 0;
                }
                if (!connection->route_data_seen &&
                    advance_route(connection) == 0)
                    return 0;
                if (!connection->route_data_seen) return -1;
                if (!connection->route_response_seen && !connection->route_tcp_only)
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

static void upstream_event(proxy_connection *connection, uint32_t events);

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
    if (connection->direct_wss && connection->upstream_eof) {
        if (events & (EPOLLRDHUP | EPOLLHUP)) connection->client_eof = 1;
    } else if (events & (EPOLLIN | EPOLLRDHUP | EPOLLHUP)) {
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
                    &connection->last_activity_ms,
                    connection) != 0) {
        connection_close(connection);
        return;
    }
    if (!connection->upstream_eof && connection->ws_pump.read_paused &&
        !connection->to_client.len) {
        connection->ws_pump.read_paused = 0;
        connection->wss_read_paused_at_ms = 0;
        ++connection->server->wss_read_resumes;
        /* TLS or the WS parser may already hold the next complete frame. */
        upstream_event(connection, EPOLLIN);
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
            if (!connection->direct_wss &&
                connection->route_kind == TG_ROUTE_DIRECT_TCP) {
                mark_ip_failure(connection);
                route_failure_record(connection, connection->route_kind,
                                     TG_EPOLL_FAILURE_TCP);
            }
            if (!connection->direct_wss)
                route_session_event(connection, connection->route_kind,
                                    TG_ROUTE_SESSION_FAILED);
            connection_close(connection);
            return;
        }
        connection->connecting = 0;
        connection->upstream_connect_deadline_ms = 0;
        if (!connection->direct_wss) {
            route_health *ip = ip_health(connection, 0);
            if (ip) ip->cooldown_until_ms = ip->next_probe_ms = 0;
            route_session_event(connection, connection->route_kind,
                                TG_ROUTE_SESSION_CONNECTED);
        }
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
        int wss_may_have_buffered_data =
            connection->wss_phase == WSS_READY &&
            (events & (EPOLLIN | EPOLLRDHUP | EPOLLHUP));
        int failed = (events & EPOLLERR) && !wss_may_have_buffered_data &&
                     socket_error(connection->upstream_fd) != 0;
        if ((events & (EPOLLHUP | EPOLLRDHUP)) &&
            connection->wss_phase != WSS_READY)
            failed = 1;
        uint64_t local_failures = buffer_failures(connection->server);
        if (!failed && progress_wss(connection, events) != 0) failed = 1;
        if (failed && buffer_failures(connection->server) != local_failures) {
            /* A local limit must not poison the shared Cloudflare route.
             * Finish any queued reply and release the terminal stream. */
            if (connection->hedge_parent) {
                proxy_connection *parent = connection->hedge_parent;
                hedge_retire_candidate(connection, 0);
                if (!hedge_candidate_count(parent)) connection_close(parent);
            } else {
                connection->upstream_eof = 1;
                advance_half_closes(connection);
                connection_update(connection);
            }
            return;
        }
        if (!failed && wss_may_have_buffered_data &&
            (events & EPOLLERR) && !connection->closed &&
            connection->wss_phase == WSS_READY &&
            !connection->ws_pump.read_paused &&
            socket_error(connection->upstream_fd) != 0)
            failed = 1;
        if (failed) {
            if (connection->hedge_parent) {
                hedge_fail_candidate(connection);
                return;
            }
            if (!connection->route_data_seen &&
                advance_route(connection) == 0) {
                connection_update(connection);
                return;
            }
            if (connection->route_data_seen) {
                if (!connection->route_response_seen && !connection->route_tcp_only)
                    route_health_failed(connection);
                connection->upstream_eof = 1;
                advance_half_closes(connection);
                if (connection->closed) return;
                connection_update(connection);
                return;
            }
            if (connection->wss_phase == WSS_READY)
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
        if (connection->route_kind == TG_ROUTE_DIRECT_TCP)
            route_failure_record(connection, connection->route_kind,
                                 TG_EPOLL_FAILURE_TCP);
        route_session_event(connection, connection->route_kind,
                            TG_ROUTE_SESSION_FAILED);
        connection_close(connection);
        return;
    }
    if (!connection->connecting && (events & (EPOLLIN | EPOLLRDHUP | EPOLLHUP))) {
        if (receive_upstream(connection) != 0) {
            if (connection->route_kind == TG_ROUTE_DIRECT_TCP) {
                route_failure_record(connection, connection->route_kind,
                                     TG_EPOLL_FAILURE_TCP);
                route_session_event(connection, connection->route_kind,
                                    TG_ROUTE_SESSION_FAILED);
            }
            connection_close(connection);
            return;
        }
    }
    if (connection->closed) return;
    if (!connection->connecting && (events & EPOLLOUT) &&
        queue_flush(connection->upstream_fd, &connection->to_upstream,
                    &connection->last_activity_ms,
                    connection) != 0) {
        if (connection->route_kind == TG_ROUTE_DIRECT_TCP)
            route_failure_record(connection, connection->route_kind,
                                 TG_EPOLL_FAILURE_TCP);
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

static int accept_clients(tg_epoll_proxy *server) {
    for (;;) {
        int fd = accept4(server->listener_fd, NULL, NULL,
                         SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
            int error = errno;
            if (error == EINTR) continue;
            if (error == EAGAIN || error == EWOULDBLOCK) return 0;
            if (error == EMFILE || error == ENFILE) ++server->accept_fd_exhaustion;
            if (error == ENOMEM || error == ENOBUFS) ++server->allocation_failures;
            if (error != EMFILE && error != ENFILE && ++server->accept_errors >= 5) {
                if (server->accept_rebinds >= 3) return -1;
                ++server->accept_rebinds;
                return TG_EPOLL_REBIND_LISTENER;
            }
            watch_remove(server, &server->listener_watch);
            server->accept_retry_at_ms = monotonic_ms() +
                (error == EMFILE || error == ENFILE ? 500u : 50u);
            return 0;
        }
        server->accept_errors = 0;
        server->accept_rebinds = 0;
        set_tcp_nodelay(fd);
        if (server->active_connections >= server->max_connections) {
            ++server->accept_limit_rejections;
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
            ++server->allocation_failures;
            close(fd);
            continue;
        }
        connection->server = server;
        connection->client_fd = fd;
        connection->upstream_fd = -1;
        connection->route_health_index = -1;
        connection->original = original;
        connection->accepted_at_us = monotonic_us();
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
        connection->route_session.id = server->connections_started;
        if (server->tracked_sessions < TG_EPOLL_MAX_ACTIVE_ROUTE_SESSIONS) {
            connection->route_session_tracked = 1;
            connection->route_session.stage = TG_ROUTE_SESSION_STAGE_ACCEPTED;
            connection->route_session.direct_state = TG_ROUTE_SESSION_IDLE;
            connection->route_session.fallback_state = TG_ROUTE_SESSION_IDLE;
            connection->route_session.next_event_sequence = 1;
            connection->route_session.started_ms = monotonic_ms();
            connection->route_session.no_progress_ms =
                connection->route_session.started_ms;
            ++server->tracked_sessions;
        }
        if (watch_update(server, &connection->client_watch,
                         client_events(connection)) != 0)
            connection_close(connection);
    }
}

static int wss_waiting_for_first_response(const proxy_connection *connection) {
    return connection && connection->direct_wss && !connection->upstream_eof &&
           !connection->route_data_seen;
}

static uint64_t client_idle_deadline(const proxy_connection *connection) {
    uint32_t timeout = connection->server->config.idle_timeout_ms;
    uint32_t close_timeout = connection->server->config.handshake_timeout_ms;
    /* Give TCP a short graceful close after a terminal WebSocket. A client
     * which never sends FIN must not keep a slot for the full idle timeout. */
    if (connection->direct_wss && connection->upstream_eof &&
        connection->client_shutdown && timeout > close_timeout)
        timeout = close_timeout;
    return connection->last_activity_ms + timeout;
}

static int timeout_until_expiry(tg_epoll_proxy *server, int timeout_ms) {
    uint64_t now = monotonic_ms(), nearest = server->accept_retry_at_ms
        ? server->accept_retry_at_ms : UINT64_MAX;
    for (proxy_connection *connection = server->connections; connection;
         connection = connection->next) {
        uint64_t expires = connection->route_dns_pending
            ? connection->route_dns_retry_at_ms
            : wss_waiting_for_first_response(connection)
                ? connection->wss_deadline_ms
                : connection->handshake_done
                    ? client_idle_deadline(connection)
                    : connection->handshake_deadline_ms;
        if (connection->wss_phase == WSS_READY && connection->next_ping_ms &&
            connection->next_ping_ms < expires)
            expires = connection->next_ping_ms;
        if (connection->route_dns_pending &&
            connection->route_dns_deadline_ms < expires)
            expires = connection->route_dns_deadline_ms;
        if (connection->connecting &&
            connection->upstream_connect_deadline_ms &&
            connection->upstream_connect_deadline_ms < expires)
            expires = connection->upstream_connect_deadline_ms;
        if (expires < nearest) nearest = expires;
        if (connection->hedge_due_ms && connection->hedge_due_ms < nearest)
            nearest = connection->hedge_due_ms;
        for (size_t i = 0; i < TG_HEDGE_CANDIDATES; ++i) {
            const proxy_connection *candidate = connection->hedges[i];
            if (candidate) {
                uint64_t expires = wss_waiting_for_first_response(candidate)
                    ? candidate->wss_deadline_ms
                    : candidate->last_activity_ms +
                      server->config.idle_timeout_ms;
                if (candidate->wss_phase == WSS_READY &&
                    candidate->next_ping_ms &&
                    candidate->next_ping_ms < expires)
                    expires = candidate->next_ping_ms;
                if (candidate->connecting &&
                    candidate->upstream_connect_deadline_ms &&
                    candidate->upstream_connect_deadline_ms < expires)
                    expires = candidate->upstream_connect_deadline_ms;
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
        for (size_t i = 0; i < TG_HEDGE_CANDIDATES && !connection->closed; ++i) {
            proxy_connection *candidate = connection->hedges[i];
            if (candidate) {
                if (candidate->wss_phase == WSS_READY &&
                    candidate->next_ping_ms &&
                    now >= candidate->next_ping_ms) {
                    if (tg_ws_pump_queue_ping(&candidate->ws_pump,
                                              (const uint8_t *)"d2k", 3) != 0) {
                        hedge_fail_candidate(candidate);
                        break;
                    }
                    candidate->next_ping_ms = now + ws_ping_interval_ms;
                    if (watch_update(server, &candidate->upstream_watch,
                                     upstream_events(candidate)) != 0) {
                        hedge_fail_candidate(candidate);
                        break;
                    }
                }
                uint64_t expires = wss_waiting_for_first_response(candidate)
                    ? candidate->wss_deadline_ms
                    : candidate->last_activity_ms +
                      server->config.idle_timeout_ms;
                if (candidate->wss_phase == WSS_READY &&
                    candidate->next_ping_ms &&
                    candidate->next_ping_ms < expires)
                    expires = candidate->next_ping_ms;
                if (candidate->connecting &&
                    candidate->upstream_connect_deadline_ms &&
                    candidate->upstream_connect_deadline_ms < expires)
                    expires = candidate->upstream_connect_deadline_ms;
                if (now >= expires) {
                    if (candidate->connecting &&
                        candidate->route_kind == TG_ROUTE_DIRECT_WSS)
                        mark_ip_failure(candidate);
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
        if (connection->wss_phase == WSS_READY && connection->next_ping_ms &&
            now >= connection->next_ping_ms) {
            if (tg_ws_pump_queue_ping(&connection->ws_pump,
                                      (const uint8_t *)"d2k", 3) != 0) {
                connection_close(connection);
                connection = next;
                continue;
            }
            connection->next_ping_ms = now + ws_ping_interval_ms;
            connection_update(connection);
            if (connection->closed) {
                connection = next;
                continue;
            }
        }
        if (connection->route_dns_pending) {
            if (now >= connection->route_dns_deadline_ms) {
                connection->route_dns_pending = 0;
                connection->route_dns_retry_at_ms = 0;
                connection->route_dns_event_active = 0;
                connection->route_index =
                    connection->route_dns_step_index + 1u;
                route_failure_record(connection, connection->route_kind,
                                     TG_EPOLL_FAILURE_DNS);
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
        if (connection->connecting &&
            connection->upstream_connect_deadline_ms &&
            now >= connection->upstream_connect_deadline_ms) {
            if (connection->route_kind == TG_ROUTE_DIRECT_WSS ||
                connection->route_kind == TG_ROUTE_DIRECT_TCP)
                mark_ip_failure(connection);
            if (connection->direct_wss && advance_route(connection) == 0) {
                connection_update(connection);
            } else if (!connection->direct_wss) {
                route_failure_record(connection, connection->route_kind,
                                     TG_EPOLL_FAILURE_TCP);
                route_session_event(connection, connection->route_kind,
                                    TG_ROUTE_SESSION_FAILED);
                connection_close(connection);
            } else {
                connection_close(connection);
            }
            connection = next;
            continue;
        }
        int awaiting_first_response = connection->direct_wss && !connection->upstream_eof &&
            (connection->wss_phase != WSS_READY ||
             !connection->route_data_seen);
        int expired = awaiting_first_response
            ? now >= connection->wss_deadline_ms
            : connection->handshake_done
                ? now >= client_idle_deadline(connection)
                : now >= connection->handshake_deadline_ms;
        if (expired && awaiting_first_response &&
            advance_route(connection) == 0) {
            connection_update(connection);
        } else if (expired) {
            if (connection->ws_pump.read_paused && !connection->upstream_eof)
                ++server->wss_paused_timeouts;
            if (connection->direct_wss && !connection->upstream_eof &&
                !connection->route_data_seen)
                route_health_failed(connection);
            connection_close(connection);
        }
        connection = next;
    }
}

void tg_epoll_proxy_update_limits(tg_epoll_proxy *server, size_t connection_limit,
                                  size_t memory_headroom_bytes, size_t memory_ceiling_bytes) {
    if (!server) return;
    server->memory_headroom_bytes = memory_headroom_bytes;
    server->memory_ceiling_bytes = memory_ceiling_bytes;
    const tg_epoll_proxy_config *config = &server->config;
    const size_t connection_reserve =
        sizeof(proxy_connection) + TG_EPOLL_RUNTIME_RESERVE_PER_CONNECTION;
    size_t memory_per_connection = connection_reserve;
    if (config->enable_direct_wss)
        memory_per_connection += TG_WS_PUMP_RX_INITIAL;
    if (connection_limit > config->configured_max_connections)
        connection_limit = config->configured_max_connections;
    size_t hedge_limit = config->routing_config
        ? config->routing_config->ws_hedge_limit : 0;
    if (hedge_limit > connection_limit) hedge_limit = connection_limit;
    size_t used = server->buffer_budget.used;
    size_t ceiling_room = memory_ceiling_bytes > used ? memory_ceiling_bytes - used : 0;
    size_t headroom = memory_headroom_bytes < ceiling_room ? memory_headroom_bytes : ceiling_room;
    size_t active_reservation = server->active_connections * memory_per_connection;
    size_t slot_budget = ceiling_room;
    if (active_reservation < ceiling_room && headroom < ceiling_room - active_reservation)
        slot_budget = active_reservation + headroom;
    server->max_connections = tg_limits_auto_max_connections(
        tg_limits_soft_nofile(), slot_budget, memory_per_connection,
        hedge_limit * (TG_HEDGE_CANDIDATES - 1u), connection_limit);

    /* MemAvailable is net of live allocations. Charge only unoccupied
     * slots against that headroom, while the device ceiling covers every
     * slot and all buffers. A smaller sample never revokes allocated bytes. */
    size_t reserved_slots = server->max_connections;
    if (reserved_slots < server->active_connections)
        reserved_slots = server->active_connections;
    size_t new_reservation = (reserved_slots - server->active_connections) * connection_reserve;
    size_t base_reservation = reserved_slots * connection_reserve;
    size_t room = headroom > new_reservation ? headroom - new_reservation : 0;
    ceiling_room = ceiling_room > base_reservation ? ceiling_room - base_reservation : 0;
    if (room > ceiling_room) room = ceiling_room;
    server->buffer_budget.limit = used + room;
    server->max_wss_connections = config->enable_direct_wss ? reserved_slots : 0;
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
    tg_epoll_proxy *server = calloc(1, sizeof(*server));
    if (!server) return NULL;
    server->epoll_fd = -1;
    server->listener_fd = config->listener_fd;
    server->config = *config;
    size_t initial_limit = config->initial_connection_limit
        ? config->initial_connection_limit : config->configured_max_connections;
    tg_epoll_proxy_update_limits(server, initial_limit, config->memory_budget_bytes,
                                 config->memory_budget_bytes);
    if (!server->max_connections) {
        free(server);
        errno = ENOMEM;
        return NULL;
    }
    time_t started = time(NULL);
    server->process_started_at = started > 0 ? (uint64_t)started : 0;
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
    server->worker_pool = worker_pool_start(&server->config, server->max_connections / 2u);
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
    worker_pool_stop(server->worker_pool);
    tg_route_dns_destroy(server->route_dns);
    free(server);
    return NULL;
}

int tg_epoll_proxy_set_listener(tg_epoll_proxy *server, int listener_fd) {
    if (!server || listener_fd < -1) return -1;
    if (listener_fd >= 0 && set_nonblocking(listener_fd) != 0) return -1;
    watch_remove(server, &server->listener_watch);
    server->listener_fd = listener_fd;
    server->listener_watch = (socket_watch){.kind = 0, .fd = listener_fd};
    server->accept_retry_at_ms = 0;
    server->accept_errors = 0;
    if (listener_fd >= 0 &&
        watch_update(server, &server->listener_watch, EPOLLIN) != 0) {
        server->listener_fd = -1;
        server->listener_watch.fd = -1;
        return -1;
    }
    return 0;
}

int tg_epoll_proxy_watch_stats(tg_epoll_proxy *server, int stats_fd) {
    if (!server || stats_fd < 0 || server->stats_watch.registered) {
        errno = EINVAL;
        return -1;
    }
    server->stats_watch.fd = stats_fd;
    return watch_update(server, &server->stats_watch, EPOLLIN);
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
    int accept_result = 0;
    if (count > 0) {
        for (int i = 0; i < count; ++i) {
            socket_watch *watch = events[i].data.ptr;
            if (!watch || watch == &server->stats_watch) continue;
            if (watch->kind == 0) {
                accept_result = accept_clients(server);
            } else if (watch->connection && watch->side == 0) {
                client_event(watch->connection, events[i].events);
            } else if (watch->connection) {
                upstream_event(watch->connection, events[i].events);
            }
        }
    }
    expire_connections(server);
    collect_retired(server);
    if (accept_result) return accept_result;
    if (server->accept_retry_at_ms &&
        monotonic_ms() >= server->accept_retry_at_ms) {
        server->accept_retry_at_ms = 0;
        if (watch_update(server, &server->listener_watch, EPOLLIN) != 0)
            return -1;
    }
    return count < 0 ? 0 : count;
}

void tg_epoll_proxy_destroy(tg_epoll_proxy *server) {
    if (!server) return;
    worker_pool_stop(server->worker_pool);
    while (server->connections) connection_close(server->connections);
    collect_retired(server);
    if (server->epoll_fd >= 0) close(server->epoll_fd);
    tg_route_dns_destroy(server->route_dns);
    free(server);
}

static void add_connection_memory_stats(const proxy_connection *connection,
                                        tg_epoll_proxy_stats *out) {
    if (!connection) return;
    out->connection_struct_bytes += sizeof(*connection);
    if (connection->client_fd >= 0) ++out->client_socket_fds;
    if (connection->upstream_fd >= 0) ++out->upstream_socket_fds;
    if (connection->upstream_ssl) ++out->tls_objects;
    out->client_queue_bytes += connection->to_client.len;
    out->upstream_queue_bytes += connection->to_upstream.len;
    out->client_queue_capacity_bytes += connection->to_client.dynamic_bytes;
    out->upstream_queue_capacity_bytes += connection->to_upstream.dynamic_bytes;
    if (connection->ws_pump_ready) {
        out->ws_rx_capacity_bytes += connection->ws_pump.rx_cap;
        out->ws_tx_memory_bytes += connection->ws_pump.tx_memory_bytes;
        out->ws_rx_capacity_bytes += connection->ws_pump.reassembly.cap;
    }
    if (connection->splitter_ready)
        out->mtproto_packet_capacity_bytes += connection->splitter.packet_cap;
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
    uint64_t now = monotonic_ms();
    out->monotonic_time_ms = now;
    out->route_cooldown_ms = TG_ROUTE_HEALTH_COOLDOWN_MS;
    out->active_connections = server->active_connections;
    out->process_started_at = server->process_started_at;
    out->proxy_struct_bytes = sizeof(*server);
    out->accepted_connections = server->connections_started;
    for (const proxy_connection *connection = server->connections; connection;
         connection = connection->next) {
        add_connection_memory_stats(connection, out);
        for (size_t j = 0; j < TG_HEDGE_CANDIDATES; ++j)
            if (connection->hedges[j])
                add_connection_memory_stats(connection->hedges[j], out);
        if (connection->ws_pump.read_paused && !connection->upstream_eof) {
            ++out->wss_reads_paused;
            uint64_t age = now - connection->wss_read_paused_at_ms;
            if (age > out->wss_oldest_pause_ms) out->wss_oldest_pause_ms = age;
        }
        if (!connection->route_session_tracked ||
            out->active_sessions_count >= TG_EPOLL_MAX_ACTIVE_ROUTE_SESSIONS)
            continue;
        size_t at = out->active_sessions_count++;
        out->active_sessions[at] = connection->route_session;
        tg_active_route_session *session = &out->active_sessions[at];
        session->client_port = connection->original.port;
        session->upstream_port = connection->upstream_target.port;
        if (connection->route_health_index >= 0 &&
            (size_t)connection->route_health_index < TG_ROUTE_HEALTH_MAX) {
            const route_health *health = &server->route_health[
                (size_t)connection->route_health_index];
            if (health->used) session->upstream_port = health->upstream_port;
        }
        session->age_ms = now >= session->started_ms
            ? now - session->started_ms : 0;
        session->no_progress_ms = now >= session->no_progress_ms
            ? now - session->no_progress_ms : 0;
        session->read_paused = (uint8_t)(connection->ws_pump.read_paused &&
                                         !connection->upstream_eof);
        session->client_queue_bytes = connection->to_client.len;
        session->upstream_queue_bytes = connection->to_upstream.len;
        session->client_queue_capacity_bytes = connection->to_client.dynamic_bytes;
        session->upstream_queue_capacity_bytes = connection->to_upstream.dynamic_bytes;
        session->ws_rx_capacity_bytes = connection->ws_pump_ready
            ? connection->ws_pump.rx_cap + connection->ws_pump.reassembly.cap : 0;
        session->ws_tx_memory_bytes = connection->ws_pump_ready
            ? connection->ws_pump.tx_memory_bytes : 0;
        session->mtproto_packet_capacity_bytes = connection->splitter_ready
            ? connection->splitter.packet_cap : 0;
    }
    for (const proxy_connection *connection = server->retired; connection;
         connection = connection->retired_next) {
        out->retired_connection_struct_bytes += sizeof(*connection);
        out->client_queue_bytes += connection->to_client.len;
        out->upstream_queue_bytes += connection->to_upstream.len;
        out->client_queue_capacity_bytes += connection->to_client.dynamic_bytes;
        out->upstream_queue_capacity_bytes += connection->to_upstream.dynamic_bytes;
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
    out->memory_headroom_bytes = server->memory_headroom_bytes;
    out->memory_ceiling_bytes = server->memory_ceiling_bytes;
    out->active_wss_connections = server->active_wss_connections;
    out->max_wss_connections = server->max_wss_connections;
    out->buffer_bytes_current = server->buffer_budget.used;
    out->buffer_bytes_peak = server->buffer_budget.peak;
    out->buffer_bytes_limit = server->buffer_budget.limit;
    out->accept_limit_rejections = server->accept_limit_rejections;
    out->accept_fd_exhaustion = server->accept_fd_exhaustion;
    out->allocation_failures = server->allocation_failures + server->buffer_budget.allocation_failures;
    out->buffer_budget_rejections = server->buffer_budget.rejections;
    out->buffer_size_rejections = server->buffer_budget.size_rejections;
    out->wss_read_pauses = server->wss_read_pauses;
    out->wss_read_resumes = server->wss_read_resumes;
    out->wss_paused_timeouts = server->wss_paused_timeouts;
    out->http_403 = server->http_403;
    out->http_501 = server->http_501;
    out->http_502 = server->http_502;
    out->last_http_status = server->last_http_status;
    memcpy(out->failure_by_stage, server->failure_by_stage,
           sizeof(out->failure_by_stage));
    out->connections_started = server->connections_started;
    out->bytes_from_clients = server->bytes_from_clients;
    out->bytes_from_upstreams = server->bytes_from_upstreams;
    out->wss_attempts = out->wss_failures = out->wss_responses =
        out->cf_wss_responses = 0;
    out->last_success_dc = server->last_success_dc;
    out->last_success_route = server->last_success_route;
    out->last_success_latency_ms = server->last_success_latency_ms;
    out->last_success_age_ms = server->last_success_ms &&
        now >= server->last_success_ms ? now - server->last_success_ms : 0;
    out->last_failure_dc = server->last_failure_dc;
    out->last_failure_route = server->last_failure_route;
    out->last_failure_stage = server->last_failure_stage;
    out->last_failure_age_ms = server->last_failure_ms &&
        now >= server->last_failure_ms ? now - server->last_failure_ms : 0;
    out->worker_pool_hits = server->worker_pool_hits;
    out->worker_pool_misses = server->worker_pool_misses;
    out->worker_pool_responses = server->worker_pool_responses;
    if (server->worker_pool) {
        worker_pool *pool = server->worker_pool;
        out->worker_pool_capacity = pool->capacity;
        out->worker_pool_struct_bytes = sizeof(*pool);
        pthread_mutex_lock(&pool->lock);
        out->worker_pool_started = pool->started;
        out->worker_pool_entries = pool->count;
        for (size_t i = 0; i < pool->capacity; ++i)
            if (pool->entries[i].ssl) {
                ++out->tls_objects;
                ++out->worker_pool_tls_objects;
            }
        pthread_mutex_unlock(&pool->lock);
    }
    out->client_response_latency_total =
        server->client_response_latency_total;
    out->client_response_latency_samples =
        server->client_response_latency_count;
    if (server->client_response_latency_count) {
        uint64_t samples[TG_CLIENT_LATENCY_SAMPLE_COUNT];
        size_t count = server->client_response_latency_count;
        size_t oldest = server->client_response_latency_count <
            TG_CLIENT_LATENCY_SAMPLE_COUNT ? 0 :
            server->client_response_latency_next;
        for (size_t i = 0; i < count; ++i)
            samples[i] = server->client_response_latency[
                (oldest + i) % TG_CLIENT_LATENCY_SAMPLE_COUNT];
        for (size_t i = 1; i < count; ++i) {
            uint64_t value = samples[i];
            size_t j = i;
            while (j && samples[j - 1u] > value) {
                samples[j] = samples[j - 1u];
                --j;
            }
            samples[j] = value;
        }
        size_t p50 = (count * 50u + 99u) / 100u - 1u;
        size_t p95 = (count * 95u + 99u) / 100u - 1u;
        out->client_response_latency_p50_us = samples[p50];
        out->client_response_latency_p95_us = samples[p95];
        out->client_response_latency_last_us = server->client_response_latency[
            (server->client_response_latency_next +
             TG_CLIENT_LATENCY_SAMPLE_COUNT - 1u) %
            TG_CLIENT_LATENCY_SAMPLE_COUNT];
    }
    for (size_t i = 0; i < TG_ROUTE_HEALTH_MAX; ++i) {
        const route_health *health = &server->route_health[i];
        if (!health->used) continue;
        add_u64(&out->wss_attempts, health->attempts);
        add_u64(&out->wss_failures, health->failures);
        add_u64(&out->wss_responses, health->responses);
        add_u64(&out->cf_wss_responses, health->cf_responses);
        if (out->route_health_count < TG_EPOLL_MAX_ROUTE_STATS) {
            tg_route_health_stat *route =
                &out->route_health[out->route_health_count++];
            route->dc = health->dc_id;
            route->client_port = health->original.port;
            route->upstream_port = health->upstream_port;
            route->is_media = (uint8_t)(health->is_media != 0);
            route->transport = health->transport;
            route->has_last_success = (uint8_t)(health->last_success_ms != 0);
            route->has_last_failure = (uint8_t)(health->last_failure_ms != 0);
            route->last_failure_stage = (uint8_t)health->last_failure_stage;
            route->attempts = health->attempts;
            route->failures = health->failures;
            route->responses = health->responses;
            route->cf_responses = health->cf_responses;
            route->latency_ms = health->latency_ms;
            route->last_success_age_ms = health->last_success_ms &&
                now >= health->last_success_ms ? now - health->last_success_ms : 0;
            route->last_failure_age_ms = health->last_failure_ms &&
                now >= health->last_failure_ms ? now - health->last_failure_ms : 0;
            route->cooldown_remaining_ms = health->cooldown_until_ms > now
                ? health->cooldown_until_ms - now : 0;
        } else {
            out->route_health_truncated = 1;
        }
        if (health->cooldown_until_ms <= now) continue;
        uint8_t transport = health->transport;
        if (transport == TG_ROUTE_SESSION_TRANSPORT_NONE) continue;
        if (out->route_cooldowns_count >= TG_EPOLL_MAX_ROUTE_COOLDOWNS) {
            out->route_cooldowns_truncated = 1;
            continue;
        }
        tg_route_cooldown *cooldown =
            &out->route_cooldowns[out->route_cooldowns_count++];
        cooldown->dc = health->dc_id;
        cooldown->is_media = (uint8_t)(health->is_media != 0);
        cooldown->transport = transport;
        cooldown->failure_stage = (uint8_t)health->last_failure_stage;
        cooldown->remaining_ms = health->cooldown_until_ms - now;
    }
    size_t problem_count = server->problem_session_total <
        TG_EPOLL_MAX_PROBLEM_SESSIONS ? (size_t)server->problem_session_total :
        TG_EPOLL_MAX_PROBLEM_SESSIONS;
    size_t problem_oldest = server->problem_session_total >
        TG_EPOLL_MAX_PROBLEM_SESSIONS
        ? (size_t)(server->problem_session_total % TG_EPOLL_MAX_PROBLEM_SESSIONS)
        : 0;
    out->problem_sessions_count = problem_count;
    for (size_t i = 0; i < problem_count; ++i)
        out->problem_sessions[i] = server->problem_sessions[
            (problem_oldest + i) % TG_EPOLL_MAX_PROBLEM_SESSIONS];
    return 0;
}

#else

struct tg_epoll_proxy { int unavailable; };

tg_epoll_proxy *tg_epoll_proxy_create(const tg_epoll_proxy_config *config) {
    (void)config;
    errno = ENOTSUP;
    return NULL;
}
void tg_epoll_proxy_update_limits(tg_epoll_proxy *server, size_t connection_limit,
                                  size_t memory_headroom_bytes, size_t memory_ceiling_bytes) {
    (void)server;
    (void)connection_limit;
    (void)memory_headroom_bytes;
    (void)memory_ceiling_bytes;
}
int tg_epoll_proxy_step(tg_epoll_proxy *server, int timeout_ms) {
    (void)server;
    (void)timeout_ms;
    errno = ENOTSUP;
    return -1;
}
int tg_epoll_proxy_watch_stats(tg_epoll_proxy *server, int stats_fd) {
    (void)server;
    (void)stats_fd;
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
