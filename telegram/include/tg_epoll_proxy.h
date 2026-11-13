#ifndef D2K_TG_EPOLL_PROXY_H
#define D2K_TG_EPOLL_PROXY_H

#include "tg_listener.h"
#include "tg_mtproto.h"
#include "tg_cf_domains.h"
#include "tg_config.h"

#include <stddef.h>
#include <stdint.h>
#include <openssl/ssl.h>

typedef struct tg_epoll_proxy tg_epoll_proxy;

typedef enum {
    TG_EPOLL_FAILURE_NONE = 0,
    TG_EPOLL_FAILURE_DNS = 1,
    TG_EPOLL_FAILURE_TCP = 2,
    TG_EPOLL_FAILURE_TLS = 3,
    TG_EPOLL_FAILURE_WEBSOCKET = 4,
    TG_EPOLL_FAILURE_MTPROTO = 5,
    TG_EPOLL_FAILURE_SETUP = 6,
    TG_EPOLL_FAILURE_ROUTE_UNAVAILABLE = 7,
    TG_EPOLL_FAILURE_WORKER_PORT = 8
} tg_epoll_failure_stage;

#define TG_EPOLL_MAX_ACTIVE_ROUTE_SESSIONS 64u
#define TG_EPOLL_MAX_ROUTE_EVENTS 6u
#define TG_EPOLL_MAX_ROUTE_COOLDOWNS 256u
#define TG_EPOLL_MAX_ROUTE_STATS 256u
#define TG_EPOLL_MAX_PROBLEM_SESSIONS 16u
#define TG_EPOLL_FAILURE_STAGE_COUNT 9u

typedef enum {
    TG_ROUTE_SESSION_STAGE_ACCEPTED = 0,
    TG_ROUTE_SESSION_STAGE_ROUTING = 1,
    TG_ROUTE_SESSION_STAGE_UPSTREAM_READY = 2,
    TG_ROUTE_SESSION_STAGE_FIRST_WSS_BINARY_RESPONSE = 3
} tg_route_session_stage;

typedef enum {
    TG_ROUTE_SESSION_IDLE = 0,
    TG_ROUTE_SESSION_CONNECTING = 1,
    TG_ROUTE_SESSION_CONNECTED = 2,
    TG_ROUTE_SESSION_SELECTED = 3,
    TG_ROUTE_SESSION_COOLDOWN = 4,
    TG_ROUTE_SESSION_FAILED = 5,
    TG_ROUTE_SESSION_CANCELLED = 6,
    TG_ROUTE_SESSION_SKIPPED = 7,
    TG_ROUTE_SESSION_FIRST_BINARY_RESPONSE = 8
} tg_route_session_state;

typedef enum {
    TG_ROUTE_SESSION_TRANSPORT_NONE = 0,
    TG_ROUTE_SESSION_TRANSPORT_DIRECT_WSS = 1,
    TG_ROUTE_SESSION_TRANSPORT_CLOUDFLARE_WORKER = 2,
    TG_ROUTE_SESSION_TRANSPORT_CLOUDFLARE_PROXY = 3,
    TG_ROUTE_SESSION_TRANSPORT_TCP_FALLBACK = 4,
    TG_ROUTE_SESSION_TRANSPORT_TCP_PASSTHROUGH = 5
} tg_route_session_transport;

typedef struct {
    uint64_t sequence;
    uint64_t timestamp_ms;
    uint8_t branch; /* 0 — direct, 1 — fallback */
    uint8_t transport;
    uint8_t state;
    uint8_t failure_stage;
} tg_route_session_event;

typedef struct {
    uint64_t id;
    uint32_t dc;
    uint8_t has_dc;
    uint8_t is_media;
    uint8_t has_media;
    uint8_t stage;
    uint8_t direct_state;
    uint8_t direct_transport;
    uint8_t fallback_state;
    uint8_t fallback_transport;
    uint8_t selected_transport;
    uint8_t telegram_response_seen;
    uint8_t event_count;
    uint16_t client_port;
    uint16_t upstream_port;
    uint8_t read_paused;
    uint64_t next_event_sequence;
    uint64_t started_ms;
    uint64_t age_ms;
    uint64_t no_progress_ms;
    uint64_t first_response_latency_ms;
    uint64_t bytes_from_clients;
    uint64_t bytes_from_upstreams;
    uint64_t client_queue_bytes;
    uint64_t upstream_queue_bytes;
    uint64_t client_queue_capacity_bytes;
    uint64_t upstream_queue_capacity_bytes;
    uint64_t ws_rx_capacity_bytes;
    uint64_t ws_tx_memory_bytes;
    uint64_t mtproto_packet_capacity_bytes;
    tg_route_session_event events[TG_EPOLL_MAX_ROUTE_EVENTS];
} tg_active_route_session;

typedef struct {
    uint32_t dc;
    uint16_t client_port;
    uint16_t upstream_port;
    uint16_t http_status;
    uint8_t is_media;
    uint8_t transport;
    uint8_t failure_stage;
    uint64_t sequence;
    uint64_t session_id;
    uint64_t age_ms;
    uint64_t bytes_from_clients;
    uint64_t bytes_from_upstreams;
} tg_problem_session;

typedef struct {
    uint32_t dc;
    uint16_t client_port;
    uint16_t upstream_port;
    uint8_t is_media;
    uint8_t transport;
    uint8_t has_last_success;
    uint8_t has_last_failure;
    uint8_t last_failure_stage;
    uint64_t attempts;
    uint64_t failures;
    uint64_t responses;
    uint64_t cf_responses;
    uint64_t latency_ms;
    uint64_t last_success_age_ms;
    uint64_t last_failure_age_ms;
    uint64_t cooldown_remaining_ms;
} tg_route_health_stat;

typedef struct {
    uint32_t dc;
    uint64_t remaining_ms;
    uint8_t is_media;
    uint8_t transport;
    uint8_t failure_stage;
} tg_route_cooldown;

typedef struct {
    size_t active_connections;
    uint64_t process_started_at;
    uint64_t accepted_connections;
    size_t active_sessions_count;
    int route_sessions_truncated;
    tg_active_route_session active_sessions[TG_EPOLL_MAX_ACTIVE_ROUTE_SESSIONS];
    size_t route_cooldowns_count;
    int route_cooldowns_truncated;
    tg_route_cooldown route_cooldowns[TG_EPOLL_MAX_ROUTE_COOLDOWNS];
    uint64_t monotonic_time_ms;
    uint32_t route_cooldown_ms;
    size_t max_connections;
    size_t memory_headroom_bytes;
    size_t memory_ceiling_bytes;
    size_t active_wss_connections;
    size_t max_wss_connections;
    size_t buffer_bytes_current;
    size_t buffer_bytes_peak;
    size_t buffer_bytes_limit;
    size_t client_queue_bytes;
    size_t upstream_queue_bytes;
    size_t client_queue_capacity_bytes;
    size_t upstream_queue_capacity_bytes;
    size_t ws_rx_capacity_bytes;
    size_t ws_tx_memory_bytes;
    size_t mtproto_packet_capacity_bytes;
    size_t proxy_struct_bytes;
    size_t connection_struct_bytes;
    size_t retired_connection_struct_bytes;
    size_t tls_objects;
    size_t worker_pool_tls_objects;
    size_t client_socket_fds;
    size_t upstream_socket_fds;
    size_t worker_pool_entries;
    size_t worker_pool_capacity;
    size_t worker_pool_struct_bytes;
    int worker_pool_started;
    uint64_t accept_limit_rejections;
    uint64_t accept_fd_exhaustion;
    uint64_t allocation_failures;
    uint64_t buffer_budget_rejections;
    uint64_t buffer_size_rejections;
    uint64_t wss_read_pauses;
    uint64_t wss_read_resumes;
    uint64_t wss_paused_timeouts;
    uint64_t http_403;
    uint64_t http_501;
    uint64_t http_502;
    uint32_t last_http_status;
    uint64_t failure_by_stage[TG_EPOLL_FAILURE_STAGE_COUNT];
    size_t route_health_count;
    int route_health_truncated;
    tg_route_health_stat route_health[TG_EPOLL_MAX_ROUTE_STATS];
    size_t problem_sessions_count;
    tg_problem_session problem_sessions[TG_EPOLL_MAX_PROBLEM_SESSIONS];
    size_t wss_reads_paused;
    uint64_t wss_oldest_pause_ms;
    uint64_t connections_started;
    uint64_t bytes_from_clients;
    uint64_t bytes_from_upstreams;
    uint64_t wss_attempts;
    uint64_t wss_failures;
    uint64_t wss_responses;
    uint64_t cf_wss_responses;
    uint32_t last_success_dc;
    uint32_t last_success_route;
    uint64_t last_success_latency_ms;
    uint64_t last_success_age_ms;
    uint32_t last_failure_dc;
    uint32_t last_failure_route;
    uint32_t last_failure_stage;
    uint64_t last_failure_age_ms;
    uint64_t worker_pool_hits;
    uint64_t worker_pool_misses;
    uint64_t worker_pool_responses;
    /* Перцентили последних 128 успешных WSS-сессий: accept TCP → MTProto. */
    uint64_t client_response_latency_total;
    size_t client_response_latency_samples;
    uint64_t client_response_latency_last_us;
    uint64_t client_response_latency_p50_us;
    uint64_t client_response_latency_p95_us;
} tg_epoll_proxy_stats;

typedef int (*tg_epoll_original_destination_fn)(
    void *context, int client_fd, tg_listener_destination *out);
typedef int (*tg_epoll_select_target_fn)(
    void *context, const tg_listener_destination *original,
    const uint8_t handshake[TG_MTPROTO_HANDSHAKE_LEN],
    tg_listener_destination *upstream);

/* Validated route metadata must survive handshake parsing. A missing DC hint
 * can be resolved from the verified destination map, and secret-based MTProto
 * handshakes must not be silently downgraded to direct TCP. */
typedef struct {
    tg_listener_destination upstream;
    uint32_t dc_id;
    int is_media;
    tg_mtproto_proto proto;
    int tcp_only;
} tg_epoll_route_selection;

typedef int (*tg_epoll_select_route_fn)(
    void *context, const tg_listener_destination *original,
    const uint8_t handshake[TG_MTPROTO_HANDSHAKE_LEN],
    tg_epoll_route_selection *selection);
/* Резолвер возвращает 0 при готовом адресе, 1 при ожидании DNS и -1 при ошибке. */
typedef int (*tg_epoll_resolve_domain_fn)(
    void *context, const char *domain, tg_listener_destination *upstream);

typedef struct {
    int listener_fd;
    size_t queue_bytes;
    size_t memory_budget_bytes;
    size_t configured_max_connections;
    size_t initial_connection_limit; /* Zero uses the configured maximum. */
    uint32_t handshake_timeout_ms;
    uint32_t idle_timeout_ms;
    uint32_t socket_mark;
    int require_socket_mark;
    int enforce_self_dial;
    int enable_direct_wss; /* Enables the shared WSS transport. */
    int cloudflare_only;
    uint16_t direct_wss_port;
    SSL_CTX *tls_context;
    const tg_config *routing_config;
    tg_cf_domain_pool *cf_domain_pool;
    tg_epoll_resolve_domain_fn resolve_domain;
    void *route_context;
    const uint16_t *listen_ports;
    size_t listen_port_count;
    tg_epoll_original_destination_fn original_destination;
    tg_epoll_select_target_fn select_target;
    tg_epoll_select_route_fn select_route;
    void *context;
} tg_epoll_proxy_config;

tg_epoll_proxy *tg_epoll_proxy_create(const tg_epoll_proxy_config *config);
/* The caller owns both the current and replacement descriptors. */
#define TG_EPOLL_REBIND_LISTENER (-2)
int tg_epoll_proxy_set_listener(tg_epoll_proxy *server, int listener_fd);
/* Wake step() when the caller-owned stats listener has a pending connection. */
int tg_epoll_proxy_watch_stats(tg_epoll_proxy *server, int stats_fd);
/* Call on the event-loop thread. Headroom comes from available memory;
 * the ceiling comes from total memory. Existing connections are not evicted. */
void tg_epoll_proxy_update_limits(tg_epoll_proxy *server, size_t connection_limit,
                                  size_t memory_headroom_bytes, size_t memory_ceiling_bytes);
int tg_epoll_proxy_step(tg_epoll_proxy *server, int timeout_ms);
void tg_epoll_proxy_destroy(tg_epoll_proxy *server);
size_t tg_epoll_proxy_active_connections(const tg_epoll_proxy *server);
size_t tg_epoll_proxy_max_connections(const tg_epoll_proxy *server);
int tg_epoll_proxy_get_stats(const tg_epoll_proxy *server,
                             tg_epoll_proxy_stats *out);

#endif
