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
    TG_EPOLL_FAILURE_ROUTE_UNAVAILABLE = 7
} tg_epoll_failure_stage;

#define TG_EPOLL_MAX_ACTIVE_ROUTE_SESSIONS 64u
#define TG_EPOLL_MAX_ROUTE_EVENTS 6u

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
    uint8_t branch; /* 0 — direct, 1 — fallback */
    uint8_t transport;
    uint8_t state;
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
    uint64_t next_event_sequence;
    tg_route_session_event events[TG_EPOLL_MAX_ROUTE_EVENTS];
} tg_active_route_session;

typedef struct {
    size_t active_connections;
    uint64_t process_started_at;
    uint64_t accepted_connections;
    size_t active_sessions_count;
    int route_sessions_truncated;
    tg_active_route_session active_sessions[TG_EPOLL_MAX_ACTIVE_ROUTE_SESSIONS];
    size_t max_connections;
    size_t active_wss_connections;
    size_t max_wss_connections;
    size_t buffer_bytes_current;
    size_t buffer_bytes_peak;
    size_t buffer_bytes_limit;
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
    uint32_t handshake_timeout_ms;
    uint32_t idle_timeout_ms;
    uint32_t socket_mark;
    int require_socket_mark;
    int enforce_self_dial;
    int enable_direct_wss;
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
int tg_epoll_proxy_step(tg_epoll_proxy *server, int timeout_ms);
void tg_epoll_proxy_destroy(tg_epoll_proxy *server);
size_t tg_epoll_proxy_active_connections(const tg_epoll_proxy *server);
size_t tg_epoll_proxy_max_connections(const tg_epoll_proxy *server);
int tg_epoll_proxy_get_stats(const tg_epoll_proxy *server,
                             tg_epoll_proxy_stats *out);

#endif
