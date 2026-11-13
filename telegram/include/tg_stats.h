#ifndef D2K_TG_STATS_H
#define D2K_TG_STATS_H
#include <stddef.h>
#include <stdint.h>

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

#define TG_CLIENT_LATENCY_SAMPLE_COUNT 128u
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
    uint64_t latency_samples[TG_CLIENT_LATENCY_SAMPLE_COUNT];
    uint64_t client_response_latency_p50_us;
    uint64_t client_response_latency_p95_us;
} tg_epoll_proxy_stats;

#endif
