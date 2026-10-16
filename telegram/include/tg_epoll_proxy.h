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

typedef struct {
    size_t active_connections;
    size_t max_connections;
    uint64_t connections_started;
    uint64_t bytes_from_clients;
    uint64_t bytes_from_upstreams;
    uint64_t wss_attempts;
    uint64_t wss_failures;
    uint64_t wss_responses;
    uint64_t cf_wss_responses;
} tg_epoll_proxy_stats;

typedef int (*tg_epoll_original_destination_fn)(
    void *context, int client_fd, tg_listener_destination *out);
typedef int (*tg_epoll_select_target_fn)(
    void *context, const tg_listener_destination *original,
    const uint8_t handshake[TG_MTPROTO_HANDSHAKE_LEN],
    tg_listener_destination *upstream);
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
