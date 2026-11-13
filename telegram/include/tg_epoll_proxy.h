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

#include "tg_stats.h"

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
