#ifndef D2K_TG_CONFIG_H
#define D2K_TG_CONFIG_H

#include <stddef.h>
#include <stdint.h>

#define TG_CONFIG_DOMAIN_SIZE 254u
#define TG_CONFIG_MAX_CF_WORKER_DOMAINS 8u
#define TG_CONFIG_MAX_CF_PROXY_DOMAINS 32u
#define TG_OUTBOUND_SOCKET_MARK 0x31u

typedef enum {
    TG_WS_ROUTING_ADAPTIVE = 0,
    TG_WS_ROUTING_SEQUENTIAL = 1,
    TG_WS_ROUTING_CF_FIRST = 2,
    TG_WS_ROUTING_HEDGED = 3
} tg_ws_routing_policy;

typedef struct {
    int enabled;
    int local_mode;
    char ca_bundle[512];
    char status_path[512];
    char dc_map_path[512];
    char cf_domain_cache_path[512];
    char stats_socket_path[108];
    char cf_worker_domains[TG_CONFIG_MAX_CF_WORKER_DOMAINS][TG_CONFIG_DOMAIN_SIZE];
    char cf_proxy_domains[TG_CONFIG_MAX_CF_PROXY_DOMAINS][TG_CONFIG_DOMAIN_SIZE];
    size_t cf_worker_domain_count;
    size_t cf_proxy_domain_count;
    tg_ws_routing_policy ws_routing;
    uint32_t ws_hedge_delay_ms;
    uint32_t ws_hedge_limit;
    int diagnostic_direct_tcp;
    int cf_balance;
    int default_domains;
    uint16_t listen_port;
} tg_config;

/* Strictly reads only Telegram-owned keys; unknown D2K config keys are ignored. */
int tg_config_read(const char *path, tg_config *out);
void tg_config_clean(tg_config *config);

#endif
