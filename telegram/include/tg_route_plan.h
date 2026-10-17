#ifndef D2K_TG_ROUTE_PLAN_H
#define D2K_TG_ROUTE_PLAN_H

#include "tg_config.h"
#include "tg_cf_domains.h"

#define TG_ROUTE_PLAN_MAX (2u + TG_CONFIG_MAX_CF_WORKER_DOMAINS + \
                           2u * TG_CF_POOL_MAX + 1u)

typedef enum {
    TG_ROUTE_DIRECT_WSS = 1,
    TG_ROUTE_CF_WORKER = 2,
    TG_ROUTE_CF_PROXY = 3,
    TG_ROUTE_DIRECT_TCP = 4
} tg_route_kind;

typedef struct {
    tg_route_kind kind;
    uint8_t index;
} tg_route_step;

typedef struct {
    tg_route_step steps[TG_ROUTE_PLAN_MAX];
    size_t count;
} tg_route_plan;

uint32_t tg_route_websocket_dc(uint32_t dc_id);
/* Cloudflare proxy hosts are kwsN.<base-domain>, never the bare domain. */
int tg_route_cf_proxy_hostname(uint32_t dc_id, int media_variant,
                               const char *domain, char *hostname,
                               size_t hostname_size);
int tg_route_plan_build(uint32_t dc_id, int is_media,
                        tg_ws_routing_policy policy, int prefer_cf,
                        size_t worker_count, size_t cf_domain_count,
                        int diagnostic_direct_tcp,
                        tg_route_plan *out);

#endif
