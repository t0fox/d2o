#include "tg_route_plan.h"

#include <string.h>

uint32_t tg_route_websocket_dc(uint32_t dc_id) {
    return dc_id == 203 ? 2 : dc_id;
}

static int append_step(tg_route_plan *plan, tg_route_kind kind, size_t index) {
    if (plan->count >= TG_ROUTE_PLAN_MAX || index > UINT8_MAX) return -1;
    plan->steps[plan->count++] = (tg_route_step){
        .kind = kind,
        .index = (uint8_t)index
    };
    return 0;
}

static int append_direct(tg_route_plan *plan, uint32_t dc_id, int is_media) {
    uint32_t websocket_dc = tg_route_websocket_dc(dc_id);
    if (websocket_dc < 1 || websocket_dc > 5) return 0;
    unsigned first = is_media ? 1u : 0u;
    return append_step(plan, TG_ROUTE_DIRECT_WSS, first) == 0 &&
           append_step(plan, TG_ROUTE_DIRECT_WSS, 1u - first) == 0 ? 0 : -1;
}

static int append_cloudflare(tg_route_plan *plan, size_t worker_count,
                             size_t cf_domain_count) {
    for (size_t i = 0; i < worker_count; ++i)
        if (append_step(plan, TG_ROUTE_CF_WORKER, i) != 0) return -1;
    for (size_t i = 0; i < cf_domain_count; ++i)
        if (append_step(plan, TG_ROUTE_CF_PROXY, i) != 0) return -1;
    return 0;
}

int tg_route_plan_build(uint32_t dc_id, int is_media,
                        tg_ws_routing_policy policy, int prefer_cf,
                        size_t worker_count, size_t cf_domain_count,
                        tg_route_plan *out) {
    if (!out || dc_id > 999 || (is_media != 0 && is_media != 1) ||
        (prefer_cf != 0 && prefer_cf != 1) ||
        worker_count > TG_CONFIG_MAX_CF_WORKER_DOMAINS ||
        cf_domain_count > TG_CF_POOL_MAX ||
        (policy != TG_WS_ROUTING_ADAPTIVE &&
         policy != TG_WS_ROUTING_SEQUENTIAL &&
         policy != TG_WS_ROUTING_CF_FIRST &&
         policy != TG_WS_ROUTING_HEDGED))
        return -1;
    memset(out, 0, sizeof(*out));
    int cf_first = policy == TG_WS_ROUTING_CF_FIRST ||
                   (policy == TG_WS_ROUTING_ADAPTIVE && prefer_cf);
    if (cf_first) {
        if (append_cloudflare(out, worker_count, cf_domain_count) != 0 ||
            append_direct(out, dc_id, is_media) != 0)
            return -1;
    } else {
        if (append_direct(out, dc_id, is_media) != 0 ||
            append_cloudflare(out, worker_count, cf_domain_count) != 0)
            return -1;
    }
    return append_step(out, TG_ROUTE_DIRECT_TCP, 0);
}
