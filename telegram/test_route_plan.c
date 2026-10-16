#include "tg_route_plan.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_adaptive_plan_prefers_direct_then_worker_and_pool(void) {
    tg_route_plan plan;
    assert(tg_route_plan_build(4, 1, TG_WS_ROUTING_ADAPTIVE, 0, 2, 3,
                              &plan) == 0);
    assert(plan.count == 11);
    assert(plan.steps[0].kind == TG_ROUTE_DIRECT_WSS && plan.steps[0].index == 1);
    assert(plan.steps[1].kind == TG_ROUTE_DIRECT_WSS && plan.steps[1].index == 0);
    assert(plan.steps[2].kind == TG_ROUTE_CF_WORKER && plan.steps[2].index == 0);
    assert(plan.steps[4].kind == TG_ROUTE_CF_PROXY && plan.steps[4].index == 1);
    assert(plan.steps[5].kind == TG_ROUTE_CF_PROXY && plan.steps[5].index == 0);
    assert(plan.steps[6].kind == TG_ROUTE_CF_PROXY && plan.steps[6].index == 3);
    assert(plan.steps[10].kind == TG_ROUTE_DIRECT_TCP);
}

static void test_cf_first_and_adaptive_preference_reorder_routes(void) {
    tg_route_plan plan;
    assert(tg_route_plan_build(2, 0, TG_WS_ROUTING_CF_FIRST, 0, 1, 2,
                              &plan) == 0);
    assert(plan.steps[0].kind == TG_ROUTE_CF_WORKER);
    assert(plan.steps[1].kind == TG_ROUTE_CF_PROXY);
    assert(plan.steps[3].kind == TG_ROUTE_DIRECT_WSS);

    assert(tg_route_plan_build(2, 0, TG_WS_ROUTING_ADAPTIVE, 1, 1, 2,
                              &plan) == 0);
    assert(plan.steps[0].kind == TG_ROUTE_CF_WORKER);
    assert(plan.steps[1].kind == TG_ROUTE_CF_PROXY);
    assert(plan.steps[3].kind == TG_ROUTE_DIRECT_WSS);
}

static void test_cf_hostnames_and_media_variants(void) {
    tg_route_plan plan;
    char host[254];
    assert(tg_route_cf_proxy_hostname(2, 0, "example.co.uk",
                                      host, sizeof(host)) == 0);
    assert(strcmp(host, "kws2.example.co.uk") == 0);
    assert(tg_route_cf_proxy_hostname(2, 1, "example.co.uk",
                                      host, sizeof(host)) == 0);
    assert(strcmp(host, "kws2-1.example.co.uk") == 0);
    assert(tg_route_cf_proxy_hostname(203, 0, "example.co.uk",
                                      host, sizeof(host)) == 0);
    assert(strcmp(host, "kws2.example.co.uk") == 0);
    assert(tg_route_cf_proxy_hostname(6, 0, "example.co.uk",
                                      host, sizeof(host)) != 0);
    assert(tg_route_cf_proxy_hostname(2, 0, "example.co.uk",
                                      host, 4) != 0);
    assert(tg_route_plan_build(2, 0, TG_WS_ROUTING_ADAPTIVE, 0,
                               0, 2, &plan) == 0);
    assert(plan.count == 5); /* direct(2), CF(2), TCP(1) */
    assert(plan.steps[2].kind == TG_ROUTE_CF_PROXY &&
           plan.steps[2].index == 0);
    assert(plan.steps[3].kind == TG_ROUTE_CF_PROXY &&
           plan.steps[3].index == 2);
}

static void test_plan_bounds_and_websocket_dc_mapping(void) {
    tg_route_plan plan;
    assert(tg_route_websocket_dc(203) == 2);
    assert(tg_route_websocket_dc(5) == 5);
    assert(tg_route_websocket_dc(999) == 999);
    assert(tg_route_plan_build(6, 0, TG_WS_ROUTING_ADAPTIVE, 0, 0, 0,
                              &plan) == 0);
    assert(plan.count == 1 && plan.steps[0].kind == TG_ROUTE_DIRECT_TCP);
    assert(tg_route_plan_build(2, 0, TG_WS_ROUTING_ADAPTIVE, 0,
                              TG_CONFIG_MAX_CF_WORKER_DOMAINS + 1u, 0,
                              &plan) != 0);
}

int main(void) {
    test_adaptive_plan_prefers_direct_then_worker_and_pool();
    test_cf_first_and_adaptive_preference_reorder_routes();
    test_plan_bounds_and_websocket_dc_mapping();
    test_cf_hostnames_and_media_variants();
    puts("Тесты плана Telegram-маршрутизации: ок");
    return 0;
}
