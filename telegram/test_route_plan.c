#include "tg_route_plan.h"

#include <assert.h>
#include <stdio.h>

static void test_adaptive_plan_prefers_direct_then_worker_and_pool(void) {
    tg_route_plan plan;
    assert(tg_route_plan_build(4, 1, TG_WS_ROUTING_ADAPTIVE, 0, 2, 3,
                              &plan) == 0);
    assert(plan.count == 8);
    assert(plan.steps[0].kind == TG_ROUTE_DIRECT_WSS && plan.steps[0].index == 1);
    assert(plan.steps[1].kind == TG_ROUTE_DIRECT_WSS && plan.steps[1].index == 0);
    assert(plan.steps[2].kind == TG_ROUTE_CF_WORKER && plan.steps[2].index == 0);
    assert(plan.steps[4].kind == TG_ROUTE_CF_PROXY && plan.steps[4].index == 0);
    assert(plan.steps[7].kind == TG_ROUTE_DIRECT_TCP);
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
    puts("Тесты плана Telegram-маршрутизации: ок");
    return 0;
}
