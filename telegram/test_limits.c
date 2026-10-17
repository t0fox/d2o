#include "tg_limits.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

static void test_connection_budget_respects_file_descriptors(void) {
    assert(tg_limits_auto_max_connections(128, 16 * 1024 * 1024, 128 * 1024,
                                          0, 512) == 47);
    assert(tg_limits_auto_max_connections(32, 16 * 1024 * 1024, 128 * 1024,
                                          0, 512) == 0);
}

static void test_connection_budget_respects_memory_and_configured_cap(void) {
    assert(tg_limits_auto_max_connections(4096, 1024 * 1024, 256 * 1024,
                                          0, 512) == 4);
    assert(tg_limits_auto_max_connections(SIZE_MAX, SIZE_MAX, 1,
                                          0, 12) == 12);
    assert(tg_limits_auto_max_connections(SIZE_MAX, SIZE_MAX, 1,
                                          0, 0) == 0);
}

static void test_reserved_resources_and_invalid_inputs_fail_closed(void) {
    assert(tg_limits_auto_max_connections(48, 1024 * 1024, 128 * 1024,
                                          16, 512) == 0);
    assert(tg_limits_auto_max_connections(256, 1024 * 1024, 0,
                                          0, 512) == 0);
    assert(tg_limits_auto_max_connections(256, 1024 * 1024, 128 * 1024,
                                          SIZE_MAX, 512) == 0);
}

static void test_runtime_memory_budget_tracks_router_ram(void) {
    const size_t mib = 1024u * 1024u;
    assert(tg_limits_runtime_memory_budget(512u * mib, 348u * mib) ==
           192u * mib);
    assert(tg_limits_runtime_memory_budget(64u * mib, 40u * mib) ==
           24u * mib);
    assert(tg_limits_runtime_memory_budget(2048u * mib, 1024u * mib) ==
           192u * mib);
    assert(tg_limits_runtime_memory_budget(512u * mib, 0) == 0);
}

int main(void) {
    test_connection_budget_respects_file_descriptors();
    test_connection_budget_respects_memory_and_configured_cap();
    test_reserved_resources_and_invalid_inputs_fail_closed();
    test_runtime_memory_budget_tracks_router_ram();
    puts("Тесты лимитов Telegram runtime: ок");
    return 0;
}
