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

static void assert_meminfo(const char *fixture, size_t expected_available) {
    FILE *file = tmpfile();
    assert(file);
    assert(fputs(fixture, file) >= 0);
    rewind(file);
    size_t total, available;
    tg_limits_read_meminfo(file, &total, &available);
    assert(total == 128u * 1024u * 1024u);
    assert(available == expected_available);
    fclose(file);
}

static void test_old_meminfo_and_real_memory_pressure(void) {
    const size_t mib = 1024u * 1024u;
    assert_meminfo("MemTotal: 131072 kB\nMemAvailable: 16384 kB\n", 16 * mib);
    assert_meminfo("MemTotal: 131072 kB\nMemFree: 4096 kB\nBuffers: 1024 kB\n"
                   "Cached: 24576 kB\nShmem: 2048 kB\n", 16 * mib);
    assert_meminfo("MemTotal: 131072 kB\nMemFree: 4096 kB\nBuffers: 1024 kB\n"
                   "Cached: 8192 kB\nShmem: 16384 kB\n", 5 * mib);
    assert_meminfo("MemTotal: 131072 kB\nMemFree: 16384 kB\nMemAvailable: 0 kB\n", 0);
}

int main(void) {
    test_connection_budget_respects_file_descriptors();
    test_connection_budget_respects_memory_and_configured_cap();
    test_reserved_resources_and_invalid_inputs_fail_closed();
    test_runtime_memory_budget_tracks_router_ram();
    test_old_meminfo_and_real_memory_pressure();
    const size_t mib = 1024u * 1024u;
    assert(tg_limits_policy_connections(1024, 128*mib, 64*mib, 32) == 32);
    assert(tg_limits_policy_connections(1024, 128*mib, 64*mib, 16) == 16);
    assert(tg_limits_policy_connections(128, 128*mib, 64*mib, 128) == 14);
    /* A cold boot on a 128 MiB router can temporarily have less
     * available RAM than the usual reserve. Keep a bounded admission limit. */
    assert(tg_limits_policy_connections(1024, 128*mib, 16*mib, 32) == 4);
    assert(tg_limits_policy_connections(1024, 128*mib, 8*mib, 32) == 2);
    assert(tg_limits_policy_connections(1024, 128*mib, 3*mib, 32) == 0);
    assert(tg_limits_policy_connections(48, 128*mib, 16*mib, 32) == 1);
    assert(tg_limits_policy_connections(32, 128*mib, 64*mib, 32) == 0);
    assert(tg_limits_policy_admission(128, 128*mib, 6*mib, 32, 4) == 5);
    assert(tg_limits_policy_admission(128, 128*mib, 1*mib, 32, 4) == 4);
    assert(tg_limits_policy_admission(128, 128*mib, 0, 32, 4) == 4);
    assert(tg_limits_policy_admission(128, 128*mib, 64*mib, 32, 13) == 14);
    assert(tg_limits_policy_admission(128, 128*mib, 16*mib, 4, 4) == 4);
    puts("Тесты лимитов Telegram runtime: ок");
    return 0;
}
