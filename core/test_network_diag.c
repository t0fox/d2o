/* Procfs fixtures exercise the real collector without depending on privileges. */
#define _POSIX_C_SOURCE 200809L
#include "network_diag.h"
#include <assert.h>
#include <stdlib.h>
#include <sys/file.h>

int main(int argc, char **argv) {
    if (argc != 5 && argc != 6) return 2;
    assert(d2k_network_history_bytes() <= D2K_NETWORK_BUDGET);
    int fd = d2k_network_open(argv[4], D2K_NETWORK_STATE, 1);
    assert(fd >= 0 && !flock(fd, LOCK_EX | LOCK_NB));
    d2k_network_history *history = d2k_network_history_map(fd, 123);
    if (!history) return 1;
    d2k_network_controller_message c = {.header.pid = 22, .generation = 7, .limit = 4,
        .cpu_free_pct = 68, .mem_available_kib = UINT32_MAX};
    d2k_network_datapath_message d = {.header.pid = 21, .generation = 6, .queue = 2000,
        .queue_limit = 1024, .fail_open = 1, .netlink_port = 12345};
    int long_run = argc == 6;
    unsigned count = long_run ? 30 * 60 * 25 : D2K_NETWORK_HISTORY + 3;
    for (unsigned i = 0; i < count; i++) {
        uint64_t now = 1000 + i * D2K_NET_DIAG_INTERVAL_MS;
        if (i % 4 == 0) {
            d.mono_ms = now;
            d.counters.packets = i;
            d.counters.verdict_samples = i;
            d.counters.verdict_max_us = 99;
        }
        if (long_run) {
            d.mono_ms = now;
            /* Four incidents with a second signal in the same incident window. */
            if (i >= 180 && i <= 930 && (i % 240 == 180 || i % 240 == 183))
                d.counters.enobufs++;
            if (i == 915) { d.generation++; d.counters.enobufs += 50; }
            c.queued = i % 30 == 2 ? 10 : 1;
        }
        c.mono_ms = now;
        c.counters.dns_failures = i;
        d2k_network_history_sample(history, now, &c, &d, argv[1], argv[2], argv[3]);
    }
    d2k_network_history *copy = d2k_network_history_copy(fd, 123);
    assert(copy && !d2k_network_history_copy(fd, 124));
    assert(!d2k_network_history_unmap(history, fd));
    assert(!d2k_network_history_copy(fd, 123));
    close(fd);
    d2k_network_history_write(stdout, copy);
    free(copy);
    return ferror(stdout) ? 1 : 0;
}
