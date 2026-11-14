/* Procfs fixtures exercise the real collector without depending on privileges. */
#define _POSIX_C_SOURCE 200809L
#include "network_diag.h"
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc != 4) return 2;
    d2k_network_history *history = d2k_network_history_new();
    if (!history) return 1;
    d2k_network_controller_message c = {.header.pid = 22, .generation = 7, .limit = 4,
        .cpu_free_pct = 68, .mem_available_kib = UINT32_MAX};
    d2k_network_datapath_message d = {.header.pid = 21, .generation = 6, .queue = 2000,
        .queue_limit = 1024, .fail_open = 1, .netlink_port = 12345};
    for (unsigned i = 0; i < D2K_NETWORK_HISTORY + 3; i++) {
        uint64_t now = 1000 + i * D2K_NET_DIAG_INTERVAL_MS;
        if (i % 4 == 0) {
            d.mono_ms = now;
            d.counters.packets = i;
            d.counters.verdict_samples = i;
            d.counters.verdict_max_us = 99;
        }
        c.mono_ms = now;
        c.counters.dns_failures = i;
        d2k_network_history_sample(history, now, &c, &d, argv[1], argv[2], argv[3]);
    }
    d2k_network_history_write(stdout, history);
    free(history);
    return ferror(stdout) ? 1 : 0;
}
