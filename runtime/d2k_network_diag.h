#ifndef D2K_NETWORK_DIAG_H
#define D2K_NETWORK_DIAG_H

#include <stdint.h>
#include "d2k_diag_ipc.h"

enum { D2K_NET_DIAG_INTERVAL_MS = 2000 };

typedef struct d2k_network_controller {
    uint64_t measurements, measurement_restarts, probe_units;
    uint64_t queue_expired, phase_deadlines, tcp_dial_deadlines;
    uint64_t dns_checks, dns_failures, dns_local_failures, dns_bootstrap_failures, dns_config_failures;
    uint64_t dns_config_max_ms;
} d2k_network_controller;

typedef struct {
    uint64_t packets, enobufs, recv_errors, verdict_errors, kernel_errors;
    uint64_t drop_verdicts, replacements, raw_send_errors;
    uint64_t verdict_samples, verdict_max_us, verdict_no_timestamp;
    uint64_t userspace_verdict_samples, userspace_verdict_max_us;
    uint64_t tcp_hold_timeouts, udp_hold_timeouts;
    uint64_t tcp_prior_exchange_actions, udp_prior_exchange_actions;
    uint64_t tcp_prior_exchange_packets, udp_prior_exchange_packets;
    uint64_t hold_actions, plan_actions, udp_follow_actions, http_actions;
    uint64_t loop_max_us, conntrack_queries, conntrack_query_errors, sweep_max_us;
    uint64_t routed_flows, flow_table_refusals;
} d2k_network_datapath;

typedef struct {
    d2k_diag_header header;
    uint64_t mono_ms, generation;
    d2k_network_controller counters;
    uint32_t active, queued, workers, limit, cpu_free_pct, mem_available_kib;
} d2k_network_controller_message;

typedef struct {
    d2k_diag_header header;
    uint64_t mono_ms, generation;
    unsigned queue, queue_limit, fail_open;
    uint32_t netlink_port;
    d2k_network_datapath counters;
} d2k_network_datapath_message;

#endif
