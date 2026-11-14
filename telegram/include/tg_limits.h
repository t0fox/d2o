#ifndef D2K_TG_LIMITS_H
#define D2K_TG_LIMITS_H

#include <stddef.h>
#include <stdio.h>

#define TG_LIMITS_MAX_CONFIGURED 128u
#define TG_LIMITS_SMALL_ROUTER_BYTES (128u * 1024u * 1024u)
#define TG_LIMITS_SMALL_ROUTER_CAP 32u
#define TG_LIMITS_GROWTH_STEP 4u
#define TG_LIMITS_OS_MARGIN_BYTES (2u * 1024u * 1024u)

enum {
    TG_LIMIT_RAM = 1u,
    TG_LIMIT_FD = 2u,
    TG_LIMIT_CONFIGURED = 4u,
    TG_LIMIT_RECOVERY = 8u,
    TG_LIMIT_SAMPLE_UNAVAILABLE = 16u,
    TG_LIMIT_SLOTS = 32u
};

typedef struct {
    size_t total, available, rss, fd_limit, fd_count;
    int valid;
} tg_limit_resources;

typedef struct {
    size_t ram, fd, configured, headroom, ceiling;
} tg_limit_plan;

tg_limit_resources tg_limits_read_resources(void);
tg_limit_plan tg_limits_plan(const tg_limit_resources *resources, size_t configured,
                            size_t active, size_t pending_upstreams,
                            size_t buffer_used, size_t slot_bytes);
size_t tg_limits_adapt(const tg_limit_plan *plan, size_t current, size_t *recovery_limit,
                       unsigned *reasons);

void tg_limits_read_meminfo(FILE *file, size_t *total, size_t *available);
size_t tg_limits_soft_nofile(void);
size_t tg_limits_auto_max_connections(size_t fd_limit, size_t memory_budget,
                                     size_t bytes_per_connection,
                                     size_t hedge_limit,
                                     size_t configured_max);
size_t tg_limits_policy_connections(size_t fd_limit, size_t total_bytes,
                                    size_t available_bytes, size_t cap);
size_t tg_limits_policy_admission(size_t fd_limit, size_t total_bytes,
                                  size_t available_bytes, size_t cap,
                                  size_t active);
size_t tg_limits_runtime_memory_budget(size_t total_bytes,
                                      size_t available_bytes);

#endif
