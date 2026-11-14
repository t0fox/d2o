#define _POSIX_C_SOURCE 200809L
#include "tg_limits.h"

#include <dirent.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/resource.h>

#define TG_LIMITS_DEFAULT_NOFILE 1024u
#define TG_LIMITS_UNLIMITED_MAX 512u
#define TG_LIMITS_RESERVED_FDS 33u
#define TG_LIMITS_FDS_PER_CONNECTION 2u
#define TG_LIMITS_MEMORY_BUDGET_MAX (192u * 1024u * 1024u)
#define MIB (1024u * 1024u)

static size_t usable_fds(size_t fd_limit) {
    return fd_limit - (fd_limit / 5u + (fd_limit % 5u != 0));
}

static size_t memory_headroom(size_t total, size_t available) {
    size_t reserve = total / 5u;
    if (available / 2u > reserve) reserve = available / 2u;
    /* Older small routers can boot below the nominal reserve. Leave at
     * least 3/4 of the available memory to the OS in that case. */
    size_t cold_reserve = available - available / 4u;
    if (reserve > cold_reserve) reserve = cold_reserve;
    return available - reserve;
}

void tg_limits_read_meminfo(FILE *file, size_t *total, size_t *available) {
    *total = *available = 0;
    if (!file) return;

    size_t free_bytes = 0, buffers = 0, cache = 0, shared = 0;
    int have_available = 0;
    char line[160];
    while (fgets(line, sizeof(line), file)) {
        unsigned long long kib;
        char field[32], unit[4];
        if (sscanf(line, "%31[^:]: %llu %3s", field, &kib, unit) != 3 ||
            strcmp(unit, "kB") != 0)
            continue;
        size_t bytes = kib > SIZE_MAX / 1024u ? SIZE_MAX : (size_t)kib * 1024u;
        if (strcmp(field, "MemTotal") == 0) *total = bytes;
        else if (strcmp(field, "MemAvailable") == 0) {
            *available = bytes;
            have_available = 1;
        } else if (strcmp(field, "MemFree") == 0) free_bytes = bytes;
        else if (strcmp(field, "Buffers") == 0) buffers = bytes;
        else if (strcmp(field, "Cached") == 0) cache = bytes;
        else if (strcmp(field, "Shmem") == 0) shared = bytes;
        if (*total && have_available) break;
    }
    if (!have_available && free_bytes <= *total) {
        /* Older router kernels omit MemAvailable. Discount file cache and
         * exclude tmpfs instead of treating Cached as entirely reclaimable. */
        *available = free_bytes;
        size_t file_cache = cache > shared ? (cache - shared) / 2u : 0;
        if (buffers <= *total - *available) *available += buffers;
        if (file_cache <= *total - *available) *available += file_cache;
    }
}

size_t tg_limits_soft_nofile(void) {
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0) return TG_LIMITS_DEFAULT_NOFILE;
    if (limit.rlim_cur == RLIM_INFINITY || limit.rlim_cur > SIZE_MAX)
        return SIZE_MAX;
    return (size_t)limit.rlim_cur;
}

size_t tg_limits_auto_max_connections(size_t fd_limit, size_t memory_budget,
                                      size_t bytes_per_connection,
                                      size_t hedge_limit,
                                      size_t configured_max) {
    if (!memory_budget || !bytes_per_connection || !configured_max) return 0;

    size_t fd_cap = TG_LIMITS_UNLIMITED_MAX;
    if (fd_limit != SIZE_MAX) {
        if (hedge_limit > SIZE_MAX - TG_LIMITS_RESERVED_FDS) return 0;
        size_t reserved = TG_LIMITS_RESERVED_FDS + hedge_limit;
        if (fd_limit <= reserved) return 0;
        fd_cap = (fd_limit - reserved) / TG_LIMITS_FDS_PER_CONNECTION;
    }
    size_t memory_cap = memory_budget / bytes_per_connection;
    size_t cap = fd_cap < memory_cap ? fd_cap : memory_cap;
    if (cap > configured_max) cap = configured_max;
    if (cap > TG_LIMITS_UNLIMITED_MAX) cap = TG_LIMITS_UNLIMITED_MAX;
    return cap;
}

size_t tg_limits_policy_admission(size_t fd_limit, size_t total_bytes,
                                  size_t available_bytes, size_t cap,
                                  size_t active) {
    if (!total_bytes || available_bytes > total_bytes) return 0;
    size_t usable = usable_fds(fd_limit);
    size_t fd_slots = usable > 32u ? (usable - 32u) / 5u : 0;
    size_t memory_slots = memory_headroom(total_bytes, available_bytes) / MIB;
    if (cap > fd_slots) cap = fd_slots;
    /* MemAvailable budgets additional clients. Counting live clients
     * against that allowance would starve new media behind idle text. */
    if (active >= cap || memory_slots >= cap - active) return cap;
    return active + memory_slots;
}

size_t tg_limits_policy_connections(size_t fd_limit, size_t total_bytes,
                                    size_t available_bytes, size_t cap) {
    return tg_limits_policy_admission(fd_limit, total_bytes, available_bytes, cap, 0);
}

size_t tg_limits_runtime_memory_budget(size_t total_bytes,
                                      size_t available_bytes) {
    if (!total_bytes || !available_bytes) return 0;
    /* Оставляем системе большую часть RAM и ограничиваем худший случай WSS. */
    size_t total_cap = (total_bytes / 5u) * 2u;
    size_t available_cap = (available_bytes / 5u) * 3u;
    size_t budget = total_cap < available_cap ? total_cap : available_cap;
    return budget < TG_LIMITS_MEMORY_BUDGET_MAX
        ? budget
        : TG_LIMITS_MEMORY_BUDGET_MAX;
}

tg_limit_resources tg_limits_read_resources(void) {
    tg_limit_resources resources = {.fd_limit = tg_limits_soft_nofile()};
    FILE *mem = fopen("/proc/meminfo", "r");
    tg_limits_read_meminfo(mem, &resources.total, &resources.available);
    if (mem) fclose(mem);
    int have_rss = 0;
    FILE *status = fopen("/proc/self/status", "r");
    if (status) {
        char line[160];
        unsigned long long kib;
        while (fgets(line, sizeof(line), status)) {
            if (sscanf(line, "VmRSS: %llu kB", &kib) != 1) continue;
            if (kib <= SIZE_MAX / 1024u) {
                resources.rss = (size_t)kib * 1024u;
                have_rss = 1;
            }
            break;
        }
        fclose(status);
    }
    DIR *fds = opendir("/proc/self/fd");
    if (fds) {
        errno = 0;
        for (struct dirent *entry; (entry = readdir(fds));)
            if (entry->d_name[0] >= '0' && entry->d_name[0] <= '9')
                ++resources.fd_count;
        if (errno) resources.fd_count = 0;
        closedir(fds);
        if (resources.fd_count) --resources.fd_count; /* Directory FD. */
    }
    resources.valid = resources.total && resources.available <= resources.total &&
        have_rss && resources.fd_count;
    return resources;
}

tg_limit_plan tg_limits_plan(const tg_limit_resources *r, size_t configured,
                            size_t active, size_t pending_upstreams,
                            size_t buffer_used, size_t slot_bytes) {
    tg_limit_plan plan = {.configured = configured};
    if (!r->valid || !slot_bytes) return plan;

    plan.headroom = memory_headroom(r->total, r->available);
    plan.ceiling = tg_limits_runtime_memory_budget(r->total, r->total);

    /* MemAvailable already excludes resident pages. Charge RSS and buffer
     * allocations against the separate process ceiling without counting the
     * same bytes twice, while preserving room for growth of live sessions. */
    size_t resident = r->rss > buffer_used ? r->rss : buffer_used;
    size_t ceiling_room = plan.ceiling > resident ? plan.ceiling - resident : 0;
    if (plan.headroom > ceiling_room) plan.headroom = ceiling_room;
    size_t new_slots = plan.headroom / (slot_bytes > MIB ? slot_bytes : MIB);
    /* A ceiling with no room for even one new client must also stop new
     * admissions when an existing session closes between samples. */
    plan.ram = new_slots ? active + new_slots : 0;

    /* Retain the original FD guard and additionally budget from live FD
     * usage. Each new client needs its downstream and primary upstream FD. */
    size_t usable = usable_fds(r->fd_limit);
    plan.fd = usable > 32u ? (usable - 32u) / 5u : 0;
    size_t remaining = usable > r->fd_count ? usable - r->fd_count : 0;
    remaining = remaining > pending_upstreams ? remaining - pending_upstreams : 0;
    if (remaining < 2u)
        plan.fd = 0;
    else if (remaining / 2u < plan.fd && active < plan.fd - remaining / 2u)
        plan.fd = active + remaining / 2u;
    return plan;
}

size_t tg_limits_adapt(const tg_limit_plan *plan, size_t current, size_t *recovery_limit,
                       unsigned *reasons) {
    size_t target = plan->ram < plan->fd ? plan->ram : plan->fd;
    if (target > plan->configured) target = plan->configured;
    *reasons = (target == plan->ram ? TG_LIMIT_RAM : 0u) |
               (target == plan->fd ? TG_LIMIT_FD : 0u) |
               (target == plan->configured ? TG_LIMIT_CONFIGURED : 0u);
    if (target <= current) {
        *recovery_limit = 0;
        return target;
    }
    size_t growth_target = target;
    size_t margin_slots = TG_LIMITS_OS_MARGIN_BYTES / MIB;
    if (plan->ram == target && target > current && target - current > margin_slots)
        growth_target = target - margin_slots;
    else if (plan->ram == target && current)
        growth_target = current;
    /* Two consecutive samples must support the increase. A lost sample
     * clears this state through the immediate reduction path above. */
    size_t confirmed = *recovery_limit < growth_target ? *recovery_limit : growth_target;
    *recovery_limit = growth_target;
    if (confirmed <= current) confirmed = current;
    if (confirmed - current > TG_LIMITS_GROWTH_STEP)
        confirmed = current + TG_LIMITS_GROWTH_STEP;
    if (confirmed < target) *reasons |= TG_LIMIT_RECOVERY;
    return confirmed;
}
