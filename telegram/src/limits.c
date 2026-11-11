#define _POSIX_C_SOURCE 200809L
#include "tg_limits.h"

#include <stdint.h>
#include <string.h>
#include <sys/resource.h>

#define TG_LIMITS_DEFAULT_NOFILE 1024u
#define TG_LIMITS_UNLIMITED_MAX 512u
#define TG_LIMITS_RESERVED_FDS 33u
#define TG_LIMITS_FDS_PER_CONNECTION 2u
#define TG_LIMITS_MEMORY_BUDGET_MAX (192u * 1024u * 1024u)

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

size_t tg_limits_policy_connections(size_t fd_limit, size_t total_bytes,
                                    size_t available_bytes, size_t cap) {
    if (!total_bytes || !available_bytes || available_bytes > total_bytes) return 0;
    size_t usable_fds = fd_limit - (fd_limit / 5u + (fd_limit % 5u != 0));
    size_t fd_slots = usable_fds > 32u ? (usable_fds - 32u) / 5u : 0;
    size_t reserved = total_bytes / 5u;
    if (available_bytes / 2u > reserved) reserved = available_bytes / 2u;
    /* Cold boot may have less RAM free than the nominal reserve alone.
     * Leave at least 3/4 of available memory for the system under pressure
     * and admit only whole slots from the remaining quarter. */
    size_t max_reserve = available_bytes - available_bytes / 4u;
    if (reserved > max_reserve) reserved = max_reserve;
    size_t memory_slots = (available_bytes - reserved) / (1024u * 1024u);
    if (cap > fd_slots) cap = fd_slots;
    return cap < memory_slots ? cap : memory_slots;
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
