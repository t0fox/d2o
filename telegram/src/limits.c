#define _POSIX_C_SOURCE 200809L
#include "tg_limits.h"

#include <stdint.h>
#include <sys/resource.h>

#define TG_LIMITS_DEFAULT_NOFILE 1024u
#define TG_LIMITS_UNLIMITED_MAX 512u
#define TG_LIMITS_RESERVED_FDS 33u
#define TG_LIMITS_FDS_PER_CONNECTION 2u

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
