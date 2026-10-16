#ifndef D2K_TG_LIMITS_H
#define D2K_TG_LIMITS_H

#include <stddef.h>

size_t tg_limits_soft_nofile(void);
size_t tg_limits_auto_max_connections(size_t fd_limit, size_t memory_budget,
                                     size_t bytes_per_connection,
                                     size_t hedge_limit,
                                     size_t configured_max);

#endif
