#ifndef D2K_TG_STATS_SOCKET_H
#define D2K_TG_STATS_SOCKET_H

#include "tg_epoll_proxy.h"
#include "tg_dc_map.h"

#include <sys/types.h>

typedef struct {
    int fd;
    char path[108];
    dev_t device;
    ino_t inode;
    uint64_t process_generation;
} tg_stats_socket;

typedef struct {
    const tg_dc_map_store *dc_map;
    int refreshing;
    const char *last_refresh_result;
    int64_t last_attempt_at;
    int64_t last_success_at;
    int64_t last_failure_at;
    int64_t next_refresh_at;
    uint64_t refresh_attempts;
    uint64_t refresh_successes;
    uint64_t refresh_failures;
    int last_refresh_errno;
    int last_manifest_errno;
} tg_stats_socket_context;

int tg_stats_socket_open(tg_stats_socket *socket, const char *path);
int tg_stats_socket_serve(tg_stats_socket *socket,
                          const tg_epoll_proxy *proxy,
                          const tg_stats_socket_context *context);
void tg_stats_socket_close(tg_stats_socket *socket);

#endif
