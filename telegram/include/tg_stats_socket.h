#ifndef D2K_TG_STATS_SOCKET_H
#define D2K_TG_STATS_SOCKET_H

#include "tg_stats.h"
#include "../../runtime/d2k_diag_ipc.h"
#ifdef TG_EPOLL_TESTING
#include "tg_epoll_proxy.h"
#endif

#include <sys/types.h>

typedef struct {
    int fd;
    char path[108];
    dev_t device;
    ino_t inode;
    uint64_t process_generation;
} tg_stats_socket;

typedef struct {
    int has_map, loaded_last_good;
    int64_t fetched_at, config_expires;
    size_t endpoint_count;
    int refreshing;
    char last_refresh_result[24];
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

typedef struct {
    d2k_diag_header header;
    uint64_t generation;
    int64_t nofile;
    tg_epoll_proxy_stats stats;
    tg_stats_socket_context map;
} tg_diag_snapshot;

_Static_assert(sizeof(tg_diag_snapshot) <= 65536, "bounded Telegram datagram");

size_t tg_stats_encode(const tg_diag_snapshot *sample, int detailed, char *response, size_t capacity);

#ifdef TG_EPOLL_TESTING
int tg_stats_socket_open(tg_stats_socket *socket, const char *path);
int tg_stats_socket_serve(tg_stats_socket *socket,
                          const tg_epoll_proxy *proxy,
                          const tg_stats_socket_context *context);
void tg_stats_socket_close(tg_stats_socket *socket);

#endif
#endif
