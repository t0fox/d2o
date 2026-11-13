#ifndef D2K_TG_STATS_SOCKET_H
#define D2K_TG_STATS_SOCKET_H

#include "tg_epoll_proxy.h"

#include <sys/types.h>

typedef struct {
    int fd;
    char path[108];
    dev_t device;
    ino_t inode;
} tg_stats_socket;

int tg_stats_socket_open(tg_stats_socket *socket, const char *path);
int tg_stats_socket_serve(tg_stats_socket *socket,
                          const tg_epoll_proxy *proxy);
void tg_stats_socket_close(tg_stats_socket *socket);

#endif
