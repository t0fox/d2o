#define _POSIX_C_SOURCE 200809L
#include "tg_stats_socket.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static int set_socket_flags(int fd) {
    int status_flags = fcntl(fd, F_GETFL, 0);
    int descriptor_flags = fcntl(fd, F_GETFD, 0);
    if (status_flags < 0 || descriptor_flags < 0 ||
        fcntl(fd, F_SETFL, status_flags | O_NONBLOCK) != 0 ||
        fcntl(fd, F_SETFD, descriptor_flags | FD_CLOEXEC) != 0)
        return -1;
    return 0;
}

static int remove_stale_socket(const char *path) {
    struct stat current;
    if (lstat(path, &current) != 0) return errno == ENOENT ? 0 : -1;
    if (!S_ISSOCK(current.st_mode) || current.st_uid != geteuid()) {
        errno = EEXIST;
        return -1;
    }

    int probe = socket(AF_UNIX, SOCK_STREAM, 0);
    if (probe < 0) return -1;
    if (set_socket_flags(probe) != 0) {
        close(probe);
        return -1;
    }
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, strlen(path) + 1);
    int rc = connect(probe, (struct sockaddr *)&address, sizeof(address));
    int saved_errno = errno;
    close(probe);
    if (rc == 0 || (saved_errno != ECONNREFUSED && saved_errno != ENOENT)) {
        errno = EADDRINUSE;
        return -1;
    }
    if (unlink(path) != 0 && errno != ENOENT) return -1;
    return 0;
}

int tg_stats_socket_open(tg_stats_socket *server, const char *path) {
    if (!server || !path || !*path) {
        errno = EINVAL;
        return -1;
    }
    memset(server, 0, sizeof(*server));
    server->fd = -1;
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    size_t path_len = strlen(path);
    if (path_len >= sizeof(address.sun_path) || path_len >= sizeof(server->path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, path_len + 1);
    if (remove_stale_socket(path) != 0) return -1;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (set_socket_flags(fd) != 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    mode_t previous_mask = umask(0077);
    int bind_rc = bind(fd, (struct sockaddr *)&address, sizeof(address));
    int bind_errno = errno;
    (void)umask(previous_mask);
    if (bind_rc != 0 || listen(fd, 8) != 0) {
        int saved_errno = bind_rc != 0 ? bind_errno : errno;
        close(fd);
        if (bind_rc == 0) unlink(path);
        errno = saved_errno;
        return -1;
    }
    struct stat created = {0}, secured = {0};
    int setup_error = 0;
    if (lstat(path, &created) != 0) setup_error = errno;
    else if (!S_ISSOCK(created.st_mode) || created.st_uid != geteuid())
        setup_error = EPERM;
    else if (chmod(path, 0600) != 0) setup_error = errno;
    else if (lstat(path, &secured) != 0) setup_error = errno;
    else if (!S_ISSOCK(secured.st_mode) || secured.st_uid != geteuid() ||
             secured.st_dev != created.st_dev || secured.st_ino != created.st_ino)
        setup_error = ESTALE;
    if (setup_error) {
        close(fd);
        struct stat current;
        if (created.st_ino && lstat(path, &current) == 0 &&
            S_ISSOCK(current.st_mode) && current.st_dev == created.st_dev &&
            current.st_ino == created.st_ino)
            unlink(path);
        errno = setup_error;
        return -1;
    }
    server->fd = fd;
    memcpy(server->path, path, path_len + 1);
    server->device = secured.st_dev;
    server->inode = secured.st_ino;
    return 0;
}

int tg_stats_socket_serve(tg_stats_socket *server,
                          const tg_epoll_proxy *proxy) {
    if (!server || server->fd < 0 || !proxy) {
        errno = EINVAL;
        return -1;
    }
    for (;;) {
        int client = accept(server->fd, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            return -1;
        }
        if (set_socket_flags(client) != 0) {
            close(client);
            continue;
        }
        tg_epoll_proxy_stats stats;
        char response[512];
        int n = tg_epoll_proxy_get_stats(proxy, &stats);
        int length = n == 0
            ? snprintf(response, sizeof(response),
                       "{\"active_connections\":%zu,\"max_connections\":%zu,\"connections_started\":%" PRIu64 ",\"bytes_from_clients\":%" PRIu64 ",\"bytes_from_upstreams\":%" PRIu64 ",\"wss_attempts\":%" PRIu64 ",\"wss_failures\":%" PRIu64 ",\"wss_responses\":%" PRIu64 ",\"cf_wss_responses\":%" PRIu64 "}\n",
                       stats.active_connections, stats.max_connections,
                       stats.connections_started, stats.bytes_from_clients,
                       stats.bytes_from_upstreams, stats.wss_attempts,
                       stats.wss_failures, stats.wss_responses,
                       stats.cf_wss_responses)
            : -1;
        if (length > 0 && (size_t)length < sizeof(response)) {
            size_t sent = 0;
            while (sent < (size_t)length) {
                ssize_t written = send(client, response + sent,
                                       (size_t)length - sent, MSG_NOSIGNAL);
                if (written > 0) {
                    sent += (size_t)written;
                    continue;
                }
                if (written < 0 && errno == EINTR) continue;
                break;
            }
        }
        close(client);
    }
}

void tg_stats_socket_close(tg_stats_socket *server) {
    if (!server) return;
    if (server->fd >= 0) close(server->fd);
    if (server->path[0]) {
        struct stat current;
        if (lstat(server->path, &current) == 0 && S_ISSOCK(current.st_mode) &&
            current.st_uid == geteuid() && current.st_dev == server->device &&
            current.st_ino == server->inode)
            (void)unlink(server->path);
    }
    memset(server, 0, sizeof(*server));
    server->fd = -1;
}
