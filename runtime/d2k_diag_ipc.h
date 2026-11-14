#ifndef D2K_DIAG_IPC_H
#define D2K_DIAG_IPC_H

#include "d2k_diagnostics_files.h"
#include <sys/socket.h>
#include <stdint.h>
#include <sys/un.h>
#include <stddef.h>

#ifndef D2K_DIAG_INPUT
#define D2K_DIAG_INPUT D2K_DIAG_DIR "/input.sock"
#endif
#define D2K_DIAG_LIVE D2K_DIAG_DIR "/telegram.json"

enum { D2K_DIAG_IPC_VERSION = 1, D2K_DIAG_IPC_TELEGRAM = 1,
       D2K_DIAG_IPC_COUNTS, D2K_DIAG_IPC_EVENT, D2K_DIAG_IPC_LIMIT,
       D2K_DIAG_IPC_NETWORK_DATAPATH, D2K_DIAG_IPC_NETWORK_CONTROLLER };

typedef struct {
    unsigned version, kind;
    long pid;
} d2k_diag_header;

static inline int d2k_diag_address(struct sockaddr_un *address, const char *path) {
    size_t len = strlen(path);
    if (len >= sizeof(address->sun_path)) { errno = ENAMETOOLONG; return -1; }
    memset(address, 0, sizeof(*address));
    address->sun_family = AF_UNIX;
    memcpy(address->sun_path, path, len + 1);
    return 0;
}

static inline int d2k_diag_sender(void) {
    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd >= 0 && fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static inline void d2k_diag_send(int fd, const char *path, const void *data, size_t size) {
    struct sockaddr_un address;
    int saved = errno;
    if (fd >= 0 && d2k_diag_address(&address, path) == 0)
        (void)sendto(fd, data, size, MSG_DONTWAIT, (struct sockaddr *)&address, sizeof(address));
    errno = saved;
}
#endif
