#ifndef D2K_COLLECT_NETWORK_DIAG_H
#define D2K_COLLECT_NETWORK_DIAG_H

#include <stdio.h>
#include "../runtime/d2k_network_diag.h"

#define D2K_NETWORK_HISTORY 240u /* Eight minutes at two seconds. */
#define D2K_NETWORK_BUDGET (2u * 1024u * 1024u)
#define D2K_NETWORK_STATE "network-state-v1"
#define D2K_NETWORK_EXPORT_LOCK "network-export.lock"

typedef struct d2k_network_history d2k_network_history;

size_t d2k_network_history_bytes(void);
uint64_t d2k_network_session(const char *dir);
int d2k_network_open(const char *dir, const char *name, int create);
int d2k_network_memory_ready(const char *proc);
d2k_network_history *d2k_network_history_map(int fd, uint64_t session);
void d2k_network_history_unmap(d2k_network_history *history, int fd);
d2k_network_history *d2k_network_history_copy(int fd, uint64_t session);

void d2k_network_history_sample(d2k_network_history *history, uint64_t now,
    const d2k_network_controller_message *controller, const d2k_network_datapath_message *datapath,
    const char *proc, const char *sys, const char *run);
void d2k_network_history_write(FILE *out, const d2k_network_history *history);

#endif
