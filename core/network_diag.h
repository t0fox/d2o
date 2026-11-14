#ifndef D2K_COLLECT_NETWORK_DIAG_H
#define D2K_COLLECT_NETWORK_DIAG_H

#include <stdio.h>
#include "../runtime/d2k_network_diag.h"

#define D2K_NETWORK_HISTORY 240u /* Eight minutes at two seconds. */

typedef struct d2k_network_history d2k_network_history;

d2k_network_history *d2k_network_history_new(void);
void d2k_network_history_sample(d2k_network_history *history, uint64_t now,
    const d2k_network_controller_message *controller, const d2k_network_datapath_message *datapath,
    const char *proc, const char *sys, const char *run);
void d2k_network_history_write(FILE *out, const d2k_network_history *history);

#endif
