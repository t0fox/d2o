#ifndef D2K_TG_TRANSPARENT_H
#define D2K_TG_TRANSPARENT_H

#include "tg_dc_map.h"
#include "tg_epoll_proxy.h"
#include "tg_listener.h"
#include "tg_mtproto.h"

typedef struct {
    tg_dc_map_store *map_store;
    const uint16_t *allowed_ports;
    size_t allowed_port_count;
    const char *const *allowed_cidrs;
    size_t allowed_cidr_count;
    /* Optional tg://proxy secrets. When set, direct local clients carrying
       any of these secrets are accepted in addition to transparent
       connections. */
    const uint8_t (*local_secrets)[16];
    size_t local_secret_count;
} tg_transparent_policy;

int tg_transparent_select_route(
    void *policy, const tg_listener_destination *original,
    const uint8_t handshake[TG_MTPROTO_HANDSHAKE_LEN],
    tg_epoll_route_selection *selection);

/* Compatibility wrapper for callers that only need the destination. */
int tg_transparent_select_target(
    void *policy, const tg_listener_destination *original,
    const uint8_t handshake[TG_MTPROTO_HANDSHAKE_LEN],
    tg_listener_destination *upstream);

#endif
