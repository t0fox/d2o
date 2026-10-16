#ifndef D2K_TG_LISTENER_H
#define D2K_TG_LISTENER_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#define TG_LISTEN_PORT 1443u
#define TG_SO_ORIGINAL_DST 80

typedef struct {
    sa_family_t family;
    uint16_t port;
    uint8_t address[16];
} tg_listener_destination;

int tg_listener_decode_original_dst(const uint8_t *raw, size_t len,
                                    uint16_t *port, uint8_t ipv4[4]);
int tg_listener_is_self_dial(const uint8_t ipv4[4], uint16_t port,
                             const uint16_t *listen_ports, size_t port_count);
int tg_listener_get_original_dst(int fd, uint16_t *port, uint8_t ipv4[4]);
int tg_listener_decode_original_dst_any(const uint8_t *raw, size_t len,
                                        tg_listener_destination *out);
int tg_listener_get_original_dst_any(int fd, tg_listener_destination *out);
int tg_listener_is_self_dial_addr(const tg_listener_destination *destination,
                                  const uint16_t *listen_ports,
                                  size_t port_count);

#endif
