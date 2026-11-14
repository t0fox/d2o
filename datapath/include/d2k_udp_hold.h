/* d2k_udp_hold.h — bounded ownership for QUIC/UDP datagrams.
 *
 * UDP is datagram-oriented: a split QUIC ClientHello must be held as the
 * original IPv4 datagrams and replayed in FIFO order.  This module never
 * concatenates payloads and never decides whether a plan is applicable.
 */
#ifndef D2K_UDP_HOLD_H
#define D2K_UDP_HOLD_H

#include <stddef.h>
#include <stdint.h>

#include "d2k_hold.h"

#define D2K_UDP_HOLD_SLOTS 16
#define D2K_UDP_HOLD_PACKETS 8
#define D2K_UDP_HOLD_PACKET 1600
#define D2K_UDP_HOLD_WAIT_NS UINT64_C(100000000)

typedef struct d2k_udp_hold d2k_udp_hold;

typedef struct {
    d2k_key key;
    size_t count;
    uint32_t ids[D2K_UDP_HOLD_PACKETS];
    size_t len[D2K_UDP_HOLD_PACKETS];
    uint8_t packets[D2K_UDP_HOLD_PACKETS][D2K_UDP_HOLD_PACKET];
    /* nfmark of each queued datagram (NFQA_MARK; 0 when the kernel gave none).
       A marked client may be policy-routed (Keenetic fwmark 0xffffaaa ->
       table 4096, e.g. a VPN): such a datagram is never re-sent raw. */
    uint32_t marks[D2K_UDP_HOLD_PACKETS];
} d2k_udp_hold_batch;

/* Releases one whole slot (expiry, overflow, free), datagrams in arrival
 * order.  The callback owns every ID in the batch.  A slot is handed back as
 * a unit, not ID by ID, because its datagrams cannot all be ACCEPTed: each
 * one reached conntrack while the head was still queued and carries its own
 * unconfirmed entry, so only the head may go to the kernel; the rest follow
 * it through the raw path (d2k_udp_release_batch, task 46). */
typedef void (*d2k_udp_hold_release)(void *ctx, const d2k_udp_hold_batch *batch);

d2k_udp_hold *d2k_udp_hold_new(void);
void d2k_udp_hold_free(d2k_udp_hold *h,
                       d2k_udp_hold_release release, void *ctx);

/* Stores the complete original datagram.  Returns 1 when the ID is owned by
 * the hold table, 0 when the caller retains ownership.  A malformed/oversize
 * datagram is never partially stored. */
int d2k_udp_hold_feed(d2k_udp_hold *h, const d2k_key *key, uint32_t id,
                      const uint8_t *packet, size_t len, uint64_t now_ns,
                      d2k_udp_hold_release release, void *ctx);
/* The same, recording the datagram's nfmark (feed records 0). */
int d2k_udp_hold_feed_marked(d2k_udp_hold *h, const d2k_key *key, uint32_t id,
                             const uint8_t *packet, size_t len, uint32_t mark,
                             uint64_t now_ns, d2k_udp_hold_release release, void *ctx);

/* Removes one flow from the table without releasing its IDs.  The caller owns
 * the returned batch and must issue the final verdict for every ID.  Call
 * d2k_udp_hold_flush with the release callback before take when deadlines are
 * being serviced. */
int d2k_udp_hold_take(d2k_udp_hold *h, const d2k_key *key, uint64_t now_ns,
                      d2k_udp_hold_batch *out);

/* Releases expired slots and reports how many original IDs were released. */
uint64_t d2k_udp_hold_timeout_packets(const d2k_udp_hold *h);
size_t d2k_udp_hold_flush(d2k_udp_hold *h, uint64_t now_ns,
                          d2k_udp_hold_release release, void *ctx);

/* Earliest slot deadline; zero when nothing is held.  The service sleeps no
 * longer than this, otherwise an expiry waits for the next unrelated packet
 * or the poll cap (up to 200 ms past D2K_UDP_HOLD_WAIT_NS). */
uint64_t d2k_udp_hold_next_ns(const d2k_udp_hold *h);

#endif
