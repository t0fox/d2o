#ifndef D2K_TG_MTPROTO_SPLITTER_H
#define D2K_TG_MTPROTO_SPLITTER_H

#include "tg_mtproto.h"
#include "tg_memory_budget.h"

#define TG_MTPROTO_MAX_PACKET (4u * 1024u * 1024u)

typedef enum {
    TG_MTPROTO_SPLIT_OK = 0,
    TG_MTPROTO_SPLIT_INVALID = -1,
    TG_MTPROTO_SPLIT_TOO_LARGE = -2,
    TG_MTPROTO_SPLIT_NO_MEMORY = -3,
    TG_MTPROTO_SPLIT_CIPHER_ERROR = -4,
    TG_MTPROTO_SPLIT_CALLBACK_ERROR = -5
} tg_mtproto_split_result;

typedef int (*tg_mtproto_packet_cb)(void *ctx, const uint8_t *packet,
                                    size_t packet_len);

typedef struct {
    tg_mtproto_proto proto;
    uint8_t header[4];
    size_t header_len;
    size_t total_len;
    uint8_t *packet;
    size_t packet_len;
    size_t packet_cap;
    int disabled;
    int error;
    tg_memory_budget *memory_budget;
} tg_mtproto_splitter;

int tg_mtproto_splitter_init(tg_mtproto_splitter *splitter,
                             tg_mtproto_proto proto);
int tg_mtproto_splitter_init_accounted(tg_mtproto_splitter *splitter,
                                       tg_mtproto_proto proto,
                                       tg_memory_budget *memory_budget);
void tg_mtproto_splitter_destroy(tg_mtproto_splitter *splitter);
int tg_mtproto_splitter_feed(tg_mtproto_splitter *splitter,
                             tg_mtproto_ctr *encrypt, uint8_t *plaintext,
                             size_t len, tg_mtproto_packet_cb callback,
                             void *callback_ctx);
int tg_mtproto_splitter_flush(tg_mtproto_splitter *splitter,
                              tg_mtproto_packet_cb callback,
                              void *callback_ctx);
int tg_mtproto_splitter_error(const tg_mtproto_splitter *splitter);
const char *tg_mtproto_split_result_text(int result);

#endif
