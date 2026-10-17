#ifndef D2K_TG_WS_H
#define D2K_TG_WS_H

#include <stddef.h>
#include <stdint.h>
#include <openssl/ssl.h>
#include <poll.h>
#include "tg_memory_budget.h"

#define TG_WS_MAX_MESSAGE (4u * 1024u * 1024u)
#define TG_WS_PUMP_RX_INITIAL (16u * 1024u)
#define TG_WS_CONTINUATION 0x0u
#define TG_WS_TEXT 0x1u
#define TG_WS_BINARY 0x2u
#define TG_WS_CLOSE 0x8u
#define TG_WS_PING 0x9u
#define TG_WS_PONG 0xau
#define TG_WS_UPGRADE_MAX_HEADER 16384u

typedef struct {
    char key[25];
    char subprotocol[64];
    uint8_t request[1024];
    size_t request_len, request_offset;
    char response[TG_WS_UPGRADE_MAX_HEADER + 1u];
    size_t response_len;
    int complete, failed;
} tg_ws_upgrade_state;

int tg_ws_upgrade_start(tg_ws_upgrade_state *state, const char *host_header,
                        const char *path);
int tg_ws_upgrade_start_ex(tg_ws_upgrade_state *state,
                           const char *host_header, const char *path,
                           const char *subprotocol, const char *origin,
                           const char *user_agent);
const uint8_t *tg_ws_upgrade_pending(const tg_ws_upgrade_state *state,
                                    size_t *length);
int tg_ws_upgrade_advance(tg_ws_upgrade_state *state, size_t length);
/* Возвращает 0 при неполном заголовке, 1 после валидного ответа и -1 при ошибке. */
int tg_ws_upgrade_feed(tg_ws_upgrade_state *state, const uint8_t *data,
                       size_t length, size_t *consumed);

int tg_ws_encode_client_frame(uint8_t *dst, size_t cap, uint8_t opcode,
                              const uint8_t *payload, size_t payload_len,
                              size_t *written);
int tg_ws_decode_server_frame(const uint8_t *src, size_t len, size_t max_payload,
                              uint8_t *opcode, const uint8_t **payload,
                              size_t *payload_len, size_t *consumed);

typedef struct {
    uint8_t *data;
    size_t len, cap;
    uint8_t opcode;
    int fragmented;
    tg_memory_budget *memory_budget;
} tg_ws_reassembly;

/* Состояние перед первым вызовом должно быть нулевым.
 * 0 — ожидается часть кадра, 1 — готовое сообщение/управляющий кадр,
 * 2 — фрагмент принят, -1 — ошибка протокола или памяти.
 * Выходной payload для собранного сообщения живёт до следующего вызова. */
int tg_ws_reassembly_feed(tg_ws_reassembly *state, const uint8_t *src,
                          size_t len, size_t max_payload, uint8_t *opcode,
                          const uint8_t **payload, size_t *payload_len,
                          size_t *consumed);
void tg_ws_reassembly_destroy(tg_ws_reassembly *state);

int tg_ws_upgrade(SSL *ssl, const char *host_header, const char *path);
int tg_ws_write_binary(SSL *ssl, const uint8_t *payload, size_t payload_len);
/* Returns 0 for one binary message, -2 for a clean peer close, -1 on protocol/I/O error. */
int tg_ws_read_binary(SSL *ssl, uint8_t *dst, size_t cap, size_t *payload_len);

typedef struct tg_ws_tx_frame tg_ws_tx_frame;
typedef struct {
    /* tx_bytes is remaining wire data; tx_memory_bytes retains the full
     * buffer and node charges until free, excluding allocator metadata. */
    SSL *ssl; int fd; uint8_t *rx; size_t rx_len,rx_cap,tx_bytes,tx_memory_bytes;
    tg_ws_tx_frame *tx_head,*tx_tail; tg_ws_reassembly reassembly;
    tg_memory_budget *memory_budget;
    int failed,closed,read_wants_write,write_wants_read;
} tg_ws_pump;
typedef int (*tg_ws_message_cb)(void *ctx,const uint8_t *payload,size_t payload_len);
int tg_ws_pump_init(tg_ws_pump *pump,SSL *ssl);
int tg_ws_pump_init_accounted(tg_ws_pump *pump, SSL *ssl,
                              tg_memory_budget *memory_budget);
void tg_ws_pump_destroy(tg_ws_pump *pump);
int tg_ws_pump_queue_binary(tg_ws_pump *pump,const uint8_t *payload,size_t payload_len);
int tg_ws_pump_queue_ping(tg_ws_pump *pump,const uint8_t *payload,size_t payload_len);
int tg_ws_pump_queue_close(tg_ws_pump *pump);
int tg_ws_pump_fd(const tg_ws_pump *pump);
short tg_ws_pump_events(const tg_ws_pump *pump);
int tg_ws_pump_process(tg_ws_pump *pump,short revents,tg_ws_message_cb callback,void *ctx);

#endif
