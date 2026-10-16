#ifndef D2K_TG_MTPROTO_H
#define D2K_TG_MTPROTO_H

#include <stddef.h>
#include <stdint.h>
#include <openssl/evp.h>

#define TG_MTPROTO_HANDSHAKE_LEN 64u
#define TG_MTPROTO_PREKEY_IV_LEN 48u

typedef enum {
    TG_MTPROTO_ABRIDGED = 1,
    TG_MTPROTO_INTERMEDIATE = 2,
    TG_MTPROTO_PADDED_INTERMEDIATE = 3
} tg_mtproto_proto;

typedef struct {
    uint32_t dc_id;
    int is_media;
    tg_mtproto_proto proto;
    uint8_t prekey_iv[TG_MTPROTO_PREKEY_IV_LEN];
} tg_mtproto_init;

typedef struct {
    EVP_CIPHER_CTX *ctx;
} tg_mtproto_ctr;

int tg_mtproto_parse_obfuscated2(
    const uint8_t packet[TG_MTPROTO_HANDSHAKE_LEN], tg_mtproto_init *out);
int tg_mtproto_parse_secret(
    const uint8_t packet[TG_MTPROTO_HANDSHAKE_LEN],
    const uint8_t *secret, size_t secret_len, tg_mtproto_init *out);
/* Контексты шифра должны быть обнулены до вызова; вызывающий освобождает их. */
int tg_mtproto_make_obfuscated2_init(tg_mtproto_proto proto, uint32_t dc_id,
                                     int is_media,
                                     uint8_t packet[TG_MTPROTO_HANDSHAKE_LEN],
                                     tg_mtproto_ctr *to_server,
                                     tg_mtproto_ctr *from_server);
int tg_mtproto_ctr_init(tg_mtproto_ctr *ctx, const uint8_t key[32],
                        const uint8_t iv[16]);
int tg_mtproto_ctr_xor(tg_mtproto_ctr *ctx, uint8_t *data, size_t len);
void tg_mtproto_ctr_destroy(tg_mtproto_ctr *ctx);
/* Создаёт client-to-server obfuscated2 CTR-потоки после 64-байтового init. */
int tg_mtproto_direct_stream_ciphers(
    const uint8_t init[TG_MTPROTO_HANDSHAKE_LEN],
    tg_mtproto_ctr *decrypt, tg_mtproto_ctr *encrypt);
int tg_mtproto_aes_ige(uint8_t *data, size_t len, const uint8_t key[32],
                       const uint8_t iv[32], int encrypt);
/* Пакует MTProto 2.0 crypto header; padding задаёт вызывающий код. */
int tg_mtproto_v2_encrypt(const uint8_t auth_key[256],
                          const uint8_t *plaintext, size_t plaintext_len,
                          const uint8_t *padding, size_t padding_len,
                          uint8_t *packet, size_t packet_cap,
                          size_t *packet_len);
int tg_mtproto_v2_decrypt(const uint8_t auth_key[256],
                          const uint8_t *packet, size_t packet_len,
                          uint8_t *plaintext, size_t plaintext_cap,
                          size_t *plaintext_len);

typedef enum {
    TG_MTPROTO_PROBE_OK = 0,
    TG_MTPROTO_PROBE_INVALID = 1,
    TG_MTPROTO_PROBE_TIMEOUT = 2,
    TG_MTPROTO_PROBE_CONNECT = 3,
    TG_MTPROTO_PROBE_IO = 4
} tg_mtproto_probe_status;

typedef enum {
    TG_MTPROTO_PROBE_STAGE_INPUT = 0,
    TG_MTPROTO_PROBE_STAGE_TCP = 1,
    TG_MTPROTO_PROBE_STAGE_MTPROTO = 2,
    TG_MTPROTO_PROBE_STAGE_RES_PQ = 3
} tg_mtproto_probe_stage;

typedef struct {
    tg_mtproto_probe_status status;
    tg_mtproto_probe_stage stage;
    uint64_t latency_ms;
    uint8_t nonce[16];
    uint8_t server_nonce[16];
    uint8_t pq[8];
    size_t pq_len;
} tg_mtproto_probe_result;

tg_mtproto_probe_status tg_mtproto_probe_res_pq(
    const char *numeric_address, uint16_t port, uint32_t dc_id, int is_media,
    uint32_t timeout_ms, tg_mtproto_probe_result *out);

#endif
