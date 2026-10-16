#ifndef D2K_TG_MTPROTO_AUTH_H
#define D2K_TG_MTPROTO_AUTH_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t nonce[16];
    uint8_t server_nonce[16];
    uint8_t new_nonce[32];
    uint8_t auth_key[256];
    int32_t time_offset;
    uint64_t first_salt;
    int auth_key_ready;
    int dh_key_ready;
    int step2_ready;
} tg_mtproto_auth_state;

/* Формирует req_DH_params по проверенному resPQ и 256 байтам случайности. */
int tg_mtproto_auth_step2(tg_mtproto_auth_state *state,
                          const uint8_t *res_pq, size_t res_pq_len,
                          const uint8_t randomness[256],
                          uint8_t *request, size_t request_cap,
                          size_t *request_len);
int tg_mtproto_auth_step3(tg_mtproto_auth_state *state,
                          const uint8_t *server_dh_params,
                          size_t server_dh_params_len,
                          const uint8_t randomness[272], int32_t now,
                          uint8_t *request, size_t request_cap,
                          size_t *request_len);
int tg_mtproto_auth_step4(tg_mtproto_auth_state *state,
                          const uint8_t *dh_gen_answer,
                          size_t dh_gen_answer_len);
void tg_mtproto_auth_clear(tg_mtproto_auth_state *state);

#endif
