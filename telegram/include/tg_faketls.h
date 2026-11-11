#ifndef D2K_TG_FAKETLS_H
#define D2K_TG_FAKETLS_H

#include <stddef.h>
#include <stdint.h>

#define TG_FAKETLS_MAX_RECORD_PAYLOAD 16384u
#define TG_FAKETLS_READ_HEADROOM 256u
#define TG_FAKETLS_MAX_RECORD \
    (5u + TG_FAKETLS_MAX_RECORD_PAYLOAD + TG_FAKETLS_READ_HEADROOM)
#define TG_FAKETLS_DIGEST_LEN 32u
#define TG_FAKETLS_MAX_HOSTNAME 253u

typedef struct {
    uint8_t random[TG_FAKETLS_DIGEST_LEN];
    uint8_t session_id[32];
    size_t session_id_len;
    uint8_t cipher_suite[2];
    char hostname[TG_FAKETLS_MAX_HOSTNAME + 1];
    int has_hostname;
} tg_faketls_client_hello;

/* Parse and authenticate a FakeTLS ClientHello record. */
int tg_faketls_parse_client_hello(const uint8_t *record, size_t record_len,
                                  const uint8_t *secret, size_t secret_len,
                                  tg_faketls_client_hello *out);

/* Build the synthetic ServerHello + CCS + ApplicationData records. */
int tg_faketls_build_server_hello(const uint8_t *secret, size_t secret_len,
                                  const tg_faketls_client_hello *hello,
                                  uint8_t *out, size_t out_cap,
                                  size_t *out_len);

/* Build and sign a ClientHello (used by tests and diagnostics). */
int tg_faketls_build_client_hello(const char *hostname,
                                  const uint8_t *secret, size_t secret_len,
                                  uint8_t *out, size_t out_cap,
                                  size_t *out_len);

#endif
