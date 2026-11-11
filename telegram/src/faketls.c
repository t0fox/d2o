#include "tg_faketls.h"

#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <string.h>
#include <time.h>

#define TLS_RECORD_HANDSHAKE 0x16u
#define TLS_RECORD_CHANGE_CIPHER_SPEC 0x14u
#define TLS_RECORD_APPLICATION_DATA 0x17u
#define TLS_HANDSHAKE_CLIENT_HELLO 0x01u
#define TLS_HANDSHAKE_SERVER_HELLO 0x02u
#define TLS_DIGEST_POS 11u
#define TLS_RANDOM_OFFSET 11u

static uint16_t read_be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t read_be24(const uint8_t *p) {
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
}

static void write_be16(uint8_t *p, uint16_t value) {
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

static void write_be24(uint8_t *p, uint32_t value) {
    p[0] = (uint8_t)(value >> 16);
    p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)value;
}

static int hmac_sha256(const uint8_t *secret, size_t secret_len,
                       const uint8_t *data, size_t data_len,
                       uint8_t out[TG_FAKETLS_DIGEST_LEN]) {
    unsigned int out_len = 0;
    if (!secret || !data || !out || secret_len > 0x7fffffff)
        return -1;
    if (!HMAC(EVP_sha256(), secret, (int)secret_len, data, data_len, out,
              &out_len) ||
        out_len != TG_FAKETLS_DIGEST_LEN)
        return -1;
    return 0;
}

static void select_cipher_suite(const uint8_t *suites, size_t suites_len,
                                uint8_t out[2]) {
    out[0] = 0x13;
    out[1] = 0x01;
    for (size_t i = 0; i + 1 < suites_len; i += 2) {
        if (suites[i] == 0x13 && suites[i + 1] >= 0x01 &&
            suites[i + 1] <= 0x03) {
            out[0] = suites[i];
            out[1] = suites[i + 1];
            return;
        }
    }
}

static int parse_sni(const uint8_t *extensions, size_t extensions_len,
                     char *hostname, size_t hostname_cap, int *has_hostname) {
    size_t offset = 0;
    *has_hostname = 0;
    while (offset + 4 <= extensions_len) {
        uint16_t type = read_be16(extensions + offset);
        uint16_t length = read_be16(extensions + offset + 2);
        offset += 4;
        if (offset + length > extensions_len) return -1;
        const uint8_t *ext = extensions + offset;
        if (type == 0x0000 && length >= 5) {
            uint16_t list_len = read_be16(ext);
            if (length < 2u + list_len || list_len < 3 || ext[2] != 0)
                return -1;
            uint16_t host_len = read_be16(ext + 3);
            if (length < 5u + host_len || host_len > hostname_cap - 1)
                return -1;
            memcpy(hostname, ext + 5, host_len);
            hostname[host_len] = '\0';
            *has_hostname = 1;
            return 0;
        }
        offset += length;
    }
    return 0;
}

int tg_faketls_parse_client_hello(const uint8_t *record, size_t record_len,
                                  const uint8_t *secret, size_t secret_len,
                                  tg_faketls_client_hello *out) {
    uint8_t signed_record[TG_FAKETLS_MAX_RECORD];
    uint8_t digest[TG_FAKETLS_DIGEST_LEN];
    if (!record || !secret || !out || record_len > sizeof(signed_record) ||
        record_len < 5u + 4u + 6u + TG_FAKETLS_DIGEST_LEN ||
        record[0] != TLS_RECORD_HANDSHAKE)
        return -1;
    memset(out, 0, sizeof(*out));
    size_t payload_len = read_be16(record + 3);
    if (payload_len + 5u != record_len) return -1;
    const uint8_t *handshake = record + 5;
    if (payload_len < 4 || handshake[0] != TLS_HANDSHAKE_CLIENT_HELLO)
        return -1;
    size_t handshake_len = read_be24(handshake + 1);
    if (handshake_len + 4u != payload_len) return -1;

    const uint8_t *client_random = record + TLS_RANDOM_OFFSET;
    memcpy(signed_record, record, record_len);
    memset(signed_record + TLS_RANDOM_OFFSET, 0, TG_FAKETLS_DIGEST_LEN);
    if (hmac_sha256(secret, secret_len, signed_record, record_len, digest) != 0)
        return -1;
    for (size_t i = 0; i < 28; ++i)
        if ((uint8_t)(digest[i] ^ client_random[i]) != 0) return -1;

    const uint8_t *body = handshake + 4;
    size_t body_len = handshake_len;
    if (body_len < 2u + 32u + 1u) return -1;
    size_t session_id_len = body[34];
    size_t session_start = 35;
    size_t session_end = session_start + session_id_len;
    if (session_id_len > sizeof(out->session_id) ||
        body_len < session_end + 2u) return -1;
    size_t suites_len = read_be16(body + session_end);
    if (suites_len < 2 || body_len < session_end + 2u + suites_len + 1u)
        return -1;
    select_cipher_suite(body + session_end + 2, suites_len,
                        out->cipher_suite);

    size_t p = session_end + 2u + suites_len;
    size_t compression_len = body[p];
    p += 1u + compression_len;
    if (body_len < p + 2u) return -1;
    size_t extensions_len = read_be16(body + p);
    p += 2;
    if (body_len < p + extensions_len) return -1;

    memcpy(out->random, client_random, TG_FAKETLS_DIGEST_LEN);
    out->session_id_len = session_id_len;
    memcpy(out->session_id, body + session_start, session_id_len);
    if (parse_sni(body + p, extensions_len, out->hostname,
                  sizeof(out->hostname), &out->has_hostname) != 0)
        return -1;
    return 0;
}

int tg_faketls_build_server_hello(const uint8_t *secret, size_t secret_len,
                                  const tg_faketls_client_hello *hello,
                                  uint8_t *out, size_t out_cap,
                                  size_t *out_len) {
    static const uint8_t server_suffix[17] = {
        0x00, 0x00, 0x2e, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,
        0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20
    };
    uint8_t random32[32], cert_random[4], digest[TG_FAKETLS_DIGEST_LEN];
    if (!secret || !hello || !out || !out_len ||
        hello->session_id_len > sizeof(hello->session_id))
        return -1;
    if (RAND_bytes(random32, sizeof(random32)) != 1 ||
        RAND_bytes(cert_random, sizeof(cert_random)) != 1)
        return -1;
    uint32_t cert_seed = ((uint32_t)cert_random[0] << 24) |
                         ((uint32_t)cert_random[1] << 16) |
                         ((uint32_t)cert_random[2] << 8) | cert_random[3];
    size_t cert_len = 1024u + (cert_seed % 3092u);
    size_t server_body_len = 86u + hello->session_id_len;
    size_t handshake_len = 4u + server_body_len;
    size_t total = 5u + handshake_len + 6u + 5u + cert_len;
    if (out_cap < total) return -1;

    uint8_t *p = out;
    p[0] = TLS_RECORD_HANDSHAKE;
    p[1] = 0x03;
    p[2] = 0x03;
    write_be16(p + 3, (uint16_t)handshake_len);
    p += 5;
    p[0] = TLS_HANDSHAKE_SERVER_HELLO;
    write_be24(p + 1, (uint32_t)server_body_len);
    p += 4;
    p[0] = 0x03;
    p[1] = 0x03;
    p += 2;
    memset(p, 0, TG_FAKETLS_DIGEST_LEN);
    p += TG_FAKETLS_DIGEST_LEN;
    *p++ = (uint8_t)hello->session_id_len;
    memcpy(p, hello->session_id, hello->session_id_len);
    p += hello->session_id_len;
    memcpy(p, hello->cipher_suite, 2);
    p += 2;
    memcpy(p, server_suffix, sizeof(server_suffix));
    p += sizeof(server_suffix);
    memcpy(p, random32, sizeof(random32));
    p += sizeof(random32);

    p[0] = TLS_RECORD_CHANGE_CIPHER_SPEC;
    p[1] = 0x03;
    p[2] = 0x03;
    p[3] = 0x00;
    p[4] = 0x01;
    p[5] = 0x01;
    p += 6;

    p[0] = TLS_RECORD_APPLICATION_DATA;
    p[1] = 0x03;
    p[2] = 0x03;
    write_be16(p + 3, (uint16_t)cert_len);
    p += 5;
    if (RAND_bytes(p, cert_len) != 1) return -1;

    {
        uint8_t mac_input[TG_FAKETLS_DIGEST_LEN + 4608];
        if (total > sizeof(mac_input) - TG_FAKETLS_DIGEST_LEN) return -1;
        memcpy(mac_input, hello->random, TG_FAKETLS_DIGEST_LEN);
        memcpy(mac_input + TG_FAKETLS_DIGEST_LEN, out, total);
        if (hmac_sha256(secret, secret_len, mac_input,
                        TG_FAKETLS_DIGEST_LEN + total, digest) != 0)
            return -1;
    }
    memcpy(out + TLS_DIGEST_POS, digest, TG_FAKETLS_DIGEST_LEN);
    *out_len = total;
    return 0;
}

int tg_faketls_build_client_hello(const char *hostname,
                                  const uint8_t *secret, size_t secret_len,
                                  uint8_t *out, size_t out_cap,
                                  size_t *out_len) {
    static const uint8_t fixed_extensions[] = {
        0x00, 0x17, 0x00, 0x00,
        0xff, 0x01, 0x00, 0x01, 0x00,
        0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08,
        0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19,
        0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,
        0x00, 0x23, 0x00, 0x00,
        0x00, 0x0d, 0x00, 0x14, 0x00, 0x12,
        0x04, 0x03, 0x08, 0x04, 0x04, 0x01,
        0x05, 0x03, 0x08, 0x05, 0x05, 0x01,
        0x08, 0x06, 0x06, 0x01, 0x02, 0x01
    };
    static const uint8_t cipher_suites[] = {
        0x13, 0x01, 0x13, 0x02, 0x13, 0x03,
        0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30,
        0xcc, 0xa9, 0xcc, 0xa8,
        0xc0, 0x13, 0xc0, 0x14,
        0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35, 0x00, 0x0a
    };
    if (!hostname || !secret || !out || !out_len) return -1;
    size_t host_len = strlen(hostname);
    if (!host_len || host_len > TG_FAKETLS_MAX_HOSTNAME) return -1;
    size_t sni_list_len = 3u + host_len;
    size_t sni_data_len = 2u + sni_list_len;
    size_t extensions_len = 4u + sni_data_len + sizeof(fixed_extensions);
    size_t hello_len = 2u + 32u + 1u + 32u + 2u + sizeof(cipher_suites) +
                       2u + 2u + extensions_len;
    size_t handshake_len = 4u + hello_len;
    size_t total = 5u + handshake_len;
    if (out_cap < total) return -1;

    uint8_t session_id[32];
    if (RAND_bytes(session_id, sizeof(session_id)) != 1) return -1;
    uint8_t *p = out;
    p[0] = TLS_RECORD_HANDSHAKE;
    p[1] = 0x03;
    p[2] = 0x01;
    write_be16(p + 3, (uint16_t)handshake_len);
    p += 5;
    p[0] = TLS_HANDSHAKE_CLIENT_HELLO;
    write_be24(p + 1, (uint32_t)hello_len);
    p += 4;
    p[0] = 0x03;
    p[1] = 0x03;
    p += 2;
    memset(p, 0, TG_FAKETLS_DIGEST_LEN);
    p += TG_FAKETLS_DIGEST_LEN;
    *p++ = sizeof(session_id);
    memcpy(p, session_id, sizeof(session_id));
    p += sizeof(session_id);
    write_be16(p, (uint16_t)sizeof(cipher_suites));
    p += 2;
    memcpy(p, cipher_suites, sizeof(cipher_suites));
    p += sizeof(cipher_suites);
    p[0] = 0x01;
    p[1] = 0x00;
    p += 2;
    write_be16(p, (uint16_t)extensions_len);
    p += 2;
    write_be16(p, 0x0000);
    write_be16(p + 2, (uint16_t)sni_data_len);
    p += 4;
    write_be16(p, (uint16_t)sni_list_len);
    p[2] = 0x00;
    write_be16(p + 3, (uint16_t)host_len);
    memcpy(p + 5, hostname, host_len);
    p += 5 + host_len;
    memcpy(p, fixed_extensions, sizeof(fixed_extensions));

    uint8_t digest[TG_FAKETLS_DIGEST_LEN];
    if (hmac_sha256(secret, secret_len, out, total, digest) != 0) return -1;
    memcpy(out + TLS_RANDOM_OFFSET, digest, 28);
    uint32_t timestamp = (uint32_t)time(NULL);
    for (size_t i = 0; i < 4; ++i) {
        out[TLS_RANDOM_OFFSET + 28 + i] =
            (uint8_t)(digest[28 + i] ^ ((timestamp >> (8 * i)) & 0xff));
    }
    *out_len = total;
    return 0;
}
