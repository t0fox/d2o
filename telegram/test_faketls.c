#include "tg_faketls.h"

#include <assert.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <string.h>

static size_t unhex(const char *text, uint8_t *out, size_t cap) {
    size_t n = strlen(text);
    assert((n & 1u) == 0 && n / 2 <= cap);
    for (size_t i = 0; i < n / 2; ++i) {
        unsigned value = 0;
        assert(sscanf(text + 2 * i, "%2x", &value) == 1);
        out[i] = (uint8_t)value;
    }
    return n / 2;
}

static void test_client_hello_roundtrip(void) {
    uint8_t secret[16], packet[1024];
    assert(unhex("101112131415161718191a1b1c1d1e1f",
                 secret, sizeof(secret)) == sizeof(secret));
    size_t packet_len = 0;
    assert(tg_faketls_build_client_hello("cdn.example.test", secret,
                                         sizeof(secret), packet,
                                         sizeof(packet), &packet_len) == 0);
    assert(packet_len > 64 && packet[0] == 0x16 && packet[1] == 0x03 &&
           packet[2] == 0x01);

    tg_faketls_client_hello hello;
    assert(tg_faketls_parse_client_hello(packet, packet_len, secret,
                                         sizeof(secret), &hello) == 0);
    assert(hello.has_hostname);
    assert(strcmp(hello.hostname, "cdn.example.test") == 0);
    assert(hello.session_id_len == 32);
    assert(hello.cipher_suite[0] == 0x13);
    assert(hello.cipher_suite[1] >= 0x01 && hello.cipher_suite[1] <= 0x03);

    uint8_t wrong[16];
    assert(unhex("000102030405060708090a0b0c0d0e0f",
                 wrong, sizeof(wrong)) == sizeof(wrong));
    assert(tg_faketls_parse_client_hello(packet, packet_len, wrong,
                                         sizeof(wrong), &hello) != 0);

    uint8_t tampered[1024];
    memcpy(tampered, packet, packet_len);
    tampered[20] ^= 0x01;
    assert(tg_faketls_parse_client_hello(tampered, packet_len, secret,
                                         sizeof(secret), &hello) != 0);
    assert(tg_faketls_parse_client_hello(packet, packet_len - 1, secret,
                                         sizeof(secret), &hello) != 0);
}

static void test_server_hello_is_signed(void) {
    uint8_t secret[16], client[1024], server[4608];
    assert(unhex("101112131415161718191a1b1c1d1e1f",
                 secret, sizeof(secret)) == sizeof(secret));
    size_t client_len = 0, server_len = 0;
    assert(tg_faketls_build_client_hello("cdn.example.test", secret,
                                         sizeof(secret), client,
                                         sizeof(client), &client_len) == 0);
    tg_faketls_client_hello hello;
    assert(tg_faketls_parse_client_hello(client, client_len, secret,
                                         sizeof(secret), &hello) == 0);
    assert(tg_faketls_build_server_hello(secret, sizeof(secret), &hello,
                                         server, sizeof(server),
                                         &server_len) == 0);
    assert(server_len > 1024);
    assert(server[0] == 0x16 && server[1] == 0x03 && server[2] == 0x03);

    uint8_t mac_input[TG_FAKETLS_DIGEST_LEN + 4608];
    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    memcpy(mac_input, hello.random, TG_FAKETLS_DIGEST_LEN);
    memcpy(mac_input + TG_FAKETLS_DIGEST_LEN, server, server_len);
    memset(mac_input + TG_FAKETLS_DIGEST_LEN + 11, 0,
           TG_FAKETLS_DIGEST_LEN);
    assert(HMAC(EVP_sha256(), secret, sizeof(secret), mac_input,
                TG_FAKETLS_DIGEST_LEN + server_len, digest,
                &digest_len) != NULL);
    assert(digest_len == TG_FAKETLS_DIGEST_LEN);
    assert(memcmp(server + 11, digest, TG_FAKETLS_DIGEST_LEN) == 0);

    assert(tg_faketls_build_server_hello(secret, sizeof(secret), &hello,
                                         server, 128, &server_len) != 0);
}

int main(void) {
    test_client_hello_roundtrip();
    test_server_hello_is_signed();
    puts("FakeTLS tests: ok");
    return 0;
}
