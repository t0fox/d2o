#include "tg_mtproto.h"

#include "testdata/mtproto-v2-vectors.h"

#include <assert.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <string.h>

static size_t decode_hex(const char *hex, uint8_t *out, size_t cap) {
    size_t len = strlen(hex);
    if ((len & 1u) || len / 2 > cap) return 0;
    for (size_t i = 0; i < len / 2; ++i) {
        unsigned high, low;
        char a = hex[i * 2], b = hex[i * 2 + 1];
        if (a >= '0' && a <= '9') high = (unsigned)(a - '0');
        else if (a >= 'a' && a <= 'f') high = (unsigned)(a - 'a' + 10);
        else return 0;
        if (b >= '0' && b <= '9') low = (unsigned)(b - '0');
        else if (b >= 'a' && b <= 'f') low = (unsigned)(b - 'a' + 10);
        else return 0;
        out[i] = (uint8_t)((high << 4) | low);
    }
    return len / 2;
}

static void test_client_encryption_matches_reference(void) {
    static const uint8_t message[] =
        "Hello, world! This data should remain secure!";
    uint8_t auth_key[256], padding[32] = {0};
    uint8_t packet[128], expected[128];
    size_t packet_len = 0;
    for (size_t i = 0; i < sizeof(auth_key); ++i) auth_key[i] = (uint8_t)i;
    size_t padding_len = 16 + (16 - (sizeof(message) - 1) % 16);
    size_t expected_len = decode_hex(VECTOR_V2_CLIENT_CIPHERTEXT, expected,
                                     sizeof(expected));
    assert(expected_len == 88 && padding_len == 19);
    assert(tg_mtproto_v2_encrypt(auth_key, message, sizeof(message) - 1,
                                 padding, padding_len, packet, sizeof(packet),
                                 &packet_len) == 0);
    assert(packet_len == expected_len);
    assert(memcmp(packet, expected, expected_len) == 0);
    OPENSSL_cleanse(auth_key, sizeof(auth_key));
}

static void test_server_decryption_and_message_key_validation(void) {
    uint8_t auth_key[256], packet[256], expected[256], plaintext[256];
    size_t packet_len = decode_hex(VECTOR_V2_SERVER_CIPHERTEXT, packet,
                                   sizeof(packet));
    size_t expected_key_len = decode_hex(VECTOR_V2_SERVER_AUTH_KEY, auth_key,
                                         sizeof(auth_key));
    size_t expected_len = decode_hex(VECTOR_V2_SERVER_PLAINTEXT, expected,
                                     sizeof(expected));
    size_t plaintext_len = 0;
    assert(packet_len == 168 && expected_key_len == 256 && expected_len == 144);
    assert(tg_mtproto_v2_decrypt(auth_key, packet, packet_len, plaintext,
                                 sizeof(plaintext), &plaintext_len) == 0);
    assert(plaintext_len == expected_len);
    assert(memcmp(plaintext, expected, expected_len) == 0);
    packet[24] ^= 1;
    plaintext_len = 99;
    assert(tg_mtproto_v2_decrypt(auth_key, packet, packet_len, plaintext,
                                 sizeof(plaintext), &plaintext_len) != 0);
    assert(plaintext_len == 0);
    OPENSSL_cleanse(auth_key, sizeof(auth_key));
    OPENSSL_cleanse(plaintext, sizeof(plaintext));
}

int main(void) {
    test_client_encryption_matches_reference();
    test_server_decryption_and_message_key_validation();
    puts("Тесты MTProto 2.0 encryption: ок");
    return 0;
}
