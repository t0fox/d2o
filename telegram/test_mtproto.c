#include "tg_mtproto.h"

#include <assert.h>
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

static void test_ctr_matches_nist_vector_across_partial_reads(void) {
    uint8_t key[32], iv[16], data[64], expected[64];
    assert(unhex("603deb1015ca71be2b73aef0857d7781"
                 "1f352c073b6108d72d9810a30914dff4", key, sizeof(key)) == 32);
    assert(unhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", iv, sizeof(iv)) == 16);
    assert(unhex("6bc1bee22e409f96e93d7e117393172a"
                 "ae2d8a571e03ac9c9eb76fac45af8e51"
                 "30c81c46a35ce411e5fbc1191a0a52ef"
                 "f69f2445df4f9b17ad2b417be66c3710", data, sizeof(data)) == 64);
    assert(unhex("601ec313775789a5b7a7f504bbf3d228"
                 "f443e3ca4d62b59aca84e990cacaf5c5"
                 "2b0930daa23de94ce87017ba2d84988d"
                 "dfc9c58db67aada613c2dd08457941a6", expected, sizeof(expected)) == 64);

    tg_mtproto_ctr ctr = {0};
    assert(tg_mtproto_ctr_init(&ctr, key, iv) == 0);
    assert(tg_mtproto_ctr_xor(&ctr, data, 19) == 0);
    assert(tg_mtproto_ctr_xor(&ctr, data + 19, sizeof(data) - 19) == 0);
    assert(memcmp(data, expected, sizeof(data)) == 0);
    tg_mtproto_ctr_destroy(&ctr);
}

static void test_direct_obfuscated2_vector_decodes_media_dc(void) {
    uint8_t packet[TG_MTPROTO_HANDSHAKE_LEN];
    tg_mtproto_init parsed;
    assert(unhex("0001020304050607000102030405060708090a0b0c0d0e0f"
                 "101112131415161718191a1b1c1d1e1f0001020304050607"
                 "08090a0b0c0d0e0f87aeb3fe059b4807", packet, sizeof(packet)) == 64);
    assert(tg_mtproto_parse_obfuscated2(packet, &parsed) == 0);
    assert(parsed.dc_id == 4 && parsed.is_media == 1);
    assert(parsed.proto == TG_MTPROTO_INTERMEDIATE);
    assert(memcmp(parsed.prekey_iv, packet + 8, sizeof(parsed.prekey_iv)) == 0);
}

static void test_secret_vector_requires_matching_secret(void) {
    uint8_t packet[TG_MTPROTO_HANDSHAKE_LEN], secret[16], wrong[16];
    tg_mtproto_init parsed;
    assert(unhex("0001020304050607000102030405060708090a0b0c0d0e0f"
                 "101112131415161718191a1b1c1d1e1f0001020304050607"
                 "08090a0b0c0d0e0f7c380b6e418caed2", packet, sizeof(packet)) == 64);
    assert(unhex("101112131415161718191a1b1c1d1e1f", secret, sizeof(secret)) == 16);
    memset(wrong, 0xa5, sizeof(wrong));
    assert(tg_mtproto_parse_secret(packet, wrong, sizeof(wrong), &parsed) != 0);
    assert(tg_mtproto_parse_secret(packet, secret, sizeof(secret), &parsed) == 0);
    assert(parsed.dc_id == 4 && parsed.is_media == 1);
    assert(parsed.proto == TG_MTPROTO_INTERMEDIATE);
}

static void test_invalid_handshake_and_secret_inputs_are_rejected(void) {
    uint8_t packet[TG_MTPROTO_HANDSHAKE_LEN] = {0};
    tg_mtproto_init parsed;
    assert(tg_mtproto_parse_obfuscated2(packet, &parsed) != 0);
    assert(tg_mtproto_parse_secret(packet, NULL, 0, &parsed) != 0);
}

static void test_reserved_protocol_prefixes_are_rejected(void) {
    uint8_t packet[TG_MTPROTO_HANDSHAKE_LEN];
    tg_mtproto_init parsed;
    assert(unhex("0001020304050607000102030405060708090a0b0c0d0e0f"
                 "101112131415161718191a1b1c1d1e1f0001020304050607"
                 "08090a0b0c0d0e0f87aeb3fe059b4807", packet,
                 sizeof(packet)) == sizeof(packet));
    memcpy(packet, "GET ", 4);
    assert(tg_mtproto_parse_obfuscated2(packet, &parsed) != 0);

    assert(unhex("0001020304050607000102030405060708090a0b0c0d0e0f"
                 "101112131415161718191a1b1c1d1e1f0001020304050607"
                 "08090a0b0c0d0e0f87aeb3fe059b4807", packet,
                 sizeof(packet)) == sizeof(packet));
    memset(packet + 4, 0, 4);
    assert(tg_mtproto_parse_obfuscated2(packet, &parsed) != 0);
}

static void test_direct_stream_ciphers_skip_obfuscated2_init(void) {
    uint8_t init[TG_MTPROTO_HANDSHAKE_LEN];
    uint8_t input[48], original[48], expected[48], stream[48];
    uint8_t zeros[TG_MTPROTO_HANDSHAKE_LEN] = {0};
    for (size_t i = 0; i < sizeof(init); ++i) init[i] = (uint8_t)(i * 3u + 1u);
    for (size_t i = 0; i < sizeof(input); ++i) input[i] = original[i] = (uint8_t)(i * 7u + 9u);
    memcpy(expected, original, sizeof(expected));
    memset(stream, 0, sizeof(stream));

    tg_mtproto_ctr reference = {0}, decrypt = {0}, encrypt = {0};
    assert(tg_mtproto_ctr_init(&reference, init + 8, init + 40) == 0);
    assert(tg_mtproto_ctr_xor(&reference, zeros, sizeof(zeros)) == 0);
    assert(tg_mtproto_ctr_xor(&reference, expected, sizeof(expected)) == 0);
    assert(tg_mtproto_direct_stream_ciphers(init, &decrypt, &encrypt) == 0);
    assert(tg_mtproto_ctr_xor(&decrypt, input, sizeof(input)) == 0);
    assert(memcmp(input, expected, sizeof(input)) == 0);
    assert(tg_mtproto_ctr_xor(&encrypt, stream, sizeof(stream)) == 0);
    for (size_t i = 0; i < sizeof(stream); ++i)
        assert(stream[i] == (uint8_t)(expected[i] ^ original[i]));

    tg_mtproto_ctr_destroy(&reference);
    tg_mtproto_ctr_destroy(&decrypt);
    tg_mtproto_ctr_destroy(&encrypt);
}

int main(void) {
    test_ctr_matches_nist_vector_across_partial_reads();
    test_direct_obfuscated2_vector_decodes_media_dc();
    test_secret_vector_requires_matching_secret();
    test_invalid_handshake_and_secret_inputs_are_rejected();
    test_reserved_protocol_prefixes_are_rejected();
    test_direct_stream_ciphers_skip_obfuscated2_init();
    puts("Тесты MTProto: ок");
    return 0;
}
