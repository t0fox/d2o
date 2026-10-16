#include "tg_mtproto_auth.h"

#include "testdata/mtproto-auth-vectors.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>

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

static void test_step2_matches_fixed_reference_vector(void) {
    uint8_t nonce[16], response[256], randomness[256], expected[512];
    uint8_t request[512];
    tg_mtproto_auth_state state = {0};
    size_t response_len = decode_hex(VECTOR_STEP1_RESPONSE, response,
                                     sizeof(response));
    size_t randomness_len = decode_hex(VECTOR_STEP2_RANDOM, randomness,
                                       sizeof(randomness));
    size_t expected_len = decode_hex(VECTOR_STEP2_REQUEST, expected,
                                     sizeof(expected));
    assert(decode_hex(VECTOR_STEP1_RANDOM, nonce, sizeof(nonce)) == sizeof(nonce));
    assert(response_len && randomness_len == sizeof(randomness) && expected_len);
    memcpy(state.nonce, nonce, sizeof(nonce));
    size_t request_len = 0;
    assert(tg_mtproto_auth_step2(&state, response, response_len, randomness,
                                 request, sizeof(request), &request_len) == 0);
    assert(request_len == expected_len);
    assert(memcmp(request, expected, expected_len) == 0);
    assert(memcmp(state.nonce, nonce, sizeof(nonce)) == 0);
    assert(memcmp(state.new_nonce, randomness, sizeof(state.new_nonce)) == 0);
    tg_mtproto_auth_clear(&state);
    OPENSSL_cleanse(randomness, sizeof(randomness));
}

static void test_step2_rejects_a_mismatched_nonce(void) {
    uint8_t nonce[16], response[256], randomness[256], request[512];
    tg_mtproto_auth_state state = {0};
    size_t response_len = decode_hex(VECTOR_STEP1_RESPONSE, response,
                                     sizeof(response));
    assert(decode_hex(VECTOR_STEP1_RANDOM, nonce, sizeof(nonce)) == sizeof(nonce));
    assert(decode_hex(VECTOR_STEP2_RANDOM, randomness,
                      sizeof(randomness)) == sizeof(randomness));
    memcpy(state.nonce, nonce, sizeof(nonce));
    response[4] ^= 1;
    size_t request_len = 99;
    assert(tg_mtproto_auth_step2(&state, response, response_len, randomness,
                                 request, sizeof(request), &request_len) != 0);
    assert(request_len == 0);
    tg_mtproto_auth_clear(&state);
    OPENSSL_cleanse(randomness, sizeof(randomness));
}

static void test_step2_rejects_prime_pq_before_factorization(void) {
    uint8_t nonce[16], response[256], randomness[256], request[512];
    static const uint8_t prime_pq[8] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc5
    };
    tg_mtproto_auth_state state = {0};
    size_t response_len = decode_hex(VECTOR_STEP1_RESPONSE, response,
                                     sizeof(response));
    assert(decode_hex(VECTOR_STEP1_RANDOM, nonce, sizeof(nonce)) == sizeof(nonce));
    assert(decode_hex(VECTOR_STEP2_RANDOM, randomness,
                      sizeof(randomness)) == sizeof(randomness));
    memcpy(state.nonce, nonce, sizeof(nonce));
    assert(response[36] == 8);
    memcpy(response + 37, prime_pq, sizeof(prime_pq));
    size_t request_len = 99;
    assert(tg_mtproto_auth_step2(&state, response, response_len, randomness,
                                 request, sizeof(request), &request_len) != 0);
    assert(request_len == 0 && !state.step2_ready);
    tg_mtproto_auth_clear(&state);
    OPENSSL_cleanse(randomness, sizeof(randomness));
}

static void test_full_auth_flow_matches_fixed_reference_vector(void) {
    uint8_t response1[256], response2[1024], response3[128];
    uint8_t random2[256], random3[272], expected2[512], expected3[512];
    uint8_t request2[512], request3[512], expected_key[256];
    tg_mtproto_auth_state state = {0};
    size_t response1_len = decode_hex(VECTOR_STEP1_RESPONSE, response1,
                                      sizeof(response1));
    size_t response2_len = decode_hex(VECTOR_STEP2_RESPONSE, response2,
                                      sizeof(response2));
    size_t response3_len = decode_hex(VECTOR_STEP3_RESPONSE, response3,
                                      sizeof(response3));
    size_t random2_len = decode_hex(VECTOR_STEP2_RANDOM, random2,
                                    sizeof(random2));
    size_t random3_len = decode_hex(VECTOR_STEP3_RANDOM, random3,
                                    sizeof(random3));
    size_t expected2_len = decode_hex(VECTOR_STEP2_REQUEST, expected2,
                                      sizeof(expected2));
    size_t expected3_len = decode_hex(VECTOR_STEP3_REQUEST, expected3,
                                      sizeof(expected3));
    size_t expected_key_len = decode_hex(VECTOR_EXPECTED_AUTH_KEY,
                                         expected_key, sizeof(expected_key));
    size_t request2_len = 0, request3_len = 0;
    assert(response1_len && response2_len && response3_len);
    assert(random2_len == sizeof(random2) && random3_len == sizeof(random3));
    assert(expected2_len && expected3_len && expected_key_len == 256);
    assert(decode_hex(VECTOR_STEP1_RANDOM, state.nonce,
                      sizeof(state.nonce)) == sizeof(state.nonce));
    assert(tg_mtproto_auth_step2(&state, response1, response1_len, random2,
                                 request2, sizeof(request2),
                                 &request2_len) == 0);
    assert(request2_len == expected2_len);
    assert(memcmp(request2, expected2, expected2_len) == 0);
    response2[40] ^= 1;
    request3_len = 77;
    assert(tg_mtproto_auth_step3(&state, response2, response2_len, random3,
                                 1693436740, request3, sizeof(request3),
                                 &request3_len) != 0);
    assert(request3_len == 0 && state.step2_ready);
    response2[40] ^= 1;
    assert(tg_mtproto_auth_step3(&state, response2, response2_len, random3,
                                 1693436740, request3, sizeof(request3),
                                 &request3_len) == 0);
    assert(request3_len == expected3_len);
    assert(memcmp(request3, expected3, expected3_len) == 0);
    response3[51] ^= 1;
    assert(tg_mtproto_auth_step4(&state, response3, response3_len) != 0);
    assert(!state.auth_key_ready && state.dh_key_ready);
    response3[51] ^= 1;
    assert(tg_mtproto_auth_step4(&state, response3, response3_len) == 0);
    assert(state.auth_key_ready);
    assert(memcmp(state.auth_key, expected_key, sizeof(expected_key)) == 0);
    assert(state.time_offset == 0);
    assert(state.first_salt == UINT64_C(4459407212920268508));
    tg_mtproto_auth_clear(&state);
    OPENSSL_cleanse(random2, sizeof(random2));
    OPENSSL_cleanse(random3, sizeof(random3));
}

int main(void) {
    test_step2_matches_fixed_reference_vector();
    test_step2_rejects_a_mismatched_nonce();
    test_step2_rejects_prime_pq_before_factorization();
    test_full_auth_flow_matches_fixed_reference_vector();
    puts("Тесты MTProto authorization: ок");
    return 0;
}
