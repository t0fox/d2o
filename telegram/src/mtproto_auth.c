#define _POSIX_C_SOURCE 200809L
#include "tg_mtproto_auth.h"
#include "tg_mtproto.h"

#include "mtproto_auth_keys.inc"

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <string.h>

#define TG_RES_PQ_CONSTRUCTOR UINT32_C(0x05162463)
#define TG_VECTOR_CONSTRUCTOR UINT32_C(0x1cb5c415)
#define TG_PQ_INNER_CONSTRUCTOR UINT32_C(0x83c95aec)
#define TG_REQ_DH_PARAMS_CONSTRUCTOR UINT32_C(0xd712e4be)
#define TG_SERVER_DH_PARAMS_FAIL UINT32_C(0x79cb045d)
#define TG_SERVER_DH_PARAMS_OK UINT32_C(0xd0e8075c)
#define TG_SERVER_DH_INNER_DATA UINT32_C(0xb5890dba)
#define TG_CLIENT_DH_INNER_DATA UINT32_C(0x6643b654)
#define TG_SET_CLIENT_DH_PARAMS UINT32_C(0xf5045f1f)
#define TG_DH_GEN_OK UINT32_C(0x3bcbf734)
#define TG_DH_GEN_RETRY UINT32_C(0x46dc1fb9)
#define TG_DH_GEN_FAIL UINT32_C(0xa69dae02)

typedef struct {
    uint8_t *data;
    size_t capacity;
    size_t length;
} auth_writer;

typedef struct {
    uint8_t nonce[16];
    uint8_t server_nonce[16];
    const uint8_t *pq;
    const uint8_t *fingerprints;
    uint32_t fingerprint_count;
} parsed_res_pq;

static uint32_t read_le32(const uint8_t *bytes) {
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static uint64_t read_le64(const uint8_t *bytes) {
    return (uint64_t)read_le32(bytes) |
           ((uint64_t)read_le32(bytes + 4) << 32);
}

static int write_bytes(auth_writer *writer, const void *data, size_t len) {
    if (!writer || writer->length > writer->capacity || (len && !data) ||
        len > writer->capacity - writer->length)
        return -1;
    if (len) memcpy(writer->data + writer->length, data, len);
    writer->length += len;
    return 0;
}

static int write_u32(auth_writer *writer, uint32_t value) {
    uint8_t bytes[4];
    for (size_t i = 0; i < sizeof(bytes); ++i)
        bytes[i] = (uint8_t)(value >> (8u * i));
    return write_bytes(writer, bytes, sizeof(bytes));
}

static int write_u64(auth_writer *writer, uint64_t value) {
    uint8_t bytes[8];
    for (size_t i = 0; i < sizeof(bytes); ++i)
        bytes[i] = (uint8_t)(value >> (8u * i));
    return write_bytes(writer, bytes, sizeof(bytes));
}

static int write_tl_bytes(auth_writer *writer, const uint8_t *value,
                          size_t value_len) {
    uint8_t prefix[4];
    size_t prefix_len, padding;
    static const uint8_t zero[3] = {0};
    if (value_len > UINT32_C(0xffffff) || (value_len && !value)) return -1;
    if (value_len < 254) {
        prefix[0] = (uint8_t)value_len;
        prefix_len = 1;
    } else {
        prefix[0] = 254;
        prefix[1] = (uint8_t)value_len;
        prefix[2] = (uint8_t)(value_len >> 8);
        prefix[3] = (uint8_t)(value_len >> 16);
        prefix_len = 4;
    }
    padding = (4u - ((prefix_len + value_len) & 3u)) & 3u;
    return write_bytes(writer, prefix, prefix_len) != 0 ||
                   write_bytes(writer, value, value_len) != 0 ||
                   write_bytes(writer, zero, padding) != 0
               ? -1
               : 0;
}

static int read_tl_bytes(const uint8_t *data, size_t len, size_t *offset,
                         const uint8_t **value, size_t *value_len) {
    size_t prefix_len, count, encoded_len, padding;
    if (!data || !offset || !value || !value_len || *offset >= len) return -1;
    uint8_t first = data[*offset];
    if (first < 254) {
        prefix_len = 1;
        count = first;
    } else if (first == 254) {
        if (len - *offset < 4) return -1;
        prefix_len = 4;
        count = (size_t)data[*offset + 1] |
                ((size_t)data[*offset + 2] << 8) |
                ((size_t)data[*offset + 3] << 16);
        if (count < 254) return -1;
    } else {
        return -1;
    }
    if (prefix_len > len - *offset || count > len - *offset - prefix_len)
        return -1;
    encoded_len = prefix_len + count;
    padding = (4u - (encoded_len & 3u)) & 3u;
    if (padding > len - *offset - encoded_len) return -1;
    for (size_t i = 0; i < padding; ++i)
        if (data[*offset + encoded_len + i] != 0) return -1;
    *value = data + *offset + prefix_len;
    *value_len = count;
    *offset += encoded_len + padding;
    return 0;
}

static int read_fixed(const uint8_t *data, size_t len, size_t *offset,
                      uint8_t *out, size_t count) {
    if (!data || !offset || !out || *offset > len || count > len - *offset)
        return -1;
    memcpy(out, data + *offset, count);
    *offset += count;
    return 0;
}

static int read_tl_u32(const uint8_t *data, size_t len, size_t *offset,
                       uint32_t *out) {
    if (!data || !offset || !out || *offset > len || len - *offset < 4)
        return -1;
    *out = read_le32(data + *offset);
    *offset += 4;
    return 0;
}

static int sha1_pair(const uint8_t *first, size_t first_len,
                     const uint8_t *second, size_t second_len,
                     uint8_t out[20]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int out_len = 0;
    int ok = ctx && EVP_DigestInit_ex(ctx, EVP_sha1(), NULL) == 1 &&
             EVP_DigestUpdate(ctx, first, first_len) == 1 &&
             EVP_DigestUpdate(ctx, second, second_len) == 1 &&
             EVP_DigestFinal_ex(ctx, out, &out_len) == 1 && out_len == 20;
    EVP_MD_CTX_free(ctx);
    return ok ? 0 : -1;
}

static int sha1_triple(const uint8_t *first, size_t first_len,
                       const uint8_t *second, size_t second_len,
                       const uint8_t *third, size_t third_len,
                       uint8_t out[20]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int out_len = 0;
    int ok = ctx && EVP_DigestInit_ex(ctx, EVP_sha1(), NULL) == 1 &&
             EVP_DigestUpdate(ctx, first, first_len) == 1 &&
             EVP_DigestUpdate(ctx, second, second_len) == 1 &&
             EVP_DigestUpdate(ctx, third, third_len) == 1 &&
             EVP_DigestFinal_ex(ctx, out, &out_len) == 1 && out_len == 20;
    EVP_MD_CTX_free(ctx);
    return ok ? 0 : -1;
}

static int parse_res_pq(const uint8_t *data, size_t len,
                        const uint8_t expected_nonce[16], parsed_res_pq *out) {
    size_t offset = 36, pq_len = 0;
    const uint8_t *pq;
    if (!data || !expected_nonce || !out || len < 44 ||
        read_le32(data) != TG_RES_PQ_CONSTRUCTOR ||
        memcmp(data + 4, expected_nonce, 16) != 0)
        return -1;
    memset(out, 0, sizeof(*out));
    memcpy(out->nonce, data + 4, sizeof(out->nonce));
    memcpy(out->server_nonce, data + 20, sizeof(out->server_nonce));
    if (read_tl_bytes(data, len, &offset, &pq, &pq_len) != 0 || pq_len != 8 ||
        len - offset < 8 || read_le32(data + offset) != TG_VECTOR_CONSTRUCTOR)
        return -1;
    offset += 4;
    uint32_t count = read_le32(data + offset);
    offset += 4;
    if (!count || count > 64 || (size_t)count > (len - offset) / 8 ||
        len - offset != (size_t)count * 8)
        return -1;
    out->pq = pq;
    out->fingerprints = data + offset;
    out->fingerprint_count = count;
    return 0;
}

static uint64_t add_mod(uint64_t left, uint64_t right, uint64_t mod) {
    return left >= mod - right ? left - (mod - right) : left + right;
}

static uint64_t mul_mod(uint64_t left, uint64_t right, uint64_t mod) {
    uint64_t result = 0;
    left %= mod;
    while (right) {
        if (right & 1u) result = add_mod(result, left, mod);
        right >>= 1;
        if (right) left = add_mod(left, left, mod);
    }
    return result;
}

static uint64_t gcd_u64(uint64_t left, uint64_t right) {
    while (right) {
        uint64_t remainder = left % right;
        left = right;
        right = remainder;
    }
    return left;
}

static uint64_t pow_mod(uint64_t base, uint64_t exponent, uint64_t mod) {
    uint64_t result = 1;
    base %= mod;
    while (exponent) {
        if (exponent & 1u) result = mul_mod(result, base, mod);
        exponent >>= 1;
        if (exponent) base = mul_mod(base, base, mod);
    }
    return result;
}

static int is_prime_u64(uint64_t value) {
    static const uint64_t small_primes[] = {
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37
    };
    static const uint64_t witnesses[] = {
        2, 325, 9375, 28178, 450775, 9780504, 1795265022
    };
    if (value < 2) return 0;
    for (size_t i = 0; i < sizeof(small_primes) / sizeof(small_primes[0]); ++i) {
        if (value == small_primes[i]) return 1;
        if (value % small_primes[i] == 0) return 0;
    }
    uint64_t odd = value - 1;
    unsigned twos = 0;
    while ((odd & 1u) == 0) {
        odd >>= 1;
        ++twos;
    }
    for (size_t i = 0; i < sizeof(witnesses) / sizeof(witnesses[0]); ++i) {
        uint64_t base = witnesses[i] % value;
        if (base < 2) continue;
        uint64_t residue = pow_mod(base, odd, value);
        if (residue == 1 || residue == value - 1) continue;
        int composite = 1;
        for (unsigned round = 1; round < twos; ++round) {
            residue = mul_mod(residue, residue, value);
            if (residue == value - 1) {
                composite = 0;
                break;
            }
        }
        if (composite) return 0;
    }
    return 1;
}

static uint64_t rho_next(uint64_t value, uint64_t constant, uint64_t mod) {
    return add_mod(mul_mod(value, value, mod), constant, mod);
}

static int factorize_pq(const uint8_t bytes[8], uint64_t *p, uint64_t *q) {
    uint64_t value = 0;
    if (!bytes || !p || !q) return -1;
    for (size_t i = 0; i < 8; ++i) value = (value << 8) | bytes[i];
    if (value < 4) return -1;
    if (is_prime_u64(value)) return -1;
    if ((value & 1u) == 0) {
        *p = 2;
        *q = value / 2;
        return 0;
    }
    for (uint64_t attempt = 1; attempt <= 32; ++attempt) {
        uint64_t constant = attempt % value;
        uint64_t x = (2 + attempt) % value, y = x, divisor = 1;
        if (!constant) constant = 1;
        for (size_t step = 0; step < 100000 && divisor == 1; ++step) {
            x = rho_next(x, constant, value);
            y = rho_next(rho_next(y, constant, value), constant, value);
            uint64_t difference = x > y ? x - y : y - x;
            divisor = gcd_u64(difference, value);
        }
        if (divisor > 1 && divisor < value && value % divisor == 0) {
            *p = divisor < value / divisor ? divisor : value / divisor;
            *q = value / *p;
            return 0;
        }
    }
    return -1;
}

static size_t u64_to_be_min(uint64_t value, uint8_t out[8]) {
    uint8_t full[8];
    size_t first = 0;
    for (size_t i = 0; i < sizeof(full); ++i)
        full[sizeof(full) - 1 - i] = (uint8_t)(value >> (8u * i));
    while (first < sizeof(full) - 1 && full[first] == 0) ++first;
    size_t len = sizeof(full) - first;
    memcpy(out, full + first, len);
    OPENSSL_cleanse(full, sizeof(full));
    return len;
}

static int sha256_pair(const uint8_t *first, size_t first_len,
                       const uint8_t *second, size_t second_len,
                       uint8_t out[32]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int out_len = 0;
    int ok = ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
             EVP_DigestUpdate(ctx, first, first_len) == 1 &&
             EVP_DigestUpdate(ctx, second, second_len) == 1 &&
             EVP_DigestFinal_ex(ctx, out, &out_len) == 1 && out_len == 32;
    EVP_MD_CTX_free(ctx);
    return ok ? 0 : -1;
}

static const char *rsa_modulus(uint64_t fingerprint) {
    if (fingerprint == UINT64_C(0xb25898df208d2603))
        return TG_TEST_RSA_MODULUS;
    if (fingerprint == UINT64_C(0xd09d1d85de64fd85))
        return TG_PROD_RSA_MODULUS;
    return NULL;
}

static int rsa_encrypt_hashed(const uint8_t *data, size_t data_len,
                              const uint8_t randomness[224], uint64_t fp,
                              uint8_t ciphertext[256]) {
    uint8_t padded[192], reversed[192], temp_key[32], input[224];
    uint8_t digest[32], encrypted_hash[32], temp_key_xor[32], iv[32] = {0};
    uint8_t block[256];
    const char *modulus_text = rsa_modulus(fp);
    BIGNUM *modulus = NULL, *exponent = NULL, *number = NULL, *result = NULL;
    BN_CTX *bn_ctx = NULL;
    int rc = -1;
    if (!data || !randomness || !ciphertext || !modulus_text || data_len > 144)
        return -1;
    modulus = BN_new(); exponent = BN_new(); number = BN_new(); result = BN_new();
    bn_ctx = BN_CTX_new();
    if (!modulus || !exponent || !number || !result || !bn_ctx ||
        !BN_dec2bn(&modulus, modulus_text) || !BN_set_word(exponent, 65537))
        goto done;
    memcpy(padded, data, data_len);
    memcpy(padded + data_len, randomness, sizeof(padded) - data_len);
    for (size_t i = 0; i < sizeof(padded); ++i)
        reversed[i] = padded[sizeof(padded) - 1 - i];
    memcpy(temp_key, randomness + 192, sizeof(temp_key));
    for (unsigned attempt = 0; attempt < 256; ++attempt) {
        if (sha256_pair(temp_key, sizeof(temp_key), padded, sizeof(padded), digest) != 0)
            goto done;
        memcpy(input, reversed, sizeof(reversed));
        memcpy(input + sizeof(reversed), digest, sizeof(digest));
        if (tg_mtproto_aes_ige(input, sizeof(input), temp_key, iv, 1) != 0 ||
            sha256_pair(input, sizeof(input), input, 0, encrypted_hash) != 0)
            goto done;
        for (size_t i = 0; i < sizeof(temp_key); ++i)
            temp_key_xor[i] = temp_key[i] ^ encrypted_hash[i];
        memcpy(block, temp_key_xor, sizeof(temp_key_xor));
        memcpy(block + sizeof(temp_key_xor), input, sizeof(input));
        if (!BN_bin2bn(block, sizeof(block), number)) goto done;
        if (BN_cmp(number, modulus) < 0) break;
        size_t i = sizeof(temp_key);
        while (i && ++temp_key[--i] == 0) {}
        if ((!i && temp_key[0] == 0) || attempt == 255) goto done;
    }
    if (BN_mod_exp(result, number, exponent, modulus, bn_ctx) != 1 ||
        BN_bn2binpad(result, ciphertext, 256) != 256)
        goto done;
    rc = 0;
done:
    BN_clear_free(modulus); BN_clear_free(exponent); BN_clear_free(number);
    BN_clear_free(result); BN_CTX_free(bn_ctx);
    OPENSSL_cleanse(padded, sizeof(padded));
    OPENSSL_cleanse(reversed, sizeof(reversed));
    OPENSSL_cleanse(temp_key, sizeof(temp_key));
    OPENSSL_cleanse(input, sizeof(input));
    OPENSSL_cleanse(digest, sizeof(digest));
    OPENSSL_cleanse(encrypted_hash, sizeof(encrypted_hash));
    OPENSSL_cleanse(temp_key_xor, sizeof(temp_key_xor));
    OPENSSL_cleanse(block, sizeof(block));
    OPENSSL_cleanse(iv, sizeof(iv));
    return rc;
}

int tg_mtproto_auth_step2(tg_mtproto_auth_state *state,
                          const uint8_t *res_pq, size_t res_pq_len,
                          const uint8_t randomness[256],
                          uint8_t *request, size_t request_cap,
                          size_t *request_len) {
    parsed_res_pq parsed;
    tg_mtproto_auth_state next_state = {0};
    uint8_t p_bytes[8] = {0}, q_bytes[8] = {0};
    uint8_t pq_inner[144] = {0}, rsa_ciphertext[256] = {0};
    uint8_t local_request[512] = {0};
    size_t p_len, q_len;
    uint64_t p, q, fingerprint = 0;
    auth_writer inner = {.data = pq_inner, .capacity = sizeof(pq_inner)};
    auth_writer output = {.data = local_request,
                          .capacity = sizeof(local_request)};
    int found = 0, rc = -1;
    if (request_len) *request_len = 0;
    if (!state || !res_pq || !randomness || !request || !request_len ||
        parse_res_pq(res_pq, res_pq_len, state->nonce, &parsed) != 0 ||
        factorize_pq(parsed.pq, &p, &q) != 0)
        goto done;
    p_len = u64_to_be_min(p, p_bytes);
    q_len = u64_to_be_min(q, q_bytes);
    for (uint32_t i = 0; i < parsed.fingerprint_count; ++i) {
        uint64_t candidate = read_le64(parsed.fingerprints + (size_t)i * 8);
        if (rsa_modulus(candidate)) {
            fingerprint = candidate;
            found = 1;
            break;
        }
    }
    if (!found || write_u32(&inner, TG_PQ_INNER_CONSTRUCTOR) != 0 ||
        write_tl_bytes(&inner, parsed.pq, 8) != 0 ||
        write_tl_bytes(&inner, p_bytes, p_len) != 0 ||
        write_tl_bytes(&inner, q_bytes, q_len) != 0 ||
        write_bytes(&inner, parsed.nonce, sizeof(parsed.nonce)) != 0 ||
        write_bytes(&inner, parsed.server_nonce, sizeof(parsed.server_nonce)) != 0 ||
        write_bytes(&inner, randomness, 32) != 0 || inner.length > 144 ||
        rsa_encrypt_hashed(inner.data, inner.length, randomness + 32,
                           fingerprint, rsa_ciphertext) != 0)
        goto done;
    if (write_u32(&output, TG_REQ_DH_PARAMS_CONSTRUCTOR) != 0 ||
        write_bytes(&output, parsed.nonce, sizeof(parsed.nonce)) != 0 ||
        write_bytes(&output, parsed.server_nonce, sizeof(parsed.server_nonce)) != 0 ||
        write_tl_bytes(&output, p_bytes, p_len) != 0 ||
        write_tl_bytes(&output, q_bytes, q_len) != 0 ||
        write_u64(&output, fingerprint) != 0 ||
        write_tl_bytes(&output, rsa_ciphertext, sizeof(rsa_ciphertext)) != 0 ||
        output.length > request_cap)
        goto done;
    next_state = *state;
    memcpy(next_state.server_nonce, parsed.server_nonce,
           sizeof(next_state.server_nonce));
    memcpy(next_state.new_nonce, randomness, sizeof(next_state.new_nonce));
    next_state.step2_ready = 1;
    memcpy(request, local_request, output.length);
    *request_len = output.length;
    *state = next_state;
    rc = 0;
done:
    OPENSSL_cleanse(&next_state, sizeof(next_state));
    OPENSSL_cleanse(p_bytes, sizeof(p_bytes));
    OPENSSL_cleanse(q_bytes, sizeof(q_bytes));
    OPENSSL_cleanse(pq_inner, sizeof(pq_inner));
    OPENSSL_cleanse(rsa_ciphertext, sizeof(rsa_ciphertext));
    OPENSSL_cleanse(local_request, sizeof(local_request));
    return rc;
}

int tg_mtproto_auth_step3(tg_mtproto_auth_state *state,
                          const uint8_t *server_dh_params,
                          size_t server_dh_params_len,
                          const uint8_t randomness[272], int32_t now,
                          uint8_t *request, size_t request_cap,
                          size_t *request_len) {
    uint8_t encrypted[1024] = {0}, plain[1024] = {0};
    uint8_t key[32] = {0}, iv[32] = {0}, hash1[20] = {0};
    uint8_t hash2[20] = {0}, hash3[20] = {0}, got_hash[20] = {0};
    uint8_t client_inner[512] = {0}, client_hash[20] = {0};
    uint8_t client_encrypted[544] = {0}, local_request[600] = {0};
    uint8_t nonce[16] = {0}, server_nonce[16] = {0};
    const uint8_t *encrypted_data = NULL, *dh_prime_bytes = NULL;
    const uint8_t *g_a_bytes = NULL;
    size_t encrypted_len = 0, dh_prime_len = 0, g_a_len = 0;
    size_t offset = 0, inner_offset = 20, client_inner_len = 0;
    size_t client_encrypted_len = 0, padding = 0;
    uint32_t constructor = 0, generator = 0, server_time_bits = 0;
    int64_t time_delta = 0;
    uint64_t retry_id = 0;
    auth_writer inner_writer = {.data = client_inner,
                                .capacity = sizeof(client_inner)};
    auth_writer output_writer = {.data = local_request,
                                 .capacity = sizeof(local_request)};
    BIGNUM *dh_prime = NULL, *dh_q = NULL, *g = NULL, *g_a = NULL;
    BIGNUM *b = NULL, *g_b = NULL, *gab = NULL, *one = NULL;
    BIGNUM *p_minus_one = NULL, *low = NULL, *high = NULL;
    BN_CTX *bn_ctx = NULL;
    tg_mtproto_auth_state next_state = {0};
    int rc = -1;
    if (request_len) *request_len = 0;
    if (!state || !state->step2_ready || !server_dh_params || !randomness || !request ||
        !request_len || server_dh_params_len < 40 ||
        server_dh_params_len > sizeof(encrypted) + 64)
        goto done;
    constructor = read_le32(server_dh_params);
    offset = 4;
    if (constructor == TG_SERVER_DH_PARAMS_FAIL) {
        if (server_dh_params_len != 52 ||
            read_fixed(server_dh_params, server_dh_params_len, &offset,
                       nonce, sizeof(nonce)) != 0 ||
            read_fixed(server_dh_params, server_dh_params_len, &offset,
                       server_nonce, sizeof(server_nonce)) != 0 ||
            read_fixed(server_dh_params, server_dh_params_len, &offset,
                       got_hash, 16) != 0 || offset != server_dh_params_len ||
            memcmp(nonce, state->nonce, sizeof(nonce)) != 0 ||
            memcmp(server_nonce, state->server_nonce, sizeof(server_nonce)) != 0 ||
            sha1_pair(state->new_nonce, sizeof(state->new_nonce), NULL, 0,
                      hash1) != 0 || memcmp(got_hash, hash1 + 4, 16) != 0)
            goto done;
        goto done;
    }
    if (constructor != TG_SERVER_DH_PARAMS_OK) goto done;
    if (read_fixed(server_dh_params, server_dh_params_len, &offset, nonce, 16) ||
        read_fixed(server_dh_params, server_dh_params_len, &offset,
                   server_nonce, 16) ||
        memcmp(nonce, state->nonce, sizeof(nonce)) != 0 ||
        memcmp(server_nonce, state->server_nonce, sizeof(server_nonce)) != 0 ||
        read_tl_bytes(server_dh_params, server_dh_params_len, &offset,
                      &encrypted_data, &encrypted_len) != 0 ||
        offset != server_dh_params_len || !encrypted_len ||
        encrypted_len > sizeof(encrypted) || encrypted_len < 64 ||
        (encrypted_len & 15u))
        goto done;
    memcpy(encrypted, encrypted_data, encrypted_len);

    if (sha1_pair(state->new_nonce, sizeof(state->new_nonce),
                  state->server_nonce, sizeof(state->server_nonce), hash1) ||
        sha1_pair(state->server_nonce, sizeof(state->server_nonce),
                  state->new_nonce, sizeof(state->new_nonce), hash2) ||
        sha1_pair(state->new_nonce, sizeof(state->new_nonce),
                  state->new_nonce, sizeof(state->new_nonce), hash3))
        goto done;
    memcpy(key, hash1, 20);
    memcpy(key + 20, hash2, 12);
    memcpy(iv, hash2 + 12, 8);
    memcpy(iv + 8, hash3, 20);
    memcpy(iv + 28, state->new_nonce, 4);
    if (tg_mtproto_aes_ige(encrypted, encrypted_len, key, iv, 0) != 0)
        goto done;
    memcpy(got_hash, encrypted, sizeof(got_hash));
    memcpy(plain, encrypted, encrypted_len);
    if (read_le32(plain + 20) != TG_SERVER_DH_INNER_DATA) goto done;
    inner_offset = 24;
    if (read_fixed(plain, encrypted_len, &inner_offset, nonce, 16) ||
        read_fixed(plain, encrypted_len, &inner_offset, server_nonce, 16) ||
        memcmp(nonce, state->nonce, sizeof(nonce)) != 0 ||
        memcmp(server_nonce, state->server_nonce, sizeof(server_nonce)) != 0 ||
        read_tl_u32(plain, encrypted_len, &inner_offset, &generator) != 0 ||
        read_tl_bytes(plain, encrypted_len, &inner_offset, &dh_prime_bytes,
                      &dh_prime_len) != 0 ||
        read_tl_bytes(plain, encrypted_len, &inner_offset, &g_a_bytes,
                      &g_a_len) != 0 ||
        read_tl_u32(plain, encrypted_len, &inner_offset,
                    &server_time_bits) != 0 ||
        inner_offset > encrypted_len || encrypted_len - inner_offset > 15 ||
        sha1_pair(plain + 20, inner_offset - 20, NULL, 0, hash1) != 0 ||
        memcmp(got_hash, hash1, sizeof(got_hash)) != 0 ||
        dh_prime_len != 256 || !g_a_len || g_a_len > 256 ||
        generator < 2 || generator > 7)
        goto done;

    dh_prime = BN_bin2bn(dh_prime_bytes, (int)dh_prime_len, NULL);
    dh_q = BN_new(); g = BN_new(); g_a = BN_bin2bn(g_a_bytes, (int)g_a_len, NULL);
    b = BN_bin2bn(randomness, 256, NULL); g_b = BN_new(); gab = BN_new();
    one = BN_new(); p_minus_one = BN_new();
    low = BN_new(); high = BN_new(); bn_ctx = BN_CTX_new();
    if (!dh_prime || !dh_q || !g || !g_a || !b || !g_b || !gab || !one ||
        !p_minus_one || !low || !high ||
        !bn_ctx || BN_num_bits(dh_prime) != 2048 || BN_set_word(g, generator) != 1 ||
        BN_set_word(one, 1) != 1 ||
        BN_copy(p_minus_one, dh_prime) == NULL ||
        BN_sub_word(p_minus_one, 1) != 1 ||
        BN_rshift1(dh_q, p_minus_one) != 1 ||
        BN_check_prime(dh_prime, bn_ctx, NULL) != 1 ||
        BN_check_prime(dh_q, bn_ctx, NULL) != 1 ||
        BN_cmp(g, one) <= 0 || BN_cmp(g, p_minus_one) >= 0 ||
        BN_cmp(g_a, one) <= 0 || BN_cmp(g_a, p_minus_one) >= 0 ||
        BN_mod_word(dh_prime, generator == 2 ? 8 : generator == 3 ? 3 :
                    generator == 5 ? 5 : generator == 6 ? 24 :
                    generator == 7 ? 7 : 1) == (BN_ULONG)-1)
        goto done;
    BN_ULONG prime_residue = BN_mod_word(
        dh_prime, generator == 2 ? 8 : generator == 3 ? 3 :
                  generator == 5 ? 5 : generator == 6 ? 24 :
                  generator == 7 ? 7 : 1);
    if ((generator == 2 && prime_residue != 7) ||
        (generator == 3 && prime_residue != 2) ||
        (generator == 5 && prime_residue != 1 && prime_residue != 4) ||
        (generator == 6 && prime_residue != 19 && prime_residue != 23) ||
        (generator == 7 && prime_residue != 3 && prime_residue != 5 &&
         prime_residue != 6) ||
        BN_one(low) != 1 || BN_lshift(low, low, 1984) != 1 ||
        BN_sub(high, dh_prime, low) != 1 || BN_cmp(g_a, low) <= 0 ||
        BN_cmp(g_a, high) >= 0 || BN_cmp(b, one) <= 0 ||
        BN_mod_exp(g_b, g, b, dh_prime, bn_ctx) != 1 ||
        BN_mod_exp(gab, g_a, b, dh_prime, bn_ctx) != 1 ||
        BN_cmp(g_b, low) <= 0 || BN_cmp(g_b, high) >= 0 ||
        BN_bn2binpad(g_b, client_encrypted, 256) != 256)
        goto done;
    time_delta = (int64_t)(int32_t)server_time_bits - (int64_t)now;
    if (time_delta < INT32_MIN || time_delta > INT32_MAX ||
        write_u32(&inner_writer, TG_CLIENT_DH_INNER_DATA) != 0 ||
        write_bytes(&inner_writer, state->nonce, sizeof(state->nonce)) != 0 ||
        write_bytes(&inner_writer, state->server_nonce,
                    sizeof(state->server_nonce)) != 0 ||
        write_u64(&inner_writer, retry_id) != 0 ||
        write_tl_bytes(&inner_writer, client_encrypted, 256) != 0)
        goto done;
    client_inner_len = inner_writer.length;
    if (sha1_pair(client_inner, client_inner_len, NULL, 0, client_hash) != 0)
        goto done;
    client_encrypted_len = sizeof(client_hash) + client_inner_len;
    padding = (16u - (client_encrypted_len & 15u)) & 15u;
    if (client_encrypted_len + padding > sizeof(client_encrypted)) goto done;
    memcpy(client_encrypted, client_hash, sizeof(client_hash));
    memcpy(client_encrypted + sizeof(client_hash), client_inner, client_inner_len);
    memcpy(client_encrypted + client_encrypted_len, randomness + 256, padding);
    client_encrypted_len += padding;
    if (tg_mtproto_aes_ige(client_encrypted, client_encrypted_len, key, iv, 1) != 0 ||
        write_u32(&output_writer, TG_SET_CLIENT_DH_PARAMS) != 0 ||
        write_bytes(&output_writer, state->nonce, sizeof(state->nonce)) != 0 ||
        write_bytes(&output_writer, state->server_nonce,
                    sizeof(state->server_nonce)) != 0 ||
        write_tl_bytes(&output_writer, client_encrypted,
                       client_encrypted_len) != 0 ||
        output_writer.length > request_cap ||
        BN_bn2binpad(gab, client_encrypted, 256) != 256)
        goto done;

    next_state = *state;
    memcpy(next_state.auth_key, client_encrypted, sizeof(next_state.auth_key));
    next_state.time_offset = (int32_t)time_delta;
    next_state.auth_key_ready = 0;
    next_state.dh_key_ready = 1;
    next_state.step2_ready = 0;
    memcpy(request, local_request, output_writer.length);
    *request_len = output_writer.length;
    *state = next_state;
    rc = 0;
done:
    BN_clear_free(dh_prime); BN_clear_free(dh_q); BN_clear_free(g);
    BN_clear_free(g_a); BN_clear_free(b); BN_clear_free(g_b); BN_clear_free(gab);
    BN_clear_free(one); BN_clear_free(p_minus_one);
    BN_clear_free(low); BN_clear_free(high); BN_CTX_free(bn_ctx);
    OPENSSL_cleanse(encrypted, sizeof(encrypted));
    OPENSSL_cleanse(plain, sizeof(plain));
    OPENSSL_cleanse(key, sizeof(key)); OPENSSL_cleanse(iv, sizeof(iv));
    OPENSSL_cleanse(hash1, sizeof(hash1)); OPENSSL_cleanse(hash2, sizeof(hash2));
    OPENSSL_cleanse(hash3, sizeof(hash3)); OPENSSL_cleanse(got_hash, sizeof(got_hash));
    OPENSSL_cleanse(client_inner, sizeof(client_inner));
    OPENSSL_cleanse(client_hash, sizeof(client_hash));
    OPENSSL_cleanse(client_encrypted, sizeof(client_encrypted));
    OPENSSL_cleanse(local_request, sizeof(local_request));
    OPENSSL_cleanse(nonce, sizeof(nonce)); OPENSSL_cleanse(server_nonce, sizeof(server_nonce));
    OPENSSL_cleanse(&next_state, sizeof(next_state));
    return rc;
}

int tg_mtproto_auth_step4(tg_mtproto_auth_state *state,
                          const uint8_t *dh_gen_answer,
                          size_t dh_gen_answer_len) {
    uint8_t nonce[16], server_nonce[16], got_hash[16], expected_hash[20];
    uint8_t auth_key_hash[20];
    uint8_t nonce_number;
    size_t offset = 4;
    uint32_t constructor;
    tg_mtproto_auth_state next_state;
    int rc = -1;
    if (!state || !dh_gen_answer || !state->dh_key_ready ||
        dh_gen_answer_len != 52)
        return -1;
    constructor = read_le32(dh_gen_answer);
    if (constructor == TG_DH_GEN_OK) nonce_number = 1;
    else if (constructor == TG_DH_GEN_RETRY) nonce_number = 2;
    else if (constructor == TG_DH_GEN_FAIL) nonce_number = 3;
    else return -1;
    if (read_fixed(dh_gen_answer, dh_gen_answer_len, &offset, nonce, 16) ||
        read_fixed(dh_gen_answer, dh_gen_answer_len, &offset, server_nonce, 16) ||
        read_fixed(dh_gen_answer, dh_gen_answer_len, &offset, got_hash, 16) ||
        offset != dh_gen_answer_len ||
        memcmp(nonce, state->nonce, sizeof(nonce)) != 0 ||
        memcmp(server_nonce, state->server_nonce, sizeof(server_nonce)) != 0 ||
        sha1_pair(state->auth_key, sizeof(state->auth_key), NULL, 0,
                  auth_key_hash) != 0 ||
        sha1_triple(state->new_nonce, sizeof(state->new_nonce), &nonce_number,
                    sizeof(nonce_number), auth_key_hash, 8,
                    expected_hash) != 0 ||
        memcmp(got_hash, expected_hash + 4, sizeof(got_hash)) != 0)
        goto done;
    if (constructor != TG_DH_GEN_OK) goto done;
    next_state = *state;
    uint8_t salt[8];
    for (size_t i = 0; i < sizeof(salt); ++i)
        salt[i] = state->new_nonce[i] ^ state->server_nonce[i];
    next_state.first_salt = read_le64(salt);
    next_state.auth_key_ready = 1;
    next_state.dh_key_ready = 0;
    *state = next_state;
    OPENSSL_cleanse(&next_state, sizeof(next_state));
    OPENSSL_cleanse(salt, sizeof(salt));
    rc = 0;
done:
    OPENSSL_cleanse(nonce, sizeof(nonce));
    OPENSSL_cleanse(server_nonce, sizeof(server_nonce));
    OPENSSL_cleanse(got_hash, sizeof(got_hash));
    OPENSSL_cleanse(expected_hash, sizeof(expected_hash));
    OPENSSL_cleanse(auth_key_hash, sizeof(auth_key_hash));
    return rc;
}

void tg_mtproto_auth_clear(tg_mtproto_auth_state *state) {
    if (state) OPENSSL_cleanse(state, sizeof(*state));
}
