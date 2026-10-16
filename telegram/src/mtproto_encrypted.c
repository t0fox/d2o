#include "tg_mtproto.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <string.h>

static int digest_parts(const EVP_MD *algorithm,
                        const uint8_t *first, size_t first_len,
                        const uint8_t *second, size_t second_len,
                        const uint8_t *third, size_t third_len,
                        uint8_t *out, unsigned int expected_len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int out_len = 0;
    int ok = ctx && EVP_DigestInit_ex(ctx, algorithm, NULL) == 1 &&
             EVP_DigestUpdate(ctx, first, first_len) == 1 &&
             EVP_DigestUpdate(ctx, second, second_len) == 1 &&
             EVP_DigestUpdate(ctx, third, third_len) == 1 &&
             EVP_DigestFinal_ex(ctx, out, &out_len) == 1 &&
             out_len == expected_len;
    EVP_MD_CTX_free(ctx);
    return ok ? 0 : -1;
}

static int derive_v2_key_iv(const uint8_t auth_key[256],
                            const uint8_t message_key[16], size_t x,
                            uint8_t aes_key[32], uint8_t aes_iv[32]) {
    uint8_t hash_a[32] = {0}, hash_b[32] = {0};
    int rc = -1;
    if (x != 0 && x != 8) return -1;
    if (digest_parts(EVP_sha256(), message_key, 16, auth_key + x, 36,
                     NULL, 0, hash_a, sizeof(hash_a)) != 0 ||
        digest_parts(EVP_sha256(), auth_key + 40 + x, 36, message_key, 16,
                     NULL, 0, hash_b, sizeof(hash_b)) != 0)
        goto done;
    memcpy(aes_key, hash_a, 8);
    memcpy(aes_key + 8, hash_b + 8, 16);
    memcpy(aes_key + 24, hash_a + 24, 8);
    memcpy(aes_iv, hash_b, 8);
    memcpy(aes_iv + 8, hash_a + 8, 16);
    memcpy(aes_iv + 24, hash_b + 24, 8);
    rc = 0;
done:
    OPENSSL_cleanse(hash_a, sizeof(hash_a));
    OPENSSL_cleanse(hash_b, sizeof(hash_b));
    return rc;
}

int tg_mtproto_v2_encrypt(const uint8_t auth_key[256],
                          const uint8_t *plaintext, size_t plaintext_len,
                          const uint8_t *padding, size_t padding_len,
                          uint8_t *packet, size_t packet_cap,
                          size_t *packet_len) {
    uint8_t auth_key_hash[20] = {0}, message_hash[32] = {0};
    uint8_t aes_key[32] = {0}, aes_iv[32] = {0};
    uint8_t message_key[16] = {0};
    size_t encrypted_len, output_len = 0;
    int rc = -1;
    if (packet_len) *packet_len = 0;
    if (!auth_key || !plaintext || !plaintext_len || !padding ||
        padding_len < 12 || padding_len > 1024 || !packet || !packet_len ||
        plaintext_len > SIZE_MAX - padding_len ||
        ((plaintext_len + padding_len) & 15u))
        goto done;
    encrypted_len = plaintext_len + padding_len;
    if (encrypted_len > SIZE_MAX - 24 || packet_cap < encrypted_len + 24)
        goto done;
    output_len = encrypted_len + 24;
    if (digest_parts(EVP_sha1(), auth_key, 256, NULL, 0, NULL, 0,
                     auth_key_hash, sizeof(auth_key_hash)) != 0 ||
        digest_parts(EVP_sha256(), auth_key + 88, 32, plaintext,
                     plaintext_len, padding, padding_len, message_hash,
                     sizeof(message_hash)) != 0)
        goto done;
    memcpy(message_key, message_hash + 8, sizeof(message_key));
    if (derive_v2_key_iv(auth_key, message_key, 0, aes_key, aes_iv) != 0)
        goto done;
    memcpy(packet, auth_key_hash + 12, 8);
    memcpy(packet + 8, message_key, sizeof(message_key));
    memcpy(packet + 24, plaintext, plaintext_len);
    memcpy(packet + 24 + plaintext_len, padding, padding_len);
    if (tg_mtproto_aes_ige(packet + 24, encrypted_len, aes_key, aes_iv, 1) != 0)
        goto done;
    *packet_len = encrypted_len + 24;
    rc = 0;
done:
    if (rc != 0 && packet && output_len) OPENSSL_cleanse(packet, output_len);
    OPENSSL_cleanse(auth_key_hash, sizeof(auth_key_hash));
    OPENSSL_cleanse(message_hash, sizeof(message_hash));
    OPENSSL_cleanse(aes_key, sizeof(aes_key));
    OPENSSL_cleanse(aes_iv, sizeof(aes_iv));
    OPENSSL_cleanse(message_key, sizeof(message_key));
    return rc;
}

int tg_mtproto_v2_decrypt(const uint8_t auth_key[256],
                          const uint8_t *packet, size_t packet_len,
                          uint8_t *plaintext, size_t plaintext_cap,
                          size_t *plaintext_len) {
    uint8_t auth_key_hash[20] = {0}, message_hash[32] = {0};
    uint8_t aes_key[32] = {0}, aes_iv[32] = {0};
    uint8_t message_key[16] = {0};
    size_t encrypted_len, padding_len, copied_len = 0;
    uint32_t message_len;
    int rc = -1;
    if (plaintext_len) *plaintext_len = 0;
    if (!auth_key || !packet || packet_len < 40 || !plaintext ||
        !plaintext_len)
        goto done;
    encrypted_len = packet_len - 24;
    if ((encrypted_len & 15u) || plaintext_cap < encrypted_len)
        goto done;
    if (digest_parts(EVP_sha1(), auth_key, 256, NULL, 0, NULL, 0,
                     auth_key_hash, sizeof(auth_key_hash)) != 0 ||
        CRYPTO_memcmp(packet, auth_key_hash + 12, 8) != 0)
        goto done;
    memcpy(message_key, packet + 8, sizeof(message_key));
    if (derive_v2_key_iv(auth_key, message_key, 8, aes_key, aes_iv) != 0)
        goto done;
    memcpy(plaintext, packet + 24, encrypted_len);
    copied_len = encrypted_len;
    if (tg_mtproto_aes_ige(plaintext, encrypted_len, aes_key, aes_iv, 0) != 0 ||
        digest_parts(EVP_sha256(), auth_key + 96, 32, plaintext,
                     encrypted_len, NULL, 0, message_hash,
                     sizeof(message_hash)) != 0 ||
        CRYPTO_memcmp(message_key, message_hash + 8, sizeof(message_key)) != 0 ||
        encrypted_len < 32)
        goto done;
    message_len = (uint32_t)plaintext[28] |
                  ((uint32_t)plaintext[29] << 8) |
                  ((uint32_t)plaintext[30] << 16) |
                  ((uint32_t)plaintext[31] << 24);
    if ((size_t)message_len > encrypted_len - 32) goto done;
    padding_len = encrypted_len - 32 - (size_t)message_len;
    if (padding_len < 12 || padding_len > 1024) goto done;
    *plaintext_len = encrypted_len;
    rc = 0;
done:
    if (rc != 0 && plaintext && copied_len)
        OPENSSL_cleanse(plaintext, copied_len);
    OPENSSL_cleanse(auth_key_hash, sizeof(auth_key_hash));
    OPENSSL_cleanse(message_hash, sizeof(message_hash));
    OPENSSL_cleanse(aes_key, sizeof(aes_key));
    OPENSSL_cleanse(aes_iv, sizeof(aes_iv));
    OPENSSL_cleanse(message_key, sizeof(message_key));
    return rc;
}
