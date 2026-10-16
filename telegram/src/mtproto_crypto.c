#include "tg_mtproto.h"

#include <limits.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

static int proto_from_bytes(const uint8_t *bytes, tg_mtproto_proto *proto) {
    static const uint8_t abridged[4] = {0xef, 0xef, 0xef, 0xef};
    static const uint8_t intermediate[4] = {0xee, 0xee, 0xee, 0xee};
    static const uint8_t padded[4] = {0xdd, 0xdd, 0xdd, 0xdd};
    if (memcmp(bytes, abridged, sizeof(abridged)) == 0)
        *proto = TG_MTPROTO_ABRIDGED;
    else if (memcmp(bytes, intermediate, sizeof(intermediate)) == 0)
        *proto = TG_MTPROTO_INTERMEDIATE;
    else if (memcmp(bytes, padded, sizeof(padded)) == 0)
        *proto = TG_MTPROTO_PADDED_INTERMEDIATE;
    else
        return -1;
    return 0;
}

static int reserved_handshake_prefix(const uint8_t *packet) {
    static const uint8_t reserved[][4] = {
        {'H', 'E', 'A', 'D'}, {'P', 'O', 'S', 'T'}, {'G', 'E', 'T', ' '},
        {0xee, 0xee, 0xee, 0xee}, {0xdd, 0xdd, 0xdd, 0xdd},
        {0x16, 0x03, 0x01, 0x02}
    };
    static const uint8_t zero[4] = {0};
    if (packet[0] == 0xef || memcmp(packet + 4, zero, sizeof(zero)) == 0)
        return 1;
    for (size_t i = 0; i < sizeof(reserved) / sizeof(reserved[0]); ++i)
        if (memcmp(packet, reserved[i], sizeof(reserved[i])) == 0) return 1;
    return 0;
}

int tg_mtproto_ctr_init(tg_mtproto_ctr *ctx, const uint8_t key[32],
                        const uint8_t iv[16]) {
    if (!ctx || !key || !iv) return -1;
    ctx->ctx = EVP_CIPHER_CTX_new();
    if (!ctx->ctx || EVP_EncryptInit_ex(ctx->ctx, EVP_aes_256_ctr(), NULL,
                                       key, iv) != 1) {
        tg_mtproto_ctr_destroy(ctx);
        return -1;
    }
    return 0;
}

int tg_mtproto_ctr_xor(tg_mtproto_ctr *ctx, uint8_t *data, size_t len) {
    if (!ctx || !ctx->ctx || (len && !data)) return -1;
    while (len) {
        int input_len = len > (size_t)INT_MAX ? INT_MAX : (int)len;
        int output_len = 0;
        if (EVP_EncryptUpdate(ctx->ctx, data, &output_len, data, input_len) != 1 ||
            output_len != input_len)
            return -1;
        data += output_len;
        len -= (size_t)output_len;
    }
    return 0;
}

void tg_mtproto_ctr_destroy(tg_mtproto_ctr *ctx) {
    if (!ctx) return;
    EVP_CIPHER_CTX_free(ctx->ctx);
    ctx->ctx = NULL;
}

int tg_mtproto_direct_stream_ciphers(
    const uint8_t init[TG_MTPROTO_HANDSHAKE_LEN],
    tg_mtproto_ctr *decrypt, tg_mtproto_ctr *encrypt) {
    uint8_t discard[TG_MTPROTO_HANDSHAKE_LEN] = {0};
    int rc = -1;
    if (!init || !decrypt || !encrypt || decrypt == encrypt ||
        decrypt->ctx || encrypt->ctx)
        return -1;
    if (tg_mtproto_ctr_init(decrypt, init + 8, init + 40) != 0 ||
        tg_mtproto_ctr_init(encrypt, init + 8, init + 40) != 0 ||
        tg_mtproto_ctr_xor(decrypt, discard, sizeof(discard)) != 0 ||
        tg_mtproto_ctr_xor(encrypt, discard, sizeof(discard)) != 0)
        goto done;
    rc = 0;
done:
    if (rc != 0) {
        tg_mtproto_ctr_destroy(decrypt);
        tg_mtproto_ctr_destroy(encrypt);
    }
    OPENSSL_cleanse(discard, sizeof(discard));
    return rc;
}

int tg_mtproto_aes_ige(uint8_t *data, size_t len, const uint8_t key[32],
                       const uint8_t iv[32], int encrypt) {
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t previous_cipher[16] = {0}, previous_plain[16] = {0};
    uint8_t input[16] = {0}, output[16] = {0};
    int out_len = 0, ok = 0;
    if (!data || !key || !iv || !len || (len & 15u) ||
        (encrypt != 0 && encrypt != 1))
        return -1;
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx || EVP_CipherInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL,
                                  encrypt) != 1 ||
        EVP_CIPHER_CTX_set_padding(ctx, 0) != 1)
        goto done;
    memcpy(previous_cipher, iv, 16);
    memcpy(previous_plain, iv + 16, 16);
    for (size_t offset = 0; offset < len; offset += 16) {
        uint8_t current_cipher[16], current_plain[16];
        if (encrypt) {
            memcpy(current_plain, data + offset, 16);
            for (size_t i = 0; i < 16; ++i)
                input[i] = current_plain[i] ^ previous_cipher[i];
            if (EVP_CipherUpdate(ctx, output, &out_len, input, 16) != 1 ||
                out_len != 16)
                goto done;
            for (size_t i = 0; i < 16; ++i)
                current_cipher[i] = output[i] ^ previous_plain[i];
            memcpy(data + offset, current_cipher, 16);
        } else {
            memcpy(current_cipher, data + offset, 16);
            for (size_t i = 0; i < 16; ++i)
                input[i] = current_cipher[i] ^ previous_plain[i];
            if (EVP_CipherUpdate(ctx, output, &out_len, input, 16) != 1 ||
                out_len != 16)
                goto done;
            for (size_t i = 0; i < 16; ++i)
                current_plain[i] = output[i] ^ previous_cipher[i];
            memcpy(data + offset, current_plain, 16);
        }
        memcpy(previous_cipher, current_cipher, 16);
        memcpy(previous_plain, current_plain, 16);
        OPENSSL_cleanse(current_cipher, sizeof(current_cipher));
        OPENSSL_cleanse(current_plain, sizeof(current_plain));
    }
    ok = 1;
done:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(previous_cipher, sizeof(previous_cipher));
    OPENSSL_cleanse(previous_plain, sizeof(previous_plain));
    OPENSSL_cleanse(input, sizeof(input));
    OPENSSL_cleanse(output, sizeof(output));
    return ok ? 0 : -1;
}

static int parse_with_key(const uint8_t packet[TG_MTPROTO_HANDSHAKE_LEN],
                          const uint8_t key[32], tg_mtproto_init *out) {
    uint8_t plain[TG_MTPROTO_HANDSHAKE_LEN];
    tg_mtproto_ctr ctr = {0};
    tg_mtproto_init parsed;
    int rc = -1;
    if (reserved_handshake_prefix(packet)) return -1;
    memcpy(plain, packet, sizeof(plain));
    if (tg_mtproto_ctr_init(&ctr, key, packet + 40) != 0 ||
        tg_mtproto_ctr_xor(&ctr, plain, sizeof(plain)) != 0 ||
        proto_from_bytes(plain + 56, &parsed.proto) != 0)
        goto done;

    int16_t signed_dc = (int16_t)((uint16_t)plain[60] |
                                  ((uint16_t)plain[61] << 8));
    uint32_t dc = signed_dc < 0 ? (uint32_t)(-(int32_t)signed_dc)
                                : (uint32_t)signed_dc;
    parsed.dc_id = dc >= 1 && dc <= 999 ? dc : 0;
    parsed.is_media = signed_dc < 0;
    memcpy(parsed.prekey_iv, packet + 8, sizeof(parsed.prekey_iv));
    *out = parsed;
    rc = 0;
done:
    tg_mtproto_ctr_destroy(&ctr);
    OPENSSL_cleanse(plain, sizeof(plain));
    return rc;
}

int tg_mtproto_parse_obfuscated2(
    const uint8_t packet[TG_MTPROTO_HANDSHAKE_LEN], tg_mtproto_init *out) {
    if (!packet || !out) return -1;
    return parse_with_key(packet, packet + 8, out);
}

int tg_mtproto_parse_secret(
    const uint8_t packet[TG_MTPROTO_HANDSHAKE_LEN],
    const uint8_t *secret, size_t secret_len, tg_mtproto_init *out) {
    uint8_t key[EVP_MAX_MD_SIZE];
    unsigned int key_len = 0;
    EVP_MD_CTX *hash = NULL;
    int rc = -1;
    if (!packet || !secret || secret_len == 0 || secret_len > 256 || !out)
        return -1;
    hash = EVP_MD_CTX_new();
    if (!hash || EVP_DigestInit_ex(hash, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(hash, packet + 8, 32) != 1 ||
        EVP_DigestUpdate(hash, secret, secret_len) != 1 ||
        EVP_DigestFinal_ex(hash, key, &key_len) != 1 || key_len != 32)
        goto done;
    rc = parse_with_key(packet, key, out);
done:
    EVP_MD_CTX_free(hash);
    OPENSSL_cleanse(key, sizeof(key));
    return rc;
}

int tg_mtproto_make_obfuscated2_init(tg_mtproto_proto proto, uint32_t dc_id,
                                     int is_media,
                                     uint8_t packet[TG_MTPROTO_HANDSHAKE_LEN],
                                     tg_mtproto_ctr *to_server,
                                     tg_mtproto_ctr *from_server) {
    static const uint8_t tags[3][4] = {
        {0xef, 0xef, 0xef, 0xef},
        {0xee, 0xee, 0xee, 0xee},
        {0xdd, 0xdd, 0xdd, 0xdd}
    };
    uint8_t keystream[TG_MTPROTO_HANDSHAKE_LEN] = {0};
    uint8_t reversed[TG_MTPROTO_PREKEY_IV_LEN];
    uint8_t padding[TG_MTPROTO_HANDSHAKE_LEN];
    tg_mtproto_ctr initial = {0};
    int rc = -1;
    if (!packet || !to_server || !from_server || to_server->ctx ||
        from_server->ctx || proto < TG_MTPROTO_ABRIDGED ||
        proto > TG_MTPROTO_PADDED_INTERMEDIATE || dc_id > 999 ||
        (is_media != 0 && is_media != 1))
        return -1;

    int generated = 0;
    for (unsigned attempt = 0; attempt < 16; ++attempt) {
        if (RAND_bytes(packet, TG_MTPROTO_HANDSHAKE_LEN) != 1) goto done;
        if (!reserved_handshake_prefix(packet)) {
            generated = 1;
            break;
        }
    }
    if (!generated) goto done;
    memcpy(padding, packet, sizeof(padding));
    if (tg_mtproto_ctr_init(&initial, packet + 8, packet + 40) != 0 ||
        tg_mtproto_ctr_xor(&initial, keystream, sizeof(keystream)) != 0)
        goto done;
    tg_mtproto_ctr_destroy(&initial);

    size_t tag_index = (size_t)proto - 1;
    for (size_t i = 0; i < 4; ++i)
        packet[56 + i] = (uint8_t)(tags[tag_index][i] ^ keystream[56 + i]);
    int16_t signed_dc = (int16_t)dc_id;
    if (is_media) signed_dc = (int16_t)-signed_dc;
    uint16_t dc_bits = (uint16_t)signed_dc;
    packet[60] = (uint8_t)dc_bits ^ keystream[60];
    packet[61] = (uint8_t)(dc_bits >> 8) ^ keystream[61];

    if (tg_mtproto_ctr_init(to_server, packet + 8, packet + 40) != 0)
        goto done;
    memset(padding, 0, sizeof(padding));
    if (tg_mtproto_ctr_xor(to_server, padding, sizeof(padding)) != 0)
        goto done;
    for (size_t i = 0; i < sizeof(reversed); ++i)
        reversed[i] = packet[55 - i];
    if (tg_mtproto_ctr_init(from_server, reversed, reversed + 32) != 0)
        goto done;
    rc = 0;
done:
    tg_mtproto_ctr_destroy(&initial);
    if (rc != 0) {
        tg_mtproto_ctr_destroy(to_server);
        tg_mtproto_ctr_destroy(from_server);
    }
    OPENSSL_cleanse(keystream, sizeof(keystream));
    OPENSSL_cleanse(reversed, sizeof(reversed));
    OPENSSL_cleanse(padding, sizeof(padding));
    return rc;
}
