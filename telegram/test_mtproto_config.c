#include "tg_mtproto_discovery.h"

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

typedef struct {
    uint8_t bytes[4096];
    size_t len;
} test_writer;

static void write_u32(test_writer *writer, uint32_t value) {
    assert(writer->len <= sizeof(writer->bytes) - 4);
    for (size_t i = 0; i < 4; ++i)
        writer->bytes[writer->len++] = (uint8_t)(value >> (8u * i));
}

static void write_bytes(test_writer *writer, const uint8_t *data, size_t len) {
    uint8_t prefix[4];
    size_t prefix_len;
    assert(len <= UINT32_C(0xffffff));
    if (len < 254) {
        prefix[0] = (uint8_t)len;
        prefix_len = 1;
    } else {
        prefix[0] = 254;
        prefix[1] = (uint8_t)len;
        prefix[2] = (uint8_t)(len >> 8);
        prefix[3] = (uint8_t)(len >> 16);
        prefix_len = 4;
    }
    size_t padding = (4u - ((prefix_len + len) & 3u)) & 3u;
    assert(writer->len <= sizeof(writer->bytes) - prefix_len - len - padding);
    memcpy(writer->bytes + writer->len, prefix, prefix_len);
    writer->len += prefix_len;
    if (len) memcpy(writer->bytes + writer->len, data, len);
    writer->len += len;
    memset(writer->bytes + writer->len, 0, padding);
    writer->len += padding;
}

static void write_string(test_writer *writer, const char *value) {
    write_bytes(writer, (const uint8_t *)value, strlen(value));
}

static void write_dc_option(test_writer *writer, uint32_t flags, int32_t id,
                            const char *address, int32_t port) {
    write_u32(writer, UINT32_C(0x18b7a10d));
    write_u32(writer, flags);
    write_u32(writer, (uint32_t)id);
    write_string(writer, address);
    write_u32(writer, (uint32_t)port);
    if (flags & (1u << 10)) {
        static const uint8_t secret[] = {0x31, 0x32, 0x33, 0x34};
        write_bytes(writer, secret, sizeof(secret));
    }
}

static size_t make_config(uint8_t *out, size_t cap, uint32_t first_id) {
    const uint32_t flags = (1u << 0) | (1u << 2) | (1u << 3) |
                           (1u << 4) | (1u << 6) | (1u << 7) |
                           (1u << 8) | (1u << 9) | (1u << 10) |
                           (1u << 11) | (1u << 12) | (1u << 14) |
                           (1u << 15) | (1u << 16);
    test_writer writer = {0};
    write_u32(&writer, UINT32_C(0xcc1a241e));
    write_u32(&writer, flags);
    write_u32(&writer, 1799999900u);
    write_u32(&writer, 1800003600u);
    write_u32(&writer, UINT32_C(0x997275b5));
    write_u32(&writer, 2);
    write_u32(&writer, UINT32_C(0x1cb5c415));
    write_u32(&writer, 9);
    write_dc_option(&writer, 0, (int32_t)first_id, "149.154.175.50", 443);
    write_dc_option(&writer, 0, 2, "149.154.167.50", 443);
    write_dc_option(&writer, 0, 3, "149.154.175.100", 443);
    write_dc_option(&writer, 0, 4, "149.154.167.91", 443);
    write_dc_option(&writer, 0, 5, "91.108.56.100", 443);
    write_dc_option(&writer, 1u << 1, 2, "149.154.167.151", 443);
    write_dc_option(&writer, 1u << 3, 3, "149.154.175.102", 443);
    write_dc_option(&writer, 1u << 0, 5, "2001:b28:f23f:f005::a", 443);
    write_dc_option(&writer, (1u << 2) | (1u << 10),
                    first_id == 1 ? 1 : 6,
                    "149.154.175.50", 443);
    write_string(&writer, "apv3.stel.com");
    for (uint32_t i = 0; i < 17; ++i) write_u32(&writer, i + 100);
    write_u32(&writer, 10);
    for (uint32_t i = 0; i < 4; ++i) write_u32(&writer, i + 200);
    write_string(&writer, "https://t.me/");
    write_string(&writer, "https://updates.example/");
    write_string(&writer, "gif");
    write_string(&writer, "venue");
    write_string(&writer, "image");
    write_string(&writer, "maps");
    write_u32(&writer, 500);
    write_u32(&writer, 4096);
    write_u32(&writer, 4);
    write_string(&writer, "ru");
    write_u32(&writer, 7);
    write_u32(&writer, 6);
    write_u32(&writer, UINT32_C(0x1b2286b8));
    write_string(&writer, "🔥");
    write_string(&writer, "token");
    assert(writer.len <= cap);
    memcpy(out, writer.bytes, writer.len);
    return writer.len;
}

static size_t gzip_compress(const uint8_t *input, size_t input_len,
                            uint8_t *out, size_t out_cap) {
    z_stream stream = {0};
    assert(input_len <= UINT_MAX && out_cap <= UINT_MAX);
    stream.next_in = (Bytef *)(uintptr_t)input;
    stream.avail_in = (uInt)input_len;
    stream.next_out = out;
    stream.avail_out = (uInt)out_cap;
    assert(deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                        MAX_WBITS + 16, 8, Z_DEFAULT_STRATEGY) == Z_OK);
    assert(deflate(&stream, Z_FINISH) == Z_STREAM_END);
    size_t compressed_len = (size_t)stream.total_out;
    assert(deflateEnd(&stream) == Z_OK);
    return compressed_len;
}

static void test_config_extracts_valid_dc_options(void) {
    uint8_t bytes[4096];
    size_t len = make_config(bytes, sizeof(bytes), 1);
    tg_dc_snapshot snapshot = {0};
    assert(tg_mtproto_config_parse(bytes, len, 1800000000, &snapshot) == 0);
    assert(snapshot.schema_version == 1 && snapshot.this_dc == 2);
    assert(snapshot.config_date == 1799999900 &&
           snapshot.config_expires == 1800003600);
    assert(snapshot.fetched_at == 1800000000 && snapshot.endpoint_count == 9);
    assert(snapshot.endpoints[5].media_only);
    assert(snapshot.endpoints[6].cdn);
    assert(snapshot.endpoints[7].family == AF_INET6);
    assert(snapshot.endpoints[8].tcpo_only && snapshot.endpoints[8].secret_len == 4);
    tg_dc_snapshot_destroy(&snapshot);
}

static void test_config_rejects_unknown_flags_trailing_data_and_missing_dc(void) {
    uint8_t bytes[4096];
    size_t len = make_config(bytes, sizeof(bytes), 6);
    tg_dc_snapshot snapshot = {0};
    assert(tg_mtproto_config_parse(bytes, len, 1800000000, &snapshot) != 0);
    assert(snapshot.endpoints == NULL);

    len = make_config(bytes, sizeof(bytes), 1);
    bytes[4] |= 0x20;
    assert(tg_mtproto_config_parse(bytes, len, 1800000000, &snapshot) != 0);
    bytes[4] &= (uint8_t)~0x20u;
    bytes[len] = 0;
    assert(tg_mtproto_config_parse(bytes, len + 1, 1800000000, &snapshot) != 0);
    assert(snapshot.endpoints == NULL);
}

static void test_config_accepts_bounded_gzip_response(void) {
    uint8_t config[4096];
    uint8_t compressed[4096];
    size_t config_len = make_config(config, sizeof(config), 1);
    size_t compressed_len = gzip_compress(config, config_len, compressed,
                                          sizeof(compressed));
    test_writer packed = {0};
    write_u32(&packed, UINT32_C(0x3072cfa1));
    write_bytes(&packed, compressed, compressed_len);
    tg_dc_snapshot snapshot = {0};
    assert(tg_mtproto_config_parse(packed.bytes, packed.len, 1800000000,
                                   &snapshot) == 0);
    assert(snapshot.this_dc == 2 && snapshot.endpoint_count == 9);
    tg_dc_snapshot_destroy(&snapshot);

    uint8_t *oversized = calloc(1024u * 1024u + 1u, 1);
    assert(oversized);
    size_t oversized_len = gzip_compress(oversized, 1024u * 1024u + 1u,
                                        compressed, sizeof(compressed));
    packed = (test_writer){0};
    write_u32(&packed, UINT32_C(0x3072cfa1));
    write_bytes(&packed, compressed, oversized_len);
    assert(tg_mtproto_config_parse(packed.bytes, packed.len, 1800000000,
                                   &snapshot) != 0);
    assert(snapshot.endpoints == NULL);
    free(oversized);
}

int main(void) {
    test_config_extracts_valid_dc_options();
    test_config_rejects_unknown_flags_trailing_data_and_missing_dc();
    test_config_accepts_bounded_gzip_response();
    puts("Тесты TL help.getConfig parser: ок");
    return 0;
}
