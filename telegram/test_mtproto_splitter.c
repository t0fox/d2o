#include "tg_mtproto_splitter.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FRAME_LIMIT 8

typedef struct {
    uint8_t *bytes[FRAME_LIMIT];
    size_t len[FRAME_LIMIT];
    size_t count;
} capture;

static int collect(void *ctx, const uint8_t *packet, size_t len) {
    capture *out = ctx;
    if (!out || !packet || out->count == FRAME_LIMIT) return -1;
    out->bytes[out->count] = malloc(len ? len : 1);
    if (!out->bytes[out->count]) return -1;
    memcpy(out->bytes[out->count], packet, len);
    out->len[out->count++] = len;
    return 0;
}

static void clear(capture *out) {
    for (size_t i = 0; i < out->count; ++i) free(out->bytes[i]);
    memset(out, 0, sizeof(*out));
}

static void test_partial_intermediate_packet_becomes_one_frame(void) {
    uint8_t packet[] = {8, 0, 0, 0, 'A', 'B', 'C', 'D', 'W', 'X', 'Y', 'Z'};
    uint8_t expected[sizeof(packet)];
    memcpy(expected, packet, sizeof(packet));
    uint8_t key[32] = {0}, iv[16] = {0};
    tg_mtproto_ctr encrypt = {0}, reference = {0};
    tg_mtproto_splitter splitter;
    capture out = {0};
    assert(tg_mtproto_ctr_init(&encrypt, key, iv) == 0);
    assert(tg_mtproto_ctr_init(&reference, key, iv) == 0);
    assert(tg_mtproto_splitter_init(&splitter, TG_MTPROTO_PADDED_INTERMEDIATE) == 0);
    assert(tg_mtproto_ctr_xor(&reference, expected, sizeof(expected)) == 0);
    assert(tg_mtproto_splitter_feed(&splitter, &encrypt, packet, 5, collect, &out) == 0);
    assert(out.count == 0);
    assert(tg_mtproto_splitter_feed(&splitter, &encrypt, packet + 5,
                                    sizeof(packet) - 5, collect, &out) == 0);
    assert(out.count == 1 && out.len[0] == sizeof(expected));
    assert(memcmp(out.bytes[0], expected, sizeof(expected)) == 0);
    clear(&out);
    tg_mtproto_splitter_destroy(&splitter);
    tg_mtproto_ctr_destroy(&encrypt);
    tg_mtproto_ctr_destroy(&reference);
}

static void test_abridged_packets_keep_individual_boundaries(void) {
    uint8_t stream[] = {2, 'a','b','c','d','e','f','g','h', 2, 'i','j','k','l','m','n','o','p'};
    uint8_t expected[sizeof(stream)];
    memcpy(expected, stream, sizeof(stream));
    uint8_t key[32] = {1}, iv[16] = {2};
    tg_mtproto_ctr encrypt = {0}, reference = {0};
    tg_mtproto_splitter splitter;
    capture out = {0};
    assert(tg_mtproto_ctr_init(&encrypt, key, iv) == 0);
    assert(tg_mtproto_ctr_init(&reference, key, iv) == 0);
    assert(tg_mtproto_splitter_init(&splitter, TG_MTPROTO_ABRIDGED) == 0);
    assert(tg_mtproto_ctr_xor(&reference, expected, sizeof(expected)) == 0);
    assert(tg_mtproto_splitter_feed(&splitter, &encrypt, stream, sizeof(stream),
                                    collect, &out) == 0);
    assert(out.count == 2);
    assert(out.len[0] == 9 && out.len[1] == 9);
    assert(memcmp(out.bytes[0], expected, 9) == 0);
    assert(memcmp(out.bytes[1], expected + 9, 9) == 0);
    clear(&out);
    tg_mtproto_splitter_destroy(&splitter);
    tg_mtproto_ctr_destroy(&encrypt);
    tg_mtproto_ctr_destroy(&reference);
}

static void test_abridged_extended_length_header_can_arrive_in_parts(void) {
    uint8_t packet[] = {0x7f, 2, 0, 0, 'A', 'B', 'C', 'D', 'W', 'X', 'Y', 'Z'};
    uint8_t expected[sizeof(packet)];
    memcpy(expected, packet, sizeof(packet));
    uint8_t key[32] = {5}, iv[16] = {6};
    tg_mtproto_ctr encrypt = {0}, reference = {0};
    tg_mtproto_splitter splitter;
    capture out = {0};
    assert(tg_mtproto_ctr_init(&encrypt, key, iv) == 0);
    assert(tg_mtproto_ctr_init(&reference, key, iv) == 0);
    assert(tg_mtproto_splitter_init(&splitter, TG_MTPROTO_ABRIDGED) == 0);
    assert(tg_mtproto_ctr_xor(&reference, expected, sizeof(expected)) == 0);
    assert(tg_mtproto_splitter_feed(&splitter, &encrypt, packet, 1, collect, &out) == 0);
    assert(out.count == 0);
    assert(tg_mtproto_splitter_feed(&splitter, &encrypt, packet + 1,
                                    sizeof(packet) - 1, collect, &out) == 0);
    assert(out.count == 1 && out.len[0] == sizeof(expected));
    assert(memcmp(out.bytes[0], expected, sizeof(expected)) == 0);
    clear(&out);
    tg_mtproto_splitter_destroy(&splitter);
    tg_mtproto_ctr_destroy(&encrypt);
    tg_mtproto_ctr_destroy(&reference);
}

static void test_zero_abridged_length_switches_to_raw_stream(void) {
    uint8_t stream[] = {2, 'a','b','c','d','e','f','g','h', 0, 'T','A','I','L'};
    uint8_t more[] = {'M','O','R','E'};
    uint8_t expected[sizeof(stream) + sizeof(more)];
    memcpy(expected, stream, sizeof(stream));
    memcpy(expected + sizeof(stream), more, sizeof(more));
    uint8_t key[32] = {3}, iv[16] = {4};
    tg_mtproto_ctr encrypt = {0}, reference = {0};
    tg_mtproto_splitter splitter;
    capture out = {0};
    assert(tg_mtproto_ctr_init(&encrypt, key, iv) == 0);
    assert(tg_mtproto_ctr_init(&reference, key, iv) == 0);
    assert(tg_mtproto_splitter_init(&splitter, TG_MTPROTO_ABRIDGED) == 0);
    assert(tg_mtproto_ctr_xor(&reference, expected, sizeof(expected)) == 0);
    assert(tg_mtproto_splitter_feed(&splitter, &encrypt, stream, sizeof(stream),
                                    collect, &out) == 0);
    assert(out.count == 2 && out.len[0] == 9 && out.len[1] == 5);
    assert(memcmp(out.bytes[0], expected, 9) == 0);
    assert(memcmp(out.bytes[1], expected + 9, 5) == 0);
    assert(tg_mtproto_splitter_feed(&splitter, &encrypt, more, sizeof(more),
                                    collect, &out) == 0);
    assert(out.count == 3 && out.len[2] == sizeof(more));
    assert(memcmp(out.bytes[2], expected + sizeof(stream), sizeof(more)) == 0);
    clear(&out);
    tg_mtproto_splitter_destroy(&splitter);
    tg_mtproto_ctr_destroy(&encrypt);
    tg_mtproto_ctr_destroy(&reference);
}

static void test_oversized_intermediate_packet_is_rejected(void) {
    uint8_t header[] = {0, 0, 0x40, 0};
    uint8_t key[32] = {0}, iv[16] = {0};
    tg_mtproto_ctr encrypt = {0};
    tg_mtproto_splitter splitter;
    capture out = {0};
    assert(tg_mtproto_ctr_init(&encrypt, key, iv) == 0);
    assert(tg_mtproto_splitter_init(&splitter, TG_MTPROTO_INTERMEDIATE) == 0);
    assert(tg_mtproto_splitter_feed(&splitter, &encrypt, header, sizeof(header),
                                    collect, &out) == TG_MTPROTO_SPLIT_TOO_LARGE);
    assert(out.count == 0);
    assert(tg_mtproto_splitter_error(&splitter) == TG_MTPROTO_SPLIT_TOO_LARGE);
    clear(&out);
    tg_mtproto_splitter_destroy(&splitter);
    tg_mtproto_ctr_destroy(&encrypt);
}

int main(void) {
    test_partial_intermediate_packet_becomes_one_frame();
    test_abridged_packets_keep_individual_boundaries();
    test_abridged_extended_length_header_can_arrive_in_parts();
    test_zero_abridged_length_switches_to_raw_stream();
    test_oversized_intermediate_packet_is_rejected();
    puts("Тесты границ MTProto-пакетов: ок");
    return 0;
}
