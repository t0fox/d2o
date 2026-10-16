#include "tg_mtproto_splitter.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint8_t *data;
    size_t len;
} packet;

typedef struct {
    packet *items;
    size_t count;
    size_t cap;
} packet_list;

static int hex_value(char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

static int decode_hex(const char *text, uint8_t **out, size_t *out_len) {
    size_t text_len = strlen(text);
    if ((text_len & 1u) != 0) return -1;
    size_t len = text_len / 2;
    uint8_t *bytes = malloc(len ? len : 1);
    if (!bytes) return -1;
    for (size_t i = 0; i < len; ++i) {
        int high = hex_value(text[i * 2]);
        int low = hex_value(text[i * 2 + 1]);
        if (high < 0 || low < 0) {
            free(bytes);
            return -1;
        }
        bytes[i] = (uint8_t)((high << 4) | low);
    }
    *out = bytes;
    *out_len = len;
    return 0;
}

static void print_hex(const uint8_t *bytes, size_t len) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; ++i) {
        putchar(digits[bytes[i] >> 4]);
        putchar(digits[bytes[i] & 0x0f]);
    }
}

static int collect_packet(void *ctx, const uint8_t *bytes, size_t len) {
    packet_list *list = ctx;
    if (list->count == list->cap) {
        size_t cap = list->cap ? list->cap * 2 : 8;
        packet *items = realloc(list->items, cap * sizeof(*items));
        if (!items) return -1;
        list->items = items;
        list->cap = cap;
    }
    uint8_t *copy = malloc(len ? len : 1);
    if (!copy) return -1;
    if (len) memcpy(copy, bytes, len);
    list->items[list->count].data = copy;
    list->items[list->count].len = len;
    ++list->count;
    return 0;
}

static void free_packets(packet_list *list) {
    for (size_t i = 0; i < list->count; ++i) free(list->items[i].data);
    free(list->items);
}

static tg_mtproto_proto parse_proto(const char *name) {
    if (strcmp(name, "abridged") == 0) return TG_MTPROTO_ABRIDGED;
    if (strcmp(name, "intermediate") == 0) return TG_MTPROTO_INTERMEDIATE;
    if (strcmp(name, "padded-intermediate") == 0)
        return TG_MTPROTO_PADDED_INTERMEDIATE;
    return 0;
}

static const char *status_text(int rc) {
    if (rc == TG_MTPROTO_SPLIT_OK) return "OK";
    if (rc == TG_MTPROTO_SPLIT_TOO_LARGE) return "TOO_LARGE";
    return "ERROR";
}

static int run_case(char *line) {
    char *fields[5];
    fields[0] = line;
    for (size_t i = 1; i < 5; ++i) {
        char *separator = strchr(fields[i - 1], '\t');
        if (!separator) return -1;
        *separator = '\0';
        fields[i] = separator + 1;
    }
    if (strchr(fields[4], '\t')) return -1;

    tg_mtproto_proto proto = parse_proto(fields[1]);
    uint8_t *key = NULL, *iv = NULL;
    size_t key_len = 0, iv_len = 0;
    if (!proto || decode_hex(fields[2], &key, &key_len) != 0 ||
        decode_hex(fields[3], &iv, &iv_len) != 0 || key_len != 32 || iv_len != 16) {
        free(key);
        free(iv);
        return -1;
    }

    tg_mtproto_ctr cipher = {0};
    tg_mtproto_splitter splitter = {0};
    packet_list packets = {0};
    int rc = TG_MTPROTO_SPLIT_OK;
    if (tg_mtproto_ctr_init(&cipher, key, iv) != 0 ||
        tg_mtproto_splitter_init(&splitter, proto) != TG_MTPROTO_SPLIT_OK) {
        free(key);
        free(iv);
        tg_mtproto_ctr_destroy(&cipher);
        return -1;
    }
    free(key);
    free(iv);

    char *chunk_save = NULL;
    for (char *hex = strtok_r(fields[4], ";", &chunk_save); hex;
         hex = strtok_r(NULL, ";", &chunk_save)) {
        uint8_t *bytes = NULL;
        size_t len = 0;
        if (decode_hex(hex, &bytes, &len) != 0) {
            rc = TG_MTPROTO_SPLIT_INVALID;
            break;
        }
        rc = tg_mtproto_splitter_feed(&splitter, &cipher, bytes, len,
                                      collect_packet, &packets);
        free(bytes);
        if (rc != TG_MTPROTO_SPLIT_OK) break;
    }
    if (rc == TG_MTPROTO_SPLIT_OK)
        rc = tg_mtproto_splitter_flush(&splitter, collect_packet, &packets);

    printf("%s\t%s\t", fields[0], status_text(rc));
    for (size_t i = 0; i < packets.count; ++i) {
        if (i) putchar(',');
        print_hex(packets.items[i].data, packets.items[i].len);
    }
    putchar('\n');

    free_packets(&packets);
    tg_mtproto_splitter_destroy(&splitter);
    tg_mtproto_ctr_destroy(&cipher);
    return 0;
}

int main(void) {
    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    size_t line_number = 0;
    while ((len = getline(&line, &cap, stdin)) >= 0) {
        ++line_number;
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';
        if (run_case(line) != 0) {
            fprintf(stderr, "неверный сценарий differential test, строка %zu\n",
                    line_number);
            free(line);
            return 2;
        }
    }
    free(line);
    return ferror(stdin) ? 1 : 0;
}
