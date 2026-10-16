#define _POSIX_C_SOURCE 200809L
#include "tg_ws.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *data;
    size_t len, cap;
} text_buffer;

static int hex_value(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static int decode_hex(const char *text, uint8_t **bytes, size_t *length) {
    size_t chars = strlen(text);
    if ((chars & 1u) != 0) return -1;
    *length = chars / 2u;
    *bytes = malloc(*length ? *length : 1u);
    if (!*bytes) return -1;
    for (size_t i = 0; i < *length; ++i) {
        int high = hex_value(text[2u * i]);
        int low = hex_value(text[2u * i + 1u]);
        if (high < 0 || low < 0) {
            free(*bytes);
            *bytes = NULL;
            return -1;
        }
        (*bytes)[i] = (uint8_t)((high << 4) | low);
    }
    return 0;
}

static int reserve(text_buffer *buffer, size_t add) {
    if (add > SIZE_MAX - buffer->len - 1u) return -1;
    size_t needed = buffer->len + add + 1u;
    if (needed <= buffer->cap) return 0;
    size_t cap = buffer->cap ? buffer->cap : 64u;
    while (cap < needed) {
        if (cap > SIZE_MAX / 2u) { cap = needed; break; }
        cap *= 2u;
    }
    char *data = realloc(buffer->data, cap);
    if (!data) return -1;
    buffer->data = data;
    buffer->cap = cap;
    return 0;
}

static int append_message(text_buffer *buffer, uint8_t opcode,
                          const uint8_t *data, size_t len) {
    static const char digits[] = "0123456789abcdef";
    if (reserve(buffer, 2u + (buffer->len ? 1u : 0u) + len * 2u) != 0)
        return -1;
    if (buffer->len) buffer->data[buffer->len++] = ';';
    buffer->data[buffer->len++] = opcode == TG_WS_TEXT ? 'T' : 'B';
    buffer->data[buffer->len++] = ':';
    for (size_t i = 0; i < len; ++i) {
        buffer->data[buffer->len++] = digits[data[i] >> 4];
        buffer->data[buffer->len++] = digits[data[i] & 0x0fu];
    }
    buffer->data[buffer->len] = '\0';
    return 0;
}

static int run_case(char *line) {
    char *id = line;
    char *first_tab = strchr(id, '\t');
    if (!first_tab) return -1;
    *first_tab++ = '\0';
    char *end = NULL;
    unsigned long chunk = strtoul(first_tab, &end, 10);
    if (!first_tab[0] || !end || *end != '\t' || chunk == 0 || chunk > SIZE_MAX)
        return -1;
    char *hex = end + 1;
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (decode_hex(hex, &wire, &wire_len) != 0) return -1;
    uint8_t *rx = malloc(wire_len ? wire_len : 1u);
    if (!rx) { free(wire); return -1; }

    tg_ws_reassembly state = {0};
    text_buffer messages = {0};
    size_t input_offset = 0, rx_len = 0;
    int failed = 0, closed = 0;
    while (input_offset < wire_len && !failed && !closed) {
        size_t amount = wire_len - input_offset;
        if (amount > chunk) amount = chunk;
        memcpy(rx + rx_len, wire + input_offset, amount);
        rx_len += amount;
        input_offset += amount;

        while (rx_len && !failed && !closed) {
            uint8_t opcode = 0;
            const uint8_t *payload = NULL;
            size_t payload_len = 0, consumed = 0;
            int ready = tg_ws_reassembly_feed(&state, rx, rx_len,
                    TG_WS_MAX_MESSAGE, &opcode, &payload, &payload_len,
                    &consumed);
            if (ready < 0 || ready == 0 || consumed == 0 || consumed > rx_len) {
                if (ready < 0) failed = 1;
                break;
            }
            if (ready == 1) {
                if (opcode == TG_WS_CLOSE) closed = 1;
                else if ((opcode == TG_WS_BINARY || opcode == TG_WS_TEXT) &&
                         append_message(&messages, opcode, payload,
                                        payload_len) != 0)
                    failed = 1;
            }
            memmove(rx, rx + consumed, rx_len - consumed);
            rx_len -= consumed;
        }
    }
    if (!failed && (!closed || rx_len || state.fragmented)) failed = 1;

    if (failed) printf("%s\tERR\n", id);
    else printf("%s\tOK\t%s\n", id, messages.data ? messages.data : "");
    tg_ws_reassembly_destroy(&state);
    free(messages.data);
    free(rx);
    free(wire);
    return 0;
}

int main(void) {
    char *line = NULL;
    size_t capacity = 0;
    ssize_t length;
    while ((length = getline(&line, &capacity, stdin)) >= 0) {
        while (length && (line[length - 1] == '\n' || line[length - 1] == '\r'))
            line[--length] = '\0';
        if (run_case(line) != 0) {
            free(line);
            return 2;
        }
    }
    free(line);
    return ferror(stdin) ? 1 : 0;
}
