#include "tg_ws.h"

#include <limits.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

static int valid_opcode(uint8_t opcode) {
    return opcode == TG_WS_BINARY || opcode == TG_WS_CLOSE ||
           opcode == TG_WS_PING || opcode == TG_WS_PONG;
}

int tg_ws_encode_client_frame(uint8_t *dst, size_t cap, uint8_t opcode,
                              const uint8_t *payload, size_t payload_len,
                              size_t *written) {
    size_t header, mask_off;
    uint8_t mask[4];
    if (!dst || !written || (payload_len && !payload) || !valid_opcode(opcode) ||
        payload_len > TG_WS_MAX_MESSAGE) return -1;
    if (opcode >= 8 && payload_len > 125) return -1;
    header = payload_len < 126 ? 2 : payload_len <= UINT16_MAX ? 4 : 10;
    if (payload_len > SIZE_MAX - header - 4 || cap < header + 4 + payload_len)
        return -1;
    if (RAND_bytes(mask, sizeof(mask)) != 1) return -1;
    dst[0] = (uint8_t)(0x80 | opcode);
    if (payload_len < 126) dst[1] = (uint8_t)(0x80 | payload_len);
    else if (payload_len <= UINT16_MAX) {
        dst[1] = 0x80 | 126;
        dst[2] = (uint8_t)(payload_len >> 8);
        dst[3] = (uint8_t)payload_len;
    } else {
        uint64_t n = (uint64_t)payload_len;
        dst[1] = 0x80 | 127;
        for (size_t i = 0; i < 8; ++i) dst[2 + i] = (uint8_t)(n >> (56 - 8*i));
    }
    mask_off = header - 2;
    memcpy(dst + 2 + mask_off, mask, sizeof(mask));
    for (size_t i = 0; i < payload_len; ++i)
        dst[header + 4 + i] = (uint8_t)(payload[i] ^ mask[i & 3]);
    *written = header + 4 + payload_len;
    return 0;
}

int tg_ws_decode_server_frame(const uint8_t *src, size_t len, size_t max_payload,
                              uint8_t *opcode, const uint8_t **payload,
                              size_t *payload_len, size_t *consumed) {
    uint64_t n;
    size_t header;
    uint8_t op;
    if (!src || !opcode || !payload || !payload_len || !consumed || len < 2)
        return -1;
    if ((src[0] & 0x70) != 0 || (src[0] & 0x80) == 0 || (src[1] & 0x80) != 0)
        return -1;
    op = src[0] & 0x0f;
    if (!valid_opcode(op)) return -1;
    if ((src[1] & 0x7f) < 126) { n = src[1] & 0x7f; header = 2; }
    else if ((src[1] & 0x7f) == 126) {
        if (len < 4) return -1;
        n = ((uint64_t)src[2] << 8) | src[3];
        if (n < 126) return -1;
        header = 4;
    } else {
        if (len < 10 || (src[2] & 0x80) != 0) return -1;
        n = 0;
        for (size_t i = 0; i < 8; ++i) n = (n << 8) | src[2 + i];
        if (n <= UINT16_MAX || n > SIZE_MAX) return -1;
        header = 10;
    }
    if (n > max_payload || n > TG_WS_MAX_MESSAGE ||
        (op >= 8 && (n > 125 || (src[0] & 0x80) == 0)) ||
        n > SIZE_MAX - header || len < header + (size_t)n) return -1;
    *opcode = op;
    *payload = src + header;
    *payload_len = (size_t)n;
    *consumed = header + (size_t)n;
    return 0;
}

static int ssl_read_all(SSL *ssl, uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        size_t n = 0;
        if (SSL_read_ex(ssl, buf + off, len - off, &n) != 1 || n == 0) return -1;
        off += n;
    }
    return 0;
}

static int ssl_write_all(SSL *ssl, const uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        size_t n = 0;
        if (SSL_write_ex(ssl, buf + off, len - off, &n) != 1 || n == 0) return -1;
        off += n;
    }
    return 0;
}

static int header_has_token(const char *value, const char *token) {
    size_t want = strlen(token);
    while (*value) {
        while (*value == ' ' || *value == '\t' || *value == ',') ++value;
        const char *start = value;
        while (*value && *value != ',') ++value;
        const char *end = value;
        while (end > start && (end[-1] == ' ' || end[-1] == '\t')) --end;
        if ((size_t)(end - start) == want && strncasecmp(start, token, want) == 0) return 1;
        if (*value) ++value;
    }
    return 0;
}

static int get_header(const char *response, const char *name, char *out, size_t cap) {
    const char *line = strstr(response, "\r\n");
    if (!line) return -1;
    line += 2;
    while (*line && !(line[0] == '\r' && line[1] == '\n')) {
        const char *end = strstr(line, "\r\n");
        const char *colon = strchr(line, ':');
        if (!end || !colon || colon >= end) return -1;
        if ((size_t)(colon - line) == strlen(name) && strncasecmp(line, name, strlen(name)) == 0) {
            const char *value = colon + 1;
            while (value < end && (*value == ' ' || *value == '\t')) ++value;
            size_t n = (size_t)(end - value);
            if (n >= cap) return -1;
            memcpy(out, value, n); out[n] = '\0';
            return 0;
        }
        line = end + 2;
    }
    return -1;
}

static int has_http_control(const char *value) {
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
        if ((*p < 0x20 && *p != '\t') || *p == 0x7f) return 1;
    }
    return 0;
}

int tg_ws_upgrade_start_ex(tg_ws_upgrade_state *state,
                           const char *host_header, const char *path,
                           const char *subprotocol, const char *origin,
                           const char *user_agent) {
    if (!state || !host_header || !*host_header || !path || path[0] != '/')
        return -1;
    memset(state, 0, sizeof(*state));
    if (has_http_control(host_header) || has_http_control(path) ||
        strpbrk(host_header, " \t") || strpbrk(path, " \t"))
        return -1;
    if ((subprotocol && (!*subprotocol || has_http_control(subprotocol) ||
                         strpbrk(subprotocol, " \t,") ||
                         strlen(subprotocol) >= sizeof(state->subprotocol))) ||
        (origin && (!*origin || has_http_control(origin))) ||
        (user_agent && (!*user_agent || has_http_control(user_agent))))
        return -1;
    uint8_t random[16];
    if (RAND_bytes(random, sizeof(random)) != 1) return -1;
    int key_len = EVP_EncodeBlock((unsigned char *)state->key, random,
                                  sizeof(random));
    OPENSSL_cleanse(random, sizeof(random));
    if (key_len != 24) return -1;
    state->key[24] = '\0';
    if (subprotocol)
        memcpy(state->subprotocol, subprotocol, strlen(subprotocol) + 1u);
    size_t used = 0;
    int n = snprintf((char *)state->request + used,
        sizeof(state->request) - used,
        "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\n"
        "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n",
        path, host_header, state->key);
    if (n <= 0 || (size_t)n >= sizeof(state->request) - used) {
        state->failed = 1;
        return -1;
    }
    used += (size_t)n;
#define TG_WS_APPEND_HEADER(format, value) do { \
    if (value) { \
        n = snprintf((char *)state->request + used, \
                     sizeof(state->request) - used, format, value); \
        if (n <= 0 || (size_t)n >= sizeof(state->request) - used) { \
            state->failed = 1; \
            return -1; \
        } \
        used += (size_t)n; \
    } \
} while (0)
    TG_WS_APPEND_HEADER("Sec-WebSocket-Protocol: %s\r\n", subprotocol);
    TG_WS_APPEND_HEADER("Origin: %s\r\n", origin);
    TG_WS_APPEND_HEADER("User-Agent: %s\r\n", user_agent);
#undef TG_WS_APPEND_HEADER
    n = snprintf((char *)state->request + used,
                 sizeof(state->request) - used, "\r\n");
    if (n != 2) {
        state->failed = 1;
        return -1;
    }
    used += (size_t)n;
    state->request_len = used;
    return 0;
}

int tg_ws_upgrade_start(tg_ws_upgrade_state *state, const char *host_header,
                        const char *path) {
    return tg_ws_upgrade_start_ex(state, host_header, path, NULL, NULL, NULL);
}

const uint8_t *tg_ws_upgrade_pending(const tg_ws_upgrade_state *state,
                                    size_t *length) {
    if (!length) return NULL;
    *length = 0;
    if (!state || state->failed || state->complete ||
        state->request_offset > state->request_len ||
        state->request_offset >= state->request_len)
        return NULL;
    *length = state->request_len - state->request_offset;
    return state->request + state->request_offset;
}

int tg_ws_upgrade_advance(tg_ws_upgrade_state *state, size_t length) {
    if (!state || state->failed || state->complete ||
        state->request_offset > state->request_len ||
        length > state->request_len - state->request_offset)
        return -1;
    state->request_offset += length;
    return 0;
}

static int validate_upgrade_response(const tg_ws_upgrade_state *state) {
    static const char guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    uint8_t digest[SHA_DIGEST_LENGTH];
    char expected[32], source[64];
    unsigned int digest_len = 0;
    char upgrade[64], connection[128], accept[64];
    if (strncmp(state->response, "HTTP/1.1 101 ", 13) != 0 &&
        strncmp(state->response, "HTTP/1.0 101 ", 13) != 0)
        return -1;
    if (get_header(state->response, "Upgrade", upgrade, sizeof(upgrade)) != 0 ||
        strcasecmp(upgrade, "websocket") != 0 ||
        get_header(state->response, "Connection", connection, sizeof(connection)) != 0 ||
        !header_has_token(connection, "upgrade") ||
        get_header(state->response, "Sec-WebSocket-Accept", accept, sizeof(accept)) != 0)
        return -1;
    if (state->subprotocol[0]) {
        char selected[64];
        if (get_header(state->response, "Sec-WebSocket-Protocol", selected,
                       sizeof(selected)) != 0 ||
            strcmp(selected, state->subprotocol) != 0)
            return -1;
    }
    int n = snprintf(source, sizeof(source), "%s%s", state->key, guid);
    if (n <= 0 || (size_t)n >= sizeof(source) ||
        EVP_Digest(source, (size_t)n, digest, &digest_len, EVP_sha1(), NULL) != 1 ||
        digest_len != sizeof(digest)) return -1;
    n = EVP_EncodeBlock((unsigned char *)expected, digest, sizeof(digest));
    if (n != 28) return -1;
    expected[28] = '\0';
    return strcmp(accept, expected) == 0 ? 0 : -1;
}

int tg_ws_upgrade_feed(tg_ws_upgrade_state *state, const uint8_t *data,
                       size_t length, size_t *consumed) {
    static const uint8_t end[] = "\r\n\r\n";
    if (!state || (length && !data) || !consumed) return -1;
    *consumed = 0;
    if (state->failed) return -1;
    if (state->complete) return 1;
    if (!state->request_len || state->request_offset != state->request_len) {
        state->failed = 1;
        return -1;
    }
    while (*consumed < length) {
        uint8_t byte = data[*consumed];
        if ((byte < 0x20 && byte != '\r' && byte != '\n' && byte != '\t') ||
            byte == 0x7f || state->response_len >= TG_WS_UPGRADE_MAX_HEADER) {
            state->failed = 1;
            return -1;
        }
        state->response[state->response_len++] = (char)byte;
        ++*consumed;
        if (state->response_len >= sizeof(end) - 1u &&
            memcmp(state->response + state->response_len - (sizeof(end) - 1u),
                   end, sizeof(end) - 1u) == 0) {
            state->response[state->response_len] = '\0';
            if (validate_upgrade_response(state) != 0) {
                state->failed = 1;
                return -1;
            }
            state->complete = 1;
            return 1;
        }
    }
    return 0;
}

int tg_ws_upgrade(SSL *ssl, const char *host_header, const char *path) {
    tg_ws_upgrade_state state = {0};
    size_t pending_len = 0;
    if (!ssl || tg_ws_upgrade_start(&state, host_header, path) != 0)
        return -1;
    const uint8_t *pending = tg_ws_upgrade_pending(&state, &pending_len);
    if (!pending || ssl_write_all(ssl, pending, pending_len) != 0 ||
        tg_ws_upgrade_advance(&state, pending_len) != 0)
        return -1;
    while (!state.complete) {
        uint8_t byte;
        size_t consumed = 0;
        if (ssl_read_all(ssl, &byte, 1) != 0 ||
            tg_ws_upgrade_feed(&state, &byte, 1, &consumed) < 0 || consumed != 1)
            return -1;
    }
    return 0;
}

static int write_frame(SSL *ssl, uint8_t opcode, const uint8_t *payload, size_t len) {
    size_t cap = len + 14, written = 0;
    uint8_t *frame = OPENSSL_malloc(cap);
    if (!frame) return -1;
    int rc = tg_ws_encode_client_frame(frame, cap, opcode, payload, len, &written);
    if (rc == 0) rc = ssl_write_all(ssl, frame, written);
    OPENSSL_clear_free(frame, cap);
    return rc;
}

int tg_ws_write_binary(SSL *ssl, const uint8_t *payload, size_t payload_len) {
    if (!ssl || (payload_len && !payload)) return -1;
    return write_frame(ssl, TG_WS_BINARY, payload, payload_len);
}

int tg_ws_read_binary(SSL *ssl, uint8_t *dst, size_t cap, size_t *payload_len) {
    uint8_t first[10], *frame = NULL;
    if (!ssl || !dst || !payload_len) return -1;
    for (;;) {
        uint64_t n;
        size_t hlen;
        if (ssl_read_all(ssl, first, 2) != 0) return -1;
        if ((first[0] & 0x70) != 0 || (first[0] & 0x80) == 0 || (first[1] & 0x80) != 0)
            return -1;
        uint8_t op = first[0] & 15;
        if ((first[1] & 127) < 126) { n = first[1] & 127; hlen = 2; }
        else if ((first[1] & 127) == 126) {
            if (ssl_read_all(ssl, first + 2, 2) != 0) return -1;
            n = ((uint64_t)first[2] << 8) | first[3];
            if (n < 126) return -1;
            hlen = 4;
        } else {
            if (ssl_read_all(ssl, first + 2, 8) != 0 || (first[2] & 0x80) != 0) return -1;
            n = 0; for (size_t i = 0; i < 8; ++i) n = (n << 8) | first[2+i];
            if (n <= UINT16_MAX || n > TG_WS_MAX_MESSAGE) return -1;
            hlen = 10;
        }
        if (n > TG_WS_MAX_MESSAGE || n > SIZE_MAX - hlen ||
            (op >= 8 && (n > 125 || (first[0] & 0x80) == 0))) return -1;
        frame = OPENSSL_malloc(hlen + (size_t)n);
        if (!frame) return -1;
        memcpy(frame, first, hlen);
        if (n && ssl_read_all(ssl, frame + hlen, (size_t)n) != 0) goto fail;
        uint8_t opcode; const uint8_t *body; size_t body_len, consumed;
        if (tg_ws_decode_server_frame(frame, hlen + (size_t)n, TG_WS_MAX_MESSAGE,
                                      &opcode, &body, &body_len, &consumed) != 0 ||
            consumed != hlen + (size_t)n) goto fail;
        if (opcode == TG_WS_PING) {
            int rc = write_frame(ssl, TG_WS_PONG, body, body_len);
            OPENSSL_clear_free(frame, hlen + (size_t)n); frame = NULL;
            if (rc != 0) return -1;
            continue;
        }
        if (opcode == TG_WS_PONG) { OPENSSL_clear_free(frame, hlen + (size_t)n); frame=NULL; continue; }
        if (opcode == TG_WS_CLOSE) {
            (void)write_frame(ssl, TG_WS_CLOSE, body, body_len);
            OPENSSL_clear_free(frame, hlen + (size_t)n); return -2;
        }
        if (opcode != TG_WS_BINARY || body_len > cap) goto fail;
        memcpy(dst, body, body_len); *payload_len = body_len;
        OPENSSL_clear_free(frame, hlen + (size_t)n);
        return 0;
fail:
        OPENSSL_clear_free(frame, hlen + (size_t)n);
        return -1;
    }
}
