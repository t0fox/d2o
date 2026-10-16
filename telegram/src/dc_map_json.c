#define _POSIX_C_SOURCE 200809L
#include "tg_dc_map.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TG_DC_CACHE_MAX_BYTES (1024u * 1024u)

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} json_buffer;

static int appendf(json_buffer *buffer, const char *format, ...) {
    if (!buffer->data) {
        buffer->cap = 1024;
        buffer->data = malloc(buffer->cap);
        if (!buffer->data) return -1;
        buffer->data[0] = '\0';
    }
    for (;;) {
        va_list args, copy;
        va_start(args, format);
        va_copy(copy, args);
        int n = vsnprintf(buffer->data + buffer->len, buffer->cap - buffer->len,
                          format, copy);
        va_end(copy);
        va_end(args);
        if (n < 0) return -1;
        size_t required = buffer->len + (size_t)n + 1;
        if (required <= buffer->cap) {
            buffer->len += (size_t)n;
            return 0;
        }
        if (required > TG_DC_CACHE_MAX_BYTES + 1u) return -1;
        size_t cap = buffer->cap;
        while (cap < required) {
            if (cap > (TG_DC_CACHE_MAX_BYTES + 1u) / 2u) {
                cap = TG_DC_CACHE_MAX_BYTES + 1u;
                break;
            }
            cap *= 2u;
        }
        char *grown = realloc(buffer->data, cap);
        if (!grown) return -1;
        buffer->data = grown;
        buffer->cap = cap;
    }
}

typedef struct {
    const uint8_t *data;
    size_t len;
    size_t pos;
} json_reader;

static void skip_space(json_reader *reader) {
    while (reader->pos < reader->len &&
           (reader->data[reader->pos] == ' ' || reader->data[reader->pos] == '\t' ||
            reader->data[reader->pos] == '\r' || reader->data[reader->pos] == '\n'))
        ++reader->pos;
}

static int take(json_reader *reader, uint8_t byte) {
    skip_space(reader);
    if (reader->pos >= reader->len || reader->data[reader->pos] != byte) return -1;
    ++reader->pos;
    return 0;
}

static int hex_value(uint8_t byte) {
    if (byte >= '0' && byte <= '9') return byte - '0';
    if (byte >= 'a' && byte <= 'f') return byte - 'a' + 10;
    if (byte >= 'A' && byte <= 'F') return byte - 'A' + 10;
    return -1;
}

static int read_string(json_reader *reader, char *out, size_t cap, size_t *out_len) {
    if (!out || cap == 0 || take(reader, '"') != 0) return -1;
    size_t used = 0;
    for (;;) {
        if (reader->pos >= reader->len) return -1;
        uint8_t byte = reader->data[reader->pos++];
        if (byte == '"') break;
        if (byte < 0x20 || byte >= 0x80) return -1;
        if (byte == '\\') {
            if (reader->pos >= reader->len) return -1;
            byte = reader->data[reader->pos++];
            if (byte == '"' || byte == '\\' || byte == '/') {
            } else if (byte == 'b') byte = '\b';
            else if (byte == 'f') byte = '\f';
            else if (byte == 'n') byte = '\n';
            else if (byte == 'r') byte = '\r';
            else if (byte == 't') byte = '\t';
            else if (byte == 'u') {
                if (reader->len - reader->pos < 4) return -1;
                unsigned value = 0;
                for (size_t i = 0; i < 4; ++i) {
                    int digit = hex_value(reader->data[reader->pos++]);
                    if (digit < 0) return -1;
                    value = value * 16u + (unsigned)digit;
                }
                if (value > 0x7f || value < 0x20) return -1;
                byte = (uint8_t)value;
            } else return -1;
            if (byte < 0x20) return -1;
        }
        if (used + 1 >= cap) return -1;
        out[used++] = (char)byte;
    }
    out[used] = '\0';
    if (out_len) *out_len = used;
    return 0;
}

static int read_integer(json_reader *reader, int64_t *out) {
    skip_space(reader);
    size_t start = reader->pos;
    if (reader->pos < reader->len && reader->data[reader->pos] == '-') ++reader->pos;
    if (reader->pos >= reader->len || !isdigit(reader->data[reader->pos])) return -1;
    if (reader->data[reader->pos] == '0') {
        ++reader->pos;
        if (reader->pos < reader->len && isdigit(reader->data[reader->pos])) return -1;
    } else {
        while (reader->pos < reader->len && isdigit(reader->data[reader->pos]))
            ++reader->pos;
    }
    size_t len = reader->pos - start;
    if (len == 0 || len >= 32) return -1;
    if (reader->pos < reader->len) {
        uint8_t next = reader->data[reader->pos];
        if (next != ',' && next != '}' && next != ']' &&
            next != ' ' && next != '\t' && next != '\r' && next != '\n')
            return -1;
    }
    char text[32];
    memcpy(text, reader->data + start, len);
    text[len] = '\0';
    errno = 0;
    char *end = NULL;
    long long value = strtoll(text, &end, 10);
    if (errno || !end || *end) return -1;
    *out = (int64_t)value;
    return 0;
}

static int read_u32(json_reader *reader, uint32_t *out) {
    int64_t value;
    if (!out || read_integer(reader, &value) != 0 || value < 0 ||
        (uint64_t)value > UINT32_MAX)
        return -1;
    *out = (uint32_t)value;
    return 0;
}

static int read_port(json_reader *reader, uint16_t *out) {
    uint32_t value;
    if (read_u32(reader, &value) != 0 || value == 0 || value > UINT16_MAX) return -1;
    *out = (uint16_t)value;
    return 0;
}

static int read_bool(json_reader *reader, int *out) {
    skip_space(reader);
    if (reader->len - reader->pos >= 4 &&
        memcmp(reader->data + reader->pos, "true", 4) == 0) {
        reader->pos += 4;
        *out = 1;
        return 0;
    }
    if (reader->len - reader->pos >= 5 &&
        memcmp(reader->data + reader->pos, "false", 5) == 0) {
        reader->pos += 5;
        *out = 0;
        return 0;
    }
    return -1;
}

static int read_nullable_secret(json_reader *reader, tg_dc_endpoint *endpoint) {
    skip_space(reader);
    if (reader->len - reader->pos >= 4 &&
        memcmp(reader->data + reader->pos, "null", 4) == 0) {
        reader->pos += 4;
        endpoint->secret_len = 0;
        return 0;
    }
    char text[TG_DC_MAP_MAX_SECRET * 2 + 1];
    size_t len = 0;
    if (read_string(reader, text, sizeof(text), &len) != 0 ||
        (len & 1u) || len / 2 > TG_DC_MAP_MAX_SECRET)
        return -1;
    for (size_t i = 0; i < len / 2; ++i) {
        int hi = hex_value((uint8_t)text[2 * i]);
        int lo = hex_value((uint8_t)text[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        endpoint->secret[i] = (uint8_t)((hi << 4) | lo);
    }
    endpoint->secret_len = len / 2;
    return 0;
}

static int read_endpoint(json_reader *reader, tg_dc_endpoint *endpoint) {
    enum { ID = 1u << 0, ADDRESS = 1u << 1, PORT = 1u << 2, IPV6 = 1u << 3,
           MEDIA = 1u << 4, TCPO = 1u << 5, CDN = 1u << 6, STATIC = 1u << 7,
           PORT_ONLY = 1u << 8, SECRET = 1u << 9, LAST_SEEN = 1u << 10 };
    const unsigned required = ID | ADDRESS | PORT | IPV6 | MEDIA | TCPO | CDN |
                              STATIC | PORT_ONLY | SECRET | LAST_SEEN;
    unsigned seen = 0;
    char address[64] = {0};
    int ipv6 = 0;
    memset(endpoint, 0, sizeof(*endpoint));
    if (take(reader, '{') != 0) return -1;
    skip_space(reader);
    if (reader->pos < reader->len && reader->data[reader->pos] == '}') return -1;
    for (;;) {
        char key[64];
        if (read_string(reader, key, sizeof(key), NULL) != 0 || take(reader, ':') != 0)
            return -1;
        unsigned bit = 0;
        int rc = -1;
        if (strcmp(key, "id") == 0) { bit = ID; rc = read_u32(reader, &endpoint->id); }
        else if (strcmp(key, "address") == 0) { bit = ADDRESS; rc = read_string(reader, address, sizeof(address), NULL); }
        else if (strcmp(key, "port") == 0) { bit = PORT; rc = read_port(reader, &endpoint->port); }
        else if (strcmp(key, "ipv6") == 0) { bit = IPV6; rc = read_bool(reader, &ipv6); }
        else if (strcmp(key, "media_only") == 0) { bit = MEDIA; rc = read_bool(reader, &endpoint->media_only); }
        else if (strcmp(key, "tcpo_only") == 0) { bit = TCPO; rc = read_bool(reader, &endpoint->tcpo_only); }
        else if (strcmp(key, "cdn") == 0) { bit = CDN; rc = read_bool(reader, &endpoint->cdn); }
        else if (strcmp(key, "is_static") == 0) { bit = STATIC; rc = read_bool(reader, &endpoint->is_static); }
        else if (strcmp(key, "this_port_only") == 0) { bit = PORT_ONLY; rc = read_bool(reader, &endpoint->this_port_only); }
        else if (strcmp(key, "secret") == 0) { bit = SECRET; rc = read_nullable_secret(reader, endpoint); }
        else if (strcmp(key, "last_seen") == 0) { bit = LAST_SEEN; rc = read_integer(reader, &endpoint->last_seen); }
        if (!bit || (seen & bit) || rc != 0) return -1;
        seen |= bit;
        skip_space(reader);
        if (reader->pos >= reader->len) return -1;
        uint8_t separator = reader->data[reader->pos++];
        if (separator == '}') break;
        if (separator != ',') return -1;
    }
    if (seen != required) return -1;
    if (inet_pton(AF_INET, address, endpoint->address) == 1)
        endpoint->family = AF_INET;
    else if (inet_pton(AF_INET6, address, endpoint->address) == 1)
        endpoint->family = AF_INET6;
    else return -1;
    return ipv6 == (endpoint->family == AF_INET6) ? 0 : -1;
}

static int read_endpoints(json_reader *reader, tg_dc_endpoint *endpoints,
                          size_t *count) {
    if (take(reader, '[') != 0) return -1;
    skip_space(reader);
    if (reader->pos < reader->len && reader->data[reader->pos] == ']') {
        ++reader->pos;
        *count = 0;
        return 0;
    }
    size_t used = 0;
    for (;;) {
        if (used == TG_DC_MAP_MAX_ENDPOINTS || read_endpoint(reader, &endpoints[used]) != 0)
            return -1;
        ++used;
        skip_space(reader);
        if (reader->pos >= reader->len) return -1;
        uint8_t separator = reader->data[reader->pos++];
        if (separator == ']') break;
        if (separator != ',') return -1;
    }
    *count = used;
    return 0;
}

int tg_dc_snapshot_parse_json(const uint8_t *json, size_t len, int64_t now,
                              tg_dc_snapshot *out) {
    enum { SCHEMA = 1u << 0, FETCHED = 1u << 1, DATE = 1u << 2,
           EXPIRES = 1u << 3, THIS_DC = 1u << 4, ENDPOINTS = 1u << 5 };
    const unsigned required = SCHEMA | FETCHED | DATE | EXPIRES | THIS_DC | ENDPOINTS;
    json_reader reader = {.data = json, .len = len};
    tg_dc_snapshot parsed = {0};
    tg_dc_endpoint *endpoints = NULL;
    unsigned seen = 0;
    int rc = -1;
    if (!json || !out || len == 0 || len > TG_DC_CACHE_MAX_BYTES) return -1;
    endpoints = calloc(TG_DC_MAP_MAX_ENDPOINTS, sizeof(*endpoints));
    if (!endpoints || take(&reader, '{') != 0) goto done;
    skip_space(&reader);
    if (reader.pos < reader.len && reader.data[reader.pos] == '}') goto done;
    for (;;) {
        char key[64];
        if (read_string(&reader, key, sizeof(key), NULL) != 0 || take(&reader, ':') != 0)
            goto done;
        unsigned bit = 0;
        int field_rc = -1;
        if (strcmp(key, "schema_version") == 0) { bit = SCHEMA; field_rc = read_u32(&reader, &parsed.schema_version); }
        else if (strcmp(key, "fetched_at") == 0) { bit = FETCHED; field_rc = read_integer(&reader, &parsed.fetched_at); }
        else if (strcmp(key, "config_date") == 0) { bit = DATE; field_rc = read_integer(&reader, &parsed.config_date); }
        else if (strcmp(key, "config_expires") == 0) { bit = EXPIRES; field_rc = read_integer(&reader, &parsed.config_expires); }
        else if (strcmp(key, "this_dc") == 0) { bit = THIS_DC; field_rc = read_u32(&reader, &parsed.this_dc); }
        else if (strcmp(key, "endpoints") == 0) { bit = ENDPOINTS; field_rc = read_endpoints(&reader, endpoints, &parsed.endpoint_count); }
        if (!bit || (seen & bit) || field_rc != 0) goto done;
        seen |= bit;
        skip_space(&reader);
        if (reader.pos >= reader.len) goto done;
        uint8_t separator = reader.data[reader.pos++];
        if (separator == '}') break;
        if (separator != ',') goto done;
    }
    skip_space(&reader);
    if (reader.pos != reader.len || seen != required) goto done;
    parsed.endpoints = endpoints;
    if (tg_dc_snapshot_validate(&parsed, now) != 0) goto done;
    *out = parsed;
    endpoints = NULL;
    rc = 0;
done:
    free(endpoints);
    return rc;
}

void tg_dc_snapshot_destroy(tg_dc_snapshot *snapshot) {
    if (!snapshot) return;
    free((void *)snapshot->endpoints);
    memset(snapshot, 0, sizeof(*snapshot));
}

static const char *bool_text(int value) {
    return value ? "true" : "false";
}

int tg_dc_snapshot_encode_json(const tg_dc_snapshot *snapshot, int64_t now,
                               uint8_t **out, size_t *out_len) {
    json_buffer buffer = {0};
    int rc = -1;
    if (!out || !out_len) return -1;
    *out = NULL;
    *out_len = 0;
    if (tg_dc_snapshot_validate(snapshot, now) != 0) return -1;
    if (appendf(&buffer,
                "{\"schema_version\":%u,\"fetched_at\":%lld,"
                "\"config_date\":%lld,\"config_expires\":%lld,"
                "\"this_dc\":%u,\"endpoints\":[",
                snapshot->schema_version, (long long)snapshot->fetched_at,
                (long long)snapshot->config_date, (long long)snapshot->config_expires,
                snapshot->this_dc) != 0)
        goto done;
    for (size_t i = 0; i < snapshot->endpoint_count; ++i) {
        const tg_dc_endpoint *endpoint = &snapshot->endpoints[i];
        char address[INET6_ADDRSTRLEN];
        char secret[TG_DC_MAP_MAX_SECRET * 2 + 1];
        int family = endpoint->family == AF_INET ? AF_INET : AF_INET6;
        if (!inet_ntop(family, endpoint->address, address, sizeof(address))) goto done;
        for (size_t j = 0; j < endpoint->secret_len; ++j) {
            static const char hex[] = "0123456789abcdef";
            secret[2 * j] = hex[endpoint->secret[j] >> 4];
            secret[2 * j + 1] = hex[endpoint->secret[j] & 15];
        }
        secret[2 * endpoint->secret_len] = '\0';
        if (appendf(&buffer,
                    "%s{\"id\":%u,\"address\":\"%s\",\"port\":%u,"
                    "\"ipv6\":%s,\"media_only\":%s,\"tcpo_only\":%s,"
                    "\"cdn\":%s,\"is_static\":%s,\"this_port_only\":%s,\"secret\":",
                    i ? "," : "", endpoint->id, address, endpoint->port,
                    bool_text(endpoint->family == AF_INET6),
                    bool_text(endpoint->media_only), bool_text(endpoint->tcpo_only),
                    bool_text(endpoint->cdn), bool_text(endpoint->is_static),
                    bool_text(endpoint->this_port_only)) != 0)
            goto done;
        if (endpoint->secret_len) {
            if (appendf(&buffer, "\"%s\"", secret) != 0) goto done;
        } else if (appendf(&buffer, "null") != 0) goto done;
        if (appendf(&buffer, ",\"last_seen\":%lld}",
                    (long long)endpoint->last_seen) != 0)
            goto done;
    }
    if (appendf(&buffer, "]}") != 0 || buffer.len > TG_DC_CACHE_MAX_BYTES) goto done;
    *out = (uint8_t *)buffer.data;
    *out_len = buffer.len;
    buffer.data = NULL;
    rc = 0;
done:
    free(buffer.data);
    return rc;
}
