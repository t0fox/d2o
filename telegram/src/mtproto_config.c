#include "tg_mtproto_discovery.h"

#include <arpa/inet.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#define TG_CONFIG_CONSTRUCTOR UINT32_C(0xcc1a241e)
#define TG_DC_OPTION_CONSTRUCTOR UINT32_C(0x18b7a10d)
#define TG_VECTOR_CONSTRUCTOR UINT32_C(0x1cb5c415)
#define TG_BOOL_TRUE UINT32_C(0x997275b5)
#define TG_BOOL_FALSE UINT32_C(0xbc799737)
#define TG_GZIP_PACKED_CONSTRUCTOR UINT32_C(0x3072cfa1)
#define TG_CONFIG_MAX_UNPACKED (1024u * 1024u)
#define TG_CONFIG_MAX_GZIP_DEPTH 4u

typedef struct {
    const uint8_t *data;
    size_t len;
    size_t offset;
} config_reader;

static uint32_t load_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int read_u32(config_reader *reader, uint32_t *out) {
    if (!reader || !out || reader->offset > reader->len ||
        reader->len - reader->offset < 4)
        return -1;
    *out = load_le32(reader->data + reader->offset);
    reader->offset += 4;
    return 0;
}

static int read_bytes(config_reader *reader, const uint8_t **out,
                      size_t *out_len) {
    if (!reader || !out || !out_len || reader->offset >= reader->len)
        return -1;
    size_t prefix_len, count;
    uint8_t first = reader->data[reader->offset];
    if (first < 254) {
        prefix_len = 1;
        count = first;
    } else if (first == 254) {
        if (reader->len - reader->offset < 4) return -1;
        prefix_len = 4;
        count = (size_t)reader->data[reader->offset + 1] |
                ((size_t)reader->data[reader->offset + 2] << 8) |
                ((size_t)reader->data[reader->offset + 3] << 16);
        if (count < 254) return -1;
    } else {
        return -1;
    }
    if (prefix_len > reader->len - reader->offset ||
        count > reader->len - reader->offset - prefix_len)
        return -1;
    size_t encoded_len = prefix_len + count;
    size_t padding = (4u - (encoded_len & 3u)) & 3u;
    if (padding > reader->len - reader->offset - encoded_len) return -1;
    for (size_t i = 0; i < padding; ++i)
        if (reader->data[reader->offset + encoded_len + i] != 0) return -1;
    *out = reader->data + reader->offset + prefix_len;
    *out_len = count;
    reader->offset += encoded_len + padding;
    return 0;
}

static int skip_bytes(config_reader *reader) {
    const uint8_t *value;
    size_t value_len;
    return read_bytes(reader, &value, &value_len);
}

static int skip_string(config_reader *reader) {
    return skip_bytes(reader);
}

static int skip_ints(config_reader *reader, size_t count) {
    if (!reader || reader->offset > reader->len ||
        count > (reader->len - reader->offset) / 4)
        return -1;
    reader->offset += count * 4;
    return 0;
}

static int parse_reaction(config_reader *reader) {
    uint32_t constructor;
    if (read_u32(reader, &constructor) != 0) return -1;
    if (constructor == UINT32_C(0x79f5d419) ||
        constructor == UINT32_C(0x523da4eb))
        return 0;
    if (constructor == UINT32_C(0x1b2286b8)) return skip_string(reader);
    if (constructor == UINT32_C(0x8935fc73)) return skip_ints(reader, 2);
    return -1;
}

static int parse_dc_option(config_reader *reader, int64_t now,
                           tg_dc_endpoint *out) {
    const uint32_t allowed_flags = UINT32_C(0x43f);
    uint32_t constructor, flags, id_bits, port_bits;
    const uint8_t *ip_bytes, *secret;
    size_t ip_len, secret_len = 0;
    char ip[INET6_ADDRSTRLEN];
    int32_t id, port;
    if (read_u32(reader, &constructor) != 0 ||
        constructor != TG_DC_OPTION_CONSTRUCTOR ||
        read_u32(reader, &flags) != 0 || (flags & ~allowed_flags) != 0 ||
        read_u32(reader, &id_bits) != 0)
        return -1;
    id = (int32_t)id_bits;
    if (read_bytes(reader, &ip_bytes, &ip_len) != 0 || ip_len == 0 ||
        ip_len >= sizeof(ip) || memchr(ip_bytes, 0, ip_len) != NULL ||
        read_u32(reader, &port_bits) != 0)
        return -1;
    port = (int32_t)port_bits;
    if ((flags & (1u << 10)) && read_bytes(reader, &secret, &secret_len) != 0)
        return -1;
    if (id < 1 || id > 999 || port < 1 || port > 65535 ||
        secret_len > TG_DC_MAP_MAX_SECRET)
        return -1;
    memcpy(ip, ip_bytes, ip_len);
    ip[ip_len] = '\0';
    memset(out, 0, sizeof(*out));
    out->id = (uint32_t)id;
    out->port = (uint16_t)port;
    out->media_only = (flags >> 1) & 1u;
    out->tcpo_only = (flags >> 2) & 1u;
    out->cdn = (flags >> 3) & 1u;
    out->is_static = (flags >> 4) & 1u;
    out->this_port_only = (flags >> 5) & 1u;
    out->secret_len = secret_len;
    if (secret_len) memcpy(out->secret, secret, secret_len);
    out->last_seen = now;
    if (inet_pton(AF_INET, ip, out->address) == 1)
        out->family = AF_INET;
    else if (inet_pton(AF_INET6, ip, out->address) == 1)
        out->family = AF_INET6;
    else
        return -1;
    if (((flags & 1u) != 0) != (out->family == AF_INET6) ||
        ((flags & (1u << 10)) && secret_len == 0))
        return -1;
    return 0;
}

static int parse_uncompressed_config(const uint8_t *data, size_t len,
                                     int64_t now, tg_dc_snapshot *out) {
    const uint32_t config_flags_allowed =
        (1u << 0) | (1u << 2) | (1u << 3) | (1u << 4) | (1u << 6) |
        (1u << 7) | (1u << 8) | (1u << 9) | (1u << 10) | (1u << 11) |
        (1u << 12) | (1u << 14) | (1u << 15) | (1u << 16);
    config_reader reader = {.data = data, .len = len};
    tg_dc_endpoint *endpoints = NULL;
    tg_dc_snapshot parsed = {0};
    uint32_t constructor, flags, date_bits, expires_bits, bool_constructor;
    uint32_t this_dc_bits, vector_constructor, count;
    int32_t date, expires, this_dc;
    int rc = -1;
    if (out) memset(out, 0, sizeof(*out));
    if (!data || !out || len < 20 || now <= 0 ||
        read_u32(&reader, &constructor) != 0 ||
        constructor != TG_CONFIG_CONSTRUCTOR || read_u32(&reader, &flags) != 0 ||
        (flags & ~config_flags_allowed) != 0 ||
        read_u32(&reader, &date_bits) != 0 ||
        read_u32(&reader, &expires_bits) != 0 ||
        read_u32(&reader, &bool_constructor) != 0 ||
        (bool_constructor != TG_BOOL_TRUE && bool_constructor != TG_BOOL_FALSE) ||
        read_u32(&reader, &this_dc_bits) != 0 ||
        read_u32(&reader, &vector_constructor) != 0 ||
        vector_constructor != TG_VECTOR_CONSTRUCTOR ||
        read_u32(&reader, &count) != 0 || count == 0 ||
        count > TG_DC_MAP_MAX_ENDPOINTS)
        goto done;
    date = (int32_t)date_bits;
    expires = (int32_t)expires_bits;
    this_dc = (int32_t)this_dc_bits;
    endpoints = calloc(count, sizeof(*endpoints));
    if (!endpoints) goto done;
    for (size_t i = 0; i < count; ++i)
        if (parse_dc_option(&reader, now, &endpoints[i]) != 0) goto done;

    if (skip_string(&reader) != 0 || skip_ints(&reader, 17) != 0)
        goto done;
    if ((flags & 1u) && skip_ints(&reader, 1) != 0) goto done;
    if (skip_ints(&reader, 4) != 0 || skip_string(&reader) != 0) goto done;
    static const unsigned optional_strings[] = {7, 9, 10, 11, 12};
    for (size_t i = 0; i < sizeof(optional_strings) / sizeof(optional_strings[0]); ++i)
        if ((flags & (1u << optional_strings[i])) && skip_string(&reader) != 0)
            goto done;
    if (skip_ints(&reader, 3) != 0) goto done;
    if (flags & (1u << 2)) {
        if (skip_string(&reader) != 0 || skip_ints(&reader, 2) != 0)
            goto done;
    }
    if ((flags & (1u << 15)) && parse_reaction(&reader) != 0) goto done;
    if ((flags & (1u << 16)) && skip_string(&reader) != 0) goto done;
    if (reader.offset != reader.len) goto done;

    parsed.schema_version = TG_DC_MAP_SCHEMA_VERSION;
    parsed.fetched_at = now;
    parsed.config_date = date;
    parsed.config_expires = expires;
    parsed.this_dc = this_dc > 0 ? (uint32_t)this_dc : 0;
    parsed.endpoints = endpoints;
    parsed.endpoint_count = count;
    if (tg_dc_snapshot_validate(&parsed, now) != 0) goto done;
    *out = parsed;
    endpoints = NULL;
    rc = 0;
done:
    free(endpoints);
    return rc;
}

static int inflate_config_gzip(const uint8_t *compressed, size_t compressed_len,
                               uint8_t **out, size_t *out_len) {
    z_stream stream = {0};
    uint8_t *expanded = NULL;
    int initialized = 0;
    int rc = -1;
    if (!compressed || compressed_len == 0 || compressed_len > UINT_MAX ||
        !out || !out_len)
        return -1;
    *out = NULL;
    *out_len = 0;
    expanded = malloc(TG_CONFIG_MAX_UNPACKED);
    if (!expanded) goto done;
    stream.next_in = (Bytef *)(uintptr_t)compressed;
    stream.avail_in = (uInt)compressed_len;
    stream.next_out = expanded;
    stream.avail_out = TG_CONFIG_MAX_UNPACKED;
    if (inflateInit2(&stream, MAX_WBITS + 16) != Z_OK) goto done;
    initialized = 1;
    if (inflate(&stream, Z_FINISH) != Z_STREAM_END || stream.total_in != compressed_len ||
        stream.total_out == 0 || stream.total_out > TG_CONFIG_MAX_UNPACKED)
        goto done;
    *out = expanded;
    *out_len = (size_t)stream.total_out;
    expanded = NULL;
    rc = 0;
done:
    if (initialized) inflateEnd(&stream);
    free(expanded);
    return rc;
}

int tg_mtproto_config_parse(const uint8_t *data, size_t len, int64_t now,
                            tg_dc_snapshot *out) {
    const uint8_t *object = data;
    size_t object_len = len;
    uint8_t *owned = NULL;
    int rc = -1;
    if (out) memset(out, 0, sizeof(*out));
    if (!data || !out || len < 4 || now <= 0) goto done;
    for (unsigned depth = 0; depth < TG_CONFIG_MAX_GZIP_DEPTH; ++depth) {
        if (object_len < 4 || load_le32(object) != TG_GZIP_PACKED_CONSTRUCTOR)
            break;
        config_reader reader = {.data = object, .len = object_len, .offset = 4};
        const uint8_t *compressed;
        size_t compressed_len;
        uint8_t *expanded = NULL;
        size_t expanded_len = 0;
        if (read_bytes(&reader, &compressed, &compressed_len) != 0 ||
            reader.offset != reader.len ||
            inflate_config_gzip(compressed, compressed_len, &expanded,
                                &expanded_len) != 0)
            goto done;
        free(owned);
        owned = expanded;
        object = owned;
        object_len = expanded_len;
    }
    if (object_len >= 4 && load_le32(object) == TG_GZIP_PACKED_CONSTRUCTOR)
        goto done;
    rc = parse_uncompressed_config(object, object_len, now, out);
done:
    free(owned);
    if (rc != 0 && out) memset(out, 0, sizeof(*out));
    return rc;
}
