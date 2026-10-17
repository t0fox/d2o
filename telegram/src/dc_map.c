#define _POSIX_C_SOURCE 200809L
#include "tg_dc_map.h"

#include <arpa/inet.h>
#include <limits.h>
#include <string.h>

#define TG_DC_FUTURE_TOLERANCE 300

typedef struct {
    uint32_t id;
    const char *address;
    int media_only;
} builtin_endpoint;

static const builtin_endpoint builtin_endpoints[] = {
    {1, "149.154.175.50", 0}, {1, "149.154.175.51", 0},
    {1, "149.154.175.52", 1}, {1, "149.154.175.53", 0},
    {1, "149.154.175.54", 0}, {2, "149.154.167.41", 0},
    {2, "149.154.167.50", 0}, {2, "149.154.167.51", 0},
    {2, "149.154.167.220", 0}, {2, "95.161.76.100", 0},
    {2, "149.154.167.151", 1}, {2, "149.154.167.222", 1},
    {2, "149.154.167.223", 1}, {2, "149.154.162.123", 1},
    {3, "149.154.175.100", 0}, {3, "149.154.175.101", 0},
    {3, "149.154.175.102", 1}, {4, "149.154.167.91", 0},
    {4, "149.154.167.43", 1},
    {4, "149.154.167.92", 0}, {4, "149.154.164.250", 1},
    {4, "149.154.166.120", 1}, {4, "149.154.166.121", 1},
    {4, "149.154.167.118", 1}, {4, "149.154.165.111", 1},
    {5, "91.108.56.100", 0}, {5, "91.108.56.101", 0},
    {5, "91.108.56.116", 0}, {5, "91.108.56.126", 0},
    {5, "149.154.171.5", 0}, {5, "91.108.56.102", 1},
    {5, "91.108.56.128", 1}, {5, "91.108.56.151", 1},
    {203, "91.105.192.100", 0},
    {1, "2001:b28:f23d:f001::a", 0},
    {2, "2001:67c:4e8:f002::a", 0},
    {3, "2001:b28:f23d:f003::a", 0},
    {4, "2001:67c:4e8:f004::a", 0},
    {5, "2001:b28:f23f:f005::a", 0}
};

size_t tg_dc_builtin_endpoint_count(void) {
    return sizeof(builtin_endpoints) / sizeof(builtin_endpoints[0]);
}

int tg_dc_builtin_endpoint_at(size_t index, int64_t now,
                              tg_dc_endpoint *out) {
    if (!out || index >= tg_dc_builtin_endpoint_count() || now <= 0) return -1;
    const builtin_endpoint *builtin = &builtin_endpoints[index];
    memset(out, 0, sizeof(*out));
    out->id = builtin->id;
    out->family = strchr(builtin->address, ':') ? AF_INET6 : AF_INET;
    if (inet_pton(out->family, builtin->address, out->address) != 1) return -1;
    out->port = 443;
    out->media_only = builtin->media_only;
    out->is_static = 1;
    out->last_seen = now;
    return 0;
}

static int ipv4_non_global(const uint8_t ip[4]) {
    return ip[0] == 0 || ip[0] == 10 || ip[0] == 127 || ip[0] >= 224 ||
           (ip[0] == 100 && (ip[1] & 0xc0) == 0x40) ||
           (ip[0] == 169 && ip[1] == 254) ||
           (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) ||
           (ip[0] == 192 && (ip[1] == 168 ||
                             (ip[1] == 0 && (ip[2] == 0 || ip[2] == 2)))) ||
           (ip[0] == 198 && (ip[1] == 18 || ip[1] == 19 ||
                             (ip[1] == 51 && ip[2] == 100))) ||
           (ip[0] == 203 && ip[1] == 0 && ip[2] == 113);
}

static int ipv6_v4_mapped(const uint8_t ip[16]) {
    static const uint8_t prefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    return memcmp(ip, prefix, sizeof(prefix)) == 0;
}

static int public_address(sa_family_t family, const uint8_t address[16]) {
    if (family == AF_INET) return !ipv4_non_global(address);
    if (family != AF_INET6) return 0;
    if (ipv6_v4_mapped(address)) return !ipv4_non_global(address + 12);
    static const uint8_t zero[16] = {0};
    return memcmp(address, zero, sizeof(zero)) != 0 &&
           !(memcmp(address, zero, 15) == 0 && address[15] == 1) &&
           (address[0] & 0xfe) != 0xfc && address[0] != 0xff &&
           !(address[0] == 0xfe && (address[1] & 0xc0) == 0x80) &&
           !(address[0] == 0x20 && address[1] == 1 &&
             address[2] == 0x0d && address[3] == 0xb8);
}

static int not_future(int64_t value, int64_t now) {
    if (value <= now || now > INT64_MAX - TG_DC_FUTURE_TOLERANCE) return 1;
    return value <= now + TG_DC_FUTURE_TOLERANCE;
}

int tg_dc_snapshot_validate(const tg_dc_snapshot *snapshot, int64_t now) {
    if (!snapshot || snapshot->schema_version != TG_DC_MAP_SCHEMA_VERSION ||
        snapshot->fetched_at <= 0 || !not_future(snapshot->fetched_at, now) ||
        snapshot->config_date <= 0 || !not_future(snapshot->config_date, now) ||
        snapshot->config_expires <= snapshot->config_date ||
        snapshot->this_dc < 1 || snapshot->this_dc > 999 ||
        !snapshot->endpoints || snapshot->endpoint_count == 0 ||
        snapshot->endpoint_count > TG_DC_MAP_MAX_ENDPOINTS)
        return -1;

    int primary[6] = {0};
    for (size_t i = 0; i < snapshot->endpoint_count; ++i) {
        const tg_dc_endpoint *endpoint = &snapshot->endpoints[i];
        if (endpoint->id < 1 || endpoint->id > 999 || endpoint->port == 0 ||
            (endpoint->family != AF_INET && endpoint->family != AF_INET6) ||
            !public_address(endpoint->family, endpoint->address) ||
            endpoint->secret_len > TG_DC_MAP_MAX_SECRET ||
            endpoint->last_seen <= 0 || !not_future(endpoint->last_seen, now) ||
            (endpoint->media_only != 0 && endpoint->media_only != 1) ||
            (endpoint->tcpo_only != 0 && endpoint->tcpo_only != 1) ||
            (endpoint->cdn != 0 && endpoint->cdn != 1) ||
            (endpoint->is_static != 0 && endpoint->is_static != 1) ||
            (endpoint->this_port_only != 0 && endpoint->this_port_only != 1))
            return -1;
        if (endpoint->id <= 5 && !endpoint->media_only && !endpoint->cdn)
            primary[endpoint->id] = 1;
    }
    for (uint32_t dc = 1; dc <= 5; ++dc)
        if (!primary[dc]) return -1;
    return 0;
}

static int normalized_destination(const tg_listener_destination *destination,
                                 tg_listener_destination *normalized) {
    if (!destination || !normalized || !destination->port) return -1;
    *normalized = *destination;
    if (destination->family == AF_INET6 && ipv6_v4_mapped(destination->address)) {
        normalized->family = AF_INET;
        memset(normalized->address, 0, sizeof(normalized->address));
        memcpy(normalized->address, destination->address + 12, 4);
    }
    return normalized->family == AF_INET || normalized->family == AF_INET6 ? 0 : -1;
}

static int endpoint_matches(const tg_dc_endpoint *endpoint,
                            const tg_listener_destination *destination) {
    size_t bytes = destination->family == AF_INET ? 4 : 16;
    return endpoint->family == destination->family &&
           memcmp(endpoint->address, destination->address, bytes) == 0;
}

static int resolve_official(const tg_dc_snapshot *snapshot,
                            const tg_listener_destination *destination,
                            int media_hint, uint32_t dc_hint, int allow_cdn,
                            tg_dc_endpoint *out) {
    size_t address_count = 0, port_count = 0, media_count = 0, dc_count = 0;
    const tg_dc_endpoint *first = NULL, *selected = NULL;
    int all_cdn = 1;
    for (size_t i = 0; i < snapshot->endpoint_count; ++i) {
        const tg_dc_endpoint *endpoint = &snapshot->endpoints[i];
        if (!endpoint_matches(endpoint, destination)) continue;
        ++address_count;
        if (endpoint->this_port_only && endpoint->port != destination->port) continue;
        ++port_count;
        if (endpoint->media_only && !media_hint) continue;
        ++media_count;
        if (dc_hint && endpoint->id != dc_hint) continue;
        ++dc_count;
        if (!endpoint->cdn) all_cdn = 0;
        if (!first) first = endpoint;
        else if (endpoint->id != first->id ||
                 endpoint->media_only != first->media_only ||
                 endpoint->cdn != first->cdn)
            return TG_DC_LOOKUP_AMBIGUOUS;
        if (endpoint->this_port_only && endpoint->port == destination->port)
            selected = endpoint;
    }
    if (!address_count) return TG_DC_LOOKUP_NOT_LISTED;
    if (!port_count) return TG_DC_LOOKUP_PORT;
    if (!media_count) return TG_DC_LOOKUP_MEDIA;
    if (!dc_count) return TG_DC_LOOKUP_DC;
    if (!allow_cdn && all_cdn) return TG_DC_LOOKUP_CDN;
    *out = *(selected ? selected : first);
    return TG_DC_LOOKUP_OK;
}

static int resolve_builtin(const tg_listener_destination *destination,
                           int media_hint, uint32_t dc_hint,
                           tg_dc_endpoint *out) {
    for (size_t i = 0; i < sizeof(builtin_endpoints) / sizeof(builtin_endpoints[0]); ++i) {
        const builtin_endpoint *builtin = &builtin_endpoints[i];
        uint8_t address[16] = {0};
        if (inet_pton(destination->family, builtin->address, address) != 1 ||
            memcmp(address, destination->address,
                   destination->family == AF_INET ? 4 : 16) != 0)
            continue;
        if (builtin->media_only && !media_hint) return TG_DC_LOOKUP_MEDIA;
        if (dc_hint && dc_hint != builtin->id) return TG_DC_LOOKUP_DC;
        memset(out, 0, sizeof(*out));
        out->id = builtin->id;
        out->family = destination->family;
        memcpy(out->address, address, sizeof(out->address));
        out->port = destination->port;
        out->media_only = builtin->media_only;
        out->is_static = 1;
        return TG_DC_LOOKUP_OK;
    }
    return TG_DC_LOOKUP_NOT_LISTED;
}

int tg_dc_resolve(const tg_dc_snapshot *snapshot,
                  const tg_listener_destination *destination,
                  int media_hint, uint32_t dc_hint, int allow_cdn,
                  tg_dc_endpoint *out, tg_dc_map_source *source) {
    tg_listener_destination normalized;
    if (!out || !source || (media_hint != 0 && media_hint != 1) ||
        (allow_cdn != 0 && allow_cdn != 1) || dc_hint > 999 ||
        normalized_destination(destination, &normalized) != 0)
        return TG_DC_LOOKUP_INVALID;
    if (snapshot) {
        if (!snapshot->endpoints || snapshot->endpoint_count == 0 ||
            snapshot->endpoint_count > TG_DC_MAP_MAX_ENDPOINTS)
            return TG_DC_LOOKUP_INVALID;
        int rc = resolve_official(snapshot, &normalized, media_hint, dc_hint,
                                  allow_cdn, out);
        if (rc != TG_DC_LOOKUP_NOT_LISTED) {
            if (rc == TG_DC_LOOKUP_OK) *source = TG_DC_MAP_OFFICIAL;
            return rc;
        }
    }
    int rc = resolve_builtin(&normalized, media_hint, dc_hint, out);
    if (rc == TG_DC_LOOKUP_OK) *source = TG_DC_MAP_BUILTIN;
    return rc;
}

const char *tg_dc_lookup_result_text(int result) {
    switch (result) {
    case TG_DC_LOOKUP_OK: return "адрес DC подтверждён";
    case TG_DC_LOOKUP_NOT_LISTED: return "адрес отсутствует в проверенной карте Telegram DC";
    case TG_DC_LOOKUP_PORT: return "адрес разрешён только на другом порту";
    case TG_DC_LOOKUP_MEDIA: return "признак media не совпадает с dcOption";
    case TG_DC_LOOKUP_DC: return "DC из рукопожатия не совпадает с dcOption";
    case TG_DC_LOOKUP_CDN: return "CDN-адрес разрешён только для прямого TCP";
    case TG_DC_LOOKUP_AMBIGUOUS: return "для адреса найдены несовместимые dcOption";
    default: return "неверные данные карты Telegram DC";
    }
}
