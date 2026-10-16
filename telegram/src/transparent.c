#define _POSIX_C_SOURCE 200809L
#include "tg_transparent.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define TG_TRANSPARENT_MAX_PORTS 32u
#define TG_TRANSPARENT_MAX_CIDRS 64u
#define TG_TRANSPARENT_MAX_SECRETS 16u

static int prefix_matches(const uint8_t *address, const uint8_t *network,
                          unsigned prefix, unsigned bytes) {
    if (prefix > bytes * 8u) return 0;
    unsigned full_bytes = prefix / 8u;
    unsigned remainder = prefix % 8u;
    if (full_bytes && memcmp(address, network, full_bytes) != 0) return 0;
    if (!remainder) return 1;
    uint8_t mask = (uint8_t)(0xffu << (8u - remainder));
    return (address[full_bytes] & mask) == (network[full_bytes] & mask);
}

static int cidr_matches(const char *text,
                        const tg_listener_destination *destination) {
    char buffer[INET6_ADDRSTRLEN + 5];
    if (!text || !*text || strlen(text) >= sizeof(buffer)) return 0;
    strcpy(buffer, text);
    char *slash = strchr(buffer, '/');
    unsigned prefix;
    if (slash) {
        *slash++ = '\0';
        if (!*slash) return 0;
        char *end = NULL;
        errno = 0;
        unsigned long value = strtoul(slash, &end, 10);
        unsigned max_prefix = destination->family == AF_INET ? 32u : 128u;
        if (errno || !end || *end || value > max_prefix) return 0;
        prefix = (unsigned)value;
    } else {
        prefix = destination->family == AF_INET ? 32u : 128u;
    }
    uint8_t network[16] = {0};
    if (inet_pton(destination->family, buffer, network) != 1) return 0;
    return prefix_matches(destination->address, network, prefix,
                          destination->family == AF_INET ? 4u : 16u);
}

static int destination_allowed(const tg_transparent_policy *policy,
                               const tg_listener_destination *destination) {
    if (!policy || !destination || !destination->port || destination->port == 80 ||
        (destination->family != AF_INET && destination->family != AF_INET6) ||
        !policy->allowed_ports || !policy->allowed_port_count ||
        policy->allowed_port_count > TG_TRANSPARENT_MAX_PORTS ||
        !policy->allowed_cidrs || !policy->allowed_cidr_count ||
        policy->allowed_cidr_count > TG_TRANSPARENT_MAX_CIDRS ||
        tg_listener_is_self_dial_addr(destination, NULL, 0))
        return 0;
    int port_allowed = 0, cidr_allowed = 0;
    for (size_t i = 0; i < policy->allowed_port_count; ++i)
        if (policy->allowed_ports[i] == destination->port) port_allowed = 1;
    for (size_t i = 0; i < policy->allowed_cidr_count; ++i)
        if (cidr_matches(policy->allowed_cidrs[i], destination)) cidr_allowed = 1;
    return port_allowed && cidr_allowed;
}

static int parse_client_handshake(const tg_transparent_policy *policy,
                                  const tg_listener_destination *destination,
                                  const uint8_t *handshake,
                                  tg_mtproto_init *parsed) {
    if (tg_mtproto_parse_obfuscated2(handshake, parsed) == 0) return 0;
    const tg_dc_snapshot *snapshot = tg_dc_map_store_current(policy->map_store);
    tg_dc_secret secrets[TG_TRANSPARENT_MAX_SECRETS];
    size_t count = tg_dc_handshake_secrets(snapshot, destination,
                                           (int64_t)time(NULL), secrets,
                                           TG_TRANSPARENT_MAX_SECRETS);
    if (count > TG_TRANSPARENT_MAX_SECRETS) return -1;
    int found = 0;
    tg_mtproto_init selected;
    for (size_t i = 0; i < count; ++i) {
        tg_mtproto_init candidate;
        if (tg_mtproto_parse_secret(handshake, secrets[i].bytes,
                                    secrets[i].len, &candidate) != 0)
            continue;
        if (found && (selected.dc_id != candidate.dc_id ||
                      selected.is_media != candidate.is_media ||
                      selected.proto != candidate.proto))
            return -1;
        selected = candidate;
        found = 1;
    }
    if (!found) return -1;
    *parsed = selected;
    return 0;
}

int tg_transparent_select_target(
    void *opaque, const tg_listener_destination *original,
    const uint8_t handshake[TG_MTPROTO_HANDSHAKE_LEN],
    tg_listener_destination *upstream) {
    const tg_transparent_policy *policy = opaque;
    if (!policy || !handshake || !upstream ||
        !destination_allowed(policy, original))
        return -1;
    tg_mtproto_init parsed;
    if (parse_client_handshake(policy, original, handshake, &parsed) != 0)
        return -1;
    int64_t now = (int64_t)time(NULL);
    tg_dc_endpoint endpoint;
    tg_dc_map_source source;
    int result = tg_dc_map_store_resolve(policy->map_store, now, original,
                                         parsed.is_media, parsed.dc_id, 1,
                                         &endpoint, &source);
    if (result != TG_DC_LOOKUP_OK &&
        !(result == TG_DC_LOOKUP_NOT_LISTED && parsed.dc_id == 0))
        return -1;
    *upstream = *original;
    return 0;
}
