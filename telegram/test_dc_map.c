#include "tg_dc_map.h"
#include "tg_listener.h"

#include <assert.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

static void endpoint(tg_dc_endpoint *out, uint32_t id, const char *ip) {
    memset(out, 0, sizeof(*out));
    out->id = id;
    out->family = strchr(ip, ':') ? AF_INET6 : AF_INET;
    assert(inet_pton(out->family, ip, out->address) == 1);
    out->port = 443;
    out->last_seen = INT64_C(1800000000);
}

static tg_dc_snapshot complete_snapshot(tg_dc_endpoint endpoints[5]) {
    endpoint(&endpoints[0], 1, "149.154.175.50");
    endpoint(&endpoints[1], 2, "149.154.167.51");
    endpoint(&endpoints[2], 3, "149.154.175.100");
    endpoint(&endpoints[3], 4, "149.154.167.91");
    endpoint(&endpoints[4], 5, "149.154.171.5");
    return (tg_dc_snapshot){
        .schema_version = TG_DC_MAP_SCHEMA_VERSION,
        .fetched_at = INT64_C(1800000000),
        .config_date = INT64_C(1799999900),
        .config_expires = INT64_C(1800086400),
        .this_dc = 2,
        .endpoints = endpoints,
        .endpoint_count = 5
    };
}

static tg_listener_destination destination(const char *ip, uint16_t port) {
    tg_listener_destination out = {.port = port};
    out.family = strchr(ip, ':') ? AF_INET6 : AF_INET;
    assert(inet_pton(out.family, ip, out.address) == 1);
    return out;
}

static void test_builtin_map_accepts_only_exact_known_dc_addresses(void) {
    tg_listener_destination dst = destination("149.154.167.51", 443);
    tg_dc_endpoint route;
    tg_dc_map_source source;
    assert(tg_dc_resolve(NULL, &dst, 0, 2, 0, &route, &source) == TG_DC_LOOKUP_OK);
    assert(route.id == 2 && !route.media_only && source == TG_DC_MAP_BUILTIN);
    assert(tg_dc_resolve(NULL, &dst, 0, 3, 0, &route, &source) == TG_DC_LOOKUP_DC);
    dst = destination("149.154.167.99", 443);
    assert(tg_dc_resolve(NULL, &dst, 0, 0, 0, &route, &source) == TG_DC_LOOKUP_NOT_LISTED);
}

static void test_builtin_map_accepts_known_ipv6_dc_addresses(void) {
    static const struct {
        uint32_t dc;
        const char *address;
    } routes[] = {
        {1, "2001:b28:f23d:f001::a"},
        {2, "2001:67c:4e8:f002::a"},
        {3, "2001:b28:f23d:f003::a"},
        {4, "2001:67c:4e8:f004::a"},
        {5, "2001:b28:f23f:f005::a"}
    };
    tg_dc_endpoint route;
    tg_dc_map_source source;
    for (size_t i = 0; i < sizeof(routes) / sizeof(routes[0]); ++i) {
        tg_listener_destination dst = destination(routes[i].address, 443);
        assert(tg_dc_resolve(NULL, &dst, 0, routes[i].dc, 0,
                             &route, &source) == TG_DC_LOOKUP_OK);
        assert(route.id == routes[i].dc && route.family == AF_INET6 &&
               source == TG_DC_MAP_BUILTIN);
    }
    tg_listener_destination unknown = destination("2001:db8::9", 443);
    assert(tg_dc_resolve(NULL, &unknown, 0, 0, 0, &route, &source) ==
           TG_DC_LOOKUP_NOT_LISTED);
}

static void test_official_map_enforces_media_dc_and_cdn_flags(void) {
    tg_dc_endpoint endpoints[8];
    tg_dc_snapshot snapshot = complete_snapshot(endpoints);
    endpoint(&endpoints[5], 2, "149.154.167.151");
    endpoints[5].media_only = 1;
    endpoint(&endpoints[6], 2, "149.154.167.152");
    endpoints[6].cdn = 1;
    endpoint(&endpoints[7], 3, "149.154.167.153");
    endpoints[7].this_port_only = 1;
    endpoints[7].port = 5222;
    snapshot.endpoint_count = 8;
    tg_dc_endpoint route;
    tg_dc_map_source source;

    tg_listener_destination dst = destination("149.154.167.151", 443);
    assert(tg_dc_resolve(&snapshot, &dst, 0, 0, 0, &route, &source) == TG_DC_LOOKUP_MEDIA);
    assert(tg_dc_resolve(&snapshot, &dst, 1, 2, 0, &route, &source) == TG_DC_LOOKUP_OK);
    assert(route.media_only && source == TG_DC_MAP_OFFICIAL);
    assert(tg_dc_resolve(&snapshot, &dst, 1, 3, 0, &route, &source) == TG_DC_LOOKUP_DC);

    dst = destination("149.154.167.152", 443);
    assert(tg_dc_resolve(&snapshot, &dst, 0, 2, 0, &route, &source) == TG_DC_LOOKUP_CDN);
    assert(tg_dc_resolve(&snapshot, &dst, 0, 2, 1, &route, &source) == TG_DC_LOOKUP_OK);
    assert(route.cdn);

    dst = destination("149.154.167.153", 443);
    assert(tg_dc_resolve(&snapshot, &dst, 0, 3, 0, &route, &source) == TG_DC_LOOKUP_PORT);
    dst.port = 5222;
    assert(tg_dc_resolve(&snapshot, &dst, 0, 3, 0, &route, &source) == TG_DC_LOOKUP_OK);
}

static void test_snapshot_validation_requires_complete_safe_primary_map(void) {
    tg_dc_endpoint endpoints[5];
    tg_dc_snapshot snapshot = complete_snapshot(endpoints);
    assert(tg_dc_snapshot_validate(&snapshot, INT64_C(1800000000)) == 0);
    snapshot.endpoint_count = 4;
    assert(tg_dc_snapshot_validate(&snapshot, INT64_C(1800000000)) != 0);
    snapshot = complete_snapshot(endpoints);
    assert(inet_pton(AF_INET, "192.168.1.2", endpoints[1].address) == 1);
    assert(tg_dc_snapshot_validate(&snapshot, INT64_C(1800000000)) != 0);
}

int main(void) {
    test_builtin_map_accepts_only_exact_known_dc_addresses();
    test_builtin_map_accepts_known_ipv6_dc_addresses();
    test_official_map_enforces_media_dc_and_cdn_flags();
    test_snapshot_validation_requires_complete_safe_primary_map();
    puts("Тесты карты Telegram DC: ок");
    return 0;
}
