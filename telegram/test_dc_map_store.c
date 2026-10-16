#define _POSIX_C_SOURCE 200809L
#include "tg_dc_map.h"

#include <assert.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void endpoint(tg_dc_endpoint *out, uint32_t id, const char *ip,
                     int64_t last_seen) {
    memset(out, 0, sizeof(*out));
    out->id = id;
    out->family = strchr(ip, ':') ? AF_INET6 : AF_INET;
    assert(inet_pton(out->family, ip, out->address) == 1);
    out->port = 443;
    out->last_seen = last_seen;
}

static tg_dc_snapshot complete_snapshot(tg_dc_endpoint endpoints[6], int64_t now) {
    endpoint(&endpoints[0], 1, "149.154.175.50", now);
    endpoint(&endpoints[1], 2, "149.154.167.51", now);
    endpoint(&endpoints[2], 3, "149.154.175.100", now);
    endpoint(&endpoints[3], 4, "149.154.167.91", now);
    endpoint(&endpoints[4], 5, "149.154.171.5", now);
    return (tg_dc_snapshot){
        .schema_version = TG_DC_MAP_SCHEMA_VERSION,
        .fetched_at = now,
        .config_date = now,
        .config_expires = now + 86400,
        .this_dc = 2,
        .endpoints = endpoints,
        .endpoint_count = 5
    };
}

static void make_paths(char dir[], char path[TG_DC_MAP_PATH_MAX]) {
    char *created = mkdtemp(dir);
    assert(created != NULL);
    assert(snprintf(path, TG_DC_MAP_PATH_MAX, "%s/map.json", created) > 0);
}

static void remove_paths(const char *path) {
    char backup[TG_DC_MAP_PATH_MAX + 16];
    assert(snprintf(backup, sizeof(backup), "%s.last-good", path) > 0);
    unlink(path);
    unlink(backup);
    char *slash = strrchr((char *)path, '/');
    assert(slash != NULL);
    char dir[TG_DC_MAP_PATH_MAX];
    size_t len = (size_t)(slash - path);
    assert(len < sizeof(dir));
    memcpy(dir, path, len);
    dir[len] = '\0';
    assert(rmdir(dir) == 0);
}

static void test_store_install_merge_and_last_known_good_recovery(void) {
    char dir[] = "/tmp/d2k-dc-map-XXXXXX";
    char path[TG_DC_MAP_PATH_MAX];
    make_paths(dir, path);
    tg_dc_map_store store = {0};
    assert(tg_dc_map_store_init(&store, path) == 0);
    assert(tg_dc_map_store_load(&store, INT64_C(1800000000)) == 0);
    assert(tg_dc_map_store_current(&store) == NULL);

    tg_dc_endpoint endpoints[6];
    tg_dc_snapshot first = complete_snapshot(endpoints, INT64_C(1800000000));
    assert(tg_dc_map_store_install(&store, &first, INT64_C(1800000000)) == 0);
    assert(tg_dc_map_store_current(&store)->endpoint_count == 5);
    assert(!tg_dc_map_store_refresh_due(&store, INT64_C(1800000000), 3600));
    assert(tg_dc_map_store_refresh_due(&store, INT64_C(1800003600), 3600));

    endpoints[5] = endpoints[1];
    endpoint(&endpoints[5], 2, "149.154.167.220", INT64_C(1800000001));
    first.endpoint_count = 6;
    first.fetched_at = INT64_C(1800000001);
    first.config_date = INT64_C(1800000001);
    first.config_expires = INT64_C(1800086401);
    first.endpoints = endpoints;
    assert(tg_dc_map_store_install(&store, &first, INT64_C(1800000001)) == 0);
    assert(tg_dc_map_store_current(&store)->endpoint_count == 6);
    assert(!tg_dc_map_store_refresh_due(&store, INT64_C(1800000001), 3600));
    tg_dc_map_store_destroy(&store);

    FILE *file = fopen(path, "w");
    assert(file != NULL && fputs("{corrupt", file) >= 0 && fclose(file) == 0);
    tg_dc_map_store recovered = {0};
    assert(tg_dc_map_store_init(&recovered, path) == 0);
    assert(tg_dc_map_store_load(&recovered, INT64_C(1800000001)) == 0);
    const tg_dc_snapshot *snapshot = tg_dc_map_store_current(&recovered);
    assert(snapshot != NULL && snapshot->endpoint_count == 5);
    assert(snapshot->config_date == INT64_C(1800000000));
    tg_dc_map_store_destroy(&recovered);
    remove_paths(path);
}

static void test_rejected_update_does_not_replace_active_snapshot(void) {
    char dir[] = "/tmp/d2k-dc-map-XXXXXX";
    char path[TG_DC_MAP_PATH_MAX];
    make_paths(dir, path);
    tg_dc_map_store store = {0};
    tg_dc_endpoint endpoints[6];
    tg_dc_snapshot snapshot = complete_snapshot(endpoints, INT64_C(1800000000));
    assert(tg_dc_map_store_init(&store, path) == 0);
    assert(tg_dc_map_store_install(&store, &snapshot, INT64_C(1800000000)) == 0);
    snapshot.endpoint_count = 4;
    snapshot.config_date = INT64_C(1800000001);
    snapshot.fetched_at = INT64_C(1800000001);
    assert(tg_dc_map_store_install(&store, &snapshot, INT64_C(1800000001)) != 0);
    assert(tg_dc_map_store_current(&store)->endpoint_count == 5);
    assert(tg_dc_map_store_current(&store)->config_date == INT64_C(1800000000));
    tg_dc_map_store_destroy(&store);
    remove_paths(path);
}

static void test_store_resolve_uses_fresh_exact_map_and_scoped_secrets(void) {
    const int64_t now = INT64_C(1800000000);
    tg_dc_endpoint endpoints[6];
    tg_dc_snapshot snapshot = complete_snapshot(endpoints, now);
    endpoint(&endpoints[5], 2, "95.161.76.101", now);
    endpoints[5].tcpo_only = 1;
    endpoints[5].this_port_only = 1;
    endpoints[5].port = 5222;
    endpoints[5].secret[0] = 0xaa;
    endpoints[5].secret[1] = 0xbb;
    endpoints[5].secret_len = 2;
    snapshot.endpoint_count = 6;
    tg_dc_map_store store = {.snapshot = snapshot, .has_snapshot = 1};
    tg_listener_destination dst = {.family = AF_INET, .port = 5222};
    assert(inet_pton(AF_INET, "95.161.76.101", dst.address) == 1);
    tg_dc_endpoint route;
    tg_dc_map_source source;
    assert(tg_dc_map_store_resolve(&store, now, &dst, 0, 2, 0,
                                   &route, &source) == TG_DC_LOOKUP_OK);
    assert(source == TG_DC_MAP_OFFICIAL && route.tcpo_only);
    tg_dc_secret secrets[2];
    assert(tg_dc_handshake_secrets(&snapshot, &dst, now, secrets, 2) == 1);
    assert(secrets[0].len == 2 && secrets[0].bytes[0] == 0xaa &&
           secrets[0].bytes[1] == 0xbb);
    dst.port = 443;
    assert(tg_dc_handshake_secrets(&snapshot, &dst, now, secrets, 2) == 0);
    assert(tg_dc_map_store_resolve(&store,
                                   now + INT64_C(90) * 24 * 60 * 60 + 1,
                                   &dst, 0, 0, 0, &route, &source) ==
           TG_DC_LOOKUP_NOT_LISTED);
}

static void test_endpoint_manifest_uses_only_allowed_exact_pairs(void) {
    char dir[] = "/tmp/d2k-dc-map-XXXXXX";
    char cache_path[TG_DC_MAP_PATH_MAX], manifest[TG_DC_MAP_PATH_MAX];
    make_paths(dir, cache_path);
    char *slash = strrchr(cache_path, '/');
    assert(slash != NULL);
    size_t dir_len = (size_t)(slash - cache_path);
    assert(snprintf(manifest, sizeof(manifest), "%.*s/endpoints.tsv",
                    (int)dir_len, cache_path) > 0);
    tg_dc_endpoint endpoints[6];
    tg_dc_snapshot snapshot = complete_snapshot(endpoints, INT64_C(1800000000));
    endpoints[5] = endpoints[1];
    endpoints[5].this_port_only = 1;
    endpoints[5].port = 5222;
    snapshot.endpoint_count = 6;
    const uint16_t ports[] = {443, 5222, 80};
    assert(tg_dc_write_endpoint_manifest(manifest, &snapshot, ports, 3,
                                         INT64_C(1800000000)) == 0);
    FILE *file = fopen(manifest, "r");
    assert(file != NULL);
    char contents[2048];
    size_t len = fread(contents, 1, sizeof(contents) - 1, file);
    assert(fclose(file) == 0);
    contents[len] = '\0';
    assert(strstr(contents, "z2k-tg-dc-options-v1 1800000000 1800000000\n") == contents);
    assert(strstr(contents, "149.154.167.51 443\n") != NULL);
    assert(strstr(contents, "149.154.167.51 5222\n") != NULL);
    assert(strstr(contents, " 80\n") == NULL);
    unlink(manifest);
    remove_paths(cache_path);
}

int main(void) {
    test_store_install_merge_and_last_known_good_recovery();
    test_rejected_update_does_not_replace_active_snapshot();
    test_store_resolve_uses_fresh_exact_map_and_scoped_secrets();
    test_endpoint_manifest_uses_only_allowed_exact_pairs();
    puts("Тесты хранилища карты Telegram DC: ок");
    return 0;
}
