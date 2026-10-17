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

static int snapshot_has_route(const tg_dc_snapshot *snapshot, uint32_t dc,
                              const char *ip, int media_only) {
    uint8_t address[16] = {0};
    if (!snapshot || inet_pton(AF_INET, ip, address) != 1) return 0;
    for (size_t i = 0; i < snapshot->endpoint_count; ++i) {
        const tg_dc_endpoint *endpoint = &snapshot->endpoints[i];
        if (endpoint->id == dc && endpoint->family == AF_INET &&
            endpoint->media_only == media_only &&
            memcmp(endpoint->address, address, 4) == 0)
            return 1;
    }
    return 0;
}

static void assert_media_catalogue(const tg_dc_map_store *store, int64_t now) {
    static const struct {
        uint32_t dc;
        const char *ip;
    } media[] = {
        {1, "149.154.175.52"},
        {2, "149.154.167.151"}, {2, "149.154.167.222"},
        {2, "149.154.167.223"}, {2, "149.154.162.123"},
        {3, "149.154.175.102"},
        {4, "149.154.167.43"}, {4, "149.154.164.250"},
        {4, "149.154.166.120"}, {4, "149.154.166.121"},
        {4, "149.154.167.118"}, {4, "149.154.165.111"},
        {5, "91.108.56.102"}, {5, "91.108.56.128"},
        {5, "91.108.56.151"}
    };
    const tg_dc_snapshot *snapshot = tg_dc_map_store_current(store);
    assert(snapshot != NULL);
    for (size_t i = 0; i < sizeof(media) / sizeof(media[0]); ++i) {
        tg_listener_destination destination = {.family = AF_INET, .port = 443};
        assert(inet_pton(AF_INET, media[i].ip, destination.address) == 1);
        assert(snapshot_has_route(snapshot, media[i].dc, media[i].ip, 1));
        tg_dc_endpoint route;
        tg_dc_map_source source;
        assert(tg_dc_map_store_resolve(store, now, &destination, 1,
                                       media[i].dc, 1, &route, &source) ==
               TG_DC_LOOKUP_OK);
        assert(source == TG_DC_MAP_OFFICIAL && route.id == media[i].dc &&
               route.media_only);
        assert(tg_dc_map_store_resolve(store, now, &destination, 0,
                                       media[i].dc, 1, &route, &source) ==
               TG_DC_LOOKUP_MEDIA);
    }
    tg_listener_destination unknown = {.family = AF_INET, .port = 443};
    assert(inet_pton(AF_INET, "149.154.167.250", unknown.address) == 1);
    tg_dc_endpoint route;
    tg_dc_map_source source;
    assert(tg_dc_map_store_resolve(store, now, &unknown, 1, 4, 1,
                                   &route, &source) == TG_DC_LOOKUP_NOT_LISTED);
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
    size_t installed_count = tg_dc_map_store_current(&store)->endpoint_count;
    assert(installed_count > 5);
    assert(snapshot_has_route(tg_dc_map_store_current(&store), 4,
                              "149.154.167.43", 1));
    assert(!tg_dc_map_store_refresh_due(&store, INT64_C(1800000000), 3600));
    assert(tg_dc_map_store_refresh_due(&store, INT64_C(1800003600), 3600));

    endpoints[5] = endpoints[1];
    endpoint(&endpoints[5], 2, "149.154.167.224", INT64_C(1800000001));
    first.endpoint_count = 6;
    first.fetched_at = INT64_C(1800000001);
    first.config_date = INT64_C(1800000001);
    first.config_expires = INT64_C(1800086401);
    first.endpoints = endpoints;
    assert(tg_dc_map_store_install(&store, &first, INT64_C(1800000001)) == 0);
    assert(tg_dc_map_store_current(&store)->endpoint_count == installed_count + 1);
    assert(!tg_dc_map_store_refresh_due(&store, INT64_C(1800000001), 3600));
    tg_dc_map_store_destroy(&store);

    FILE *file = fopen(path, "w");
    assert(file != NULL && fputs("{corrupt", file) >= 0 && fclose(file) == 0);
    tg_dc_map_store recovered = {0};
    assert(tg_dc_map_store_init(&recovered, path) == 0);
    assert(tg_dc_map_store_load(&recovered, INT64_C(1800000001)) == 0);
    const tg_dc_snapshot *snapshot = tg_dc_map_store_current(&recovered);
    assert(snapshot != NULL && snapshot->endpoint_count == installed_count);
    assert(snapshot_has_route(snapshot, 4, "149.154.167.43", 1));
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
    size_t installed_count = tg_dc_map_store_current(&store)->endpoint_count;
    snapshot.endpoint_count = 4;
    snapshot.config_date = INT64_C(1800000001);
    snapshot.fetched_at = INT64_C(1800000001);
    assert(tg_dc_map_store_install(&store, &snapshot, INT64_C(1800000001)) != 0);
    assert(tg_dc_map_store_current(&store)->endpoint_count == installed_count);
    assert(tg_dc_map_store_current(&store)->config_date == INT64_C(1800000000));
    tg_dc_map_store_destroy(&store);
    remove_paths(path);
}

static void test_refresh_keeps_complete_media_route_catalogue(void) {
    const int64_t now = INT64_C(1800000000);
    char dir[] = "/tmp/d2k-dc-media-XXXXXX";
    char path[TG_DC_MAP_PATH_MAX];
    make_paths(dir, path);
    tg_dc_map_store store = {0};
    tg_dc_endpoint endpoints[6];
    tg_dc_snapshot snapshot = complete_snapshot(endpoints, now);
    assert(tg_dc_map_store_init(&store, path) == 0);
    assert(tg_dc_map_store_install(&store, &snapshot, now) == 0);
    assert_media_catalogue(&store, now);

    /* help.getConfig не перечисляет алиасы: обновление сохраняет проверенный
     * каталог media-маршрутов вместо удаления записей из карты. */
    snapshot.fetched_at = now + 1;
    snapshot.config_date = now + 1;
    snapshot.config_expires = now + 86401;
    for (size_t i = 0; i < snapshot.endpoint_count; ++i)
        endpoints[i].last_seen = now + 1;
    assert(tg_dc_map_store_install(&store, &snapshot, now + 1) == 0);
    assert_media_catalogue(&store, now + 1);
    tg_dc_map_store_destroy(&store);
    remove_paths(path);
}

static void test_load_migrates_old_cache_with_builtin_media_routes(void) {
    const int64_t now = INT64_C(1800000000);
    char dir[] = "/tmp/d2k-dc-load-media-XXXXXX";
    char path[TG_DC_MAP_PATH_MAX];
    make_paths(dir, path);
    tg_dc_endpoint endpoints[6];
    tg_dc_snapshot old_snapshot = complete_snapshot(endpoints, now);
    uint8_t *json = NULL;
    size_t json_len = 0;
    assert(tg_dc_snapshot_encode_json(&old_snapshot, now, &json,
                                      &json_len) == 0);
    FILE *file = fopen(path, "wb");
    assert(file != NULL);
    assert(fwrite(json, 1, json_len, file) == json_len);
    assert(fclose(file) == 0);
    free(json);

    tg_dc_map_store store = {0};
    assert(tg_dc_map_store_init(&store, path) == 0);
    assert(tg_dc_map_store_load(&store, now) == 0);
    assert_media_catalogue(&store, now);

    file = fopen(path, "rb");
    assert(file != NULL);
    char persisted[65536];
    size_t persisted_len = fread(persisted, 1, sizeof(persisted) - 1, file);
    assert(!ferror(file) && fclose(file) == 0);
    persisted[persisted_len] = '\0';
    assert(strstr(persisted, "\"address\":\"149.154.167.43\"") != NULL);
    tg_dc_map_store_destroy(&store);
    remove_paths(path);
}

static void test_official_dc_option_overrides_builtin_alias_conflict(void) {
    const int64_t now = INT64_C(1800000000);
    char dir[] = "/tmp/d2k-dc-alias-conflict-XXXXXX";
    char path[TG_DC_MAP_PATH_MAX];
    make_paths(dir, path);
    tg_dc_map_store store = {0};
    tg_dc_endpoint endpoints[6];
    tg_dc_snapshot snapshot = complete_snapshot(endpoints, now);
    endpoint(&endpoints[5], 4, "149.154.167.43", now);
    snapshot.endpoint_count = 6;
    assert(tg_dc_map_store_init(&store, path) == 0);
    assert(tg_dc_map_store_install(&store, &snapshot, now) == 0);
    assert(snapshot_has_route(tg_dc_map_store_current(&store), 4,
                              "149.154.167.43", 0));
    assert(!snapshot_has_route(tg_dc_map_store_current(&store), 4,
                               "149.154.167.43", 1));
    tg_listener_destination destination = {.family = AF_INET, .port = 443};
    assert(inet_pton(AF_INET, "149.154.167.43", destination.address) == 1);
    tg_dc_endpoint route;
    tg_dc_map_source source;
    assert(tg_dc_map_store_resolve(&store, now, &destination, 1, 4, 1,
                                   &route, &source) == TG_DC_LOOKUP_OK);
    assert(source == TG_DC_MAP_OFFICIAL && route.id == 4 &&
           !route.media_only);
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
    test_refresh_keeps_complete_media_route_catalogue();
    test_load_migrates_old_cache_with_builtin_media_routes();
    test_official_dc_option_overrides_builtin_alias_conflict();
    test_store_resolve_uses_fresh_exact_map_and_scoped_secrets();
    test_endpoint_manifest_uses_only_allowed_exact_pairs();
    puts("Тесты хранилища карты Telegram DC: ок");
    return 0;
}
