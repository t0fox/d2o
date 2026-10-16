#include "tg_dc_map.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char valid_json[] =
    "{\"schema_version\":1,\"fetched_at\":1800000000,"
    "\"config_date\":1799999900,\"config_expires\":1800086400,"
    "\"this_dc\":2,\"endpoints\":["
    "{\"id\":1,\"address\":\"149.154.175.50\",\"port\":443,\"ipv6\":false,\"media_only\":false,\"tcpo_only\":true,\"cdn\":false,\"is_static\":true,\"this_port_only\":false,\"secret\":\"aabbccdd\",\"last_seen\":1800000000},"
    "{\"id\":2,\"address\":\"149.154.167.51\",\"port\":443,\"ipv6\":false,\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":true,\"this_port_only\":false,\"secret\":null,\"last_seen\":1800000000},"
    "{\"id\":3,\"address\":\"149.154.175.100\",\"port\":443,\"ipv6\":false,\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":false,\"this_port_only\":false,\"secret\":null,\"last_seen\":1800000000},"
    "{\"id\":4,\"address\":\"149.154.167.91\",\"port\":443,\"ipv6\":false,\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":false,\"this_port_only\":false,\"secret\":null,\"last_seen\":1800000000},"
    "{\"id\":5,\"address\":\"149.154.171.5\",\"port\":443,\"ipv6\":false,\"media_only\":false,\"tcpo_only\":false,\"cdn\":false,\"is_static\":false,\"this_port_only\":false,\"secret\":null,\"last_seen\":1800000000}]}";

static void test_bounded_json_parser_reads_official_snapshot_shape(void) {
    tg_dc_snapshot snapshot = {0};
    assert(tg_dc_snapshot_parse_json((const uint8_t *)valid_json,
                                     sizeof(valid_json) - 1,
                                     INT64_C(1800000000), &snapshot) == 0);
    assert(snapshot.schema_version == TG_DC_MAP_SCHEMA_VERSION);
    assert(snapshot.this_dc == 2 && snapshot.endpoint_count == 5);
    assert(snapshot.endpoints[0].id == 1 && snapshot.endpoints[0].secret_len == 4);
    assert(snapshot.endpoints[0].secret[0] == 0xaa &&
           snapshot.endpoints[0].secret[3] == 0xdd);
    assert(snapshot.endpoints[1].id == 2 && snapshot.endpoints[1].secret_len == 0);
    tg_dc_snapshot_destroy(&snapshot);
    assert(snapshot.endpoints == NULL && snapshot.endpoint_count == 0);
}

static void test_parser_rejects_unknown_duplicate_and_malformed_fields(void) {
    static const char duplicate[] = "{\"schema_version\":1,\"schema_version\":1}";
    static const char unknown[] = "{\"unexpected\":true}";
    static const char bad_address[] =
        "{\"schema_version\":1,\"fetched_at\":1800000000,"
        "\"config_date\":1799999900,\"config_expires\":1800086400,"
        "\"this_dc\":2,\"endpoints\":[{\"id\":1,\"address\":\"bad\"}]}";
    tg_dc_snapshot snapshot = {0};
    assert(tg_dc_snapshot_parse_json((const uint8_t *)duplicate,
                                     sizeof(duplicate) - 1, 1800000000, &snapshot) != 0);
    assert(tg_dc_snapshot_parse_json((const uint8_t *)unknown,
                                     sizeof(unknown) - 1, 1800000000, &snapshot) != 0);
    assert(tg_dc_snapshot_parse_json((const uint8_t *)bad_address,
                                     sizeof(bad_address) - 1, 1800000000, &snapshot) != 0);
}

static void test_parser_rejects_cache_over_one_mib(void) {
    size_t len = 1024u * 1024u + 1u;
    uint8_t *json = malloc(len);
    tg_dc_snapshot snapshot = {0};
    assert(json != NULL);
    memcpy(json, valid_json, sizeof(valid_json) - 1);
    memset(json + sizeof(valid_json) - 1, ' ', len - (sizeof(valid_json) - 1));
    assert(tg_dc_snapshot_parse_json(json, len, 1800000000, &snapshot) != 0);
    free(json);
}

static void test_parser_rejects_future_time_without_signed_overflow(void) {
    tg_dc_snapshot snapshot = {0};
    assert(tg_dc_snapshot_parse_json((const uint8_t *)valid_json,
                                     sizeof(valid_json) - 1,
                                     INT64_MIN, &snapshot) != 0);
}

static void test_encoder_writes_parser_compatible_bounded_snapshot(void) {
    tg_dc_snapshot parsed = {0}, decoded = {0};
    uint8_t *json = NULL;
    size_t len = 0;
    assert(tg_dc_snapshot_parse_json((const uint8_t *)valid_json,
                                     sizeof(valid_json) - 1,
                                     INT64_C(1800000000), &parsed) == 0);
    assert(tg_dc_snapshot_encode_json(&parsed, INT64_C(1800000000),
                                      &json, &len) == 0);
    assert(json != NULL && len <= 1024u * 1024u && json[len] == 0);
    assert(strstr((const char *)json, "\"schema_version\":1") != NULL);
    assert(strstr((const char *)json, "\"address\":\"149.154.175.50\"") != NULL);
    assert(strstr((const char *)json, "\"secret\":\"aabbccdd\"") != NULL);
    assert(strstr((const char *)json, "\"secret\":null") != NULL);
    assert(tg_dc_snapshot_parse_json(json, len, INT64_C(1800000000), &decoded) == 0);
    assert(decoded.endpoint_count == parsed.endpoint_count);
    assert(decoded.endpoints[0].secret_len == parsed.endpoints[0].secret_len);
    free(json);
    tg_dc_snapshot_destroy(&parsed);
    tg_dc_snapshot_destroy(&decoded);
}

int main(void) {
    test_bounded_json_parser_reads_official_snapshot_shape();
    test_parser_rejects_unknown_duplicate_and_malformed_fields();
    test_parser_rejects_cache_over_one_mib();
    test_parser_rejects_future_time_without_signed_overflow();
    test_encoder_writes_parser_compatible_bounded_snapshot();
    puts("Тесты JSON карты Telegram DC: ок");
    return 0;
}
