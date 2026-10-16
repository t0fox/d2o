#include "tg_transparent.h"

#include <assert.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static size_t unhex(const char *text, uint8_t *out, size_t cap) {
    size_t n = strlen(text);
    assert((n & 1u) == 0 && n / 2 <= cap);
    for (size_t i = 0; i < n / 2; ++i) {
        unsigned value = 0;
        assert(sscanf(text + 2 * i, "%2x", &value) == 1);
        out[i] = (uint8_t)value;
    }
    return n / 2;
}

static void destination(tg_listener_destination *out, const char *ip,
                        uint16_t port) {
    memset(out, 0, sizeof(*out));
    out->family = AF_INET;
    out->port = port;
    assert(inet_pton(AF_INET, ip, out->address) == 1);
}

static void make_no_dc_handshake(uint8_t handshake[TG_MTPROTO_HANDSHAKE_LEN]) {
    tg_mtproto_ctr ctr = {0};
    uint8_t key[32], iv[16];
    memcpy(key, handshake + 8, sizeof(key));
    memcpy(iv, handshake + 40, sizeof(iv));
    assert(tg_mtproto_ctr_init(&ctr, key, iv) == 0);
    assert(tg_mtproto_ctr_xor(&ctr, handshake, TG_MTPROTO_HANDSHAKE_LEN) == 0);
    tg_mtproto_ctr_destroy(&ctr);
    handshake[60] = 0;
    handshake[61] = 0;
    assert(tg_mtproto_ctr_init(&ctr, key, iv) == 0);
    assert(tg_mtproto_ctr_xor(&ctr, handshake, TG_MTPROTO_HANDSHAKE_LEN) == 0);
    tg_mtproto_ctr_destroy(&ctr);
}

static void test_known_dc_is_validated_and_target_is_preserved(void) {
    uint8_t handshake[TG_MTPROTO_HANDSHAKE_LEN];
    assert(unhex("0001020304050607000102030405060708090a0b0c0d0e0f"
                 "101112131415161718191a1b1c1d1e1f0001020304050607"
                 "08090a0b0c0d0e0f87aeb3fe059b4807",
                 handshake, sizeof(handshake)) == sizeof(handshake));
    const uint16_t ports[] = {443, 5222};
    const char *cidrs[] = {"149.154.0.0/16"};
    tg_transparent_policy policy = {
        .allowed_ports = ports,
        .allowed_port_count = 2,
        .allowed_cidrs = cidrs,
        .allowed_cidr_count = 1,
    };
    tg_listener_destination original, upstream;
    destination(&original, "149.154.167.91", 443);
    assert(tg_transparent_select_target(&policy, &original, handshake,
                                        &upstream) == 0);
    assert(upstream.family == original.family && upstream.port == original.port);
    destination(&original, "149.154.167.91", 5222);
    assert(tg_transparent_select_target(&policy, &original, handshake,
                                        &upstream) == 0);
    assert(upstream.family == original.family && upstream.port == original.port);
    assert(memcmp(upstream.address, original.address, 4) == 0);
}

static void test_policy_rejects_wrong_port_cidr_and_unlisted_dc(void) {
    uint8_t handshake[TG_MTPROTO_HANDSHAKE_LEN];
    assert(unhex("0001020304050607000102030405060708090a0b0c0d0e0f"
                 "101112131415161718191a1b1c1d1e1f0001020304050607"
                 "08090a0b0c0d0e0f87aeb3fe059b4807",
                 handshake, sizeof(handshake)) == sizeof(handshake));
    const uint16_t ports[] = {443};
    const char *cidrs[] = {"149.154.0.0/16"};
    tg_transparent_policy policy = {
        .allowed_ports = ports,
        .allowed_port_count = 1,
        .allowed_cidrs = cidrs,
        .allowed_cidr_count = 1,
    };
    tg_listener_destination original, upstream;
    destination(&original, "149.154.167.91", 80);
    assert(tg_transparent_select_target(&policy, &original, handshake,
                                        &upstream) != 0);
    destination(&original, "149.154.167.91", 5222);
    assert(tg_transparent_select_target(&policy, &original, handshake,
                                        &upstream) != 0);
    destination(&original, "8.8.8.8", 443);
    assert(tg_transparent_select_target(&policy, &original, handshake,
                                        &upstream) != 0);
    destination(&original, "149.154.167.250", 443);
    assert(tg_transparent_select_target(&policy, &original, handshake,
                                        &upstream) != 0);
}

static void test_unmapped_direct_route_preserves_exact_original_target(void) {
    uint8_t handshake[TG_MTPROTO_HANDSHAKE_LEN];
    assert(unhex("0001020304050607000102030405060708090a0b0c0d0e0f"
                 "101112131415161718191a1b1c1d1e1f0001020304050607"
                 "08090a0b0c0d0e0f87aeb3fe059b4807",
                 handshake, sizeof(handshake)) == sizeof(handshake));
    make_no_dc_handshake(handshake);
    tg_mtproto_init parsed;
    assert(tg_mtproto_parse_obfuscated2(handshake, &parsed) == 0);
    assert(parsed.dc_id == 0 && parsed.is_media == 0);
    const uint16_t ports[] = {443};
    const char *cidrs[] = {"149.154.0.0/16"};
    tg_transparent_policy policy = {
        .allowed_ports = ports,
        .allowed_port_count = 1,
        .allowed_cidrs = cidrs,
        .allowed_cidr_count = 1,
    };
    tg_listener_destination original, upstream;
    destination(&original, "149.154.167.250", 443);
    assert(tg_transparent_select_target(&policy, &original, handshake,
                                        &upstream) == 0);
    assert(memcmp(upstream.address, original.address, 4) == 0);
    assert(upstream.port == original.port);
}

static void test_exact_tcpo_secret_is_used_for_original_destination_only(void) {
    uint8_t handshake[TG_MTPROTO_HANDSHAKE_LEN], secret[16];
    assert(unhex("0001020304050607000102030405060708090a0b0c0d0e0f"
                 "101112131415161718191a1b1c1d1e1f0001020304050607"
                 "08090a0b0c0d0e0f7c380b6e418caed2",
                 handshake, sizeof(handshake)) == sizeof(handshake));
    assert(unhex("101112131415161718191a1b1c1d1e1f", secret,
                 sizeof(secret)) == sizeof(secret));
    int64_t now = (int64_t)time(NULL);
    tg_dc_endpoint endpoints[6] = {0};
    const char *addresses[] = {
        "149.154.175.50", "149.154.167.50", "149.154.175.100",
        "149.154.167.91", "91.108.56.100", "149.154.167.91"
    };
    for (size_t i = 0; i < 6; ++i) {
        endpoints[i].id = i == 5 ? 4u : (uint32_t)i + 1u;
        endpoints[i].family = AF_INET;
        endpoints[i].port = 443;
        endpoints[i].last_seen = now;
        assert(inet_pton(AF_INET, addresses[i], endpoints[i].address) == 1);
    }
    endpoints[5].tcpo_only = 1;
    endpoints[5].secret_len = sizeof(secret);
    memcpy(endpoints[5].secret, secret, sizeof(secret));
    tg_dc_map_store store = {
        .snapshot = {
            .schema_version = TG_DC_MAP_SCHEMA_VERSION,
            .fetched_at = now,
            .config_date = now - 1,
            .config_expires = now + 3600,
            .this_dc = 2,
            .endpoints = endpoints,
            .endpoint_count = 6,
        },
        .has_snapshot = 1,
    };
    const uint16_t ports[] = {443};
    const char *cidrs[] = {"149.154.0.0/16"};
    tg_transparent_policy policy = {
        .map_store = &store,
        .allowed_ports = ports,
        .allowed_port_count = 1,
        .allowed_cidrs = cidrs,
        .allowed_cidr_count = 1,
    };
    tg_listener_destination original, upstream;
    destination(&original, "149.154.167.91", 443);
    assert(tg_transparent_select_target(&policy, &original, handshake,
                                        &upstream) == 0);
    destination(&original, "149.154.167.92", 443);
    assert(tg_transparent_select_target(&policy, &original, handshake,
                                        &upstream) != 0);
}

int main(void) {
    test_known_dc_is_validated_and_target_is_preserved();
    test_policy_rejects_wrong_port_cidr_and_unlisted_dc();
    test_unmapped_direct_route_preserves_exact_original_target();
    test_exact_tcpo_secret_is_used_for_original_destination_only();
    puts("Тесты политики прозрачного Telegram-прокси: ок");
    return 0;
}
