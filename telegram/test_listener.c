#include "tg_listener.h"

#include <assert.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>

static void test_original_destination_decodes_ipv4_and_ipv6(void) {
    struct sockaddr_in v4 = {0};
    tg_listener_destination out;
    v4.sin_family = AF_INET;
    v4.sin_port = htons(443);
    assert(inet_pton(AF_INET, "149.154.167.51", &v4.sin_addr) == 1);
    assert(tg_listener_decode_original_dst_any((const uint8_t *)&v4,
                                               sizeof(v4), &out) == 0);
    assert(out.family == AF_INET && out.port == 443);
    assert(memcmp(out.address, &v4.sin_addr, 4) == 0);

    struct sockaddr_in6 v6 = {0};
    v6.sin6_family = AF_INET6;
    v6.sin6_port = htons(1443);
    assert(inet_pton(AF_INET6, "2001:db8::1234", &v6.sin6_addr) == 1);
    assert(tg_listener_decode_original_dst_any((const uint8_t *)&v6,
                                               sizeof(v6), &out) == 0);
    assert(out.family == AF_INET6 && out.port == 1443);
    assert(memcmp(out.address, &v6.sin6_addr, 16) == 0);
}

static void test_original_destination_rejects_truncated_or_invalid_socket_address(void) {
    struct sockaddr_in v4 = {0};
    tg_listener_destination out;
    v4.sin_family = AF_INET;
    v4.sin_port = htons(443);
    assert(tg_listener_decode_original_dst_any((const uint8_t *)&v4,
                                               sizeof(v4) - 1, &out) != 0);
    v4.sin_port = 0;
    assert(tg_listener_decode_original_dst_any((const uint8_t *)&v4,
                                               sizeof(v4), &out) != 0);
    v4.sin_family = AF_UNIX;
    v4.sin_port = htons(443);
    assert(tg_listener_decode_original_dst_any((const uint8_t *)&v4,
                                               sizeof(v4), &out) != 0);
}

static void test_private_and_listener_destinations_are_rejected(void) {
    tg_listener_destination dst = {.family = AF_INET, .port = 443};
    const uint16_t listeners[] = {1443, 1444};
    assert(inet_pton(AF_INET, "192.168.1.1", dst.address) == 1);
    assert(tg_listener_is_self_dial_addr(&dst, listeners, 2));
    assert(inet_pton(AF_INET, "149.154.167.51", dst.address) == 1);
    assert(!tg_listener_is_self_dial_addr(&dst, listeners, 2));
    assert(inet_pton(AF_INET, "192.2.0.1", dst.address) == 1);
    assert(!tg_listener_is_self_dial_addr(&dst, listeners, 2));
    assert(inet_pton(AF_INET, "198.51.99.1", dst.address) == 1);
    assert(!tg_listener_is_self_dial_addr(&dst, listeners, 2));
    dst.port = 1443;
    assert(tg_listener_is_self_dial_addr(&dst, listeners, 2));
    dst.port = 443;
    assert(tg_listener_is_self_dial_addr(NULL, listeners, 2));
}

static void test_ipv6_local_and_mapped_destinations_are_classified(void) {
    tg_listener_destination dst = {.family = AF_INET6, .port = 443};
    assert(inet_pton(AF_INET6, "fc00::1", dst.address) == 1);
    assert(tg_listener_is_self_dial_addr(&dst, NULL, 0));
    assert(inet_pton(AF_INET6, "fe80::1", dst.address) == 1);
    assert(tg_listener_is_self_dial_addr(&dst, NULL, 0));
    assert(inet_pton(AF_INET6, "::ffff:192.168.1.1", dst.address) == 1);
    assert(tg_listener_is_self_dial_addr(&dst, NULL, 0));
    assert(inet_pton(AF_INET6, "2001:4860:4860::8888", dst.address) == 1);
    assert(!tg_listener_is_self_dial_addr(&dst, NULL, 0));
}

int main(void) {
    test_original_destination_decodes_ipv4_and_ipv6();
    test_original_destination_rejects_truncated_or_invalid_socket_address();
    test_private_and_listener_destinations_are_rejected();
    test_ipv6_local_and_mapped_destinations_are_classified();
    puts("Тесты исходного назначения: ок");
    return 0;
}
