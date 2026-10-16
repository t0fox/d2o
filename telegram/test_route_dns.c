#define _POSIX_C_SOURCE 200809L
#include "tg_route_dns.h"

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

typedef struct {
    pthread_mutex_t mutex;
    size_t calls;
    int fail;
    int private_only;
} resolver_fixture;

static int test_lookup(void *opaque, const char *domain,
                       tg_listener_destination addresses[TG_ROUTE_DNS_ADDRESS_MAX],
                       size_t *count) {
    resolver_fixture *fixture = opaque;
    assert(strcmp(domain, "edge.example") == 0 ||
           strcmp(domain, "private.example") == 0 ||
           strcmp(domain, "offline.example") == 0);
    pthread_mutex_lock(&fixture->mutex);
    ++fixture->calls;
    int fail = fixture->fail;
    int private_only = fixture->private_only;
    pthread_mutex_unlock(&fixture->mutex);
    *count = 0;
    if (fail) return -1;
    if (private_only) {
        addresses[0] = (tg_listener_destination){.family = AF_INET,
                                                 .port = 443,
                                                 .address = {10, 0, 0, 1}};
        *count = 1;
        return 0;
    }
    addresses[0] = (tg_listener_destination){.family = AF_INET,
                                             .port = 443,
                                             .address = {1, 1, 1, 1}};
    addresses[1] = (tg_listener_destination){.family = AF_INET,
                                             .port = 443,
                                             .address = {8, 8, 8, 8}};
    *count = 2;
    return 0;
}

static size_t calls(resolver_fixture *fixture) {
    pthread_mutex_lock(&fixture->mutex);
    size_t value = fixture->calls;
    pthread_mutex_unlock(&fixture->mutex);
    return value;
}

static int wait_resolved(tg_route_dns *cache, const char *domain,
                         tg_listener_destination *out) {
    for (unsigned attempt = 0; attempt < 200; ++attempt) {
        if (tg_route_dns_resolve(cache, domain, out) == 0) return 0;
        struct timespec delay = {.tv_nsec = 10000000L};
        (void)nanosleep(&delay, NULL);
    }
    return -1;
}

static void test_doh_dns_message_validation(void) {
    const uint8_t response[] = {
        0x12,0x34, 0x81,0x80, 0x00,0x01, 0x00,0x01, 0x00,0x00, 0x00,0x00,
        0x04,'e','d','g','e', 0x07,'e','x','a','m','p','l','e',0x00,
        0x00,0x01,0x00,0x01,
        0xc0,0x0c, 0x00,0x01, 0x00,0x01, 0x00,0x00,0x00,0x3c,
        0x00,0x04, 0x01,0x01,0x01,0x01
    };
    tg_listener_destination addresses[TG_ROUTE_DNS_ADDRESS_MAX] = {{0}};
    size_t count = 0;
    assert(tg_route_dns_parse_response(response, sizeof(response), 0x1234,
                                       addresses, &count) == 0);
    assert(count == 1 && addresses[0].family == AF_INET &&
           addresses[0].port == 443 &&
           memcmp(addresses[0].address, (uint8_t[]){1, 1, 1, 1}, 4) == 0);
    assert(tg_route_dns_parse_response(response, sizeof(response), 0x5678,
                                       addresses, &count) != 0);
    uint8_t error_response[sizeof(response)];
    memcpy(error_response, response, sizeof(response));
    error_response[3] = 3;
    assert(tg_route_dns_parse_response(error_response, sizeof(error_response),
                                       0x1234, addresses, &count) != 0);
    assert(tg_route_dns_parse_response(response, sizeof(response) - 1u, 0x1234,
                                       addresses, &count) != 0);
}

static void test_http_body_parser_accepts_bounded_chunked_response(void) {
    static const uint8_t response[] =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
        "Connection: close\r\n\r\n5\r\nhello\r\n6\r\n world\r\n"
        "0\r\n\r\n";
    uint8_t body[32] = {0};
    size_t body_len = 0;
    assert(tg_route_dns_parse_http_response(response, sizeof(response) - 1u,
                                            body, sizeof(body), &body_len) == 0);
    assert(body_len == 11 && memcmp(body, "hello world", body_len) == 0);
    static const uint8_t bad_status[] =
        "HTTP/1.1 503 Busy\r\nContent-Length: 1\r\n\r\nx";
    assert(tg_route_dns_parse_http_response(bad_status,
        sizeof(bad_status) - 1u, body, sizeof(body), &body_len) != 0);
    static const uint8_t oversized[] =
        "HTTP/1.1 200 OK\r\nContent-Length: 33\r\n\r\n";
    assert(tg_route_dns_parse_http_response(oversized,
        sizeof(oversized) - 1u, body, sizeof(body), &body_len) != 0);
}

static void test_cache_returns_bounded_public_addresses(void) {
    resolver_fixture fixture = {0};
    assert(pthread_mutex_init(&fixture.mutex, NULL) == 0);
    tg_route_dns *cache = tg_route_dns_create(NULL, 0, NULL,
                                               test_lookup, &fixture);
    assert(cache && tg_route_dns_prefetch(cache, "edge.example") == 0);
    tg_listener_destination first, second;
    assert(wait_resolved(cache, "edge.example", &first) == 0);
    assert(tg_route_dns_resolve(cache, "edge.example", &second) == 0);
    assert(first.family == AF_INET && first.port == 443 &&
           memcmp(first.address, (uint8_t[]){1, 1, 1, 1}, 4) == 0);
    assert(second.family == AF_INET && second.port == 443 &&
           memcmp(second.address, (uint8_t[]){8, 8, 8, 8}, 4) == 0);
    assert(calls(&fixture) == 1);
    tg_route_dns_destroy(cache);
    pthread_mutex_destroy(&fixture.mutex);
}

static void test_private_and_invalid_results_are_rejected(void) {
    resolver_fixture fixture = {.private_only = 1};
    assert(pthread_mutex_init(&fixture.mutex, NULL) == 0);
    tg_route_dns *cache = tg_route_dns_create(NULL, 0, NULL,
                                               test_lookup, &fixture);
    assert(cache);
    assert(tg_route_dns_prefetch(cache, "not a domain") != 0);
    assert(tg_route_dns_resolve(cache, "private.example",
                               &(tg_listener_destination){0}) != 0);
    struct timespec delay = {.tv_nsec = 20000000L};
    (void)nanosleep(&delay, NULL);
    assert(calls(&fixture) == 1);
    assert(tg_route_dns_resolve(cache, "private.example",
                               &(tg_listener_destination){0}) != 0);
    assert(calls(&fixture) == 1);
    tg_route_dns_destroy(cache);
    pthread_mutex_destroy(&fixture.mutex);
}

int main(void) {
    test_doh_dns_message_validation();
    test_http_body_parser_accepts_bounded_chunked_response();
    test_cache_returns_bounded_public_addresses();
    test_private_and_invalid_results_are_rejected();
    puts("Тесты DNS-кэша Telegram-маршрутов: ок");
    return 0;
}
