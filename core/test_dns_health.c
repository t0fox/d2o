#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "include/d2k_sched.h"
#include "../runtime/d2k_dns_config.h"

#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "test_dns_health:%d: %s\n", __LINE__, #expr); exit(1); \
} } while (0)

static void live_json(d2k_sched *sched, char *out, size_t cap) {
    char path[] = "/tmp/d2k-dns-health-live-XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    CHECK(close(fd) == 0);
    CHECK(d2k_sched_write_live(sched, path, "catalog.json") == 0);
    FILE *f = fopen(path, "r");
    CHECK(f);
    size_t n = fread(out, 1, cap - 1, f);
    out[n] = '\0';
    fclose(f);
    unlink(path);
}

static void test_bootstrap_without_observed_flow(void) {
    d2k_catalog catalog = {0};
    d2k_sched *sched = d2k_sched_new(&catalog, -1, 0);
    CHECK(sched);
    d2k_dns_service service = {0};
    snprintf(service.protocol, sizeof service.protocol, "doh");
    snprintf(service.host, sizeof service.host, "resolver.example");
    snprintf(service.sni, sizeof service.sni, "resolver.example");
    snprintf(service.path, sizeof service.path, "/dns-query");
    snprintf(service.bootstrap_dns, sizeof service.bootstrap_dns, "192.0.2.53");
    service.port = 443;
    d2k_sched_set_dns_services(sched, &service, 1);

    (void)d2k_sched_tick(sched, 1000);
    char json[32768];
    live_json(sched, json, sizeof json);
    CHECK(strstr(json, "настроенный bootstrap DNS") != NULL);
    CHECK(strstr(json, "\"check_attempts\": 1") != NULL);
    CHECK(strstr(json, "\"state\": \"checking\"") != NULL);

    struct timespec pause = { .tv_sec = 0, .tv_nsec = 50000000 };
    for (unsigned i = 0; i < 40; i++) {
        (void)nanosleep(&pause, NULL);
        (void)d2k_sched_tick(sched, 1001 + i);
        live_json(sched, json, sizeof json);
        if (strstr(json, "\"state\": \"failed\"")) break;
    }
    CHECK(strstr(json, "\"state\": \"failed\"") != NULL);
    CHECK(strstr(json, "\"dns_answer_confirmed\": false") != NULL);
    (void)d2k_sched_tick(sched, 62000);
    live_json(sched, json, sizeof json);
    CHECK(strstr(json, "\"check_attempts\": 2") != NULL);
    CHECK(strstr(json, "\"state\": \"checking\"") != NULL ||
          strstr(json, "\"state\": \"failed\"") != NULL);
    d2k_sched_free(sched);
    d2k_catalog_free(&catalog);
}

static void test_dot_bootstrap_without_observed_flow(void) {
    d2k_catalog catalog = {0};
    d2k_sched *sched = d2k_sched_new(&catalog, -1, 0);
    CHECK(sched);
    d2k_dns_service service = {0};
    snprintf(service.protocol, sizeof service.protocol, "dot");
    snprintf(service.host, sizeof service.host, "127.0.0.1");
    snprintf(service.path, sizeof service.path, "/");
    snprintf(service.bootstrap_dns, sizeof service.bootstrap_dns, "192.0.2.53");
    service.port = 853;
    d2k_sched_set_dns_services(sched, &service, 1);

    (void)d2k_sched_tick(sched, 1000);
    char json[32768];
    live_json(sched, json, sizeof json);
    CHECK(strstr(json, "\"check_attempts\": 1") != NULL);
    CHECK(strstr(json, "\"state\": \"checking\"") != NULL ||
          strstr(json, "\"state\": \"failed\"") != NULL);
    d2k_sched_free(sched);
    d2k_catalog_free(&catalog);
}

int main(void) {
    int reserve = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(reserve >= 0);
    struct sockaddr_in addr = { .sin_family = AF_INET,
                                .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    CHECK(bind(reserve, (struct sockaddr *)&addr, sizeof addr) == 0);
    socklen_t addr_len = sizeof addr;
    CHECK(getsockname(reserve, (struct sockaddr *)&addr, &addr_len) == 0);
    uint16_t port = ntohs(addr.sin_port);
    close(reserve); /* a closed endpoint makes the network probe return promptly */

    d2k_catalog catalog = {0};
    d2k_sched *sched = d2k_sched_new(&catalog, -1, 0);
    CHECK(sched);
    d2k_dns_service service = {0};
    snprintf(service.protocol, sizeof service.protocol, "doh");
    snprintf(service.host, sizeof service.host, "resolver.example");
    snprintf(service.sni, sizeof service.sni, "tls.resolver.example");
    snprintf(service.path, sizeof service.path, "/dns-query");
    snprintf(service.bootstrap_dns, sizeof service.bootstrap_dns, "192.0.2.53");
    snprintf(service.source, sizeof service.source, "test");
    service.port = port;
    d2k_sched_set_dns_services(sched, &service, 1);

    d2k_ev hello = {0};
    hello.kind = D2K_EV_HELLO;
    hello.transport = 6;
    hello.family = 4;
    hello.low_ip[0] = 127; hello.low_ip[3] = 1;
    hello.low_port = port;
    hello.high_ip[0] = 127; hello.high_ip[3] = 1;
    hello.high_port = 65535; /* keep this client end above the random server port */
    snprintf(hello.name, sizeof hello.name, "resolver.example");
    CHECK(d2k_sched_event(sched, &hello) == 0);
    char json[32768];
    live_json(sched, json, sizeof json);
    CHECK(strstr(json, "\"resolved_ip\": \"127.0.0.1\"") != NULL);
    CHECK(strstr(json, "\"plan_applied\": false") != NULL);

    d2k_ev applied = hello;
    applied.kind = D2K_EV_APPLIED;
    applied.plan_id[0] = 0x12;
    applied.plan_id[1] = 0x34;
    CHECK(d2k_sched_event(sched, &applied) == 0);
    live_json(sched, json, sizeof json);
    CHECK(strstr(json, "\"plan_applied\": true") != NULL);
    CHECK(strstr(json, "\"applied_plan_id\": \"12340000000000000000000000000000\"") != NULL);

    d2k_ev trial_applied = applied;
    trial_applied.trial_id[0] = 1;
    trial_applied.plan_id[0] = 0xab;
    CHECK(d2k_sched_event(sched, &trial_applied) == 0);
    live_json(sched, json, sizeof json);
    CHECK(strstr(json, "\"applied_plan_id\": \"12340000000000000000000000000000\"") != NULL);

    (void)d2k_sched_tick(sched, 1000);
    live_json(sched, json, sizeof json);
    CHECK(strstr(json, "\"dns_answer_confirmed\": false") != NULL);
    CHECK(strstr(json, "\"check_attempts\": 1") != NULL);
    CHECK(strstr(json, "\"state\": \"checking\"") != NULL ||
          strstr(json, "\"state\": \"failed\"") != NULL);
    d2k_sched_set_dns_services(sched, &service, 1); /* periodic config refresh */
    live_json(sched, json, sizeof json);
    CHECK(strstr(json, "\"resolved_ip\": \"127.0.0.1\"") != NULL);
    hello.low_ip[3] = 2; /* a changed A record resets the check for that endpoint */
    CHECK(d2k_sched_event(sched, &hello) == 0);
    live_json(sched, json, sizeof json);
    CHECK(strstr(json, "\"resolved_ip\": \"127.0.0.2\"") != NULL);
    CHECK(strstr(json, "\"plan_applied\": false") != NULL);
    CHECK(strstr(json, "\"applied_plan_id\": \"\"") != NULL);
    struct timespec pause = { .tv_sec = 0, .tv_nsec = 50000000 };
    for (unsigned i = 0; i < 40; i++) {
        (void)nanosleep(&pause, NULL);
        (void)d2k_sched_tick(sched, 1001 + i);
    }
    live_json(sched, json, sizeof json);
    CHECK(strstr(json, "\"resolved_ip\": \"127.0.0.2\"") != NULL);
    d2k_sched_free(sched);
    d2k_catalog_free(&catalog);
    test_bootstrap_without_observed_flow();
    test_dot_bootstrap_without_observed_flow();
    puts("test_dns_health: automatically probes the observed endpoint");
    return 0;
}
