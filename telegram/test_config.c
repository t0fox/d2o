#define _POSIX_C_SOURCE 200809L
#include "tg_config.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void test_config_values_and_legacy_fields(void) {
    char path[]="/tmp/d2k-tg-config-XXXXXX";int fd=mkstemp(path);assert(fd>=0);
    FILE *f=fdopen(fd,"w");assert(f);
    fputs("MODE=apply\nTG_ENABLED=1\nTG_MODE=local\n"
          "TG_RELAY_URL='wss://213.176.74.63.nip.io/ws'\n"
          "TG_RELAY_SECRET='old-secret'\nTG_IDENTITY=/opt/d2k/state/tg.identity\n"
          "TG_CA_BUNDLE=/opt/d2k/files/tg-roots.pem\n"
          "TG_STATUS=/opt/d2k/state/telegram.status\nTG_PORT=1443\n"
          "TG_ENROLL_PORT=9443\n",f);assert(fclose(f)==0);
    tg_config cfg;assert(tg_config_read(path,&cfg)==0);unlink(path);
    assert(cfg.enabled==1&&cfg.local_mode&&cfg.listen_port==1443);
    assert(strcmp(cfg.ca_bundle,"/opt/d2k/files/tg-roots.pem")==0);
    assert(strcmp(cfg.status_path,"/opt/d2k/state/telegram.status")==0);
    assert(strcmp(cfg.stats_socket_path,"/opt/d2k/state/telegram.stats.sock")==0);
    tg_config_clean(&cfg);
}

static void test_duplicate_and_incomplete_keys_rejected(void) {
    char path[]="/tmp/d2k-tg-config-XXXXXX";int fd=mkstemp(path);assert(fd>=0);
    FILE *f=fdopen(fd,"w");assert(f);fputs("TG_ENABLED=1\nTG_ENABLED=0\n",f);assert(fclose(f)==0);
    tg_config cfg;assert(tg_config_read(path,&cfg)!=0);unlink(path);
    assert(tg_config_read("/path/that/does/not/exist",&cfg)!=0);
}

static void test_local_mode_needs_no_relay_url_or_secret(void) {
    char path[]="/tmp/d2k-tg-local-config-XXXXXX";int fd=mkstemp(path);assert(fd>=0);
    FILE *f=fdopen(fd,"w");assert(f);
    fputs("TG_ENABLED=1\nTG_MODE=local\nTG_DC_MAP_PATH=/tmp/tg-dc.json\nTG_STATS_SOCKET=/tmp/tg-stats.sock\n",f);
    assert(fclose(f)==0);
    tg_config cfg;assert(tg_config_read(path,&cfg)==0);unlink(path);
    assert(cfg.enabled && cfg.local_mode && cfg.default_domains);
    assert(strcmp(cfg.dc_map_path,"/tmp/tg-dc.json")==0);
    assert(strcmp(cfg.stats_socket_path,"/tmp/tg-stats.sock")==0);
    tg_config_clean(&cfg);

    f=fopen(path,"w");assert(f);
    fputs("TG_ENABLED=1\nTG_MODE=local\nSTATE_DIR=/tmp/tg-state\nTG_DEFAULT_DOMAINS=0\n",f);
    assert(fclose(f)==0);
    assert(tg_config_read(path,&cfg)==0);
    assert(strcmp(cfg.stats_socket_path,"/tmp/tg-state/telegram.stats.sock")==0);
    assert(!cfg.default_domains);
    tg_config_clean(&cfg);
    unlink(path);
}

static void test_relay_mode_is_rejected(void) {
    char path[] = "/tmp/d2k-tg-relay-mode-XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0);
    FILE *file = fdopen(fd, "w");
    assert(file);
    fputs("TG_ENABLED=1\nTG_MODE=relay\n"
          "TG_RELAY_URL=wss://relay.example/ws\n"
          "TG_RELAY_SECRET=old-secret\n", file);
    assert(fclose(file) == 0);

    tg_config config;
    assert(tg_config_read(path, &config) != 0);
    unlink(path);
}

static void test_local_route_options_are_bounded_and_normalized(void) {
    char path[] = "/tmp/d2k-tg-routes-XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0);
    FILE *file = fdopen(fd, "w");
    assert(file);
    fputs("TG_ENABLED=1\nTG_MODE=local\n"
          "TG_CF_WORKER_DOMAIN=HTTPS://Tunnel.Example/path,backup.example\n"
          "TG_CF_DOMAIN=Edge.Example,edge2.example\n"
          "TG_CF_BALANCE=1\nTG_WS_ROUTING=cf-first\n"
          "TG_WS_HEDGE_DELAY_MS=250\nTG_WS_HEDGE_LIMIT=4\n"
          "TG_DEFAULT_DOMAINS=1\n", file);
    assert(fclose(file) == 0);

    tg_config config;
    assert(tg_config_read(path, &config) == 0);
    assert(config.local_mode && config.cf_balance && config.default_domains);
    assert(config.cf_worker_domain_count == 2);
    assert(strcmp(config.cf_worker_domains[0], "tunnel.example") == 0);
    assert(strcmp(config.cf_worker_domains[1], "backup.example") == 0);
    assert(config.cf_proxy_domain_count == 2);
    assert(strcmp(config.cf_proxy_domains[0], "edge.example") == 0);
    assert(config.ws_routing == TG_WS_ROUTING_CF_FIRST);
    assert(config.ws_hedge_delay_ms == 250 && config.ws_hedge_limit == 4);
    tg_config_clean(&config);

    file = fopen(path, "w");
    assert(file);
    fputs("TG_CF_WORKER_DOMAIN=127.0.0.1\n", file);
    assert(fclose(file) == 0);
    assert(tg_config_read(path, &config) != 0);

    file = fopen(path, "w");
    assert(file);
    fputs("TG_WS_ROUTING=unknown\n", file);
    assert(fclose(file) == 0);
    assert(tg_config_read(path, &config) != 0);
    unlink(path);
}

static void test_managed_resource_root(void) {
    char path[]="/tmp/d2k-managed-config-XXXXXX";int fd=mkstemp(path);assert(fd>=0);close(fd);
    assert(!setenv("D2K_TG_CA_BUNDLE","/tmp/release/files/tg-roots.pem",1));
    tg_config cfg;assert(!tg_config_read(path,&cfg));assert(!strcmp(cfg.ca_bundle,"/tmp/release/files/tg-roots.pem"));
    FILE *f=fopen(path,"w");assert(f);fputs("TG_CA_BUNDLE=/tmp/personal-ca.pem\n",f);fclose(f);
    assert(!tg_config_read(path,&cfg));assert(!strcmp(cfg.ca_bundle,"/tmp/personal-ca.pem"));
    unsetenv("D2K_TG_CA_BUNDLE");unlink(path);
}
int main(void) {
    test_managed_resource_root();
    test_config_values_and_legacy_fields();
    test_local_mode_needs_no_relay_url_or_secret();
    test_relay_mode_is_rejected();
    test_local_route_options_are_bounded_and_normalized();
    test_duplicate_and_incomplete_keys_rejected();puts("config tests: ok");return 0;
}
