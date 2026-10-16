CC ?= cc
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Werror -pedantic
RELEASE_ID ?= dev
CPPFLAGS += -D_POSIX_C_SOURCE=200809L -Iinclude -DD2K_RELEASE_ID='"$(RELEASE_ID)"'
BUILD_DIR ?= build
OPENSSL_CFLAGS ?= $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS ?= $(shell pkg-config --libs openssl 2>/dev/null || echo -lssl -lcrypto)
ZLIB_LIBS ?= -lz

.PHONY: test san test-ws test-tls test-config test-enroll test-identity test-mtproto test-mtproto-probe test-mtproto-splitter test-mtproto-auth test-mtproto-encrypted test-mtproto-config test-listener test-dc-map test-dc-map-json test-dc-map-store test-cf-domains test-route-plan test-route-dns test-limits test-epoll-proxy test-transparent clean arm64 d2ktg

test: test-ws test-tls test-config test-enroll test-identity test-mtproto test-mtproto-probe test-mtproto-splitter test-mtproto-auth test-mtproto-encrypted test-mtproto-config test-listener test-dc-map test-dc-map-json test-dc-map-store test-cf-domains test-route-plan test-route-dns test-limits test-epoll-proxy test-transparent

san:
	$(MAKE) BUILD_DIR=build/san CFLAGS='-O1 -g -std=c11 -Wall -Wextra -Werror -pedantic -fsanitize=address,undefined -fno-omit-frame-pointer' test d2ktg

test-mtproto-auth: $(BUILD_DIR)/test-mtproto-auth
	./$(BUILD_DIR)/test-mtproto-auth

$(BUILD_DIR)/test-mtproto-auth: test_mtproto_auth.c src/mtproto_auth.c src/mtproto_auth_keys.inc src/mtproto_crypto.c include/tg_mtproto_auth.h include/tg_mtproto.h testdata/mtproto-auth-vectors.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(OPENSSL_CFLAGS) $(CFLAGS) -o $@ test_mtproto_auth.c src/mtproto_auth.c src/mtproto_crypto.c $(OPENSSL_LIBS)

test-mtproto-encrypted: $(BUILD_DIR)/test-mtproto-encrypted
	./$(BUILD_DIR)/test-mtproto-encrypted

$(BUILD_DIR)/test-mtproto-encrypted: test_mtproto_encrypted.c src/mtproto_crypto.c src/mtproto_encrypted.c include/tg_mtproto.h testdata/mtproto-v2-vectors.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(OPENSSL_CFLAGS) $(CFLAGS) -o $@ test_mtproto_encrypted.c src/mtproto_crypto.c src/mtproto_encrypted.c $(OPENSSL_LIBS)

test-mtproto-config: $(BUILD_DIR)/test-mtproto-config
	./$(BUILD_DIR)/test-mtproto-config

$(BUILD_DIR)/test-mtproto-config: test_mtproto_config.c src/mtproto_config.c src/dc_map.c src/dc_map_json.c include/tg_mtproto_discovery.h include/tg_dc_map.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ test_mtproto_config.c src/mtproto_config.c src/dc_map.c src/dc_map_json.c $(ZLIB_LIBS)

test-mtproto-probe: $(BUILD_DIR)/test-mtproto-probe
	./$(BUILD_DIR)/test-mtproto-probe

$(BUILD_DIR)/test-mtproto-probe: test_mtproto_probe.c src/mtproto_crypto.c src/mtproto_encrypted.c src/mtproto_probe.c src/mtproto_auth.c src/mtproto_auth_keys.inc src/mtproto_config.c src/dc_map.c src/dc_map_json.c src/tls.c src/ws.c src/ws_pump.c src/net.c include/tg_mtproto.h include/tg_mtproto_auth.h include/tg_mtproto_discovery.h include/tg_tls.h include/tg_ws.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(OPENSSL_CFLAGS) $(CFLAGS) -pthread -o $@ test_mtproto_probe.c src/mtproto_crypto.c src/mtproto_encrypted.c src/mtproto_probe.c src/mtproto_auth.c src/mtproto_config.c src/dc_map.c src/dc_map_json.c src/tls.c src/ws.c src/ws_pump.c src/net.c $(OPENSSL_LIBS) $(ZLIB_LIBS)

test-transparent: $(BUILD_DIR)/test-transparent
	./$(BUILD_DIR)/test-transparent

$(BUILD_DIR)/test-transparent: test_transparent.c src/transparent.c src/mtproto_crypto.c src/listener.c src/dc_map.c src/dc_map_store.c src/dc_map_json.c include/tg_transparent.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(OPENSSL_CFLAGS) $(CFLAGS) -o $@ test_transparent.c src/transparent.c src/mtproto_crypto.c src/listener.c src/dc_map.c src/dc_map_store.c src/dc_map_json.c $(OPENSSL_LIBS)

test-epoll-proxy: $(BUILD_DIR)/test-epoll-proxy
	./$(BUILD_DIR)/test-epoll-proxy

$(BUILD_DIR)/test-epoll-proxy: test_epoll_proxy.c src/epoll_proxy.c src/stats_socket.c src/limits.c src/listener.c src/tls.c src/ws.c src/ws_pump.c src/mtproto_crypto.c src/mtproto_splitter.c src/cf_domains.c src/route_plan.c src/route_dns.c include/tg_epoll_proxy.h include/tg_stats_socket.h include/tg_mtproto.h include/tg_mtproto_splitter.h include/tg_tls.h include/tg_ws.h include/tg_cf_domains.h include/tg_route_plan.h include/tg_route_dns.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(OPENSSL_CFLAGS) $(CFLAGS) -DTG_ROUTE_HEALTH_COOLDOWN_MS=1000u -pthread -o $@ test_epoll_proxy.c src/epoll_proxy.c src/stats_socket.c src/limits.c src/listener.c src/tls.c src/ws.c src/ws_pump.c src/mtproto_crypto.c src/mtproto_splitter.c src/cf_domains.c src/route_plan.c src/route_dns.c $(OPENSSL_LIBS)

test-limits: $(BUILD_DIR)/test-limits
	./$(BUILD_DIR)/test-limits

$(BUILD_DIR)/test-limits: test_limits.c src/limits.c include/tg_limits.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ test_limits.c src/limits.c

test-mtproto: $(BUILD_DIR)/test-mtproto
	./$(BUILD_DIR)/test-mtproto

test-mtproto-splitter: $(BUILD_DIR)/test-mtproto-splitter
	./$(BUILD_DIR)/test-mtproto-splitter

test-listener: $(BUILD_DIR)/test-listener
	./$(BUILD_DIR)/test-listener

test-dc-map: $(BUILD_DIR)/test-dc-map
	./$(BUILD_DIR)/test-dc-map

test-dc-map-json: $(BUILD_DIR)/test-dc-map-json
	./$(BUILD_DIR)/test-dc-map-json

test-dc-map-store: $(BUILD_DIR)/test-dc-map-store
	./$(BUILD_DIR)/test-dc-map-store

test-cf-domains: $(BUILD_DIR)/test-cf-domains
	./$(BUILD_DIR)/test-cf-domains

$(BUILD_DIR)/test-cf-domains: test_cf_domains.c src/cf_domains.c src/route_dns.c src/tls.c include/tg_cf_domains.h include/tg_route_dns.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(OPENSSL_CFLAGS) $(CFLAGS) -pthread -o $@ test_cf_domains.c src/cf_domains.c src/route_dns.c src/tls.c $(OPENSSL_LIBS)

test-route-plan: $(BUILD_DIR)/test-route-plan
	./$(BUILD_DIR)/test-route-plan

test-route-dns: $(BUILD_DIR)/test-route-dns
	./$(BUILD_DIR)/test-route-dns

$(BUILD_DIR)/test-route-dns: test_route_dns.c src/route_dns.c src/cf_domains.c src/tls.c include/tg_route_dns.h include/tg_cf_domains.h include/tg_listener.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(OPENSSL_CFLAGS) $(CFLAGS) -pthread -o $@ test_route_dns.c src/route_dns.c src/cf_domains.c src/tls.c $(OPENSSL_LIBS)

$(BUILD_DIR)/test-route-plan: test_route_plan.c src/route_plan.c include/tg_route_plan.h include/tg_config.h include/tg_cf_domains.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ test_route_plan.c src/route_plan.c

$(BUILD_DIR)/test-mtproto: test_mtproto.c src/mtproto_crypto.c include/tg_mtproto.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(OPENSSL_CFLAGS) $(CFLAGS) -o $@ test_mtproto.c src/mtproto_crypto.c $(OPENSSL_LIBS)

$(BUILD_DIR)/test-mtproto-splitter: test_mtproto_splitter.c src/mtproto_crypto.c src/mtproto_splitter.c include/tg_mtproto_splitter.h include/tg_mtproto.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(OPENSSL_CFLAGS) $(CFLAGS) -o $@ test_mtproto_splitter.c src/mtproto_crypto.c src/mtproto_splitter.c $(OPENSSL_LIBS)

$(BUILD_DIR)/test-listener: test_listener.c src/listener.c include/tg_listener.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ test_listener.c src/listener.c

$(BUILD_DIR)/test-dc-map: test_dc_map.c src/dc_map.c include/tg_dc_map.h include/tg_listener.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ test_dc_map.c src/dc_map.c

$(BUILD_DIR)/test-dc-map-json: test_dc_map_json.c src/dc_map.c src/dc_map_json.c include/tg_dc_map.h include/tg_listener.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ test_dc_map_json.c src/dc_map.c src/dc_map_json.c

$(BUILD_DIR)/test-dc-map-store: test_dc_map_store.c src/dc_map.c src/dc_map_json.c src/dc_map_store.c include/tg_dc_map.h include/tg_listener.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ test_dc_map_store.c src/dc_map.c src/dc_map_json.c src/dc_map_store.c

test-enroll: $(BUILD_DIR)/test-enroll
	./$(BUILD_DIR)/test-enroll

$(BUILD_DIR)/test-enroll: test_enroll.c src/enroll.c src/identity.c include/tg_enroll.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(OPENSSL_CFLAGS) $(CFLAGS) -o $@ test_enroll.c src/enroll.c src/identity.c $(OPENSSL_LIBS)

test-ws: $(BUILD_DIR)/test-ws
	./$(BUILD_DIR)/test-ws

test-tls: $(BUILD_DIR)/test-tls
	./$(BUILD_DIR)/test-tls

test-config: $(BUILD_DIR)/test-config
	./$(BUILD_DIR)/test-config

d2ktg: $(BUILD_DIR)/d2ktg

$(BUILD_DIR)/d2ktg: ../runtime/d2k_runtime.h ../runtime/d2k_protocol.h src/main.c src/config.c src/tls.c src/ws.c src/ws_pump.c src/net.c src/listener.c src/mtproto_crypto.c src/mtproto_encrypted.c src/mtproto_config.c src/mtproto_probe.c src/mtproto_auth.c src/mtproto_auth_keys.inc src/mtproto_splitter.c src/dc_map.c src/dc_map_json.c src/dc_map_store.c src/cf_domains.c src/route_plan.c src/route_dns.c src/limits.c src/epoll_proxy.c src/transparent.c src/stats_socket.c include/tg_mtproto_auth.h include/tg_mtproto_discovery.h include/tg_tls.h include/tg_ws.h include/tg_mtproto.h include/tg_cf_domains.h include/tg_route_plan.h include/tg_route_dns.h include/tg_stats_socket.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(OPENSSL_CFLAGS) $(CFLAGS) -pthread -o $@ $(filter %.c,$^) $(OPENSSL_LIBS) $(ZLIB_LIBS)

$(BUILD_DIR)/test-ws: test_ws.c src/ws.c src/ws_pump.c src/net.c include/tg_ws.h include/tg_net.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(OPENSSL_CFLAGS) $(CFLAGS) -o $@ test_ws.c src/ws.c src/ws_pump.c src/net.c $(OPENSSL_LIBS)


$(BUILD_DIR)/test-tls: test_tls.c ../files/tg-roots.pem src/tls.c src/ws.c src/ws_pump.c include/tg_tls.h include/tg_ws.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(OPENSSL_CFLAGS) $(CFLAGS) -pthread -o $@ test_tls.c src/tls.c src/ws.c src/ws_pump.c $(OPENSSL_LIBS)

$(BUILD_DIR)/test-config: test_config.c src/config.c include/tg_config.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(OPENSSL_CFLAGS) $(CFLAGS) -o $@ test_config.c src/config.c $(OPENSSL_LIBS)

arm64:
	../scripts/build-openssl-tg.sh

clean:
	rm -rf $(BUILD_DIR)

# GCC проверяет весь runtime и тесты с теми же строгими предупреждениями.
.PHONY: gcc-warn
gcc-warn:
	$(MAKE) clean
	$(MAKE) CC=gcc test d2ktg

.PHONY: test-identity
test-identity: $(BUILD_DIR)/test-identity
	./$(BUILD_DIR)/test-identity
$(BUILD_DIR)/test-identity: test_identity.c src/identity.c include/tg_identity.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(OPENSSL_CFLAGS) $(CFLAGS) -o $@ test_identity.c src/identity.c $(OPENSSL_LIBS)
