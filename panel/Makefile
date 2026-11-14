.DEFAULT_GOAL := all
CC ?= cc
ZIG ?= /opt/homebrew/bin/zig
CFLAGS ?= -O2 -std=c11 -Wall -Wextra -Werror -D_POSIX_C_SOURCE=200809L
RELEASE_ID ?= dev
# override: CFLAGS из командной строки (lab-install.sh пересобирает панель с
# -O1) иначе отбрасывал release ID.
override CFLAGS += -D_GNU_SOURCE -DD2K_RELEASE_ID='"$(RELEASE_ID)"'
VERSION ?= dev
COMMIT ?=
BUILT ?=
DIRTY ?= 0

server.o d2kpanel release test_server test_server_san test_header_deadline test_response_deadline test_config_values test_status_cache test_diagnostics: ../core/network_diag.h

.PHONY: all test test-js test-cli san clean d2kpanel-linux-arm64

all: d2kpanel

d2kpanel: main.c server.h server.c ../runtime/d2k_dns_config.c ../core/network_diag.c ../runtime/d2k_dns_config.h ../runtime/d2k_runtime.h ../runtime/d2k_protocol.h
	$(CC) $(CFLAGS) -o $@ main.c server.c ../runtime/d2k_dns_config.c ../core/network_diag.c

TARGET ?= aarch64-linux-musl
TARGET_FLAGS ?=
ARCH ?= arm64
BUILDDIR ?= ../builds
.PHONY: release
d2kpanel-linux-arm64: release
release: main.c server.h server.c ../runtime/d2k_dns_config.c ../core/network_diag.c ../runtime/d2k_dns_config.h ../runtime/d2k_runtime.h ../runtime/d2k_protocol.h
	mkdir -p $(BUILDDIR)
	$(ZIG) cc -target $(TARGET) $(TARGET_FLAGS) -static -Wl,-S -Os -std=c11 -Wall -Wextra -Werror \
		-D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE -DD2K_RELEASE_ID='"$(RELEASE_ID)"' -DD2K_PANEL_VERSION='"$(VERSION)"' \
		-DD2K_PANEL_COMMIT='"$(COMMIT)"' -DD2K_PANEL_BUILT='"$(BUILT)"' \
		-DD2K_PANEL_DIRTY=$(DIRTY) -o $(BUILDDIR)/d2kpanel-linux-$(ARCH) main.c server.c ../runtime/d2k_dns_config.c ../core/network_diag.c

test_server: test_server.c server.h server.c ../runtime/d2k_dns_config.c ../core/network_diag.c ../runtime/d2k_dns_config.h
	$(CC) $(CFLAGS) -DD2K_PANEL_ACTION_TIMEOUT_MS=1000 -pthread -o $@ test_server.c server.c ../runtime/d2k_dns_config.c ../core/network_diag.c

test_server_san: test_server.c server.h server.c ../runtime/d2k_dns_config.c ../core/network_diag.c ../runtime/d2k_dns_config.h
	$(CC) $(CFLAGS) -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
		-DD2K_PANEL_ACTION_TIMEOUT_MS=1000 -pthread -o $@ test_server.c server.c ../runtime/d2k_dns_config.c ../core/network_diag.c

san: test_server_san
	ASAN_OPTIONS=detect_leaks=0 ./test_server_san


.PHONY: test-header-deadline
test: test-header-deadline
test-header-deadline: test_header_deadline
	./test_header_deadline
test_header_deadline: test_header_deadline.c server.c server.h ../runtime/d2k_dns_config.c ../core/network_diag.c ../runtime/d2k_dns_config.h
	$(CC) $(CFLAGS) -DD2K_PANEL_HEADER_TIMEOUT_MS=100 -o $@ test_header_deadline.c ../runtime/d2k_dns_config.c ../core/network_diag.c

.PHONY: test-response-deadline
test: test-response-deadline
test-response-deadline: test_response_deadline
	./test_response_deadline
test_response_deadline: test_response_deadline.c server.c server.h ../runtime/d2k_dns_config.c ../core/network_diag.c ../runtime/d2k_dns_config.h
	$(CC) $(CFLAGS) -DD2K_PANEL_RESPONSE_TIMEOUT_MS=100 -o $@ test_response_deadline.c ../runtime/d2k_dns_config.c ../core/network_diag.c

.PHONY: clean-header-deadline
clean: clean-header-deadline
clean-header-deadline:
	$(RM) test_header_deadline test_response_deadline

test-js:
	node test_ui.cjs
	node test_telegram_flow.cjs
	node test_poll.cjs
	node test_status_cache.cjs
	node test_updates.cjs


.PHONY: test-config-values
test: test-config-values
test-config-values: test_config_values
	./test_config_values
test_config_values: test_config_values.c main.c server.c ../runtime/d2k_dns_config.c ../core/network_diag.c ../runtime/d2k_dns_config.h
	$(CC) $(CFLAGS) -o $@ test_config_values.c server.c ../runtime/d2k_dns_config.c ../core/network_diag.c

.PHONY: clean-config-values
clean: clean-config-values
clean-config-values:
	$(RM) test_config_values

test-cli: d2kpanel
	node test_cli.cjs

test: test_server d2kpanel test-js
	./test_server
	node test_cli.cjs

clean:
	rm -f test_server test_server_san d2kpanel

.PHONY: test-status-cache clean-status-cache
test: test-status-cache
test-status-cache: test_status_cache
	./test_status_cache
test_status_cache: test_status_cache.c server.c server.h ../runtime/d2k_dns_config.c ../core/network_diag.c ../runtime/d2k_dns_config.h
	$(CC) $(CFLAGS) -o $@ test_status_cache.c ../runtime/d2k_dns_config.c ../core/network_diag.c
clean: clean-status-cache
clean-status-cache:
	$(RM) test_status_cache

.PHONY: test-diagnostics clean-diagnostics
test: test-diagnostics
test-diagnostics: test_diagnostics
	./test_diagnostics
	node test_diagnostics.cjs
test_diagnostics: test_diagnostics.c server.c server.h ../runtime/d2k_diagnostics_files.h ../runtime/d2k_dns_config.c ../core/network_diag.c ../runtime/d2k_dns_config.h
	$(CC) $(CFLAGS) -o $@ test_diagnostics.c ../runtime/d2k_dns_config.c ../core/network_diag.c
clean: clean-diagnostics
clean-diagnostics:
	$(RM) test_diagnostics

server.o d2kpanel test_server test_server_san test_config_values test_header_deadline test_response_deadline: ../runtime/d2k_diagnostics_files.h
