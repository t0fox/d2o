# dnsprobe — отдельный измеритель DoH/DoT/DoQ.
# Не входит в runtime d2kc: это инструмент проверки и полигон для правил,
# которые потом переносятся в core. Собирается отдельно, чтобы не менять
# зависимости продуктовых бинарников.
CC      ?= cc
CFLAGS  ?= -std=c99 -O2 -Wall -Wextra -Werror
CPPFLAGS += -Iinclude -I../core/include -I../datapath/include -I../runtime
LDFLAGS ?=
LDLIBS  ?= -lpthread

BUILD := build
CORE_SRC := tls13.c tls12.c tls13core.c x25519.c p256.c crypto.c diagnostics.c
CORE_OBJ := $(CORE_SRC:%.c=$(BUILD)/core_%.o)
OUR_OBJ  := $(BUILD)/dnsprobe.o $(BUILD)/main.o

.PHONY: all check clean live lab
all: $(BUILD)/d2k-dnsprobe

$(BUILD):
	mkdir -p $@

$(BUILD)/core_%.o: ../core/%.c | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) -DD2K_RELEASE_ID='"dev"' -c -o $@ $<

$(BUILD)/dnsprobe.o: src/dnsprobe.c include/d2k_dnsprobe.h | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

$(BUILD)/main.o: src/main.c include/d2k_dnsprobe.h | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

$(BUILD)/d2k-dnsprobe: $(OUR_OBJ) $(CORE_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)

$(BUILD)/test_dnsprobe: test/test_dnsprobe.c src/dnsprobe.c include/d2k_dnsprobe.h $(CORE_OBJ) | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ test/test_dnsprobe.c src/dnsprobe.c $(CORE_OBJ) $(LDFLAGS) $(LDLIBS)

check: $(BUILD)/test_dnsprobe
	./$(BUILD)/test_dnsprobe

lab: $(BUILD)/d2k-dnsprobe
	sh test/lab_sni.sh

clean:
	rm -rf $(BUILD)
