# Датапат d2k. Здесь живёт то, что видит чужие пакеты, и только оно.
#
# -Werror не роскошь: непереносимость обязана ловиться в тот день, когда её
# внесли, а не на роутере. Замер этапа 0 показал, что C даёт ошибки работы с
# памятью там, где Go не даёт, и единственная защита — жёсткие ключи и тесты.

CC      ?= cc
CFLAGS  ?= -std=c99 -O2 -Wall -Wextra -Werror -Iinclude -I$(CORE_DIR)/include
RELEASE_ID ?= dev
CFLAGS += -DD2K_RELEASE_ID='"$(RELEASE_ID)"'
LDFLAGS ?=

# Кросс-компиляторы для проверки переносимости. Пути переопределяются извне.
ZIG        ?= /opt/homebrew/bin/zig
MIPSEL_CC  ?= mipsel-unknown-linux-gnu-gcc
# Big-endian mips — своим gcc (на Ubuntu это пакет gcc-mips-linux-gnu), если он
# в системе есть; на машине разработки его обычно нет, поэтому он
# НЕОБЯЗАТЕЛЕН. Сам порядок байт при этом проверяется всегда: zig-проход в
# цели cross установленных цепочек не требует.
MIPS_CC    ?= mips-unknown-linux-gnu-gcc
# Та же тройка, что у выпуска (см. scripts/build-target.sh).
MIPS_BE_ZIG ?= -target mips-linux-musleabi -mcpu=mips32+soft_float

# Разбор QUIC (задача 2 этой же вертикали) живёт в core/ — отдельной единице
# сборки со своим Makefile. Датапату он нужен на каждом UDP-пакете в горячем
# пути (session.c), и линкуется ИСХОДНИКАМИ, а не копией: crypto.c/quic.c
# зависят только от <string.h> и собственных заголовков, CFLAGS ядра побайтно
# совпадают с датапатовскими (сверено построчно с core/Makefile), а pthread
# нужен только тестам ядра — этим двум файлам нет.
#
# Объектники — под своими именами ЗДЕСЬ, в датапате (core_quic.o,
# core_crypto.o), а НЕ в ../core/: если бы оба Makefile метили в один и тот же
# путь, каждый считал бы файл своим, и несовпадение mtime/флагов одного билда
# портило бы зависимости другого молча.
CORE_DIR = ../core
CORESRC  = $(CORE_DIR)/quic.c $(CORE_DIR)/quicsnap.c $(CORE_DIR)/quicwire.c $(CORE_DIR)/crypto.c $(CORE_DIR)/ipfrag.c $(CORE_DIR)/httpup_logic.c
COREOBJ  = core_quic.o core_quicwire.o core_quicsnap.o core_crypto.o core_ipfrag.o core_httpup_logic.o
COREHDR  = $(CORE_DIR)/include/d2k_quicsnap.h $(CORE_DIR)/include/d2k_arm.h $(CORE_DIR)/include/d2k_quic.h $(CORE_DIR)/include/d2k_quicwire.h $(CORE_DIR)/include/d2k_crypto.h $(CORE_DIR)/include/d2k_ipfrag.h $(CORE_DIR)/include/d2k_httpup.h
QUIC_FIXTURE_OBJ = core_quichello.o core_hello.o core_tls13core.o core_x25519.o

# Переносимый датапат: собирается и проверяется на любой машине.
SRC     = icmpguard.c http80.c http_trace.c addr.c plan_parse.c plan_apply.c tls.c capture.c hold.c udp_hold.c udp_release.c udp_path.c routemark.c wire.c wire_udp.c track.c session.c nat.c nl.c ctq.c sched.c journal.c plans.c ctl.c ctlsrv.c
# Системный слой: только Linux. На маке не собирается намеренно — подделывать
# сокеты ядра ради сборки значило бы проверять подделку. Проверяется целью
# cross, которая линкует ПОЛНУЮ службу под обе целевые арки: полная сборка
# доказывает больше, чем компиляция объектников.
LINUXSRC = nfq.c raw.c routemark_nl.c
DAEMON   = d2kd.c
HDR     = include/d2k_icmpguard.h include/d2k_hold.h include/d2k_udp_hold.h include/d2k_udp_release.h include/d2k_udp_path.h include/d2k_routemark.h include/d2k_capture.h include/d2k_plan.h include/d2k_nat.h include/d2k_tls.h include/d2k_wire.h include/d2k_track.h include/d2k_session.h include/d2k_nl.h include/d2k_ctq.h include/d2k_sched.h include/d2k_nfq.h include/d2k_raw.h include/d2k_journal.h include/d2k_plans.h include/d2k_ctl.h include/d2k_ctlsrv.h include/d2k_http80.h plan_internal.h $(COREHDR)

HDR += include/d2k_http_response.h include/d2k_http_request_stream.h
HDR += ../runtime/d2k_runtime.h ../runtime/d2k_protocol.h include/d2k_http_trace.h

# Тесты и их объектные файлы. Один список — чтобы санитайзерная цель не
# разъезжалась с обычной: разъехавшись, она проверяла бы не то дерево.
TESTS   = test_icmpguard test_addr test_hold test_udp_hold test_udp_release test_udp_path test_routemark test_capture test_plan_parse test_plan_apply test_tls test_wire test_wire_udp test_track test_session test_nat test_nl test_sched test_journal test_plans test_ctl test_stun_session test_quic_session test_ctq test_http80 test_http_hello test_http_trace

.PHONY: all check san gcc-warn ctlprobe d2kd-linux-arm64 test-parse test-apply test-tls test-wire test-wire-udp test-track test-session test-nat test-nl test-sched test-journal test-plans test-ctl test-quic-session test-stun-session test-udp-release test-udp-path test-routemark cross clean

all: planlab ctlprobe

HDR += include/d2k_packet.h
HDR += $(CORE_DIR)/include/d2k_ip6frag_send.h

# Implicitly compiled objects also depend on shared structure layouts.
$(SRC:.c=.o): $(HDR) include/d2k_addr.h

test_addr: test_addr.c addr.c include/d2k_addr.h include/d2k_packet.h
	$(CC) $(CFLAGS) -o $@ test_addr.c addr.c $(LDFLAGS)

.PHONY: test-addr
test-addr: test_addr
	./test_addr

# Real raw IPv6 delivery and failure injection. Linux network namespace only.
.PHONY: test-raw6-linux
test-raw6-linux: test_raw6.c raw.c wire_udp.c $(HDR)
	$(CC) $(CFLAGS) -Dsetsockopt=d2k_test_setsockopt -c raw.c -o raw6_test.o
	$(CC) $(CFLAGS) -o test_raw6 test_raw6.c raw6_test.o wire_udp.c ../core/ipfrag.c $(LDFLAGS)
	./test_raw6

# Предел посылки проверяется в отдельном сетевом пространстве имён Linux.
.PHONY: test-raw-cap-linux
test-raw-cap-linux: test_raw_cap.c raw.c wire_udp.c $(HDR)
	$(CC) $(CFLAGS) -o test_raw_cap test_raw_cap.c raw.c wire_udp.c ../core/ipfrag.c $(LDFLAGS)
	sh test_raw_cap.sh

check: test-addr

# ICMP time-exceeded на собственные фальшивки (поле 04.10.2026, icmp-rua.pcap).
icmpguard.o: icmpguard.c include/d2k_icmpguard.h
	$(CC) $(CFLAGS) -c -o $@ $<

test_icmpguard: test_icmpguard.c icmpguard.o include/d2k_icmpguard.h
	$(CC) $(CFLAGS) -o $@ test_icmpguard.c icmpguard.o $(LDFLAGS)

.PHONY: test-icmpguard
test-icmpguard: test_icmpguard
	./test_icmpguard

check: test-icmpguard

plan_parse.o: plan_parse.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

plan_apply.o: plan_apply.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

test_plan_parse: test_plan_parse.c plan_parse.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_plan_parse.c plan_parse.o $(LDFLAGS)

tls.o: tls.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

capture.o: capture.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

hold.o: hold.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

udp_hold.o: udp_hold.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

udp_release.o: udp_release.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

test_udp_hold: test_udp_hold.c udp_hold.o udp_release.o hold.o capture.o track.o http80.o wire.o core_httpup_logic.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_udp_hold.c udp_hold.o udp_release.o hold.o capture.o track.o http80.o wire.o core_httpup_logic.o $(LDFLAGS)

udp_path.o: udp_path.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Владение ID в обвязке d2kd (задача 46, ревью M4): сессия, удержание и
# выпуск — настоящие модули, сокеты заменены записью вызовов.
test_udp_path: test_udp_path.c udp_path.o udp_hold.o udp_release.o routemark.o session.o http80.o hold.o capture.o nat.o ctq.o nl.o track.o tls.o wire.o wire_udp.o journal.o plans.o plan_parse.o plan_apply.o $(COREOBJ) $(QUIC_FIXTURE_OBJ) $(HDR)
	$(CC) $(CFLAGS) -o $@ test_udp_path.c udp_path.o udp_hold.o udp_release.o routemark.o session.o http80.o hold.o capture.o nat.o ctq.o nl.o track.o tls.o wire.o wire_udp.o journal.o plans.o plan_parse.o plan_apply.o $(COREOBJ) $(QUIC_FIXTURE_OBJ) $(LDFLAGS)

test-udp-path: test_udp_path
	./test_udp_path

routemark.o: routemark.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Какие метки клиента выбирают маршрут по политике (задача 47): разбор дампа
# RTM_GETRULE и сопоставление — без сокета.
test_routemark: test_routemark.c routemark.o nl.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_routemark.c routemark.o nl.o $(LDFLAGS)

test-routemark: test_routemark
	./test_routemark

test_udp_release: test_udp_release.c udp_release.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_udp_release.c udp_release.o $(LDFLAGS)

.PHONY: test-udp-release
test-udp-release: test_udp_release
	./test_udp_release

.PHONY: test-udp-hold
test-udp-hold: test_udp_hold
	./test_udp_hold

test_hold: test_hold.c hold.o capture.o track.o http80.o wire.o core_httpup_logic.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_hold.c hold.o capture.o track.o http80.o wire.o core_httpup_logic.o $(LDFLAGS)

.PHONY: test-hold
test-hold: test_hold
	./test_hold

test_capture: test_capture.c capture.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_capture.c capture.o $(LDFLAGS)

.PHONY: test-capture
test-capture: test_capture
	./test_capture

test_tls: test_tls.c tls.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_tls.c tls.o $(LDFLAGS)

# core/quic.c и core/crypto.c компилируются СЮДА, под именами core_quic.o и
# core_crypto.o — см. большой комментарий у CORE_DIR выше про то, почему не
# в ../core/.
core_quic.o: $(CORE_DIR)/quic.c $(COREHDR)
	$(CC) $(CFLAGS) -c -o $@ $<

core_quicsnap.o: $(CORE_DIR)/quicsnap.c $(COREHDR)
	$(CC) $(CFLAGS) -c -o $@ $<

core_quicwire.o: $(CORE_DIR)/quicwire.c $(COREHDR)
	$(CC) $(CFLAGS) -c -o $@ $<

core_crypto.o: $(CORE_DIR)/crypto.c $(COREHDR)
	$(CC) $(CFLAGS) -c -o $@ $<

core_ipfrag.o: $(CORE_DIR)/ipfrag.c $(COREHDR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Узнавание портала блокировки в ответе — тот же разбор, что был у d2khttp
# (задача 51): датапат видит запрос и ответ разными пакетами.
core_httpup_logic.o: $(CORE_DIR)/httpup_logic.c $(COREHDR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Вставка провайдера в открытый HTTP (задача 51).
http80.o: http80.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

test_http80: test_http80.c http80.o wire.o core_httpup_logic.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_http80.c http80.o wire.o core_httpup_logic.o $(LDFLAGS)

.PHONY: test-http80
test-http80: test_http80
	./test_http80

check: test-http80

# Запрос HTTP как вход плана (задача 51, шаг 4).
test_http_hello: test_http_hello.c session.o http80.o hold.o capture.o nat.o track.o tls.o wire.o wire_udp.o journal.o plans.o plan_parse.o plan_apply.o $(COREOBJ) $(HDR)
	$(CC) $(CFLAGS) -o $@ test_http_hello.c session.o http80.o hold.o capture.o nat.o track.o tls.o wire.o wire_udp.o journal.o plans.o plan_parse.o plan_apply.o $(COREOBJ) $(LDFLAGS)

.PHONY: test-http-hello
test-http-hello: test_http_hello
	./test_http_hello

check: test-http-hello

test_http_trace: test_http_trace.c http_trace.o http80.o wire.o core_httpup_logic.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_http_trace.c http_trace.o http80.o wire.o core_httpup_logic.o $(LDFLAGS)
.PHONY: test-http-trace
test-http-trace: test_http_trace
	./test_http_trace
check: test-http-trace

core_quichello.o: $(CORE_DIR)/quichello.c $(COREHDR) $(CORE_DIR)/include/d2k_quichello.h $(CORE_DIR)/include/d2k_hello.h
	$(CC) $(CFLAGS) -c -o $@ $<

# hello.c #include'ит сгенерированный core/hello_profiles.inc: на чистом
# дереве (CI) его ещё нет, если ядро не собиралось раньше датапата.
$(CORE_DIR)/hello_profiles.inc:
	$(MAKE) -C $(CORE_DIR) hello_profiles.inc

core_hello.o: $(CORE_DIR)/hello.c $(COREHDR) $(CORE_DIR)/include/d2k_hello.h $(CORE_DIR)/hello_profiles.inc
	$(CC) $(CFLAGS) -c -o $@ $<

core_tls13core.o: $(CORE_DIR)/tls13core.c $(COREHDR) $(CORE_DIR)/include/d2k_tls13core.h
	$(CC) $(CFLAGS) -c -o $@ $<

core_x25519.o: $(CORE_DIR)/x25519.c $(COREHDR)
	$(CC) $(CFLAGS) -c -o $@ $<

# session.c — единственный потребитель разбора QUIC в датапате (задача 4),
# поэтому единственная новая зависимость по ссылке — здесь.
session.o: session.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

journal.o: journal.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

plans.o: plans.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

ctl.o: ctl.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

# ctlsrv.o и вся цепочка session.o добавлены задачей про вытеснение таблицы
# планов: test_ctl проверял только framing сокета (d2k_ctl.c), а разбор
# команд SET_NAME/SET_ADDR (d2k_ctlsrv_command, ctlsrv.c) не проверялся
# настоящим кадром вовсе — отказ «нет места» от отказа «план негоден»
# различимы на уровне ЭТОГО разбора, и подделывать его нельзя (см. шапку
# файла). Тот же список объектников, что у test_session/ctlprobe.
test_ctl: test_ctl.c ctl.o ctlsrv.o session.o http80.o hold.o capture.o nat.o ctq.o nl.o journal.o track.o tls.o wire.o \
          wire_udp.o plans.o plan_parse.o plan_apply.o core_quic.o core_quicwire.o \
          core_crypto.o core_ipfrag.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_ctl.c ctl.o ctlsrv.o session.o http80.o hold.o capture.o nat.o ctq.o nl.o journal.o \
	    track.o tls.o wire.o wire_udp.o plans.o plan_parse.o plan_apply.o \
	    $(COREOBJ) $(LDFLAGS)

test_plans: test_plans.c plans.o plan_parse.o plan_apply.o $(COREOBJ) $(HDR)
	$(CC) $(CFLAGS) -o $@ test_plans.c plans.o plan_parse.o plan_apply.o $(COREOBJ) $(LDFLAGS)

test_journal: test_journal.c journal.o track.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_journal.c journal.o track.o $(LDFLAGS)

# wire_udp.o и core_quic.o/core_crypto.o добавлены задачей 4: session.c теперь
# зовёт d2k_wire_build_udp и разбор QUIC на UDP-ветке пакетного пути, и без
# них линковка падает неопределёнными ссылками.
test_session: test_session.c session.o http80.o hold.o capture.o nat.o ctq.o nl.o track.o tls.o wire.o wire_udp.o journal.o plans.o plan_parse.o plan_apply.o $(COREOBJ) $(HDR)
	$(CC) $(CFLAGS) -o $@ test_session.c session.o http80.o hold.o capture.o nat.o ctq.o nl.o track.o tls.o wire.o wire_udp.o journal.o plans.o plan_parse.o plan_apply.o $(COREOBJ) $(LDFLAGS)

# test_quic_session.c (задача 4) — то же самое дерево модулей, что и
# test_session, тем же списком объектников: обе проверяют d2k_session_packet
# целиком, только на разных транспортах.
test_quic_session: test_quic_session.c session.o http80.o hold.o capture.o nat.o ctq.o nl.o track.o tls.o wire.o wire_udp.o journal.o plans.o plan_parse.o plan_apply.o $(COREOBJ) $(QUIC_FIXTURE_OBJ) $(HDR)
	$(CC) $(CFLAGS) -o $@ test_quic_session.c session.o http80.o hold.o capture.o nat.o ctq.o nl.o track.o tls.o wire.o wire_udp.o journal.o plans.o plan_parse.o plan_apply.o $(COREOBJ) $(QUIC_FIXTURE_OBJ) $(LDFLAGS)

# Keep the STUN datapath proof independently runnable while QUIC acceptance is deferred.
test_stun_session: test_stun_session.c session.o http80.o hold.o capture.o nat.o ctq.o nl.o track.o tls.o wire.o wire_udp.o journal.o plans.o plan_parse.o plan_apply.o $(COREOBJ) $(QUIC_FIXTURE_OBJ) $(HDR)
	$(CC) $(CFLAGS) -o $@ test_stun_session.c session.o http80.o hold.o capture.o nat.o ctq.o nl.o track.o tls.o wire.o wire_udp.o journal.o plans.o plan_parse.o plan_apply.o $(COREOBJ) $(QUIC_FIXTURE_OBJ) $(LDFLAGS)

track.o: track.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

test_track: test_track.c track.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_track.c track.o $(LDFLAGS)

wire.o: wire.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

wire_udp.o: wire_udp.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Трансляция NAT: каким адресом поток виден серверу. Нужна ПОТОМУ, что
# очередь висит на mangle POSTROUTING, а SNAT делается позже — см. d2k_nat.h.
nat.o: nat.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

test_nat: test_nat.c nat.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_nat.c nat.o $(LDFLAGS)

test-nat: test_nat
	./test_nat

ctq.o: ctq.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

test_ctq: test_ctq.c ctq.o nl.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_ctq.c ctq.o nl.o $(LDFLAGS)

.PHONY: test-ctq
test-ctq: test_ctq
	./test_ctq

check: test-ctq

nl.o: nl.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

test_nl: test_nl.c nl.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_nl.c nl.o $(LDFLAGS)

sched.o: sched.c $(HDR)
	$(CC) $(CFLAGS) -c -o $@ $<

test_sched: test_sched.c sched.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_sched.c sched.o $(LDFLAGS)

test_wire: test_wire.c wire.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_wire.c wire.o $(LDFLAGS)

test_wire_udp: test_wire_udp.c wire_udp.o $(HDR)
	$(CC) $(CFLAGS) -o $@ test_wire_udp.c wire_udp.o $(LDFLAGS)

test_plan_apply: test_plan_apply.c plan_parse.o plan_apply.o wire_udp.o $(COREOBJ) $(HDR) $(CORE_DIR)/test_quic_vector.h
	$(CC) $(CFLAGS) -o $@ test_plan_apply.c plan_parse.o plan_apply.o wire_udp.o $(COREOBJ) $(LDFLAGS)

planlab: planlab.c plan_parse.o plan_apply.o $(COREOBJ) $(HDR)
	$(CC) $(CFLAGS) -o $@ planlab.c plan_parse.o plan_apply.o $(COREOBJ) $(LDFLAGS)

# Стенд управляющего сокета: тот же разбор команд и та же сессия, что в d2kd,
# но пакеты собираются на месте. Нужен, чтобы Go-клиент проверялся против
# настоящего C-сервера, а не против представления о нём.
#
# $(COREOBJ) добавлен задачей 4 по той же причине, что и у test_session: SRC
# содержит session.c, а он теперь зовёт разбор QUIC — без объектников ядра
# ссылки останутся неопределёнными.
ctlprobe: ctlprobe.c $(SRC:.c=.o) $(COREOBJ) $(HDR)
	$(CC) $(CFLAGS) -o $@ ctlprobe.c $(SRC:.c=.o) $(COREOBJ) $(LDFLAGS)

test-parse: test_plan_parse
	./test_plan_parse

test-apply: test_plan_apply
	./test_plan_apply

test-tls: test_tls
	./test_tls

test-wire: test_wire
	./test_wire

test-wire-udp: test_wire_udp
	./test_wire_udp

test-track: test_track
	./test_track

test-session: test_session
	./test_session

test-nl: test_nl
	./test_nl

test-sched: test_sched
	./test_sched

test-journal: test_journal
	./test_journal

test-plans: test_plans
	./test_plans

test-ctl: test_ctl
	./test_ctl

test-quic-session: test_quic_session
	./test_quic_session

test-stun-session: test_stun_session
	./test_stun_session

# Тот же набор под санитайзерами. «Не упало» и «не читало за буфером» — разные
# утверждения, а весь датапат состоит из разбора чужих байтов. Отдельная цель,
# потому что -fsanitize замедляет и не собирается частью кросс-компиляторов.
#
# planlab добавлен отдельным шагом, а не в TESTS: он не самопроверяющийся
# бинарник (нет CHECK/fails), а инструмент со своим argv. Но именно planlab —
# доказательство того, что план делает НА ПРОВОДЕ (см. шапку planlab.c), и
# самый рискованный класс UB (сравнение указателей из разных выделений) этот
# набор санитайзеров и так ловит плохо — тем более нельзя оставлять сам
# инструмент несобранным с той же строгостью, что и остальной датапат.
SANFLAGS = -std=c99 -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
           -fno-omit-frame-pointer -Wall -Wextra -Werror -Iinclude -I$(CORE_DIR)/include
san: $(CORE_DIR)/hello_profiles.inc
	@set -e; for t in $(TESTS); do \
		echo "== $$t =="; \
		extra=; if [ "$$t" = test_quic_session ] || [ "$$t" = test_stun_session ] || [ "$$t" = test_udp_path ]; then extra="$(CORE_DIR)/quichello.c $(CORE_DIR)/hello.c $(CORE_DIR)/tls13core.c $(CORE_DIR)/x25519.c"; fi; \
		$(CC) $(SANFLAGS) -o /tmp/d2k-san-$$t $$t.c \
			$$(echo "$(SRC)" | tr ' ' '\n' | grep -v '^$$') $(CORESRC) $$extra; \
		/tmp/d2k-san-$$t; \
	done
	@echo "== planlab =="
	@$(CC) $(SANFLAGS) -o /tmp/d2k-san-planlab planlab.c plan_parse.c plan_apply.c $(CORESRC)
	@/tmp/d2k-san-planlab testdata/fake_before.tlv testdata/one_hello.txt >/dev/null
	@echo "санитайзеры: все проверки прошли"

# Тот же набор ЧУЖИМ компилятором. Не роскошь: локально всё собирает clang, а
# CI — gcc, и они расходятся. gcc ловит sign-compare там, где clang молчит, и
# из-за этого КАЖДЫЙ прогон CI был красным с первого коммита, пока локальный
# гейт горел зелёным. Компиляция без запуска: цель тут — предупреждения, а
# исполняются те же тесты обычной целью check.
#
# Берётся кросс-компилятор под mipsel, потому что это настоящий gcc и он уже
# нужен для переносимости. Переопределяется через GCC=.
GCC ?= mipsel-unknown-linux-gnu-gcc
gcc-warn:
	@for f in $(SRC) $(CORESRC) $(LINUXSRC) $(DAEMON) planlab.c ctlprobe.c $(TESTS:=.c); do \
		$(GCC) $(CFLAGS) -c -o /tmp/d2k-gccwarn.o $$f || exit 1; \
	done
	@echo "чужой компилятор: предупреждений нет"

# Переносимость проверяется компиляцией под целевые арки. Запускать там нечего
# и не нужно: ловим порядок байт, выравнивание и ширину типов. planlab слинкован
# целиком по той же причине, что и d2kd целиком чуть ниже: компиляция
# по-файлово в цикле выше не гарантирует, что именно ЭТА комбинация объектов
# слинкуется под обеими целевыми libc.
cross:
	@for f in $(SRC) $(CORESRC); do \
		echo "== $$f =="; \
		$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -c -o /tmp/d2k-a64.o $$f || exit 1; \
		$(ZIG) cc $(MIPS_BE_ZIG) $(CFLAGS) -c -o /tmp/d2k-mips.o $$f || exit 1; \
		$(MIPSEL_CC) $(CFLAGS) -c -o /tmp/d2k-mipsel.o $$f || exit 1; \
	done
	@echo "== d2kd целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/d2kd-a64 \
		$(DAEMON) $(LINUXSRC) $(SRC) $(CORESRC) || exit 1
	@$(ZIG) cc $(MIPS_BE_ZIG) $(CFLAGS) -o /tmp/d2kd-mips \
		$(DAEMON) $(LINUXSRC) $(SRC) $(CORESRC) || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/d2kd-mipsel $(DAEMON) $(LINUXSRC) $(SRC) $(CORESRC) || exit 1
	@echo "== planlab целиком =="
	@$(ZIG) cc -target aarch64-linux-musl $(CFLAGS) -o /tmp/planlab-a64 \
		planlab.c plan_parse.c plan_apply.c $(CORESRC) || exit 1
	@$(ZIG) cc $(MIPS_BE_ZIG) $(CFLAGS) -o /tmp/planlab-mips \
		planlab.c plan_parse.c plan_apply.c $(CORESRC) || exit 1
	@$(MIPSEL_CC) $(CFLAGS) -o /tmp/planlab-mipsel planlab.c plan_parse.c plan_apply.c $(CORESRC) || exit 1
	@# Big-endian mips НАСТОЯЩИМ gcc — отдельным блоком, потому что этой цепочки
	@# на машине разработки обычно нет, и «не нашлась» не должна ронять
	@# переносимость целиком (тот же приём, что в detect/Makefile). Порядок байт
	@# уже проверен zig-проходами выше; gcc добавляет к ним свои предупреждения.
	@if command -v $(MIPS_CC) >/dev/null 2>&1; then \
	  echo "== big-endian mips: $(MIPS_CC) =="; \
	  for f in $(SRC) $(CORESRC); do \
	    $(MIPS_CC) $(CFLAGS) -c -o /tmp/d2k-mips-gcc.o $$f || exit 1; \
	  done; \
	  rm -f /tmp/d2k-mips-gcc.o; \
	  $(MIPS_CC) $(CFLAGS) -o /tmp/d2kd-mips-gcc $(DAEMON) $(LINUXSRC) $(SRC) $(CORESRC) || exit 1; \
	else \
	  echo "cross: $(MIPS_CC) не найден — big-endian mips проверен zig-проходом выше"; \
	fi
	@echo "переносимость: aarch64, mipsel и big-endian mips собираются, служба линкуется"

# Служба ДЛЯ ЭТОЙ ЖЕ МАШИНЫ. Не удобство, а проверка: лаборатория установки
# (scripts/lab-install.sh) ставит то, что собрала сама, а не то, что кто-то
# положил в builds/ неизвестно когда и из какого дерева.
#
# На маке НЕ СОБИРАЕТСЯ и не должна: nfq.c/raw.c — Linux (см. LINUXSRC выше).
# Отказ здесь честен; подделывать сокеты ядра ради сборки значило бы
# проверять подделку.
d2kd: $(DAEMON) $(LINUXSRC) $(SRC) $(CORESRC) $(HDR)
	$(CC) $(CFLAGS) -o $@ $(DAEMON) $(LINUXSRC) $(SRC) $(CORESRC) $(LDFLAGS)

# Служба для целевого устройства. Статическая musl: на роутере нет ни нужной
# libc, ни желания зависеть от той, что там есть.
#
# ИМЯ ФАЙЛА — то же, что у сборок Go (builds/d2k-linux-arm64): его ищет
# scripts/install.sh, и расхождение здесь означало бы «скачанного файла нет»
# на живом роутере. Одно имя на всё, а не два похожих.
BUILDDIR ?= ../builds
TARGET ?= aarch64-linux-musl
TARGET_FLAGS ?=
ARCH ?= arm64
.PHONY: release
d2kd-linux-arm64: release
release:
	@mkdir -p $(BUILDDIR)
	$(ZIG) cc -target $(TARGET) $(TARGET_FLAGS) $(CFLAGS) -static -Wl,-S \
		-o $(BUILDDIR)/d2kd-linux-$(ARCH) $(DAEMON) $(LINUXSRC) $(SRC) $(CORESRC)
	@ls -l $(BUILDDIR)/d2kd-linux-$(ARCH)

# planlab тоже в зависимостях, и это не украшение: он собирается отдельной
# целью, поэтому однажды check остался зелёным при несобирающейся
# лаборатории. Проверка, не собирающая всё, что есть, проверяет не дерево.
test_ctlprobe: test_ctlprobe.c ctlprobe
	$(CC) $(CFLAGS) -o $@ test_ctlprobe.c $(LDFLAGS)

test-ctlprobe: test_ctlprobe
	./test_ctlprobe

.PHONY: test-ctlprobe

check: all test-hold test-udp-hold test-udp-release test-udp-path test-routemark test-capture test-parse test-apply test-tls test-wire test-wire-udp test-track test-session test-nat test-nl test-sched test-journal test-plans test-ctl test-stun-session test-quic-session test-ctlprobe

clean:
	rm -f *.o $(TESTS) test_ctlprobe test_raw_cap planlab ctlprobe d2kd
