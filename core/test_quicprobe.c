/* test_quicprobe.c — вопросник по QUIC проверяется в ДВЕ РАЗНЫЕ СТОРОНЫ,
 * умышленно разными средствами:
 *
 * 1. ДИСЦИПЛИНА ДЕРЕВА (порядок вопросов, УСЛОВНАЯ ротация адреса — только
 *    после обнаружения остаточной блокировки, бюджет, учёт метки и приём
 *    "N из K" на каждом шаге, "незаданный, а не проваленный") — через
 *    подмену d2k_quic_ask_hook. Причина не лень: чтобы честно проверить
 *    ротацию, нужно НЕСКОЛЬКО РАЗЛИЧИМЫХ адресов назначения, а bind() на
 *    127.0.0.x при x≠1 без явного алиаса интерфейса на macOS падает с "Can't
 *    assign requested address" (проверено эмпирически) — настоящий
 *    многоадресный стенд здесь непереносим. Мок ДОПОЛНИТЕЛЬНО умеет
 *    форсировать ЛЮБОЙ d2k_tally (частичный результат, ошибку транспорта,
 *    непровтверждённую метку) на конкретный вызов через очередь — без этого
 *    учёт метки и приём "2 из 3" на шагах 2-4 не доказаны ничем, кроме
 *    честного слова (см. находку 4 ревью 2026-09-06, круг 2: шесть мутаций
 *    ревьюера прошли зелёными именно потому, что обычная, детерминированная
 *    по содержимому модель стенда не умела ни того, ни другого).
 *
 * 2. САМ ОРАКУЛ (шифрование, аутентичность и ПРОГРЕСС рукопожатия в ответе,
 *    реальный ICMP при закрытом порте, согласование версии, реальные часы
 *    бюджета) — НАСТОЯЩИМИ сокетами на единственном настоящем адресе
 *    127.0.0.1. Стенд честно шифрует ответ (AES-128-GCM, "server in") —
 *    d2k_ghash_for_test здесь уместен ПО ПРЯМОМУ НАЗНАЧЕНИЮ (см. d2k_crypto.h:
 *    "не для общего пользования" — про продакшен-код, не про тестовый стенд).
 *
 * Так дисциплина дерева проверяется без сетевых допущений, а оракул — без
 * подмены сети.
 */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "d2k_crypto.h"
#include "d2k_meas.h"
#include "d2k_quic.h"
#include "d2k_quic_arms.h"
#include "d2k_quicprobe.h"
#include "test_quic_pq.h"
#include "d2k_quicsnap.h"
#include "d2k_quichello.h"
#include "d2k_quicwire.h"
#include "test_quic_vector.h"

static int g_progress_sum, g_progress_calls;
static char g_progress_last[96];
static void record_progress(const char *question, int probes)
{
    g_progress_calls++;
    g_progress_sum += probes;
    snprintf(g_progress_last, sizeof g_progress_last, "%s", question ? question : "");
}


static int fails;
#define CHECK(cond, msg)                          \
    do {                                           \
        if (!(cond)) {                             \
            printf("ПРОВАЛ: %s\n", (msg));         \
            fails++;                               \
        }                                          \
    } while (0)

/* ---------------------------------------------------------------------
 * Снимки: минимально валидные заголовки Initial v1. Тело после заголовка
 * для НАШИХ отправляемых снимков не обязано разбираться как ClientHello:
 * quicprobe.c не расшифровывает то, что сам отправляет — только извлекает
 * DCID (см. шапку quicprobe.c). DCID у триггера и контроля РАЗНЫЙ, чтобы
 * стенд из части 2 мог вывести им разные ключи.
 * --------------------------------------------------------------------- */

static size_t build_plain_initial(uint8_t dcid_byte, uint8_t *out, size_t cap) {
    uint8_t dcid[8];
    memset(dcid, dcid_byte, sizeof dcid);
    if (cap < 5 + 1 + 8 + 1 + 1 + 1 + 1 + 36) {
        return 0;
    }
    size_t off = 0;
    out[off++] = 0xC0;
    out[off++] = 0x00;
    out[off++] = 0x00;
    out[off++] = 0x00;
    out[off++] = 0x01;
    out[off++] = 0x08;
    memcpy(out + off, dcid, 8);
    off += 8;
    out[off++] = 0x00; /* scid_len */
    out[off++] = 0x00; /* token varint 0 */
    out[off++] = 0x25; /* length varint (1 байт): pn(1)+тело(20)+тег(16)=37 */
    out[off] = 0x00;   /* pn */
    off += 1;
    for (int i = 0; i < 36; i++) {
        out[off + (size_t)i] = (uint8_t)(0xA0 + i);
    }
    off += 36;
    return off;
}

/* Настоящий Initial с БОЛЬШИМ приветствием (как у браузеров с ML-KEM):
 * ClientHello вектора RFC 9001 A.2, дополненный расширением padding (0x0015)
 * на pad байт, запечатанный обычными ключами Initial. Датаграмма — ровно по
 * содержимому, без добивки. 0 — не собралось. */
static size_t build_large_snapshot(size_t pad, uint8_t *out, size_t cap) {
    uint8_t ch[D2K_QW_MAX_DGRAM];
    size_t ch_len = 0;
    if (d2k_quic_client_hello(d2k_test_v1_initial, sizeof d2k_test_v1_initial,
                              ch, sizeof ch, &ch_len) != 0 || ch_len < 4 + 2 + 32 + 1) {
        return 0;
    }
    size_t o = 4 + 2 + 32;
    o += 1 + ch[o];                               /* session id */
    o += 2 + ((size_t)ch[o] << 8 | ch[o + 1]);    /* cipher suites */
    o += 1 + ch[o];                               /* compression */
    size_t ext_len_off = o;
    size_t ext_len = (size_t)ch[o] << 8 | ch[o + 1];
    if (ext_len_off + 2 + ext_len != ch_len || ch_len + 4 + pad > sizeof ch) {
        return 0;
    }
    ch[ch_len++] = 0x00; ch[ch_len++] = 0x15;
    ch[ch_len++] = (uint8_t)(pad >> 8); ch[ch_len++] = (uint8_t)pad;
    memset(ch + ch_len, 0, pad);
    ch_len += pad;
    ext_len += 4 + pad;
    ch[ext_len_off] = (uint8_t)(ext_len >> 8); ch[ext_len_off + 1] = (uint8_t)ext_len;
    size_t hs = ch_len - 4;
    ch[1] = (uint8_t)(hs >> 16); ch[2] = (uint8_t)(hs >> 8); ch[3] = (uint8_t)hs;

    uint8_t body[D2K_QW_MAX_DGRAM];
    size_t b = 0;
    body[b++] = 0x06;                              /* CRYPTO */
    body[b++] = 0x00;                              /* offset 0 */
    b += d2k_qw_varint_write(body + b, sizeof body - b, ch_len);
    if (b + ch_len > sizeof body) { return 0; }
    memcpy(body + b, ch, ch_len);
    b += ch_len;
    static const uint8_t dcid[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t sec[32];
    d2k_qw_keys k;
    if (d2k_qw_initial_secret(D2K_QW_V1, dcid, sizeof dcid, D2K_QW_CLIENT, sec) != 0 ||
        d2k_qw_keys_from_secret(D2K_QW_V1, sec, &k) != 0) {
        return 0;
    }
    uint8_t hdr[64];
    size_t hlen = d2k_qw_long_hdr(hdr, sizeof hdr, D2K_QW_V1, D2K_QW_LT_INITIAL,
                                  dcid, sizeof dcid, NULL, 0, 4, b);
    if (hlen == 0) { return 0; }
    return d2k_qw_seal(&k, 1, hdr, hlen, 0, 4, body, b, out, cap);
}

#define QP_DCID_OFF 6
#define QP_DCID_LEN 8

static uint8_t g_trig_buf[64], g_ctl_buf[2048];
static size_t g_trig_len, g_ctl_len;
static const uint8_t *g_trig_bytes, *g_ctl_bytes;

/* ---------------------------------------------------------------------
 * Часть 1: подмена оракула — дисциплина дерева.
 * --------------------------------------------------------------------- */

struct mock_addr_state {
    char addr[D2K_QUIC_ADDR_LEN];
    int poisoned;
};
static struct mock_addr_state g_mock_states[16];
static size_t g_mock_n;
static int g_mock_mark_ok = 1;
static int g_mock_garbage_defeats;
/* 1 (умолчание) — триггер поражает адрес остаточной блокировкой, как и
 * положено сработавшей коробке. 0 — нужен отдельному сценарию: коробка
 * молчит на триггер, но остаточной блокировки НЕТ. */
static int g_mock_poison_on_trigger = 1;
/* Сколько вопросов мок получил датаграммой ровно в 1300 байт. */
static int g_mock_len_1300;
/* Если не пустая строка — контроль молчит ИМЕННО на этом адресе (и только на
 * нём), остальные адреса отвечают как обычно. Раньше был глобальный
 * g_mock_ctl_dead (молчит контроль ВЕЗДЕ) — с появлением базовой живости
 * (шаг 0, тоже контроль на pool[0]) это стало ломать её без причины;
 * per-адресный флаг нацеливает "мёртвый сервер" ровно на нужный шаг. */
static char g_mock_dead_addr[D2K_QUIC_ADDR_LEN];
static int g_expect_no_sni, g_no_sni_failures, g_arm_calls;

/* Очередь принудительных исходов — см. шапку файла и находку 4 ревью (круг 2).
 * g_mock_force_refused — ПАРАЛЛЕЛЬНЫЙ массив (не поле d2k_tally: refused —
 * отдельный out-параметр хука, находка 5 ревью, круг 4), нужен находке 2
 * ревью круга 5: без него мок не мог отдать pass>0 ОДНОВРЕМЕННО с refused>0
 * — смешанный исход (цель ответила, но не на все три попытки, часть отказана
 * сетью), которым проверяется вложенность порога refused>0 внутрь pass==0. */
#define MOCK_FORCE_MAX 8
static d2k_tally g_mock_force[MOCK_FORCE_MAX];
static int g_mock_force_refused[MOCK_FORCE_MAX];
static size_t g_mock_force_n, g_mock_force_i;

static void mock_force_push_refused(int pass, int fail, int err, int marked, int refused) {
    d2k_tally t;
    t.pass = pass;
    t.fail = fail;
    t.err = err;
    t.marked = marked;
    g_mock_force_refused[g_mock_force_n] = refused;
    g_mock_force[g_mock_force_n++] = t;
}

static void mock_force_push(int pass, int fail, int err, int marked) {
    mock_force_push_refused(pass, fail, err, marked, 0);
}

static void mock_reset(void) {
    g_mock_n = 0;
    memset(g_mock_states, 0, sizeof g_mock_states);
    g_mock_mark_ok = 1;
    g_mock_garbage_defeats = 0;
    g_mock_poison_on_trigger = 1;
    g_mock_dead_addr[0] = '\0';
    g_mock_force_n = 0;
    g_mock_force_i = 0;
}

static struct mock_addr_state *mock_state_for(const char *addr) {
    for (size_t i = 0; i < g_mock_n; i++) {
        if (strcmp(g_mock_states[i].addr, addr) == 0) {
            return &g_mock_states[i];
        }
    }
    struct mock_addr_state *s = &g_mock_states[g_mock_n++];
    memset(s, 0, sizeof *s);
    strncpy(s->addr, addr, sizeof s->addr - 1);
    return s;
}

/* Модель: адрес, увидевший ТРИГГЕР (и не защищённый мусором-обманкой),
 * "поражается" и с этого момента молчит НА ЛЮБОЕ содержимое — ровно то
 * поведение остаточной блокировки, которое описывает донор (USENIX Sec'25 по
 * GFW). Контроль проходит на непоражённом адресе, кроме g_mock_dead_addr
 * (сервер, который сам недоступен). */
static d2k_tally mock_ask(const char *addr, uint16_t port,
                           const uint8_t *prefix, size_t prefix_len,
                           d2k_hello msg, uint32_t wait_ms, uint32_t mark,
                           int repeats, uint32_t *rtt_ms_out, int *refused_out, int *sent_out,
                           uint8_t *ttl_in_out) {
    (void)port;
    (void)wait_ms;
    if (ttl_in_out) { *ttl_in_out = 0; } /* мок сокетов не трогает: TTL взять неоткуда */
    /* Мок проверяет ДИСЦИПЛИНУ ДЕРЕВА по содержимому, не сетевые коды
       ошибок — различие "не отправилось" от "отправилось и получило отказ"
       (находка 5 ревью, круг 4) проверяется НАСТОЯЩИМИ, ПЕРЕНОСИМЫМИ
       (Linux и macOS) сокетами в Части 2, не здесь: мок никогда не "не
       отправляет" содержательно, поэтому sent_out тут всегда repeats —
       вся семантика "не ушло на провод" живёт в quic_ask_ex, не в моке
       (находка 1 ревью, круг 5: порт 0 не был переносим, заменён на
       255.255.255.255 — вещание без SO_BROADCAST, отказ на связи, а не в
       выдумке этого мока). refused_out мок отдаёт ТОЛЬКО из принудительной
       очереди (находка 2 ревью, круг 5: без этого нельзя было проверить
       вложенность порога refused>0 внутрь pass==0 — обычная,
       детерминированная по содержимому логика мока никогда сама не
       порождает refused>0). */
    if (sent_out) {
        *sent_out = repeats;
    }
    if (msg.len == 1300) {
        g_mock_len_1300++;
    }
    d2k_tally t;
    if (g_mock_force_i < g_mock_force_n) {
        size_t idx = g_mock_force_i;
        t = g_mock_force[g_mock_force_i++];
        if (refused_out) {
            *refused_out = g_mock_force_refused[idx];
        }
    } else {
        if (refused_out) {
            *refused_out = 0;
        }
        struct mock_addr_state *st = mock_state_for(addr);
        memset(&t, 0, sizeof t);
        t.marked = (mark == 0) || g_mock_mark_ok;
        int is_trig = (msg.bytes == g_trig_bytes && msg.len == g_trig_len);
        int is_ctl = (msg.bytes == g_ctl_bytes && msg.len == g_ctl_len);
        if (g_expect_no_sni && !is_ctl && msg.bytes && msg.len) {
            char seen_sni[256];
            if (d2k_quic_sni(msg.bytes, msg.len, seen_sni, sizeof seen_sni) == 0) {
                g_no_sni_failures++;
            }
        }
        int is_dead = (g_mock_dead_addr[0] != '\0' && strcmp(addr, g_mock_dead_addr) == 0);
        for (int i = 0; i < repeats; i++) {
            int passed;
            if (st->poisoned) {
                passed = 0; /* остаточная блокировка: тишина НА ЛЮБОЕ содержимое */
            } else if (is_trig) {
                if (prefix && prefix_len > 0 && g_mock_garbage_defeats) {
                    passed = 1; /* мусор перед Initial "сбил" разбор коробки */
                } else {
                    if (g_mock_poison_on_trigger) {
                        st->poisoned = 1; /* коробка увидела триггер и сработала */
                    }
                    passed = 0;
                }
            } else if (is_ctl) {
                passed = is_dead ? 0 : 1;
            } else {
                passed = 0;
            }
            if (passed) {
                t.pass++;
            } else {
                t.fail++;
            }
        }
    }
    if (rtt_ms_out) {
        *rtt_ms_out = (t.pass > 0) ? 10u : 0u;
    }
    return t;
}

static d2k_tally mock_arm(const d2k_quic_arm_question *q, const char *sni,
                          uint16_t port, uint32_t wait_ms, uint32_t mark,
                          int *sent_out) {
    (void)q; (void)port; (void)wait_ms; (void)mark;
    uint8_t initial[1500]; size_t initial_len = 0;
    char seen_sni[256];
    g_arm_calls++;
    if (q && q->control) {
        /* Выживаемость фрагментов: имени у вызывающего нет, провод сам
           берёт свежий neutralName() на каждую попытку (arms.go:204-205). */
        if (sni) {
            g_no_sni_failures++;
        }
    } else {
        int built = sni && d2k_quic_probe_initial(sni, initial, sizeof initial,
                                                   &initial_len) == 0;
        int has_sni = built &&
            d2k_quic_sni(initial, initial_len, seen_sni, sizeof seen_sni) == 0;
        if (!built || has_sni) {
            g_no_sni_failures++;
        }
    }
    if (sent_out) { *sent_out = D2K_QUIC_REPEATS; }
    d2k_tally t = {0};
    t.fail = D2K_QUIC_REPEATS;
    t.marked = 1;
    return t;
}

/* Вопросы 4 и 7 ходят своими хуками (пара датаграмм и низкий исходный порт —
 * см. d2k_quicprobe.h, почему не расширением d2k_quic_ask_fn). Подменять надо
 * и их: неподменённый хук — это НАСТОЯЩИЕ сокеты в наружную сеть прямо из
 * теста, то есть минуты ожидания и вердикт, зависящий от чужой линии. Обе
 * заглушки сводятся к тому же mock_ask — вопросник проверяется по дисциплине
 * (что задано, что записано), а не по транспорту. */
static d2k_tally mock_ask_srcport(const char *addr, uint16_t port, int src_port,
                                   d2k_hello msg, uint32_t wait_ms, uint32_t mark,
                                   int repeats, int *sent_out) {
    (void)src_port;
    return mock_ask(addr, port, NULL, 0, msg, wait_ms, mark, repeats, NULL, NULL, sent_out, NULL);
}

static d2k_tally mock_ask_split(const char *addr, uint16_t port, d2k_hello snap,
                                 const char *sni, uint32_t wait_ms, uint32_t mark,
                                 int repeats, int *sent_out) {
    (void)sni;
    return mock_ask(addr, port, NULL, 0, snap, wait_ms, mark, repeats, NULL, NULL, sent_out, NULL);
}

static char g_extra_pool[8][D2K_QUIC_ADDR_LEN];
static size_t g_extra_n;

/* trigger/control — параметры d2k_quic_classify (правка ревью 2026-09-06,
 * круг 1), не снимаются через крючок. no_hello() воспроизводит "снимка нет"
 * явно, тем же bytes==NULL, каким его увидел бы настоящий вызывающий. */
static d2k_hello trig_hello(void) {
    d2k_hello h = {0};
    h.bytes = g_trig_bytes;
    h.len = g_trig_len;
    return h;
}
static d2k_hello ctl_hello(void) {
    d2k_hello h = {0};
    h.bytes = g_ctl_bytes;
    h.len = g_ctl_len;
    return h;
}
static d2k_hello no_hello(void) {
    d2k_hello h = {0};
    h.bytes = NULL;
    h.len = 0;
    return h;
}

static size_t test_resolve(const char *sni, char out[][D2K_QUIC_ADDR_LEN], size_t cap) {
    (void)sni;
    size_t n = g_extra_n < cap ? g_extra_n : cap;
    for (size_t i = 0; i < n; i++) {
        memcpy(out[i], g_extra_pool[i], D2K_QUIC_ADDR_LEN);
    }
    return n;
}

/* Хук, который ВРЁТ про число адресов — заполняет ровно cap строк (честно, в
 * пределах своего буфера out), но СООБЩАЕТ, что их вдесятеро больше. Нужен
 * ровно одному тесту (находка 9 ревью, круг 2): без явного зажима n_extra в
 * d2k_quic_classify цикл дедупликации читал бы extra[i] ЗА ГРАНИЦЕЙ локального
 * массива вызывающего — порча памяти, ловится санитайзером (`make -C core
 * san`), а не только этим тестом на голой логике.
 *
 * ВСЕ строки — ОДИН И ТОТ ЖЕ адрес (10.9.9.9): если бы они были различны,
 * дедупликация в d2k_quic_classify заполнила бы пул (n_pool) первыми же
 * cap записями и остановила цикл СВОИМ ЖЕ условием (n_pool < MAX_ADDRS)
 * раньше, чем i дошло бы до границы массива extra[] — маскируя ровно ту
 * порчу памяти, которую тест обязан проверить (обнаружено при разработке
 * этого теста: с уникальными адресами санитайзер молчал). Одинаковый адрес
 * держит n_pool на единице и даёт i честно добежать до extra[cap]. */
static size_t misbehaving_resolve(const char *sni, char out[][D2K_QUIC_ADDR_LEN], size_t cap) {
    (void)sni;
    for (size_t i = 0; i < cap; i++) {
        snprintf(out[i], D2K_QUIC_ADDR_LEN, "10.9.9.9");
    }
    return cap * 10; /* заведомая ложь сверх cap */
}

/* ---------------------------------------------------------------------
 * Часть 2: настоящий оракул на 127.0.0.1 — честный AEAD в обратную сторону,
 * реальный ICMP, реальное согласование версии, реальные часы.
 * --------------------------------------------------------------------- */

static const uint8_t v1_salt[20] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};

static void qp_inc32(uint8_t b[16]) {
    for (int i = 15; i >= 12; i--) {
        b[i] = (uint8_t)(b[i] + 1);
        if (b[i] != 0) {
            break;
        }
    }
}

static void qp_ctr_xor(const uint8_t key[16], const uint8_t icb[16],
                        const uint8_t *in, size_t n, uint8_t *out) {
    uint8_t cb[16];
    memcpy(cb, icb, 16);
    size_t i = 0;
    while (i < n) {
        uint8_t ks[16];
        d2k_aes128_ecb(key, cb, ks);
        size_t take = n - i;
        if (take > 16) {
            take = 16;
        }
        for (size_t j = 0; j < take; j++) {
            out[i + j] = (uint8_t)(in[i + j] ^ ks[j]);
        }
        i += take;
        qp_inc32(cb);
    }
}

/* Тело ответа: 0x06 (CRYPTO) + смещение varint(0) + длина varint(N) + N байт
 * "ServerHello" — минимальный кадр, дающий qp_progressed увидеть прогресс
 * рукопожатия (находка 5 ревью, круг 2: аутентичности одной мало). */
static size_t build_crypto_body(uint8_t *out, size_t cap) {
    if (cap < 1 + 1 + 1 + 8) {
        return 0;
    }
    size_t off = 0;
    out[off++] = 0x06; /* CRYPTO */
    out[off++] = 0x00; /* offset varint = 0 */
    out[off++] = 0x08; /* length varint = 8 */
    memcpy(out + off, "SERVHELO", 8);
    off += 8;
    return off;
}

/* Тело ответа "вежливый отказ" — CONNECTION_CLOSE(0x1c) без единого CRYPTO;
 * аутентичный, но НЕ прогресс (та же находка 5). */
static size_t build_close_body(uint8_t *out, size_t cap) {
    if (cap < 1 + 1 + 1 + 1) {
        return 0;
    }
    size_t off = 0;
    out[off++] = 0x1c; /* CONNECTION_CLOSE, транспортный */
    out[off++] = 0x00; /* error code varint */
    out[off++] = 0x00; /* frame type varint */
    out[off++] = 0x00; /* reason length varint = 0 */
    return off;
}

static size_t build_authentic_v1(const uint8_t *dcid, size_t dcid_len,
                                  const uint8_t *plaintext, size_t pt_len,
                                  uint8_t *out, size_t cap) {
    size_t need_length = 1 + pt_len + 16;
    if (need_length >= 64 || dcid_len > 20) {
        return 0;
    }
    size_t hdr_len = 5 + 1 + dcid_len + 1 + 1 + 1 + 1;
    if (hdr_len + pt_len + 16 > cap) {
        return 0;
    }
    size_t off = 0;
    out[off++] = 0xC0;
    out[off++] = 0x00;
    out[off++] = 0x00;
    out[off++] = 0x00;
    out[off++] = 0x01;
    out[off++] = (uint8_t)dcid_len;
    memcpy(out + off, dcid, dcid_len);
    off += dcid_len;
    out[off++] = 0x00;
    out[off++] = 0x00;
    out[off++] = (uint8_t)need_length;
    size_t pn_offset = off;
    out[off] = 0x00;
    off += 1;

    uint8_t initial_secret[32], secret[32], key[16], iv[12], hp[16];
    d2k_hkdf_extract(v1_salt, sizeof v1_salt, dcid, dcid_len, initial_secret);
    if (d2k_hkdf_expand_label(initial_secret, "server in", secret, sizeof secret) != 0) {
        return 0;
    }
    if (d2k_hkdf_expand_label(secret, "quic key", key, sizeof key) != 0) {
        return 0;
    }
    if (d2k_hkdf_expand_label(secret, "quic iv", iv, sizeof iv) != 0) {
        return 0;
    }
    if (d2k_hkdf_expand_label(secret, "quic hp", hp, sizeof hp) != 0) {
        return 0;
    }

    uint8_t j0[16];
    memcpy(j0, iv, 12);
    j0[12] = 0;
    j0[13] = 0;
    j0[14] = 0;
    j0[15] = 1;

    uint8_t ct[256];
    uint8_t icb[16];
    memcpy(icb, j0, 16);
    qp_inc32(icb);
    qp_ctr_xor(key, icb, plaintext, pt_len, ct);

    uint8_t zero[16];
    memset(zero, 0, 16);
    uint8_t h[16];
    d2k_aes128_ecb(key, zero, h);
    uint8_t s[16];
    d2k_ghash_for_test(h, out, pn_offset + 1, ct, pt_len, s);
    uint8_t j0ks[16];
    d2k_aes128_ecb(key, j0, j0ks);
    uint8_t tag[16];
    for (int i = 0; i < 16; i++) {
        tag[i] = (uint8_t)(s[i] ^ j0ks[i]);
    }

    memcpy(out + off, ct, pt_len);
    off += pt_len;
    memcpy(out + off, tag, 16);
    off += 16;
    size_t total = off;

    size_t sample_off = pn_offset + 4;
    uint8_t mask[16];
    d2k_aes128_ecb(hp, out + sample_off, mask);
    out[0] = (uint8_t)(out[0] ^ (mask[0] & 0x0f));
    out[pn_offset] = (uint8_t)(out[pn_offset] ^ mask[1]);

    return total;
}

/* respond: 0 молчать; 1 ответить аутентично+CRYPTO на триггер и контроль; 2
 * ответить мусором (не аутентично); 3 ответить аутентично+CRYPTO ТОЛЬКО на
 * контроль (триггер молчит — нужно тесту на реальные часы бюджета); 4
 * ответить аутентично, но БЕЗ CRYPTO (только CONNECTION_CLOSE — находка 5). */
static volatile int g_rs_respond;
static int g_rs_fd = -1;
static pthread_t g_rs_thread;

static int is_neutral_control_packet(const uint8_t *packet, size_t packet_len) {
    char sni[256];
    if (d2k_quic_sni(packet, packet_len, sni, sizeof sni) != 0 ||
        strlen(sni) != 23 || sni[0] != 'z' || strcmp(sni + 11, ".example.com") != 0) {
        return 0;
    }
    for (size_t i = 1; i <= 10; i++) {
        if (!isdigit((unsigned char)sni[i]) && !(sni[i] >= 'a' && sni[i] <= 'f')) {
            return 0;
        }
    }
    return 1;
}

/* Кадр ACK (RFC 9000 §19.3): тип, наибольший номер, задержка, число
   диапазонов, первый диапазон. Ровно то, чем настоящий сервер отвечает
   первым, подтверждая приём, но ещё не начиная рукопожатие. */
static size_t build_ack_body(uint8_t *out, size_t cap) {
    if (cap < 5) { return 0; }
    out[0] = 0x02; /* ACK без ECN */
    out[1] = 0x01; /* наибольший подтверждённый номер */
    out[2] = 0x00; /* задержка */
    out[3] = 0x00; /* дополнительных диапазонов нет */
    out[4] = 0x01; /* первый диапазон */
    return 5;
}

/* Retry (RFC 9000 §17.2.5) для v1: тип 0b11 в битах 4-5, версия 1, свои
 * DCID/SCID, токен и 16 байт тега целостности. Тег НУЛЕВОЙ нарочно: донор
 * (z2k-detect/internal/quicprobe/parse.go:118-122) засчитывает Retry по
 * типу и версии, тег не проверяет — тест обязан закрепить ровно это. */
static size_t build_retry_v1(uint8_t *out, size_t cap) {
    static const uint8_t pkt[] = {
        0xF0, 0x00, 0x00, 0x00, 0x01,
        0x08, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
        0x08, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
        'T', 'O', 'K', 'E', 'N',
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    if (cap < sizeof pkt) return 0;
    memcpy(out, pkt, sizeof pkt);
    return sizeof pkt;
}

/* Version Negotiation (RFC 9000 §17.2.1): длинный заголовок, версия 0,
 * DCID/SCID, список версий. Донор (parse.go:110-116) узнаёт его по нулевой
 * версии, не сверяя CID с нашими. */
static size_t build_vn_reply(uint8_t *out, size_t cap) {
    static const uint8_t pkt[] = {
        0x80, 0x00, 0x00, 0x00, 0x00,
        0x08, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
        0x08, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
        0x00, 0x00, 0x00, 0x01};
    if (cap < sizeof pkt) return 0;
    memcpy(out, pkt, sizeof pkt);
    return sizeof pkt;
}

static int recv_fault_hostunreach(int fd) {
    (void)fd;
    return EHOSTUNREACH;
}

static void *rs_run(void *arg) {
    (void)arg;
    int ctl_answered = 0;
    for (;;) {
        uint8_t buf[2048];
        struct sockaddr_storage from;
        socklen_t fl = sizeof from;
        ssize_t n = recvfrom(g_rs_fd, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl);
        if (n < 0) {
            return NULL;
        }
        if (g_rs_respond == 0) {
            continue;
        }
        if (g_rs_respond == 2) {
            uint8_t junk[80];
            memset(junk, 0x55, sizeof junk);
            (void)sendto(g_rs_fd, junk, sizeof junk, 0, (struct sockaddr *)&from, fl);
            continue;
        }
        int is_trig = ((size_t)n == g_trig_len && memcmp(buf, g_trig_bytes, (size_t)n) == 0);
        int is_ctl = ((size_t)n == g_ctl_len && memcmp(buf, g_ctl_bytes, (size_t)n) == 0) ||
                     is_neutral_control_packet(buf, (size_t)n);
        if ((g_rs_respond == 3 || g_rs_respond == 7 || g_rs_respond == 8 ||
             g_rs_respond == 9) && is_trig) {
            continue; /* триггер молчит нарочно */
        }
        if ((g_rs_respond == 7 || g_rs_respond == 8) && is_ctl) {
            uint8_t pkt[64];
            size_t pl = g_rs_respond == 7 ? build_retry_v1(pkt, sizeof pkt)
                                          : build_vn_reply(pkt, sizeof pkt);
            (void)sendto(g_rs_fd, pkt, pl, 0, (struct sockaddr *)&from, fl);
            continue;
        }
        const uint8_t *dcid = NULL;
        size_t dcid_len = QP_DCID_LEN;
        if (g_rs_respond == 10) {
            /* РЕЖИМ 10: как настоящий сервер — отвечает на любой Initial его
               же DCID. Нужен замеру пачкой: пачка перезапечатана свежим DCID
               и ни с одним заранее известным триггером не совпадает. */
            d2k_qw_hdr hdr;
            if (d2k_qw_hdr_parse(buf, (size_t)n, 0, &hdr) == 0) {
                dcid = buf + hdr.dcid_off;
                dcid_len = hdr.dcid_len;
            }
        } else if (is_trig) {
            dcid = g_trig_bytes + QP_DCID_OFF;
        } else if (is_ctl) {
            if ((size_t)n == g_ctl_len && memcmp(buf, g_ctl_bytes, (size_t)n) == 0) {
                dcid = g_ctl_bytes + QP_DCID_OFF;
            } else {
                d2k_qw_hdr hdr;
                if (d2k_qw_hdr_parse(buf, (size_t)n, 0, &hdr) == 0) {
                    dcid = buf + hdr.dcid_off;
                    dcid_len = hdr.dcid_len;
                }
            }
        }
        if (dcid) {
            /* РЕЖИМ 5: СНАЧАЛА ACK, ПОТОМ ServerHello — ДВУМЯ ДАТАГРАММАМИ.
               Так отвечает настоящий сервер, когда клиент прислал несколько
               Initial: замер 17.09 на www.google.com дал ровно это — 48 байт
               с одним кадром ACK, потом ещё ACK, и лишь ТРЕТЬИМ пакетом
               CRYPTO. Оракул, закрывающий зонд на первой же пришедшей
               датаграмме, объявит такой сервер молчащим. */
            uint8_t resp[512];
            if (g_rs_respond == 5) {
                uint8_t ack[32];
                size_t al2 = build_ack_body(ack, sizeof ack);
                size_t rl0 = build_authentic_v1(dcid, dcid_len, ack, al2, resp, sizeof resp);
                if (rl0 > 0) {
                    (void)sendto(g_rs_fd, resp, rl0, 0, (struct sockaddr *)&from, fl);
                }
            }
            uint8_t body[32];
            int close_only = g_rs_respond == 4 || (g_rs_respond == 6 && is_trig);
            size_t bl = close_only ? build_close_body(body, sizeof body)
                                   : build_crypto_body(body, sizeof body);
            size_t rl = build_authentic_v1(dcid, dcid_len, body, bl, resp, sizeof resp);
            if (rl > 0) {
                (void)sendto(g_rs_fd, resp, rl, 0, (struct sockaddr *)&from, fl);
            }
            /* РЕЖИМ 9: ответив на D2K_QUIC_REPEATS контролей базовой
               живости, стенд закрывает порт — всё дальнейшее (прямой зонд,
               остаточная проверка) получает настоящий ICMP «порт
               недоступен». */
            if (g_rs_respond == 9 && is_ctl && ++ctl_answered >= D2K_QUIC_REPEATS) {
                /* g_rs_fd не трогаем: тест режима 9 ждёт этот поток
                   pthread_join'ом и сам сокет больше не закрывает. */
                close(g_rs_fd);
                return NULL;
            }
        }
    }
}

static uint16_t rs_start_family(int family) {
    g_rs_fd = socket(family, SOCK_DGRAM, 0);
    struct sockaddr_storage a;
    memset(&a, 0, sizeof a);
    socklen_t alen;
    if (family == AF_INET6) {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&a;
        v6->sin6_family = AF_INET6; v6->sin6_addr = in6addr_loopback;
        alen = sizeof *v6;
    } else {
        struct sockaddr_in *v4 = (struct sockaddr_in *)&a;
        v4->sin_family = AF_INET; v4->sin_addr.s_addr = htonl(0x7f000001);
        alen = sizeof *v4;
    }
    if (bind(g_rs_fd, (struct sockaddr *)&a, alen) != 0) return 0;
    socklen_t al = sizeof a;
    getsockname(g_rs_fd, (struct sockaddr *)&a, &al);
    uint16_t port = family == AF_INET6 ? ntohs(((struct sockaddr_in6 *)&a)->sin6_port)
                                     : ntohs(((struct sockaddr_in *)&a)->sin_port);
    pthread_create(&g_rs_thread, NULL, rs_run, NULL);
    if (g_rs_respond != 9) {
        pthread_detach(g_rs_thread); /* режим 9 закрывается сам и ждётся join'ом */
    }
    return port;
}

static uint16_t rs_start(void) { return rs_start_family(AF_INET); }

/* Стенд для "путь жив только через согласование версии": молчит на ЛЮБОЙ
 * настоящий Initial (control/trigger), но честно отвечает на зонд
 * согласования версии (длинный заголовок, версия 0x00000000 — RFC 9000 §6).
 * Отдельный стенд, не переиспользует rs_run: там нет ветки "узнать VN и
 * ответить на неё", а сюда для симметрии не нужна ветка "ответить на
 * Initial". */
static int g_vn_fd = -1;
static volatile int g_vn_should_answer = 1;
/* Сколько ПЕРВЫХ пришедших датаграмм стенд молча роняет (не отвечает), не
 * доходя до проверки "отвечать ли вообще", — нужен находке C ревью (круг 3):
 * симулирует ОБЫЧНУЮ потерю пакета в сети, а не решение стенда "не отвечать".
 * Единственный писатель — main() ДО vn_start(); единственный читатель —
 * vn_run(), обычный int без атомарности достаточен. */
static volatile int g_vn_drop_first_n;
/* Зонды согласования версии, как их увидел стенд (донор probe.go:303-306:
 * свои случайные DCID и SCID по 8 байт на КАЖДУЮ попытку). */
static uint8_t g_vn_seen[3][2048];
static size_t g_vn_seen_len[3];
static volatile int g_vn_seen_n;

static void *vn_run(void *arg) {
    (void)arg;
    for (;;) {
        uint8_t buf[2048];
        struct sockaddr_in from;
        socklen_t fl = sizeof from;
        ssize_t n = recvfrom(g_vn_fd, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl);
        if (n < 0) {
            return NULL;
        }
        if (n < 5 || (buf[0] & 0x80) == 0) {
            continue; /* не длинный заголовок — не наш клиент */
        }
        /* Реальный Initial (control/trigger, версия 1 или 2) — не зонд
           согласования версии; этот стенд НАРОЧНО молчит на такие пакеты
           (сценарий "control не отвечает вовсе"), и они не должны ни
           отвечаться, ни тратить g_vn_drop_first_n — иначе счётчик потерь
           списывался бы на базовую живость (шаг 0), которая шлёт свои три
           датаграммы РАНЬШЕ зонда согласования версии, и тест находки C
           проверял бы не то. */
        if (n >= 5) {
            uint32_t version =
                (uint32_t)buf[1] << 24 | (uint32_t)buf[2] << 16 | (uint32_t)buf[3] << 8 | (uint32_t)buf[4];
            if (version == 0x00000001u || version == 0x6b3343cfu) {
                continue;
            }
        }
        if (g_vn_seen_n < 3) {
            memcpy(g_vn_seen[g_vn_seen_n], buf, (size_t)n);
            g_vn_seen_len[g_vn_seen_n] = (size_t)n;
            g_vn_seen_n++;
        }
        if (g_vn_drop_first_n > 0) {
            g_vn_drop_first_n--;
            continue; /* обычная потеря пакета, не решение "не отвечать" */
        }
        if (!g_vn_should_answer) {
            continue;
        }
        /* Отвечаем VN-пакетом: версия 0, эхо DCID/SCID клиента как SCID/DCID
           ответа не обязательно для нашей структурной проверки (см.
           qp_looks_like_vn в quicprobe.c — она смотрит только на длинный
           заголовок и нулевую версию), поэтому просто отражаем вход целиком
           с обнулённой версией. */
        uint8_t resp[2048];
        size_t rl = (size_t)n;
        if (rl > sizeof resp) {
            rl = sizeof resp;
        }
        memcpy(resp, buf, rl);
        resp[0] = 0x80;
        resp[1] = 0;
        resp[2] = 0;
        resp[3] = 0;
        resp[4] = 0;
        (void)sendto(g_vn_fd, resp, rl, 0, (struct sockaddr *)&from, fl);
    }
}

static uint16_t vn_start(void) {
    g_vn_fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(0x7f000001);
    a.sin_port = 0;
    bind(g_vn_fd, (struct sockaddr *)&a, sizeof a);
    socklen_t al = sizeof a;
    getsockname(g_vn_fd, (struct sockaddr *)&a, &al);
    uint16_t port = ntohs(a.sin_port);
    pthread_t t;
    pthread_create(&t, NULL, vn_run, NULL);
    pthread_detach(t);
    return port;
}

static int mark_never_ok(int fd, uint32_t mark) {
    (void)fd;
    (void)mark;
    return -1;
}

/* Успевает подтвердить метку на первых g_mark_fail_from-1 вызовах, дальше
 * всегда проваливает. Нужен ИМЕННО находке A: базовая живость (шаг 0) и
 * зонд согласования версии идут через ОДИН И ТОТ ЖЕ d2k_mark_hook, значит
 * mark_never_ok заваливает метку СРАЗУ на базе — all_marked падает там, и
 * тест не отличает "VN не учитывает свою метку" от "база не учла свою". Этот
 * хук пропускает базовые три вызова и валит только зонд согласования версии,
 * идущий следом, — единственный способ изолированно проверить находку A. */
static int g_mark_call_count;
static int g_mark_fail_from; /* 1-based; 0 — никогда не проваливать */
static int mark_fail_from_nth(int fd, uint32_t mark) {
    (void)fd;
    (void)mark;
    g_mark_call_count++;
    if (g_mark_fail_from > 0 && g_mark_call_count >= g_mark_fail_from) {
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    /* Цель стенда живёт на петле по построению — см. d2k_quic_allow_local.
       Без этого весь вопросник отвечает «имя разрешается в приватный адрес»,
       и проверять становится нечего. */
    d2k_quic_allow_local = 1;

    uint32_t saved_wait_ms = d2k_quic_wait_ms; /* контракт: тест ужимает и ОБЯЗАН вернуть (находка 9, круг 2) */
    d2k_quic_resolve_hook = test_resolve;
    d2k_quic_wait_ms = 150; /* тест не обязан ждать боевые 3 с тишины на каждый опыт */

    g_trig_len = build_plain_initial(0x11, g_trig_buf, sizeof g_trig_buf);
    g_ctl_len = 0;
    CHECK(d2k_quic_hello_rename(d2k_test_v1_initial, sizeof d2k_test_v1_initial,
                                "c0000000000.example.com", g_ctl_buf,
                                sizeof g_ctl_buf, &g_ctl_len) == 0,
          "не собрался валидный QUIC-профиль контроля для wire-переименования");
    CHECK(g_trig_len > 0 && g_ctl_len > 0, "не собрались тестовые снимки триггера/контроля");
    g_trig_bytes = g_trig_buf;
    g_ctl_bytes = g_ctl_buf;

    {
        char pool[4][D2K_QUIC_ADDR_LEN];
        g_extra_n = 2;
        snprintf(g_extra_pool[0], D2K_QUIC_ADDR_LEN, "192.0.2.1");
        snprintf(g_extra_pool[1], D2K_QUIC_ADDR_LEN, "2001:db8::2");
        size_t n = d2k_quic_build_pool("2001:db8:1234:5678::1", "x.example", pool, 4);
        CHECK(n == 2 && strcmp(pool[0], "2001:db8:1234:5678::1") == 0 &&
              strcmp(pool[1], "2001:db8::2") == 0,
              "IPv6 pool preserves target and excludes IPv4 answers");
        n = d2k_quic_build_pool("192.0.2.2", "x.example", pool, 4);
        CHECK(n == 2 && strcmp(pool[1], "192.0.2.1") == 0,
              "IPv4 pool excludes IPv6 answers");
        g_extra_n = 0;
        g_rs_respond = 1;
        uint16_t port = rs_start_family(AF_INET6);
        CHECK(port != 0, "IPv6 QUIC measurement fixture starts");
        d2k_vres r = d2k_quic_classify("::1", port, "x.example", trig_hello(), ctl_hello(), 0);
        CHECK(r.verdict == D2K_V_CLEAR, "native IPv6 QUIC measurement accepts authenticated response");
        CHECK(r.qprops.server_ttl_in > 0, "IPv6 reply hop limit is measured");
        if (argc == 2 && strcmp(argv[1], "--ipv6-fragments") == 0) {
            for (int shape = 1; shape <= 2; shape++) {
                int sent = 0;
                d2k_quic_arm_question q = {.addr="::1", .frag=shape};
                d2k_tally t = d2k_quic_ask_arm_hook(&q, "z0123456789.example.com",
                                                   port, 500, 0xd200, &sent);
                if (sent != D2K_QUIC_REPEATS || t.pass != D2K_QUIC_REPEATS || t.err != 0)
                    fprintf(stderr, "IPv6 fragment shape=%d sent=%d pass=%d fail=%d err=%d\n",
                            shape, sent, t.pass, t.fail, t.err);
                CHECK(sent == D2K_QUIC_REPEATS && t.pass == D2K_QUIC_REPEATS && t.err == 0,
                      "native IPv6 fragmented QUIC probe receives authenticated answer");
            }
        }
        d2k_quic_allow_local = 0;
        r = d2k_quic_classify("::1", port, "x.example", trig_hello(), ctl_hello(), 0);
        CHECK(r.verdict == D2K_V_LOCAL_ADDRESS, "IPv6 loopback is not an ISP measurement");
        d2k_quic_allow_local = 1;
        close(g_rs_fd);
    }
    if (argc == 2 && (strcmp(argv[1], "--ipv6") == 0 ||
                      strcmp(argv[1], "--ipv6-fragments") == 0)) return fails ? 1 : 0;

    /* --- БЮДЖЕТ ПОКРЫВАЕТ ХУДШИЙ ПУТЬ RUN. Худший путь: база на
     * d2k_quic_wait_ms (3 с донора), затем 31 опрос по dyn_wait = 3×RTT в
     * [1,5; 6] с: прямой зонд, повторный контроль, до 4 опросов стратегии
     * (задача 40: два вопроса с одним повтором), 18 вопросов askArms
     * (5 фальшивок + 2×2 копии + 4 TTL + выживаемость + 4 формы фрагментов),
     * 7 вопросов questions.go. Прежние (1+2+20+3)×3000 мс = 78 с обрывали его
     * уже при RTT 1 с (3 + 27×3 = 84 с). */
    {
        uint32_t saved_wait = d2k_quic_wait_ms;
        d2k_quic_wait_ms = D2K_QUIC_WAIT_MS_DEFAULT;
        CHECK(d2k_quic_budget_ms(1000) >= 3000u + 31u * 3000u,
              "бюджет при RTT 1 с меньше худшего пути 3000 + 31×3000 мс");
        CHECK(d2k_quic_budget_ms(10000) >= 3000u + 31u * D2K_QUIC_RTT_WAIT_CEIL_MS,
              "бюджет при потолке ожидания меньше худшего пути");
        CHECK(d2k_quic_budget_ms(0) >= 3000u + 31u * D2K_QUIC_RTT_WAIT_FLOOR_MS,
              "бюджет при полу ожидания меньше худшего пути");
        uint32_t saved_budget = d2k_quic_budget_s;
        d2k_quic_budget_s = 2;
        CHECK(d2k_quic_budget_ms(1000) == 2000u, "явный тестовый бюджет не соблюдён");
        d2k_quic_budget_s = saved_budget;
        d2k_quic_wait_ms = saved_wait;
    }

    /* ===================================================================
     * Часть 1: дисциплина дерева (подмена d2k_quic_ask_hook).
     * =================================================================== */

    d2k_quic_ask_fn real_ask = d2k_quic_ask_hook;
    d2k_quic_ask_fn real_longer = d2k_quic_ask_longer_hook;
    d2k_quic_ask_fn real_frames = d2k_quic_ask_frames_hook;
    d2k_quic_ask_fn real_control = d2k_quic_ask_control_hook;
    d2k_quic_ask_hook = mock_ask;
    d2k_quic_ask_longer_hook = mock_ask;
    d2k_quic_ask_frames_hook = mock_ask;
    d2k_quic_ask_control_hook = mock_ask;
    d2k_quic_ask_srcport_hook = mock_ask_srcport;
    d2k_quic_ask_split_hook = mock_ask_split;

    /* Полный донорский Run для буквального IP: все сетевые границы здесь
       подменены детерминированными hooks, но Initial/question builders,
       no-SNI преобразования, Run-порядок и arm ladder настоящие. */
    {
        uint8_t ip_trigger[1500]; size_t ip_trigger_len = 0;
        d2k_quic_ask_arm_fn saved_arm_hook = d2k_quic_ask_arm_hook;
        const uint8_t *saved_trig_bytes = g_trig_bytes;
        size_t saved_trig_len = g_trig_len;
        CHECK(d2k_quic_probe_initial("203.0.113.7", ip_trigger,
                                     sizeof ip_trigger, &ip_trigger_len) == 0,
              "не собрался no-SNI вход адресного Run");
        g_trig_bytes = ip_trigger;
        g_trig_len = ip_trigger_len;
        g_expect_no_sni = 1;
        g_no_sni_failures = g_arm_calls = 0;
        g_mock_poison_on_trigger = 0;
        d2k_quic_ask_arm_hook = mock_arm;
        d2k_quic_arm ip_arm;
        g_progress_sum = 0; g_progress_calls = 0;
        d2k_quic_progress_hook = record_progress;
        d2k_vres r = d2k_quic_run("203.0.113.7", 443, "203.0.113.7",
                                  trig_hello(), ctl_hello(), 0x2d, &ip_arm);
        d2k_quic_progress_hook = NULL;
        CHECK(g_progress_sum == r.probes,
              "QUIC: ход полного Run с приёмами (askArms) не сходится с итогом зондов");
        CHECK(r.verdict == D2K_V_OPAQUE,
              "полный Run не сохранил verdict для блокируемой IP-цели");
        CHECK(g_arm_calls > 0,
              "полный Run пропустил исходную QUIC arm ladder для IP-цели");
        CHECK(g_no_sni_failures == 0,
              "полный Run добавил SNI при target IP в control/questions/arms");
        d2k_quic_ask_arm_hook = saved_arm_hook;
        g_trig_bytes = saved_trig_bytes;
        g_trig_len = saved_trig_len;
        g_expect_no_sni = 0;
        mock_reset();
    }

    /* --- Задача 32: базовый вопрос QUIC отдельно и полный прогон с его
     * ответом. Тот же исход и вердикт, что без подсказки, но шаги 0–1 не
     * опрашиваются второй раз. ------------------------------------------- */
    {
        mock_reset();
        d2k_vres base = d2k_quic_base("203.0.113.7", 443, "203.0.113.7",
                                      trig_hello(), ctl_hello(), 0x2d);
        CHECK(base.base_blocked && base.base.valid && base.base.direct_asked &&
              base.base.ctl_pass == D2K_QUIC_REPEATS && base.base.pass == 0,
              "QUIC base: контроль отвечает, Initial молчит — блокировка не подтверждена");
        CHECK(base.probes == 2 * D2K_QUIC_REPEATS, "QUIC base: лишние зонды сверх шагов 0–1");
        d2k_vres seeded = d2k_quic_run_seeded("203.0.113.7", 443, "203.0.113.7",
                                              trig_hello(), ctl_hello(), 0x2d, NULL, &base.base);
        mock_reset();
        /* Задача 49: ход QUIC-прогона доходит до планировщика вопрос за
           вопросом, и сумма зондов хода равна итогу прогона. */
        g_progress_sum = 0; g_progress_calls = 0; g_progress_last[0] = '\0';
        d2k_quic_progress_hook = record_progress;
        d2k_vres plain = d2k_quic_classify("203.0.113.7", 443, "203.0.113.7",
                                           trig_hello(), ctl_hello(), 0x2d);
        d2k_quic_progress_hook = NULL;
        CHECK(g_progress_calls >= 3 && g_progress_sum == plain.probes && g_progress_last[0],
              "QUIC: ход прогона не дошёл до планировщика или сумма зондов не равна итогу");
        CHECK(seeded.verdict == plain.verdict &&
              seeded.qprops.residual_blocking == plain.qprops.residual_blocking,
              "QUIC seed: вердикт с ответом базы расходится с обычным прогоном");
        CHECK(seeded.probes == plain.probes - base.probes,
              "QUIC seed: шаги 0–1 опрошены второй раз");
        mock_reset();
        g_mock_dead_addr[0] = '\0';
        mock_force_push(D2K_QUIC_REPEATS, 0, 0, 1);
        mock_force_push(D2K_QUIC_REPEATS, 0, 0, 1);
        base = d2k_quic_base("203.0.113.7", 443, "203.0.113.7", trig_hello(), ctl_hello(), 0x2d);
        CHECK(!base.base_blocked && base.base.valid && base.base.pass == D2K_QUIC_REPEATS,
              "QUIC base: проходящий Initial объявлен блокировкой");
        mock_reset();
    }

    /* --- НАХОДКА 2 РЕВЬЮ (круг 4): d2k_quic_ask_hook — ЧАСТЬ ПУБЛИЧНОГО
     * КОНТРАКТА (extern в d2k_quicprobe.h), не только внутренность дерева.
     * Прежняя редакция называла repeats > D2K_QUIC_MAX_ADDRS "недостижимым",
     * проверив только вызовы ИЗНУТРИ d2k_quic_classify (которые всегда
     * просят D2K_QUIC_REPEATS=3) — но
     * хук extern, и любой код, включивший ТОЛЬКО d2k_quicprobe.h, может
     * вызвать его напрямую с любым repeats. Тот же прогон, которым ревьюер
     * это доказал: repeats=99, в обход d2k_quic_classify целиком; отказ до
     * единого send() — сети не касается, поэтому 127.0.0.1 здесь условность,
     * а не требование стенда. --------------------------------------------- */
    {
        uint32_t rtt_ms = 999;
        int refused = -1;
        int sent = -1;
        d2k_tally t =
            real_ask("127.0.0.1", 443, NULL, 0, trig_hello(), 150, 0, 99, &rtt_ms, &refused, &sent, NULL);
        CHECK(t.err == 99, "repeats > D2K_QUIC_MAX_ADDRS обязан отказать всей серии, err == repeats");
        CHECK(t.fail == 99, "отказ — это fail тоже (d2k_tally: err — подмножество fail)");
        CHECK(t.pass == 0, "отказанная серия не может дать ни одного pass");
        CHECK(rtt_ms == 0, "отказ обязан обнулить rtt_ms_out, а не оставить мусор вызывающего");
        CHECK(refused == 0, "отказ до единой отправки — отказывать нечему, refused_out обязан быть 0");
        CHECK(sent == 0, "отказ до единой отправки — на провод не ушло ничего, sent_out обязан быть 0");
    }

    /* --- структурно непригодный вход: ни одного опыта (FLAKY, единый класс,
     * находка 9 ревью круг 2 — раньше !trigger.bytes давал INCONCLUSIVE) --- */
    {
        d2k_vres r = d2k_quic_classify(NULL, 443, "x.example", no_hello(), no_hello(), 0);
        CHECK(r.verdict == D2K_V_FLAKY, "пустой ip не распознан как структурно непригодный вход");
        CHECK(r.probes == 0, "на структурно непригодном входе не должно быть ни одного опыта");
        CHECK(r.reason[0] != 0, "вердикт без причины нечитаем");
    }
    {
        d2k_vres r = d2k_quic_classify("10.0.0.1", 443, "x.example", no_hello(), ctl_hello(), 0);
        CHECK(r.verdict == D2K_V_FLAKY, "нет снимка триггера — тот же класс FLAKY, что и !ip/!sni");
        CHECK(r.probes == 0, "без снимка не должно быть отправлено ни одного опыта");
    }
    {
        /* Длинный адрес молча обрезался бы strncpy — находка 9: вместо
           честного "вход непригоден" получился бы поход на ЧУЖОЙ адрес. */
        char toolong[64];
        memset(toolong, '1', sizeof toolong - 1);
        toolong[sizeof toolong - 1] = '\0';
        d2k_vres r = d2k_quic_classify(toolong, 443, "x.example", trig_hello(), ctl_hello(), 0);
        CHECK(r.verdict == D2K_V_FLAKY, "адрес длиннее буфера пула обязан быть структурно непригодным");
        CHECK(r.probes == 0, "слишком длинный адрес не должен провоцировать ни одного опыта");
    }
    {
        /* НАХОДКА E РЕВЬЮ (круг 3): "999.999.999.999" короче буфера пула, но
           не разбирается как IPv4 — раньше проходил guard по длине и утекал
           в оракул, где давал UNREACHABLE (сетевое утверждение из
           непригодного ввода вместо честного "вход непригоден"). */
        d2k_vres r =
            d2k_quic_classify("999.999.999.999", 443, "x.example", trig_hello(), ctl_hello(), 0);
        CHECK(r.verdict == D2K_V_FLAKY,
              "нечитаемый как IPv4 адрес обязан быть структурно непригодным входом, не сетевым "
              "молчанием");
        CHECK(r.probes == 0, "непригодный адрес не должен провоцировать ни одного сетевого опыта");
    }

    /* --- ГЛАВНАЯ ПРОВЕРКА: остаточная блокировка -> ротация на свежий адрес
     * ТОЛЬКО ПОСЛЕ обнаружения (находка 1 ревью, круг 2) -------------------- */
    {
        mock_reset();
        g_extra_n = 2;
        strncpy(g_extra_pool[0], "10.0.0.2", D2K_QUIC_ADDR_LEN);
        strncpy(g_extra_pool[1], "10.0.0.3", D2K_QUIC_ADDR_LEN);

        d2k_vres r = d2k_quic_classify("10.0.0.1", 443, "x.example", trig_hello(), ctl_hello(), 0);

        CHECK(r.verdict == D2K_V_OPAQUE,
              "коробка блокирует триггер, но пропускает контроль на чистом адресе — должен быть OPAQUE");
        CHECK(mock_state_for("10.0.0.1")->poisoned == 1, "адрес A обязан быть отмечен поражённым");
        CHECK(strstr(r.reason, "ост.блокировка") != NULL,
              "причина обязана явно упомянуть наблюдение остаточной блокировки (шаг 2)");
        CHECK(r.probes == 15,
              "3(база)+3(прямой)+3(остаточная)+3(мусор)+3(низкий порт); лишнего контроля нет");
    }

    /* --- ОДИН адрес у цели: ротировать НЕЧЕМ, но контроль ТОЛЬКО ЧТО (шаг 2)
     * ответил на этом же адресе 3/3 — вердикт обязан быть OPAQUE БЕЗ
     * ротации, а не "адрес не задан" (это и есть провал безусловной ротации,
     * найденный ревьюером прогоном, находка 1) ----------------------------- */
    {
        mock_reset();
        g_mock_poison_on_trigger = 0; /* триггер молчит, но НЕ поражает адрес — коробка просто не отвечает */
        g_extra_n = 0;                /* адресов для ротации нет вовсе */

        d2k_vres r = d2k_quic_classify("10.0.1.1", 443, "x.example", trig_hello(), ctl_hello(), 0);

        CHECK(r.verdict == D2K_V_OPAQUE,
              "один адрес: контроль до и после триггера прошёл на нём же — доказательство есть без "
              "ротации, находка 1 ревью");
        CHECK(r.qprops.residual_blocking == D2K_PROP_NO,
              "original Run: контроль после триггера ответил — остаточной блокировки нет");
        /* НАХОДКА B РЕВЬЮ (круг 3): правило "адрес закреплён, пока нет
           остаточной блокировки" — ОДНО на все вопросы, включая плечо. Раньше
           плечо ротировало БЕЗУСЛОВНО и на цели с одним адресом честно
           говорило "не задано (адреса)", хотя спросить было чем — pool[0]
           уже дважды подтверждён живым. Теперь плечо спрашивает pool[0] и
           реально измеряется (3 опыта, не "незадано"). */
        CHECK(strstr(r.reason, "не задано 1 (адреса)") == NULL &&
              strstr(r.reason, "не задано 2 (адреса)") == NULL,
              "спросить было чем (адрес живой) — вопросы не имеют права остаться незаданными по адресам");
        CHECK(r.qprops.junk_ahead == D2K_PROP_NO,
              "вопрос про мусор обязан реально измериться на закреплённом адресе, а не быть пропущен");
        CHECK(r.qprops.low_source_port == D2K_PROP_NO,
              "вопрос про низкий исходный порт обязан измериться: снимок ему не нужен");
        /* Снимок у этого мока — не настоящий Initial, поэтому три вопроса
           с пересборкой («кадры», «бит», «длина»; «версия2» снята задачей 57)
           и пара датаграмм честно НЕ СОБИРАЮТСЯ и остаются неизмеренными:
           несобравшийся зонд не измерение. */
        CHECK(r.qprops.split_crypto == D2K_PROP_UNKNOWN &&
              r.qprops.split_datagrams == D2K_PROP_UNKNOWN,
              "несобравшийся зонд обязан оставить свойство неизмеренным, а не «не помогает»");
        CHECK(strstr(r.reason, "не задано 4 (не собралось)") != NULL,
              "несобранные вопросы обязаны быть названы прямо");
        CHECK(r.probes == 15, "3(база)+3(прямой)+3(шаг2)+3(мусор)+3(низкий порт) на pool[0]");
    }

    /* Original Run: residual consumes spare addresses, NOT the diagnosis.
       Independent real-socket coverage: TestD2KResidualParity/blocked. */
    {
        mock_reset();
        g_extra_n = 0;

        d2k_vres r = d2k_quic_classify("10.0.2.1", 443, "x.example", trig_hello(), ctl_hello(), 0);

        CHECK(r.verdict == D2K_V_OPAQUE, "content diagnosis survives exhausted spare pool");
        CHECK(r.qprops.residual_blocking == D2K_PROP_YES, "residual observation retained");
        CHECK(strstr(r.reason, "не задано 2 (адреса)") != NULL, "questions remain unasked");
        CHECK(strstr(r.reason, "недоступен") == NULL,
              "нельзя подменять «не смогли спросить» выводом «сервер недоступен»");
        CHECK(r.probes == 9, "3(база)+3(прямой)+3(шаг2) — дальше дерево не пошло, адресов не осталось");
    }

    /* --- блокировка есть, один лишний адрес хватает на устройство, но на
     * плечо уже не хватает: OPAQUE получен, плечо честно названо незаданным - */
    {
        mock_reset();
        g_extra_n = 1;
        strncpy(g_extra_pool[0], "10.0.3.2", D2K_QUIC_ADDR_LEN);

        d2k_vres r = d2k_quic_classify("10.0.3.1", 443, "x.example", trig_hello(), ctl_hello(), 0);

        CHECK(r.verdict == D2K_V_OPAQUE, "устройство измерено — должен быть OPAQUE несмотря на "
                                          "нехватку адреса для плеча");
        CHECK(strstr(r.reason, "не задано 1 (адреса)") != NULL,
              "нехватка адресов на вопросник обязана быть названа прямо, а не проглочена");
        CHECK(r.probes == 12, "3+3+3+3 — вопросы не заданы, их опыты не считаются");
    }

    /* --- нет контрольного имени: даже базовая живость не проверяется ------- */
    {
        mock_reset();
        d2k_vres r = d2k_quic_classify("10.0.4.1", 443, "x.example", trig_hello(), no_hello(), 0);
        CHECK(r.verdict == D2K_V_INCONCLUSIVE, "без контроля даже базовая живость не проверяется");
        CHECK(strstr(r.reason, "контрольного имени") != NULL,
              "причина обязана прямо назвать нехватку контрольного имени");
        CHECK(r.probes == 0, "без контроля НИ ОДНОГО опыта: базовая живость на нём и стоит");
    }

    /* The donor does not insert another clean-address control. The spare
       is used for the next question, whose failure does not erase content. */
    {
        mock_reset();
        strncpy(g_mock_dead_addr, "10.0.5.2", D2K_QUIC_ADDR_LEN);
        g_extra_n = 1;
        strncpy(g_extra_pool[0], "10.0.5.2", D2K_QUIC_ADDR_LEN);

        d2k_vres r = d2k_quic_classify("10.0.5.1", 443, "x.example", trig_hello(), ctl_hello(), 0);

        CHECK(r.verdict == D2K_V_OPAQUE, "no invented clean-address control branch");
        CHECK(r.qprops.junk_ahead == D2K_PROP_NO, "spare was used by junk question");
    }

    /* --- плечо "мусор перед Initial" уже помогает --------------------------- */
    {
        mock_reset();
        g_mock_garbage_defeats = 1;
        g_extra_n = 2;
        strncpy(g_extra_pool[0], "10.0.6.2", D2K_QUIC_ADDR_LEN);
        strncpy(g_extra_pool[1], "10.0.6.3", D2K_QUIC_ADDR_LEN);

        d2k_vres r = d2k_quic_classify("10.0.6.1", 443, "x.example", trig_hello(), ctl_hello(), 0);

        CHECK(r.verdict == D2K_V_OPAQUE, "плечо не отменяет вердикт по содержимому — остаётся OPAQUE");
        CHECK(strstr(r.reason, "взяли мусор") != NULL,
              "reason обязан назвать положительный сигнал по мусору прямо");
        CHECK(r.qprops.junk_ahead == D2K_PROP_YES,
              "свойство обязано быть записано, а не только упомянуто в тексте причины");
    }

    /* Runtime udplen preserves the measured large input; no 1300-byte
       substitute profile is introduced by the question. */
    {
        static uint8_t big[D2K_QW_MAX_DGRAM];
        size_t big_len = build_large_snapshot(1080, big, sizeof big);
        uint8_t tmp[D2K_QW_MAX_DGRAM];
        size_t tmp_len = 0;
        CHECK(big_len > 1300 &&
              d2k_quic_hello_ask(big, big_len, D2K_QASK_PLAIN, "www.example.com",
                                 tmp, sizeof tmp, &tmp_len) == 0 &&
              d2k_quic_hello_ask(big, big_len, D2K_QASK_LONGER, "www.example.com",
                                 tmp, sizeof tmp, &tmp_len) != 0,
              "стенд: большой снимок обязан быть целым, но не помещаться в 1300");
        mock_reset();
        g_mock_poison_on_trigger = 0;
        g_extra_n = 0;
        g_mock_len_1300 = 0;
        d2k_hello snap = {big, big_len, NULL, 0, 0, 0};
        d2k_vres r = d2k_quic_classify("10.0.20.1", 443, "www.example.com", snap, ctl_hello(), 0);
        CHECK(r.verdict == D2K_V_OPAQUE, "большой снимок: контроль жив, решает содержимое");
        CHECK(r.qprops.longer != D2K_PROP_UNKNOWN,
              "большое приветствие потеряло вопрос «длина» — запасной Initial донора не задан");
        CHECK(strcmp(r.qtrace[5].label, "длина") == 0 && r.qtrace[5].sent == D2K_QUIC_REPEATS,
              "runtime length retains the captured form");
        CHECK(strstr(r.reason, "«длина» задана PROFILE") == NULL,
              "runtime length must not claim a profile substitution");
        CHECK(g_mock_len_1300 == 0, "no replacement with a fixed 1300-byte Initial");
        CHECK(r.qprops.longer_profile == 0,
              "length now acts on the captured form, not PROFILE");
    }

    /* --- ВОПРОСНИК ЦЕЛИКОМ: СЕМЬ ВОПРОСОВ НА НАСТОЯЩЕМ СНИМКЕ -------------
     *
     * Прочие проверки этой части дают моку выдуманный снимок, и четыре
     * вопроса с пересборкой честно не собираются. Здесь снимок НАСТОЯЩИЙ
     * (вектор RFC 9001 A.2), значит собирается всё, и проверяется главное:
     * задан КАЖДЫЙ вопрос и записано КАЖДОЕ свойство.
     *
     * Почему это важнее, чем кажется: неизмеренное свойство и «приём не
     * помогает» — разные вещи, и раскладка с нулём в значении «не измерено»
     * (d2k_quic_props) молчаливо превращает первое во второе при любой
     * ошибке в вопроснике. Утверждение «ни одно свойство не осталось
     * неизмеренным» ловит ровно это. */
    {
        mock_reset();
        g_mock_poison_on_trigger = 0; /* коробка молчит на триггер, но адрес не поражает */
        g_extra_n = 0;

        d2k_hello snap = {0};
        snap.bytes = d2k_test_v1_initial;
        snap.len = sizeof d2k_test_v1_initial;
        d2k_vres r = d2k_quic_classify("10.0.20.1", 443, "www.example.com", snap, ctl_hello(), 0);

        CHECK(r.verdict == D2K_V_OPAQUE, "контроль жив до и после — решает содержимое");
        CHECK(strstr(r.reason, "не собралось") == NULL,
              "на настоящем снимке не собраться не может ни один вопрос");
        CHECK(strcmp(r.qtrace[5].label, "длина") == 0 && strstr(r.reason, "PROFILE") == NULL,
              "снимок помещается в 1300 — «длина» задаётся снимком, без PROFILE");
        CHECK(r.qprops.longer_profile == 0, "«длина» снимком помечена PROFILE");
        CHECK(r.qprops.junk_ahead != D2K_PROP_UNKNOWN &&
              r.qprops.split_crypto != D2K_PROP_UNKNOWN &&
              r.qprops.split_datagrams != D2K_PROP_UNKNOWN &&
              r.qprops.clear_fixed_bit != D2K_PROP_UNKNOWN &&
              r.qprops.low_source_port != D2K_PROP_UNKNOWN &&
              r.qprops.longer != D2K_PROP_UNKNOWN,
              "хоть одно свойство осталось неизмеренным — вопрос не задан, а вывод по нему будет");
        /* Восьмой вопрос оригинала (фальшивка с разрешённым именем) здесь не
           задаётся намеренно: он живёт в задаче 6 вместе с числом копий и
           развёрткой TTL. Незаданное обязано остаться неизмеренным. */
        CHECK(r.qprops.fake_ahead == D2K_PROP_UNKNOWN,
              "вопрос, который вопросник не задаёт, не имеет права получить значение");
        /* «ВЕРСИЯ2» НЕ ЗАДАЁТСЯ (задача 57, поле 14.10.2026). Cloudflare
           Initial второй версии молча отбрасывает (на смазочную версию
           отвечает Version Negotiation), коробка линии режет QUIC по имени во
           всех версиях, а движок версию на живом пакете переписать не может —
           ответ ничего не давал и стоил три зонда в каждом проваленном поиске. */
        CHECK(r.qprops.version2 == D2K_PROP_UNKNOWN,
              "вопрос «версия2» снова задаётся");
        for (size_t qi = 0; qi < D2K_QTRACE_MAX; qi++)
            CHECK(strcmp(r.qtrace[qi].label, "версия2") != 0,
                  "в трассе вопрос «версия2», которого больше нет");
        CHECK(r.probes == 9 + 6 * D2K_QUIC_REPEATS,
              "3(база)+3(прямой)+3(шаг2)+шесть вопросов по три");

        /* ТРАССА: по строке на КАЖДЫЙ заданный вопрос, с числами. Из одних
           свойств «приём не сработал» неотличимо от «зонд не долетел по
           другой причине» — а на стенде это различие уже понадобилось. */
        int lines = 0;
        for (size_t qi = 0; qi < D2K_QTRACE_MAX; qi++) {
            if (!r.qtrace[qi].label[0]) { continue; }
            lines++;
            CHECK(r.qtrace[qi].sent == D2K_QUIC_REPEATS,
                  "в трассе не столько зондов, сколько ушло на провод");
            CHECK(r.qtrace[qi].answered <= r.qtrace[qi].sent,
                  "ответов больше, чем зондов");
        }
        CHECK(lines == 6, "трасса обязана нести строку на каждый заданный вопрос");
    }

    /* --- СЫРОЙ TTL ОТВЕТА: ФАКТ, А НЕ РАССТОЯНИЕ ------------------------
     *
     * Оригинал снимает TTL входящего пакета и кладёт его в вывод БЕЗ
     * пересчёта в расстояние — и это не осторожность: замер 04.09 показал,
     * что на один и тот же адрес ICMP и QUIC отдают разные TTL (56 против
     * 86), то есть отвечают РАЗНЫЕ УЗЛЫ, и «расстояние» из одного наблюдения
     * было бы выдуманным числом. Здесь того же факта не снималось вовсе.
     *
     * Проверяем, что он снимается и что ноль означает «не измерено», а не
     * «TTL нулевой»: нулевого TTL у дошедшего пакета не бывает. */
    {
        mock_reset();
        g_mock_poison_on_trigger = 0;
        g_extra_n = 0;
        d2k_hello snap = {0};
        snap.bytes = d2k_test_v1_initial;
        snap.len = sizeof d2k_test_v1_initial;
        d2k_vres r = d2k_quic_classify("10.0.22.1", 443, "www.example.com", snap, ctl_hello(), 0);
        /* Мок сокетов не трогает и TTL ниоткуда взять не может — значит
           «не измерено», и никакого выдуманного числа. */
        CHECK(r.qprops.server_ttl_in == 0,
              "TTL выдуман там, где пакетов не было вовсе");
    }

    /* --- НАХОДКИ: ПРИЁМ ВЗЯЛ, А ИСПОЛНИТЬ ЕГО НЕЧЕМ ----------------------
     *
     * Шесть из семи вопросов ломают коробку, но движок сегодня не умеет ни
     * одного. Оригинал такие исходы называет прямо и отдельно от плеч, и это
     * не формальность: прятать их значит терять самый ценный выход замера, а
     * выдавать за плечо — обещать человеку обход, которого нет. */
    {
        d2k_quic_props p;
        memset(&p, 0, sizeof p);
        char out[1024];

        CHECK(d2k_quic_props_findings(&p, out, sizeof out) == 0 && out[0] == '\0',
              "не измерено ничего, а находки нашлись");

        p.split_crypto = D2K_PROP_NO;
        CHECK(d2k_quic_props_findings(&p, out, sizeof out) == 0,
              "«приём не помогает» — это не находка");

        p.split_crypto = D2K_PROP_YES;
        CHECK(d2k_quic_props_findings(&p, out, sizeof out) == 1 &&
              strstr(out, "кадра CRYPTO") != NULL,
              "взявший приём обязан быть назван человеку");
        /* Задача 40: разрез CRYPTO движок теперь исполняет (quicsplit) —
           находка обязана сказать это, а не «не умеет». */
        CHECK(strstr(out, "quicsplit") != NULL && strstr(out, "не умеет") == NULL,
              "исполнимый разрез CRYPTO назван исполнимым");
        p.split_crypto = D2K_PROP_UNKNOWN;
        p.split_datagrams = D2K_PROP_YES;
        CHECK(d2k_quic_props_findings(&p, out, sizeof out) == 1 &&
              strstr(out, "не умеет") != NULL,
              "находку нельзя выдавать за готовый обход: две датаграммы движок не исполняет");
        p.split_datagrams = D2K_PROP_UNKNOWN;
        p.split_crypto = D2K_PROP_YES;
        (void)d2k_quic_props_findings(&p, out, sizeof out);

        p.version2 = D2K_PROP_YES;
        p.low_source_port = D2K_PROP_YES;
        CHECK(d2k_quic_props_findings(&p, out, sizeof out) == 3,
              "три взявших приёма — три находки");

        /* Буфер меньше находки: обрезать можно, выйти за него нельзя. */
        char tiny[8];
        memset(tiny, 0x7f, sizeof tiny);
        (void)d2k_quic_props_findings(&p, tiny, sizeof tiny);
        CHECK(tiny[sizeof tiny - 1] == '\0', "находки вышли за буфер");
    }

    /* --- свойства НЕ ЗАПОЛНЯЮТСЯ, когда вопросника не было ----------------
     * Ноль в d2k_quic_props значит «не измерено», и вердикт, до вопросника
     * не доживший, обязан оставить все свойства нулевыми — иначе он молча
     * утверждает «ни один приём не помогает». */
    {
        mock_reset();
        d2k_vres r = d2k_quic_classify("10.0.21.1", 443, "x.example", no_hello(), ctl_hello(), 0);
        CHECK(r.verdict == D2K_V_FLAKY, "снимка нет — измерения не было");
        CHECK(r.qprops.junk_ahead == D2K_PROP_UNKNOWN &&
              r.qprops.low_source_port == D2K_PROP_UNKNOWN &&
              r.qprops.longer == D2K_PROP_UNKNOWN,
              "вердикт без вопросника выдал свойства коробки — это выдумка, а не замер");
    }

    /* --- бюджет исчерпан ДО базовой живости (спецслучай budget_s==0,
     * детерминированный — см. budget_left в quicprobe.c) ------------------- */
    {
        mock_reset();
        uint32_t saved_budget = d2k_quic_budget_s;
        d2k_quic_budget_s = 0;
        d2k_vres r = d2k_quic_classify("10.0.7.1", 443, "x.example", trig_hello(), ctl_hello(), 0);
        d2k_quic_budget_s = saved_budget;

        CHECK(r.verdict == D2K_V_INCONCLUSIVE, "нулевой бюджет обязан остановить дерево честно");
        CHECK(strstr(r.reason, "бюджет") != NULL && strstr(r.reason, "НЕ ЗАДАН") != NULL,
              "причина обязана назвать именно бюджет");
        CHECK(r.probes == 0, "бюджет исчерпан ещё до базовой живости — ни одного опыта");
    }

    /* ===================================================================
     * НАХОДКА 4 РЕВЬЮ (круг 2): шесть мутаций, шесть отдельных тестов.
     * Обычная модель mock_ask детерминирована по содержимому и не умеет ни
     * частичного результата, ни ошибки транспорта — без принудительной
     * очереди (mock_force_push) шесть мутаций ревьюера (снятие учёта метки
     * на шагах 2/3/4, приём "2 из 3" на шагах 2/3, ослабление err>0)
     * проходили зелёными. Каждый тест ниже закрывает ровно одну.
     * =================================================================== */

    /* 1/6: учёт метки на шаге 2 (проверка остаточной блокировки). */
    {
        mock_reset();
        mock_force_push(D2K_QUIC_REPEATS, 0, 0, 1);              /* база: живость 3/3, помечено */
        mock_force_push(0, D2K_QUIC_REPEATS, 0, 1);               /* прямой зонд: молчит 0/3, помечено */
        mock_force_push(D2K_QUIC_REPEATS, 0, 0, 0);               /* шаг 2: 3/3, НО не помечено */
        d2k_vres r = d2k_quic_classify("10.0.8.1", 443, "x.example", trig_hello(), ctl_hello(), 99);
        CHECK(r.verdict == D2K_V_OPAQUE, "1/6: неучёт метки на шаге 2 не должен менять вердикт");
        CHECK(r.marked == 0, "1/6: r.marked обязан упасть — шаг 2 не был помечен");
    }

    /* 2/6: учёт метки на шаге 3 (устройство, после обнаруженной блокировки). */
    {
        mock_reset();
        g_extra_n = 1;
        strncpy(g_extra_pool[0], "10.0.8.9", D2K_QUIC_ADDR_LEN);
        mock_force_push(D2K_QUIC_REPEATS, 0, 0, 1); /* база: живость */
        mock_force_push(0, D2K_QUIC_REPEATS, 0, 1);  /* прямой зонд: молчит */
        mock_force_push(0, D2K_QUIC_REPEATS, 0, 1);  /* шаг 2: молчит — блокировка обнаружена */
        mock_force_push(D2K_QUIC_REPEATS, 0, 0, 0);  /* шаг 3: 3/3, НЕ помечено */
        d2k_vres r = d2k_quic_classify("10.0.8.2", 443, "x.example", trig_hello(), ctl_hello(), 99);
        CHECK(r.verdict == D2K_V_OPAQUE, "2/6: неучёт метки на шаге 3 не должен менять вердикт");
        CHECK(r.marked == 0, "2/6: r.marked обязан упасть — шаг 3 не был помечен");
    }

    /* 3/6: учёт метки на шаге 4 (плечо). */
    {
        mock_reset();
        g_extra_n = 1;
        strncpy(g_extra_pool[0], "10.0.8.9", D2K_QUIC_ADDR_LEN);
        mock_force_push(D2K_QUIC_REPEATS, 0, 0, 1); /* база: живость */
        mock_force_push(0, D2K_QUIC_REPEATS, 0, 1);  /* прямой зонд: молчит */
        mock_force_push(D2K_QUIC_REPEATS, 0, 0, 1);  /* шаг 2: 3/3 — блокировки НЕТ, сразу OPAQUE+плечо */
        mock_force_push(0, D2K_QUIC_REPEATS, 0, 0);  /* плечо: 0/3, НЕ помечено */
        d2k_vres r = d2k_quic_classify("10.0.8.3", 443, "x.example", trig_hello(), ctl_hello(), 99);
        CHECK(r.verdict == D2K_V_OPAQUE, "3/6: неучёт метки на плече не должен менять вердикт");
        CHECK(r.marked == 0, "3/6: r.marked обязан упасть — плечо не было помечено");
    }

    /* Original residual criterion is Answered == 0, not unanimous control.
       Independent coverage: TestD2KResidualParity/partial. */
    {
        mock_reset();
        mock_force_push(D2K_QUIC_REPEATS, 0, 0, 1);
        mock_force_push(0, D2K_QUIC_REPEATS, 0, 1);
        mock_force_push(2, 1, 0, 1); /* шаг 2: 2 из 3 — не единогласно */
        d2k_vres r = d2k_quic_classify("10.0.8.4", 443, "x.example", trig_hello(), ctl_hello(), 0);
        CHECK(r.verdict == D2K_V_OPAQUE && r.qprops.residual_blocking == D2K_PROP_NO,
              "partial residual control permits pinned search, as in original");
    }

    /* The next question is a property, not an invented clean control. */
    {
        mock_reset();
        g_extra_n = 1;
        strncpy(g_extra_pool[0], "10.0.8.9", D2K_QUIC_ADDR_LEN);
        mock_force_push(D2K_QUIC_REPEATS, 0, 0, 1);
        mock_force_push(0, D2K_QUIC_REPEATS, 0, 1);
        mock_force_push(0, D2K_QUIC_REPEATS, 0, 1); /* шаг 2: молчит — блокировка обнаружена */
        mock_force_push(2, 1, 0, 1);                 /* шаг 3: 2 из 3 */
        d2k_vres r = d2k_quic_classify("10.0.8.5", 443, "x.example", trig_hello(), ctl_hello(), 0);
        CHECK(r.verdict == D2K_V_OPAQUE && r.qprops.junk_ahead != D2K_PROP_YES,
              "partial property success does not erase diagnosis or pass the arm");
    }

    /* 6/6: ошибка транспорта на шаге 2 обязана быть FLAKY даже когда pass==0
     * (иначе неотличимо от "молчит — блокировка обнаружена"). pass=2 здесь
     * не годится: err>0 тогда ВСЕГДА совпадает с "0<pass<REPEATS", и ослабленная
     * до err==REPEATS проверка всё равно ловится ЧУЖИМ, соседним guard'ом
     * (сама эта путаница и есть находка: тест обязан бить ИМЕННО по err,
     * не разделяя правку с партиционным guard'ом). pass=0 исключает эту
     * путаницу: единственный guard, которому есть что проверять, — err>0. */
    {
        mock_reset();
        mock_force_push(D2K_QUIC_REPEATS, 0, 0, 1);
        mock_force_push(0, D2K_QUIC_REPEATS, 0, 1);
        mock_force_push(0, D2K_QUIC_REPEATS, 1, 1); /* шаг 2: 0 прошли, 1 из 3 — ошибка транспорта */
        d2k_vres r = d2k_quic_classify("10.0.8.6", 443, "x.example", trig_hello(), ctl_hello(), 0);
        CHECK(r.verdict == D2K_V_FLAKY, "6/6: ошибка транспорта на шаге 2 обязана быть FLAKY, не "
                                         "«блокировка обнаружена» по совпадению pass==0");
    }

    /* --- НАХОДКА 9 РЕВЬЮ (круг 2): резолвер, вернувший больше cap, не должен
     * читаться дальше своего же буфера — под `make -C core san` без зажима
     * n_extra это redzone-переполнение, здесь — хотя бы не падение и
     * содержательный, а не мусорный вердикт. -------------------------------- */
    {
        mock_reset();
        d2k_quic_resolve_fn saved_resolve = d2k_quic_resolve_hook;
        d2k_quic_resolve_hook = misbehaving_resolve;
        d2k_vres r = d2k_quic_classify("10.0.9.1", 443, "x.example", trig_hello(), ctl_hello(), 0);
        d2k_quic_resolve_hook = saved_resolve;
        CHECK(r.verdict == D2K_V_OPAQUE || r.verdict == D2K_V_INCONCLUSIVE,
              "лживый резолвер не должен портить память или ронять процесс — вердикт остаётся "
              "содержательным (OPAQUE с ротацией или INCONCLUSIVE, если пул честно исчерпался)");
    }

    /* --- НАХОДКА 2 РЕВЬЮ (круг 5): порог refused>0 обязан быть ВЛОЖЕН
     * внутрь pass==0 (донор: probe.go:292-297, `if base.Answered == 0 { if
     * base.Refused > 0`), а не проверяться первым независимо от pass. Мок
     * форсирует смешанный исход — базовая живость даёт 2 из 3 аутентичных
     * ответов (доказано: цель жива и говорит по QUIC) и 1 сетевой отказ на
     * ТРЕТЬЕЙ параллельной попытке (анкаст-нода, рейт-лимит, инъекция ICMP
     * — не отличить, и не нужно: доказательство уже есть). Это обязано
     * продолжить прямой зонд, как Run оригинала: контроль требует хотя бы
     * одного ответа, а не единогласия. ----------------------------------- */
    {
        mock_reset();
        mock_force_push_refused(2, 1, 0, 1, 1); /* база: 2 из 3 прошли, 1 — сетевой отказ (fail, не err — probe.go:573-574) */
        mock_force_push(3, 0, 0, 1); /* прямой зонд: исходные три ответа */
        d2k_vres r = d2k_quic_classify("10.0.10.1", 443, "x.example", trig_hello(), ctl_hello(), 0);
        CHECK(r.verdict == D2K_V_CLEAR,
              "положительный контроль с частичным отказом не довёл до прямого зонда оригинала");
        CHECK(r.probes == 2 * D2K_QUIC_REPEATS,
              "прямой успех изменил исходное число серий (контроль + прямой)");
    }
    {
        /* Контрольный случай той же находки: pass=0,refused=1 — ЕДИНСТВЕННЫЙ
         * из измеренных ревьюером трёх, где сетевой отказ действительно
         * должен решать (донорский порог), проверен ЯВНО рядом с
         * "неправильными" двумя, чтобы порог не оказался вырожденным
         * (закрытым для любого входа). */
        mock_reset();
        mock_force_push_refused(0, 3, 0, 1, 1); /* база: 0 из 3, 1 — сетевой отказ, 2 — тишина (отказ — fail, не err) */
        d2k_vres r = d2k_quic_classify("10.0.10.2", 443, "x.example", trig_hello(), ctl_hello(), 0);
        CHECK(r.verdict == D2K_V_NO_QUIC,
              "pass=0,refused=1 — единственный случай тройки ревьюера, где сетевой отказ "
              "действительно должен решать (находка 2)");
    }

    /* --- НАХОДКА 5.1 РЕВЬЮ (круг 5, мелкое): частичное "не отправилось"
     * (err>0, err<REPEATS, pass==0, refused==0 — часть попыток не ушла на
     * провод, часть просто тишина без ошибки) обязано говорить "наша
     * сторона", как и полное "не отправилось" тремя строками выше в коде,
     * а не абстрактный "транспорт". ---------------------------------------- */
    {
        mock_reset();
        mock_force_push_refused(0, 3, 1, 1, 0); /* база: 0 из 3, 1 не отправился, 2 — тишина */
        d2k_vres r = d2k_quic_classify("10.0.10.3", 443, "x.example", trig_hello(), ctl_hello(), 0);
        CHECK(r.verdict == D2K_V_FLAKY, "частичное 'не отправилось' без refused — FLAKY");
        CHECK(strstr(r.reason, "наша сторона") != NULL,
              "err без refused здесь ВЕСЬ целиком 'не отправилось' — причина обязана сказать "
              "честно, как и соседняя ветка (находка 5.1)");
    }

    d2k_quic_ask_hook = real_ask;
    d2k_quic_ask_longer_hook = real_longer;
    d2k_quic_ask_frames_hook = real_frames;
    d2k_quic_ask_control_hook = real_control;

    /* ===================================================================
     * Часть 2: настоящий оракул — реальные сокеты на 127.0.0.1, реальный
     * AES-128-GCM с обеих сторон, реальный ICMP, реальное согласование
     * версии, реальные часы бюджета.
     * =================================================================== */
    g_extra_n = 0;

    /* --- прямой зонд проходит по-настоящему (аутентично + кадр CRYPTO): CLEAR */
    {
        g_rs_respond = 1;
        uint16_t port = rs_start();
        d2k_vres r = d2k_quic_classify("127.0.0.1", port, "x.example", trig_hello(), ctl_hello(), 0);
        CHECK(r.verdict == D2K_V_CLEAR, "настоящий аутентичный ответ с CRYPTO на триггер — должен быть CLEAR");
        close(g_rs_fd);
    }

    /* --- ВХОД ЗАМЕРА — ПАЧКА ДАТАГРАММ КЛИЕНТА (задача 66) --------------
     *
     * Приветствие Chrome с ML-KEM занимает два Initial, и снимком становится
     * весь полёт. Ответ сервера на пачку обязан засчитываться: проверщик
     * разбирал байты пачки как одиночный Initial, разбор не проходил, и
     * любой ответ отвергался — замер пачкой на отвечающем сервере читал
     * «имя молчит», то есть ложную блокировку (стенд 15.10.2026). */
    {
        uint8_t d1[1500], d2[1500];
        size_t l1 = 0, l2 = 0;
        CHECK(d2k_test_pq_initials("x.example", d1, &l1, d2, &l2) == 0, "стенд двух Initial");
        const uint8_t *dgs[2] = {d1, d2};
        size_t lens[2] = {l1, l2};
        static uint8_t pack[D2K_SHAPE_MAX];
        size_t pl = d2k_qsnap_pack(dgs, lens, 2, pack, sizeof pack);
        CHECK(pl > 0, "пачка не упаковалась");
        g_rs_respond = 10;
        uint16_t port = rs_start();
        d2k_hello ptrig = {pack, pl, NULL, 0, 0, 0};
        d2k_vres r = d2k_quic_classify("127.0.0.1", port, "x.example", ptrig, ctl_hello(), 0);
        if (r.verdict != D2K_V_CLEAR)
            fprintf(stderr, "пачка: verdict=%d reason=%s\n", (int)r.verdict, r.reason);
        CHECK(r.verdict == D2K_V_CLEAR, "замер пачкой на отвечающем стенде не дал CLEAR");
        close(g_rs_fd);
    }

    /* --- СЕРВЕР ОТВЕТИЛ ACK, А ServerHello ПРИСЛАЛ СЛЕДОМ ----------------
     *
     * Так отвечает НАСТОЯЩИЙ сервер, когда клиент прислал несколько Initial:
     * замер 17.09 на www.google.com — 48 байт с одним кадром ACK, потом ещё
     * ACK, и только ТРЕТЬИМ пакетом CRYPTO. Это не редкость и не край:
     * браузер с постквантовым key_share шлёт два Initial ВСЕГДА, то есть так
     * будет отвечать вся живая цель.
     *
     * Оракул, закрывающий зонд на первой же пришедшей датаграмме, объявит
     * такой сервер молчащим — а молчание здесь и есть основание всех
     * вердиктов. Стенд 17.09 поймал это как «вопрос про две датаграммы 0/3»
     * там, где игрушечная коробка обязана была пропустить. */
    {
        g_rs_respond = 5;
        uint16_t port = rs_start();
        d2k_vres r = d2k_quic_classify("127.0.0.1", port, "x.example", trig_hello(), ctl_hello(), 0);
        CHECK(r.verdict == D2K_V_CLEAR,
              "ServerHello пришёл ВТОРОЙ датаграммой, а зонд закрылся на первой — сервер объявлен молчащим");
        close(g_rs_fd);
    }

    /* --- СЫРОЙ TTL ОТВЕТА СНИМАЕТСЯ С НАСТОЯЩЕГО ПАКЕТА ------------------
     * На петле ответ приходит с обычным TTL хоста (у Linux и macOS 64), и
     * важно здесь не конкретное число, а что поле ЗАПОЛНЕНО измеренным
     * значением: ноль означал бы «не измерено», а выдуманное число — ровно ту
     * ошибку, из-за которой оригинал и держит этот факт СЫРЫМ, без пересчёта
     * в расстояние (замер 04.09: ICMP и QUIC на один адрес отдали 56 и 86 —
     * отвечают разные узлы). */
    {
        g_rs_respond = 1;
        uint16_t port = rs_start();
        d2k_vres r = d2k_quic_classify("127.0.0.1", port, "x.example", trig_hello(), ctl_hello(), 0);
        CHECK(r.qprops.server_ttl_in > 0,
              "TTL входящего ответа не снят — сырой факт потерян");
        close(g_rs_fd);
    }

    /* --- метка запрошена, но не подтвердилась: CLEAR не выдаём ------------ */
    {
        g_rs_respond = 1;
        uint16_t port = rs_start();
        d2k_mark_fn saved = d2k_mark_hook;
        d2k_mark_hook = mark_never_ok;
        d2k_vres r = d2k_quic_classify("127.0.0.1", port, "x.example", trig_hello(), ctl_hello(), 777);
        d2k_mark_hook = saved;
        CHECK(r.verdict == D2K_V_INCONCLUSIVE,
              "триггер прошёл, но метка ни разу не подтвердилась — CLEAR принимать нельзя");
        CHECK(r.marked == 0, "r.marked обязан честно сказать, что метка не подтверждена");
        close(g_rs_fd);
    }

    /* --- похожий на ответ, но НЕ аутентичный (тег не сходится): не должен
     * засчитаться успехом -------------------------------------------------- */
    {
        g_rs_respond = 2; /* мусор вместо настоящего AEAD */
        uint16_t port = rs_start();
        d2k_vres r = d2k_quic_classify("127.0.0.1", port, "x.example", trig_hello(), ctl_hello(), 0);
        CHECK(r.verdict != D2K_V_CLEAR,
              "recv()>0 без аутентичности — это НЕ доказательство успеха, CLEAR здесь ошибка");
        close(g_rs_fd);
    }

    /* --- ОТВЕТ СЕРВЕРА — ЛЮБОЙ РАСШИФРОВАННЫЙ Initial, ВКЛЮЧАЯ
     * CONNECTION_CLOSE БЕЗ CRYPTO. Прежде здесь была закреплена «находка 5
     * ревью, круг 2» — отступление от оригинала (вежливый отказ не
     * засчитывался). Критерий донора: Response.Answered()
     * (z2k-detect/internal/quicprobe/parse.go:72-74) — KindInitial ставится
     * за успешную расшифровку (parse.go:176-178), кадры на ответ не влияют.
     * По AGENTS.md («не перепридумывать критерии оригинала») и плану
     * .superpowers/sdd/2026-10-02-review-fixes, задача 10, паритет: CLEAR. */
    {
        g_rs_respond = 4; /* аутентично, но только CONNECTION_CLOSE, без CRYPTO */
        uint16_t port = rs_start();
        d2k_vres r = d2k_quic_classify("127.0.0.1", port, "x.example", trig_hello(), ctl_hello(), 0);
        CHECK(r.verdict == D2K_V_CLEAR,
              "аутентичный CONNECTION_CLOSE — ответ сервера у донора (parse.go:72-74), прямой "
              "зонд 3/3 даёт clear (probe.go:326-327)");
        close(g_rs_fd);
    }

    /* --- Границы критерия донора на уровне одного пакета (parse.go:77-127):
     * Retry засчитывается только для НАШЕЙ версии и типа; VN — по нулевой
     * версии; обрезанный SCID и короткий заголовок — не ответ. ----------- */
    {
        uint8_t pkt[64];
        size_t pl = build_retry_v1(pkt, sizeof pkt);
        CHECK(d2k_quic_verify_response(pkt, pl, trig_hello()) == 0, "Retry v1 на v1 — ответ (parse.go:118-122)");
        pkt[4] = 0x02;
        CHECK(d2k_quic_verify_response(pkt, pl, trig_hello()) != 0, "Retry чужой версии — не ответ (parse.go:123-127)");
        pl = build_vn_reply(pkt, sizeof pkt);
        CHECK(d2k_quic_verify_response(pkt, pl, trig_hello()) == 0, "VN — ответ (parse.go:110-116)");
        CHECK(d2k_quic_verify_response(pkt, 14, trig_hello()) != 0, "VN с обрезанным SCID — не ответ (parse.go:96-98)");
        pkt[0] = 0x40;
        CHECK(d2k_quic_verify_response(pkt, pl, trig_hello()) != 0, "короткий заголовок — не ответ (parse.go:81-85)");
    }

    /* --- Цель получает CONNECTION_CLOSE, контроль — ServerHello: у донора
     * оба «ответили» (parse.go:72-74), прямой зонд 3/3 -> clear
     * (probe.go:326-327), а не content/OPAQUE. ---------------------------- */
    {
        g_rs_respond = 6;
        uint16_t port = rs_start();
        d2k_vres r = d2k_quic_classify("127.0.0.1", port, "x.example", trig_hello(), ctl_hello(), 0);
        CHECK(r.verdict == D2K_V_CLEAR,
              "CONNECTION_CLOSE на имя при ответившем контроле — clear донора, не OPAQUE");
        close(g_rs_fd);
    }

    /* --- Контроль получает Retry (тег не проверяется — как у донора,
     * parse.go:118-122): это ответ, база жива, замер продолжается прямым
     * зондом; имя молчит -> content (OPAQUE), не NO_QUIC/ADDRESS. ------ */
    {
        g_rs_respond = 7;
        uint16_t port = rs_start();
        uint32_t saved_budget = d2k_quic_budget_s;
        d2k_quic_budget_s = 2; /* хватает на шаги 1-2; вопросы дальше не нужны тесту */
        d2k_vres r = d2k_quic_classify("127.0.0.1", port, "x.example", trig_hello(), ctl_hello(), 0);
        d2k_quic_budget_s = saved_budget;
        CHECK(r.verdict == D2K_V_OPAQUE,
              "Retry на контроль — ответ у донора (parse.go:72-74), замер обязан дойти до content");
        CHECK(r.qprops.residual_blocking == D2K_PROP_NO,
              "Retry на повторный контроль — ответ, остаточной блокировки нет");
        close(g_rs_fd);
    }

    /* --- Контроль получает Version Negotiation: тоже ответ донора
     * (parse.go:110-116 — по нулевой версии, без сверки CID). --------- */
    {
        g_rs_respond = 8;
        uint16_t port = rs_start();
        uint32_t saved_budget = d2k_quic_budget_s;
        d2k_quic_budget_s = 2;
        d2k_vres r = d2k_quic_classify("127.0.0.1", port, "x.example", trig_hello(), ctl_hello(), 0);
        d2k_quic_budget_s = saved_budget;
        CHECK(r.verdict == D2K_V_OPAQUE,
              "VN на контроль — ответ у донора (parse.go:72-74), замер обязан дойти до content");
        close(g_rs_fd);
    }

    /* --- ICMP «порт недоступен» на ПРЯМОЙ зонд после ответившего контроля.
     * Донор: ECONNREFUSED (probe.go:663) — не ответ (measure probe.go:573-574
     * считает его в Refused, не в NotBuilt), прямой зонд Answered==0 -> content (probe.go:322-337), и
     * повторный контроль Answered==0 -> residual=true (probe.go:355). Не
     * FLAKY «транспорт». Стенд режима 9 закрывает порт после трёх
     * ответов базовой живости. ------------------------------------------ */
    {
        g_rs_respond = 9;
        uint16_t port = rs_start();
        uint32_t saved_budget = d2k_quic_budget_s;
        d2k_quic_budget_s = 5;
        d2k_vres r = d2k_quic_classify("127.0.0.1", port, "x.example", trig_hello(), ctl_hello(), 0);
        d2k_quic_budget_s = saved_budget;
        CHECK(r.verdict == D2K_V_OPAQUE,
              "ICMP на прямой зонд после ответившего контроля — content донора, не FLAKY");
        CHECK(r.qprops.residual_blocking == D2K_PROP_YES,
              "ICMP на повторный контроль — Answered==0, residual=true (probe.go:355)");
        pthread_join(g_rs_thread, NULL); /* поток сам закрыл свой сокет */
    }

    /* --- Ошибка чтения, НЕ ECONNREFUSED (EHOSTUNREACH), — тишина, не отказ.
     * Донор exchange (probe.go:660-663, frag_linux.go:91): refused только
     * при errors.Is(rerr, ECONNREFUSED). База молчит без отказа -> VN-зонд
     * (стенд на VN не отвечает) -> address (probe.go:303-311), не no_quic. */
    {
        g_rs_respond = 1;
        uint16_t port = rs_start();
        d2k_quic_recv_fault_hook = recv_fault_hostunreach;
        uint32_t rtt_ms = 0;
        int refused = -1, sent = -1;
        d2k_tally t = real_ask("127.0.0.1", port, NULL, 0, trig_hello(), 500, 0,
                               D2K_QUIC_REPEATS, &rtt_ms, &refused, &sent, NULL);
        CHECK(sent == D2K_QUIC_REPEATS && refused == 0 && t.err == 0 && t.pass == 0 &&
                  t.fail == D2K_QUIC_REPEATS,
              "EHOSTUNREACH при чтении — тишина (fail), не refused и не err");
        d2k_vres r = d2k_quic_classify("127.0.0.1", port, "x.example", trig_hello(), ctl_hello(), 0);
        d2k_quic_recv_fault_hook = NULL;
        CHECK(r.verdict == D2K_V_ADDRESS,
              "EHOSTUNREACH на базовом контроле — донор идёт в VN и даёт address, не no_quic");
        close(g_rs_fd);
    }

    /* --- нет UDP-ответа вовсе: настоящий ICMP port-unreachable -> pass==0 И
     * refused>0 -> NO_QUIC оригинала. Сверка с неизменённым Go Run
     * донора велась Go-обвязкой (удалена 06.10.2026, см. историю git).
     * Ограничение локализации ICMP остаётся отдельным фактом, не вердиктом.
     * Датаграмма ОТПРАВЛЯЕТСЯ успешно (connect()+send() на UDP не видят
     * закрытый порт — проверено эмпирически на macOS И Linux: ICMP приходит
     * асинхронно, всплывает на recv()/poll() как ECONNREFUSED), значит это
     * ветка "refused > 0", не "не отправилось" — см. соседний тест ниже на
     * 255.255.255.255 для второй половины находки 5 ревью (круг 4/5). ----- */
    {
        int probe = socket(AF_INET, SOCK_DGRAM, 0);
        CHECK(probe >= 0, "не удалось открыть щуп для свободного порта");
        struct sockaddr_in a;
        memset(&a, 0, sizeof a);
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(0x7f000001);
        a.sin_port = 0;
        bind(probe, (struct sockaddr *)&a, sizeof a);
        socklen_t al = sizeof a;
        getsockname(probe, (struct sockaddr *)&a, &al);
        uint16_t closed_port = ntohs(a.sin_port);
        close(probe); /* порт снова закрыт — гарантированный ICMP port-unreachable на UDP */

        d2k_vres r = d2k_quic_classify("127.0.0.1", closed_port, "x.example", trig_hello(), ctl_hello(), 0);
        CHECK(r.verdict == D2K_V_NO_QUIC,
              "исход NO_QUIC оригинала подменён другим вердиктом после ICMP");
        CHECK(r.probes == D2K_QUIC_REPEATS,
              "вердикт выносится сразу по базовой живости, дальше дерево не идёт; датаграммы "
              "ушли на провод (refused, не not-sent), значит probes == repeats, не 0");
        CHECK(strstr(r.reason, "сетевым отказом") != NULL,
              "донорский порог (refused>0): причина обязана назвать это сетевым отказом, а не "
              "просто 'нет ответа' (находка 5)");
        CHECK(strstr(r.reason, "не локализован") != NULL,
              "причина обязана честно признать неразличимость отказа цели и отказа с пути, а не "
              "утверждать 'не решение коробки' (находка 3)");
        CHECK(strstr(r.reason, "не решение коробки") == NULL,
              "старая формулировка утверждала ровно то, чего знать нельзя (находка 3)");

        /* Контракт оракула: ECONNREFUSED (probe.go:663) — измеренная
           тишина, не «опыт не состоялся». Донор measure (probe.go:573-574):
           case r.refused стоит ДО case r.err, отказ не попадает в NotBuilt. */
        uint32_t rtt_ms = 0;
        int refused = -1, sent = -1;
        d2k_tally t = real_ask("127.0.0.1", closed_port, NULL, 0, trig_hello(), 500, 0,
                               D2K_QUIC_REPEATS, &rtt_ms, &refused, &sent, NULL);
        CHECK(sent == D2K_QUIC_REPEATS && refused == D2K_QUIC_REPEATS,
              "ICMP-отказ: все попытки ушли и получили отказ");
        CHECK(t.err == 0 && t.pass == 0 && t.fail == D2K_QUIC_REPEATS,
              "ICMP-отказ — «нет ответа» (fail), не err: донор probe.go:573-574");
    }

    /* --- НЕ ОТПРАВИЛОСЬ ни разу (наша сторона) -> FLAKY, НЕ UNREACHABLE
     * (находка 5 ревью, круг 4, вторая половина; ПЕРЕНОСИМОСТЬ — находка 1
     * ревью круг 5). Порт 0 НЕ является переносимым триггером: на macOS
     * connect(port=0) отказывает синхронно (EADDRNOTAVAIL), но на Linux
     * connect() и send() оба УСПЕВАЮТ (проверено в контейнере gcc:14 — 66
     * байт реально уходят на провод), то есть на боевой платформе (роутер —
     * Linux) эта ветка была вообще недостижима этим способом. Замена:
     * 255.255.255.255 — вещание БЕЗ SO_BROADCAST отклоняется на любой
     * POSIX-системе (send(2): EACCES "destination address ... broadcast
     * address, но SO_BROADCAST не установлен"), только точка отказа разная
     * (connect() на Linux, send() на macOS — обе внутри qp_send_one, обе
     * дают ОДИНАКОВЫЙ result[i]=-1, "не отправилось", ДО единого байта на
     * сети на ОБЕИХ платформах — проверено эмпирически на обеих). --------- */
    {
        d2k_vres r =
            d2k_quic_classify("255.255.255.255", 443, "x.example", trig_hello(), ctl_hello(), 0);
        CHECK(r.verdict == D2K_V_FLAKY,
              "не отправилось ни разу — наша сторона, сеть не спрошена; НЕ сетевое утверждение "
              "UNREACHABLE (находка 5)");
        CHECK(strstr(r.reason, "не отправилось") != NULL,
              "причина обязана честно сказать, что мы не спросили сеть, а не что сеть отказала");
        CHECK(r.probes == 0,
              "НАХОДКА 4 РЕВЬЮ (круг 5): ноль байт на проводе обязан дать r.probes == 0, а не "
              "pass+fail (тождественно repeats) — иначе это ровно та подмена 'незадан' на "
              "'неудался', только в числе, а не в тексте");
    }

    /* --- ИМЯ РАЗРЕШИЛОСЬ В ПРИВАТНЫЙ АДРЕС.
     *
     * Подменяют и роутер, и AdGuard, и наш собственный редирект по хостлисту.
     * Провайдерская коробка до такого адреса физически не участвует, и любой
     * вердикт о ней был бы выдумкой — а прежде получалось «режут адрес».
     * Замер донора 04.09 на этой же линии: rutracker.org локально даёт
     * 10.171.171.171, а 8.8.8.8 — 188.186.154.79.
     *
     * Ни одного опыта при этом не задаётся: это отказ ДО измерения. ------- */
    {
        static const char *locals[] = {
            "10.171.171.171", "192.168.1.1", "172.16.0.1", "127.0.0.1",
            "169.254.1.1", "100.64.0.1", "0.0.0.0"
        };
        d2k_quic_allow_local = 0;   /* как в продукте, а не как на стенде */
        for (size_t i = 0; i < sizeof locals / sizeof locals[0]; i++) {
            d2k_vres r = d2k_quic_classify(locals[i], 443, "x.example",
                                           trig_hello(), ctl_hello(), 0);
            CHECK(r.verdict == D2K_V_LOCAL_ADDRESS,
                  "приватный адрес обязан давать отдельный вердикт, а не «режут адрес»");
            CHECK(r.probes == 0,
                  "это отказ ДО измерения: ни одна датаграмма не должна уйти на провод");
            CHECK(strstr(r.reason, "приватн") != NULL,
                  "причина обязана назвать подмену на уровне DNS, а не блокировку");
        }
        /* Настоящий адрес через ту же проверку обязан проходить: иначе она
           закрыла бы вообще всё. Зонды при этом ПОДМЕНЕНЫ — иначе проверка
           одной строки ушла бы в настоящую сеть и ждала бы там таймаутов; в
           первой редакции этого теста так и было, и core check вырос на
           минуты. */
        d2k_quic_ask_fn saved_ask = d2k_quic_ask_hook;
        d2k_quic_ask_fn saved_longer = d2k_quic_ask_longer_hook;
        d2k_quic_ask_fn saved_frames = d2k_quic_ask_frames_hook;
        d2k_quic_ask_fn saved_control = d2k_quic_ask_control_hook;
        d2k_quic_ask_hook = mock_ask;
    d2k_quic_ask_longer_hook = mock_ask;
    d2k_quic_ask_frames_hook = mock_ask;
        d2k_quic_ask_control_hook = mock_ask;
        d2k_vres ok = d2k_quic_classify("203.0.113.7", 443, "x.example",
                                        trig_hello(), ctl_hello(), 0);
        d2k_quic_ask_hook = saved_ask;
        d2k_quic_ask_longer_hook = saved_longer;
        d2k_quic_ask_frames_hook = saved_frames;
        d2k_quic_ask_control_hook = saved_control;
        CHECK(ok.verdict != D2K_V_LOCAL_ADDRESS,
              "внешний адрес принят за приватный — проверка закрыла бы весь продукт");
        d2k_quic_allow_local = 1;   /* остальным проверкам нужна петля */
    }

    /* --- Путь жив через VN: исход NO_QUIC после двух серий, как в Run.
     * Прежний тест приписывал оригиналу требование третьей серии. Реальный
     * Go-оригинал в независимом стенде подтвердил 6 зондов, не 9.
     * Нельзя ни добавлять вопрос ради формулировки, ни объявлять его заданным. */
    {
        g_vn_should_answer = 1;
        g_vn_seen_n = 0;
        uint16_t port = vn_start();
        d2k_vres r = d2k_quic_classify("127.0.0.1", port, "x.example", trig_hello(), ctl_hello(), 0);
        CHECK(r.verdict == D2K_V_NO_QUIC,
              "путь жив (VN ответило), контроль молчит — потерян NO_QUIC оригинала");
        /* Донор probe.go:303-306 + hello.go:99-111: на каждую попытку
           randomID(8) для DCID и для SCID, 1200 байт. Шесть идентификаторов
           трёх попыток — все разные (постоянный D0..D7 и пустой SCID делали
           три повтора одной датаграммой). */
        CHECK(g_vn_seen_n == 3, "стенд не увидел три зонда согласования версии");
        {
            const uint8_t *ids[6];
            int shape_ok = 1;
            for (int i = 0; i < g_vn_seen_n && i < 3; i++) {
                const uint8_t *p = g_vn_seen[i];
                if (g_vn_seen_len[i] != 1200 || p[5] != 8 || p[14] != 8 || p[23] != 0) {
                    shape_ok = 0;
                    continue;
                }
                ids[2 * i] = p + 6;
                ids[2 * i + 1] = p + 15;
            }
            CHECK(shape_ok, "зонд VN: не 1200 байт либо DCID/SCID не по 8 байт (hello.go:99-111)");
            int distinct = shape_ok && g_vn_seen_n == 3;
            for (int i = 0; distinct && i < 6; i++) {
                for (int j = i + 1; j < 6; j++) {
                    if (memcmp(ids[i], ids[j], 8) == 0) { distinct = 0; break; }
                }
            }
            CHECK(distinct, "зонд VN: шесть DCID/SCID трёх попыток обязаны быть разными (probe.go:303-306)");
        }
        CHECK(r.probes == 2 * D2K_QUIC_REPEATS,
              "ветка NO_QUIC добавила третью серию, которой нет в оригинале");
        CHECK(strstr(r.reason, "не спрашивалось") != NULL && strstr(r.reason, "ОБА имени") == NULL,
              "неотправленное имя выдано за проверенное");
        CHECK(strstr(r.reason, "адрес") == NULL,
              "§2.3: в тексте не должно быть утверждения про блокировку АДРЕСА");
        close(g_vn_fd);
    }

    /* --- молчит вообще всё, включая согласование версии -> ADDRESS оригинала, НЕ
     * UNREACHABLE (правка ревью 2026-09-06, круг 4, находка 3): все шесть
     * датаграмм (3 база + 3 VN) ушли успешно, ответа нет ни на одну — опыты
     * СОСТОЯЛИСЬ и получили тишину, а не "транспорт не случился". Полная
     * тишина на UDP/443 одинаково объясняется мёртвым путём и блокировкой
     * порта/протокола целиком — различить нельзя (§2.3), значит нельзя
     * утверждать "не решение коробки": прежняя редакция знала ровно то, чего
     * знать нельзя, только с другой стороны запрета. ------------------------ */
    {
        g_vn_should_answer = 0;
        uint16_t port = vn_start();
        d2k_vres r = d2k_quic_classify("127.0.0.1", port, "x.example", trig_hello(), ctl_hello(), 0);
        CHECK(r.verdict == D2K_V_ADDRESS,
              "исход ADDRESS оригинала после молчащих Initial и VN подменён");
        CHECK(r.probes == 2 * D2K_QUIC_REPEATS,
              "ветка ADDRESS не выполнила ровно две серии оригинала");
        CHECK(strstr(r.reason, "нельзя отличить") != NULL,
              "причина обязана честно признать неразличимость (§2.3), а не утверждать транспорт");
        CHECK(strstr(r.reason, "не решение коробки") == NULL,
              "старая формулировка утверждала ровно то, чего знать нельзя (находка 3)");
        close(g_vn_fd);
    }

    /* --- НАХОДКА A РЕВЬЮ (круг 3): зонд согласования версии обязан идти С
     * МЕТКОЙ, и её неудача обязана попасть в r.marked. База (шаг 0) идёт тем
     * же d2k_mark_hook, поэтому "просто mark_never_ok" не различил бы "VN не
     * учитывает свою метку" от "база не учла свою" — база сама завалила бы
     * all_marked первой. mark_fail_from_nth пропускает первые 3 (база) и
     * валит метку начиная с 4-го вызова (зонд согласования версии) —
     * изолированная проверка именно находки A. ------------------------------ */
    {
        g_vn_should_answer = 1;
        uint16_t port = vn_start();
        d2k_mark_fn saved = d2k_mark_hook;
        g_mark_call_count = 0;
        g_mark_fail_from = D2K_QUIC_REPEATS + 1; /* 4-й и далее вызовы — мимо метки */
        d2k_mark_hook = mark_fail_from_nth;
        d2k_vres r = d2k_quic_classify("127.0.0.1", port, "x.example", trig_hello(), ctl_hello(), 555);
        d2k_mark_hook = saved;
        g_mark_fail_from = 0;
        CHECK(r.verdict == D2K_V_NO_QUIC, "вердикт не должен зависеть от того, встала ли метка");
        CHECK(r.marked == 0,
              "база помечена честно (первые 3 вызова), но зонд согласования версии — нет (вызовы "
              "4-6): r.marked обязан упасть на этом одном, а не остаться истинным (находка A)");
        close(g_vn_fd);
    }

    /* --- НАХОДКА 1 РЕВЬЮ (круг 4): зонд согласования версии — ПОРОГ
     * ПРИСУТСТВИЯ, НЕ ЕДИНОГЛАСИЯ. Круг 3 (находка C) требовал здесь
     * единогласия 3/3 и объявлял 2/3 FLAKY — это было ошибкой формулировки
     * диспетча, не реализации: единогласие отвечает на вопрос "одинаково ли
     * коробка решает" (про РЕШЕНИЕ), а этот зонд спрашивает про ФАКТ "жив ли
     * путь" — ОДИН пришедший ответ уже доказывает факт, второй и третий
     * ничего не добавляют и отнять доказательство не могут. RFC 9000 §6.1
     * разрешает серверу отвечать VN не на каждый пакет; донор (probe.go:308)
     * использует тот же порог: `if vn.Answered == 0`. Проверены ОБЕ границы:
     * 2 из 3 (одна обычная потеря) и 1 из 3 (сервер отвечает на минимум,
     * например из-за собственного лимита VN, §21.5.4) — обе INCONCLUSIVE,
     * ОБЕ измерены отдельно, чтобы граница "хотя бы один" не осталась
     * проверенной только с одной стороны. -------------------------------- */
    {
        g_vn_should_answer = 1;
        g_vn_drop_first_n = 1; /* стенд теряет РОВНО одну из трёх датаграмм: 2/3 отвечают */
        uint16_t port = vn_start();
        d2k_vres r = d2k_quic_classify("127.0.0.1", port, "x.example", trig_hello(), ctl_hello(), 0);
        g_vn_drop_first_n = 0;
        CHECK(r.verdict == D2K_V_NO_QUIC,
              "2 из 3 отвечают — присутствие уже доказано, не единогласие; НЕ FLAKY (находка 1)");
        CHECK(strstr(r.reason, "no_quic") != NULL && r.probes == 2 * D2K_QUIC_REPEATS,
              "тот же вывод, что и при 3/3: порог VN — присутствие, а не единогласие");
        close(g_vn_fd);
    }
    {
        g_vn_should_answer = 1;
        g_vn_drop_first_n = 2; /* стенд теряет ДВЕ из трёх датаграмм: 1/3 отвечает — граница */
        uint16_t port = vn_start();
        d2k_vres r = d2k_quic_classify("127.0.0.1", port, "x.example", trig_hello(), ctl_hello(), 0);
        g_vn_drop_first_n = 0;
        CHECK(r.verdict == D2K_V_NO_QUIC,
              "1 из 3 отвечает — присутствие уже доказано на самой границе (находка 1)");
        CHECK(strstr(r.reason, "версии 1/3") != NULL,
              "причина обязана назвать измеренное число ответивших, не округлить его");
        close(g_vn_fd);
    }

    /* --- НАХОДКА "ПРО БЮДЖЕТ": исчерпание РЕАЛЬНЫМ временем, не спецслучаем
     * budget_s==0 — единственный шов, который не подменяется, часы, должен
     * быть прогнан хотя бы одним тестом (замечание ревьюера, круг 2). Контроль
     * отвечает (живость есть), триггер молчит нарочно (g_rs_respond=3) —
     * пол ожидания 1500 мс (D2K_QUIC_RTT_WAIT_FLOOR_MS) на шаге 1 сам по себе
     * съедает больше секундного бюджета. ------------------------------------ */
    {
        g_rs_respond = 3; /* отвечает только на контроль */
        uint16_t port = rs_start();
        uint32_t saved_budget = d2k_quic_budget_s;
        d2k_quic_budget_s = 1; /* 1 настоящая секунда, не 0 — проверяем часы, не спецслучай */
        d2k_vres r = d2k_quic_classify("127.0.0.1", port, "x.example", trig_hello(), ctl_hello(), 0);
        d2k_quic_budget_s = saved_budget;
        close(g_rs_fd);

        CHECK(r.verdict == D2K_V_INCONCLUSIVE,
              "реальный бюджет в 1 с обязан истечь до шага 2 (пол ожидания 1,5 с на шаге 1 один "
              "съедает больше) — проверка настоящих часов, не спецслучая budget_s==0");
        CHECK(strstr(r.reason, "бюджет") != NULL, "причина обязана назвать именно бюджет");
    }

    d2k_quic_wait_ms = saved_wait_ms; /* контракт: вернуть, как и положено (находка 9, круг 2) */

    if (fails) {
        printf("ПРОВАЛОВ: %d\n", fails);
        return 1;
    }
    printf("вопросник по QUIC: все проверки прошли\n");
    return 0;
}
