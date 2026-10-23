/* test_session.c — склейка модулей на настоящих пакетах.
 *
 * Правило, которое здесь проверяется главным образом: НЕ ПОНЯЛ — НЕ ТРОГАЙ.
 * Проверок на «пропустили и объяснили почему» больше, чем на «применили»:
 * пропустить чужой пакет безвредно, тронуть непонятый — значит испортить
 * человеку соединение и не узнать об этом.
 */
#include <stdio.h>
#include <string.h>
#include "test_nat_stub.h"
#include "d2k_nat.h"
#include "d2k_session.h"
#include "d2k_hold.h"
#include "d2k_tls.h"
#include "d2k_ctq.h"

static int fails;
static size_t hold_released;
static void hold_release(void *ctx, uint32_t id, const uint8_t *p, size_t n) {
    (void)id;
    hold_released++;
    d2k_session_observe_tcp(ctx, p, n, 20);
}
#define CHECK(cond, msg)                                   \
    do {                                                   \
        if (!(cond)) {                                     \
            printf("ПРОВАЛ: %s\n", msg);                   \
            fails++;                                       \
        }                                                  \
    } while (0)

/* Сколько раз в журнале встретился отказ плана (D2K_JRN_PLAN_REFUSED) — по
   count, не по note: разные причины отказа делят один и тот же вид записи
   (см. d2k_journal.h), а здесь для каждого сценария в таблице ровно одна
   цель, так что кода причины достаточно. */
static size_t count_plan_refused(const d2k_session *s) {
    const d2k_journal *j = d2k_session_journal(s);
    size_t n = d2k_journal_count(j);
    size_t c = 0;
    for (size_t i = 0; i < n; i++) {
        const d2k_jrn_entry *e = d2k_journal_at(j, i);
        if (e && e->kind == D2K_JRN_PLAN_REFUSED) {
            c++;
        }
    }
    return c;
}

/* Сколько записей заданного вида в журнале. Отдельно от count_plan_refused:
   «план не доисполнен» и «план не применялся» — разные виды записи, и считать
   их одной функцией значило бы снова смешать два разных факта. */
static size_t count_kind(const d2k_session *s, uint8_t kind) {
    const d2k_journal *j = d2k_session_journal(s);
    size_t n = d2k_journal_count(j);
    size_t c = 0;
    for (size_t i = 0; i < n; i++) {
        const d2k_jrn_entry *e = d2k_journal_at(j, i);
        if (e && e->kind == kind) {
            c++;
        }
    }
    return c;
}

/* Последняя запись заданного вида. NULL — такой не было. */
static const d2k_jrn_entry *last_of_kind(const d2k_session *s, uint8_t kind) {
    const d2k_journal *j = d2k_session_journal(s);
    size_t n = d2k_journal_count(j);
    const d2k_jrn_entry *found = NULL;
    for (size_t i = 0; i < n; i++) {
        const d2k_jrn_entry *e = d2k_journal_at(j, i);
        if (e && e->kind == kind) {
            found = e;
        }
    }
    return found;
}

/* Тот же план плюс защита от чужого сброса. minexec=2: защита появилась во
   второй версии исполнителя, и план обязан это объявлять. */
static const uint8_t plan_guard[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 2, 0, 0, 0, 5,
    0x00, 0x10, 0x00, 0x05, 0x00, 0x01, 0xDE, 0xAD, 0xBE,
    0x00, 0x11, 0x00, 0x08, 0x00, 0x01, 0x03, 0x01, 0, 0, 0, 0,
    0x01, 0x01, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x01, 0x02, 0x00,
                            0x00, 0x01, 0x30, 0xB0,
    0x01, 0x03, 0x00, 0x01, 0x00,
    0x01, 0x04, 0x00, 0x01, 0x01
};

/* План: одна фальшивка перед куском, две копии с паузой 78 мс. */
static const uint8_t plan_bytes[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 4,
    0x00, 0x10, 0x00, 0x05, 0x00, 0x01, 0xDE, 0xAD, 0xBE,
    0x00, 0x11, 0x00, 0x08, 0x00, 0x01, 0x03, 0x01, 0, 0, 0, 0,
    0x01, 0x01, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x01, 0x02, 0x00,
                            0x00, 0x01, 0x30, 0xB0,
    0x01, 0x03, 0x00, 0x01, 0x00
};

/* Тот же план, что plan_bytes, плюс запись REC_ID (тип 0x0001, длина 16) —
 * записей в заголовке поэтому пять. Идентификатор НЕпечатный (0xС0..0xCF)
 * нарочно: он двоичный, и путь от разбора плана до ТОЧКИ ОТПРАВКИ не имеет
 * права его чистить под печать — дорога через поле имени журнала заменила бы
 * каждый такой байт точкой (journal.c), и проверка печатным идентификатором
 * прошла бы мимо этого. */
static const uint8_t want_send_id[16] = {
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
    0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF
};
static const uint8_t plan_with_send_id[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 5,
    0x00, 0x01, 0x00, 0x10,
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
    0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
    0x00, 0x10, 0x00, 0x05, 0x00, 0x01, 0xDE, 0xAD, 0xBE,
    0x00, 0x11, 0x00, 0x08, 0x00, 0x01, 0x03, 0x01, 0, 0, 0, 0,
    0x01, 0x01, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x01, 0x02, 0x00,
                            0x00, 0x01, 0x30, 0xB0,
    0x01, 0x03, 0x00, 0x01, 0x00
};

/* Тот же план, но ВЛАДЕЮЩИЙ НАГРУЗКОЙ: добавлена запись REC_PACE (0x0105,
 * 4 байта, 12000 мкс). Наличие разноса во времени означает, что правду
 * выпускает план, а не ядро, — оригинал снимается (fate DROP). Нужен веткам
 * отказа: только у такого плана «оригинал уже не наш» вообще возможно.
 * Записей шесть: ID, PAYLOAD, POISON, FAKE, ORDER, PACE. */
static const uint8_t plan_owns_payload[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 6,
    0x00, 0x01, 0x00, 0x10,
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
    0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
    0x00, 0x10, 0x00, 0x05, 0x00, 0x01, 0xDE, 0xAD, 0xBE,
    0x00, 0x11, 0x00, 0x08, 0x00, 0x01, 0x03, 0x01, 0, 0, 0, 0,
    0x01, 0x01, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x01, 0x02, 0x00,
                            0x00, 0x01, 0x30, 0xB0,
    0x01, 0x03, 0x00, 0x01, 0x00,
    0x01, 0x05, 0x00, 0x04, 0x00, 0x00, 0x2E, 0xE0
};

/* План с числом повторов D2K_RESULT_MAX+1: больше вместимости результата.
 * Он должен отвергаться целиком, а не тихо обрезаться. Заголовок schema=1
 * + minexec=1 + flags=0 + число записей=2: REC_PAYLOAD (id=1, байт 0xAA) и
 * REC_FAKE (payload_id=1, poison_id=0, placement=PLACE_BEFORE,
 * gap_us=0). */
static const uint8_t plan_too_many_repeats[] = {
    'D', '2', 'K', 'P', 0, 1, 0, 1, 0, 0, 0, 2,
    0x00, 0x10, 0x00, 0x03, 0x00, 0x01, 0xAA,
    0x01, 0x01, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x00, D2K_RESULT_MAX + 1, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/* Порты в ключе потока лежат в СЕТЕВОМ порядке (d2k_key_make, d2k_track.h):
   сравнивать их с числом напрямую значит сравнить по-разному на разных арках.
   Своя функция, а не htons: <arpa/inet.h> тянуть в переносимый тест незачем. */
static uint16_t htons16(uint16_t v) {
    uint8_t b[2];
    b[0] = (uint8_t)(v >> 8);
    b[1] = (uint8_t)v;
    uint16_t o;
    memcpy(&o, b, 2);
    return o;
}

static void wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

/* Собирает IPv4/TCP пакет с заданной нагрузкой. */
static size_t build_pkt(uint8_t *o, uint16_t sport, uint8_t flags,
                        const uint8_t *pay, size_t paylen) {
    size_t total = 20 + 20 + paylen;
    memset(o, 0, 40);
    o[0] = 0x45;
    wr16(o + 2, (uint16_t)total);
    wr16(o + 4, 0x1000);
    o[8] = 64;
    o[9] = 6;
    uint8_t s[4] = {192, 168, 1, 67}, d[4] = {1, 2, 3, 4};
    memcpy(o + 12, s, 4);
    memcpy(o + 16, d, 4);
    wr16(o + 20, sport);
    wr16(o + 22, 443);
    wr32(o + 24, 1000);
    wr32(o + 28, 0x11223344);
    o[32] = 0x50;
    o[33] = flags;
    wr16(o + 34, 64240);
    if (paylen) {
        memcpy(o + 40, pay, paylen);
    }
    return total;
}

/* Настоящее приветствие с именем hetzner.com. */
static size_t build_hello(uint8_t *out) {
    uint8_t body[256];
    size_t b = 0;
    body[b++] = 0x03; body[b++] = 0x03;
    for (int i = 0; i < 32; i++) body[b++] = (uint8_t)i;
    body[b++] = 0;
    body[b++] = 0x00; body[b++] = 0x02; body[b++] = 0x13; body[b++] = 0x01;
    body[b++] = 0x01; body[b++] = 0x00;
    const char *sni = "hetzner.com";
    size_t nl = strlen(sni);
    uint8_t ext[64]; size_t e = 0;
    ext[e++] = 0x00; ext[e++] = 0x00;
    ext[e++] = 0x00; ext[e++] = (uint8_t)(5 + nl);
    ext[e++] = 0x00; ext[e++] = (uint8_t)(3 + nl);
    ext[e++] = 0x00;
    ext[e++] = 0x00; ext[e++] = (uint8_t)nl;
    memcpy(ext + e, sni, nl); e += nl;
    body[b++] = 0x00; body[b++] = (uint8_t)e;
    memcpy(body + b, ext, e); b += e;

    size_t o = 0;
    out[o++] = 0x16; out[o++] = 0x03; out[o++] = 0x01;
    out[o++] = (uint8_t)((b + 4) >> 8); out[o++] = (uint8_t)(b + 4);
    out[o++] = 0x01; out[o++] = 0x00;
    out[o++] = (uint8_t)(b >> 8); out[o++] = (uint8_t)b;
    memcpy(out + o, body, b); o += b;
    return o;
}

/* То же приветствие, добитое расширением padding (RFC 7685) до want байт на
   проводе. Нужно затем, что «перекрытие на полном сегменте» — отдельный
   случай приёмки U3: статическая проверка длины считает только объявленные
   планом части, а кусок нагрузки приходит ИЗ ПАКЕТА, и на коротком
   приветствии расхождение не видно. */
static size_t build_hello_pad(uint8_t *out, size_t want) {
    size_t base = build_hello(out);
    if (want <= base + 4) { return base; }
    size_t pad = want - base - 4;
    if (pad > 0xFF00) { return base; }

    /* Три длины растут на одну величину: блок расширений, тело рукопожатия и
       запись. Позиция длины блока расширений считается ПРОХОДОМ по телу —
       зашитое смещение поменялось бы от любой правки build_hello. */
    size_t q = 5 + 4 + 2 + 32;                      /* запись, заголовок, версия, random */
    q += 1 + out[q];                                /* session_id */
    q += 2 + ((size_t)out[q] << 8 | out[q + 1]);    /* cipher_suites */
    q += 1 + out[q];                                /* compression */
    wr16(out + q, (uint16_t)(((size_t)out[q] << 8 | out[q + 1]) + 4 + pad));

    size_t end = base;
    out[end++] = 0x00; out[end++] = 0x15;           /* padding */
    wr16(out + end, (uint16_t)pad); end += 2;
    memset(out + end, 0, pad); end += pad;

    wr16(out + 7, (uint16_t)(((size_t)out[7] << 8 | out[8]) + 4 + pad));
    wr16(out + 3, (uint16_t)(((size_t)out[3] << 8 | out[4]) + 4 + pad));
    return end;
}

/* Пакет с ОПЦИЯМИ TCP: смещение данных растёт, и всё, что собирается из
   пакета, растёт вместе с ним. Опции — NOP'ы: их содержимое здесь не предмет,
   предмет — длина. */
static size_t build_pkt_opt(uint8_t *o, uint16_t sport, uint8_t flags,
                            const uint8_t *pay, size_t paylen, size_t optlen) {
    size_t total = 20 + 20 + optlen + paylen;
    memset(o, 0, 40 + optlen);
    o[0] = 0x45;
    wr16(o + 2, (uint16_t)total);
    wr16(o + 4, 0x1000);
    o[8] = 64;
    o[9] = 6;
    uint8_t s[4] = {192, 168, 1, 67}, d[4] = {1, 2, 3, 4};
    memcpy(o + 12, s, 4);
    memcpy(o + 16, d, 4);
    wr16(o + 20, sport);
    wr16(o + 22, 443);
    wr32(o + 24, 1000);
    wr32(o + 28, 0x11223344);
    o[32] = (uint8_t)(((20 + optlen) / 4) << 4);
    o[33] = flags;
    wr16(o + 34, 64240);
    memset(o + 40, 0x01, optlen);          /* NOP */
    if (paylen) {
        memcpy(o + 40 + optlen, pay, paylen);
    }
    return total;
}

/* Тот же поток, но со стороны сервера: концы поменяны местами. */
static size_t build_rev_pkt_ttl(uint8_t *o, uint16_t client_port, uint8_t flags,
                                const uint8_t *pay, size_t paylen, uint8_t ttl);

static size_t build_rev_pkt(uint8_t *o, uint16_t client_port, uint8_t flags,
                            const uint8_t *pay, size_t paylen) {
    return build_rev_pkt_ttl(o, client_port, flags, pay, paylen, 64);
}

static size_t build_rev_pkt_ttl(uint8_t *o, uint16_t client_port, uint8_t flags,
                                const uint8_t *pay, size_t paylen, uint8_t ttl) {
    size_t total = 20 + 20 + paylen;
    memset(o, 0, 40);
    o[0] = 0x45;
    wr16(o + 2, (uint16_t)total);
    wr16(o + 4, 0x2000);
    o[8] = ttl;
    o[9] = 6;
    uint8_t s[4] = {1, 2, 3, 4}, d[4] = {192, 168, 1, 67};
    memcpy(o + 12, s, 4);
    memcpy(o + 16, d, 4);
    wr16(o + 20, 443);
    wr16(o + 22, client_port);
    wr32(o + 24, 5000);
    wr32(o + 28, 1001);
    o[32] = 0x50;
    o[33] = flags;
    wr16(o + 34, 64240);
    if (paylen) {
        memcpy(o + 40, pay, paylen);
    }
    return total;
}

/* --- ПРОМАХ CONNTRACK: ОДИН ОТВЕТ ЕЩЁ НЕ ОТВЕТ ----------------------------
 *
 * Справка о трансляции читается из /proc/net/nf_conntrack, и это чтение НЕ
 * атомарно: замер 17.09 на стенде транзита поймал случай, когда запрос вернул
 * «записи нет», а повторный запрос сразу же, без паузы, ту же запись нашёл
 * (диагностика печатала «ПОВТОР СРАЗУ ЖЕ: rc=0»).
 *
 * Цена одного промаха оказалась несоразмерной. Мелкое следствие: клиент, чьё
 * приветствие пришлось на промах, остаётся без обхода — один из тридцати.
 * Тяжёлое: если промах попадает на поток СОБСТВЕННОГО ЗОНДА, план к нему не
 * применяется, зонд не доходит до приложения, единственный найденный
 * кандидат объявляется негодным и цель остаётся без обхода ЦЕЛИКОМ. Именно
 * это дало «прошло 0 из 30» в прогоне 17.09.
 *
 * Поэтому промах перепроверяется. Здесь проверяется ровно это, и с двух
 * сторон: гонка обязана лечиться, а настоящее отсутствие записи обязано
 * по-прежнему отвергать план — иначе посылки уйдут мимо NAT с локальным
 * адресом (13.09, docs/field/2026-09-13-transit-vs-local.md). */
static int nat_calls;
static int nat_miss_first_n;   /* сколько первых вызовов отвечают «нет записи» */

static int nat_stub(const char *path, uint8_t proto,
                    uint32_t src_ip, uint16_t src_port,
                    uint32_t dst_ip, uint16_t dst_port,
                    uint32_t *out_src, uint16_t *out_sport) {
    (void)path; (void)proto; (void)dst_ip; (void)dst_port;
    nat_calls++;
    if (nat_calls <= nat_miss_first_n) { return -1; }
    *out_src = src_ip;
    *out_sport = src_port;
    return 0;
}

/* --- ПОДОЗРЕНИЕ ГОВОРИТ, ПРИМЕНЯЛСЯ ЛИ ПЛАН К ЭТОМУ ПОТОКУ ----------------
 *
 * Поле 18.09.2026: через две секунды после «ПОДТВЕРЖДЕНО» приходило
 * «подозрение при подтверждённом плане — наблюдение прекращаю», хотя клиент
 * тут же получал 200 четыре раза подряд. Подозрение было о потоке, начатом
 * ДО того, как план доехал до датапата: такой поток шёл без обхода, и уликой
 * против плана он не является.
 *
 * Отличить их может только датапат: он один знает, применялся ли план к
 * ЭТОМУ потоку. Три состояния, а не два: «не сказано» нужно для старой
 * службы, где поля ещё нет, — иначе её подозрения молча сменили бы смысл. */
static const d2k_jrn_entry *last_suspect(const d2k_session *s) {
    const d2k_journal *j = d2k_session_journal(s);
    size_t n = d2k_journal_count(j);
    for (size_t i = n; i > 0; i--) {
        const d2k_jrn_entry *e = d2k_journal_at(j, i - 1);
        if (e && e->kind == D2K_JRN_SUSPECT) { return e; }
    }
    return NULL;
}

static void test_suspect_tells_planned(void) {
    uint8_t hello[512];
    size_t hl = build_hello(hello);

    /* План стоит и применился — подозрение по ЭТОМУ потоку улика настоящая. */
    {
        d2k_session *s = d2k_session_new(64, 64);
        d2k_plan *p = NULL;
        char err[160];
        CHECK(d2k_plan_load(plan_owns_payload, sizeof plan_owns_payload, &p,
                            err, sizeof err) == 0, "план не загрузился");
        d2k_session_set_plan(s, p);
        uint8_t pkt[1024], buf[8192];
        d2k_result r;
        size_t pn = build_pkt(pkt, 47700, 0x18, hello, hl);
        d2k_session_packet(s, pkt, pn, 1000, buf, sizeof buf, &r);
        CHECK(r.applied, "план не применился — проверять нечего");
        /* Два повтора того же приветствия: клиент ждёт ответа. */
        d2k_session_packet(s, pkt, pn, 2000, buf, sizeof buf, &r);
        d2k_session_packet(s, pkt, pn, 3000, buf, sizeof buf, &r);
        const d2k_jrn_entry *e = last_suspect(s);
        CHECK(e != NULL, "подозрение по повтору приветствия не записано");
        CHECK(e && e->d_planned == D2K_PLANNED_YES,
              "подозрение молчит о том, что план к этому потоку применялся");
        d2k_session_free(s);
    }

    /* A duplicate ClientHello after a real server TLS response is not
       evidence that the hello went unanswered. Late response cuts have their
       own RST/FIN path and must not re-enter the early-hello search. */
    {
        d2k_session *s = d2k_session_new(64, 64);
        d2k_plan *p = NULL; char err[160];
        CHECK(d2k_plan_load(plan_owns_payload, sizeof plan_owns_payload, &p,
                            err, sizeof err) == 0, "answered-repeat plan fixture");
        d2k_session_set_plan(s, p);
        uint8_t pkt[1024], buf[8192]; d2k_result r;
        size_t pn = build_pkt(pkt, 47702, 0x18, hello, hl);
        d2k_session_packet(s, pkt, pn, 1000, buf, sizeof buf, &r);
        const uint8_t appdata[] = {0x17, 0x03, 0x03, 0x00, 0x01, 0x00};
        pn = build_rev_pkt(pkt, 47702, 0x18, appdata, sizeof appdata);
        d2k_session_packet(s, pkt, pn, 2000, buf, sizeof buf, &r);
        pn = build_pkt(pkt, 47702, 0x18, hello, hl);
        d2k_session_packet(s, pkt, pn, 3000, buf, sizeof buf, &r);
        d2k_session_packet(s, pkt, pn, 4000, buf, sizeof buf, &r);
        CHECK(!last_suspect(s), "answered TLS flow must not restart search on duplicate hello");
        d2k_session_free(s);
    }

    /* A record-type byte or truncated/invalid header is not a TLS reply. */
    for (unsigned variant=0; variant<3; variant++) {
        d2k_session *s=d2k_session_new(64,64);
        uint8_t pkt[1024],buf[8192]; d2k_result r;
        size_t pn=build_pkt(pkt,47703,0x18,hello,hl);
        d2k_session_packet(s,pkt,pn,1000,buf,sizeof buf,&r);
        const uint8_t bad[][6]={{0x17}, {0x17,0x03,0x03,0x00,0x10,0x00},
                              {0x17,0x03,0xff,0x00,0x01,0x00}};
        pn=build_rev_pkt(pkt,47703,0x18,bad[variant],variant?6:1);
        d2k_session_packet(s,pkt,pn,2000,buf,sizeof buf,&r);
        pn=build_pkt(pkt,47703,0x18,hello,hl);
        d2k_session_packet(s,pkt,pn,3000,buf,sizeof buf,&r);
        d2k_session_packet(s,pkt,pn,4000,buf,sizeof buf,&r);
        const d2k_jrn_entry *e=last_suspect(s);
        CHECK(e && e->code==D2K_SUSPECT_REPEAT,
              "malformed reverse payload must not hide unanswered ClientHello repeats");
        d2k_session_free(s);
    }

    /* Плана не было вовсе — подозрение о таком потоке про план не говорит. */
    {
        d2k_session *s = d2k_session_new(64, 64);
        uint8_t pkt[1024], buf[8192];
        d2k_result r;
        size_t pn = build_pkt(pkt, 47701, 0x18, hello, hl);
        d2k_session_packet(s, pkt, pn, 1000, buf, sizeof buf, &r);
        CHECK(!r.applied, "план взялся ниоткуда");
        d2k_session_packet(s, pkt, pn, 2000, buf, sizeof buf, &r);
        d2k_session_packet(s, pkt, pn, 3000, buf, sizeof buf, &r);
        const d2k_jrn_entry *e = last_suspect(s);
        CHECK(e != NULL, "подозрение по повтору приветствия не записано");
        CHECK(e && e->d_planned == D2K_PLANNED_NO,
              "поток без плана объявлен таким, к которому план применялся");
        d2k_session_free(s);
    }
}

/* Поздний RST после TLS app-data — лишь триггер узкой проверки объёма.
   Он не должен сливаться с ранним RST «в ответ на ClientHello»: сервер уже
   прислал прикладные данные, поэтому причиной поиска может стать только
   воспроизводимый обрыв ответа, измеренный контроллером. */
static void test_late_rst_after_tls_appdata(void) {
    d2k_session *s = d2k_session_new(64, 64);
    CHECK(s != NULL, "сессия позднего RST не создалась");
    if (!s) { return; }

    uint8_t hello[512], pkt[1024], buf[8192];
    size_t hlen = build_hello(hello);
    d2k_result r;

    size_t n = build_pkt(pkt, 47801, 0x18, hello, hlen);
    d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);

    /* Тип записи 23 важен, содержимое зашифровано и разбирать его не надо. */
    const uint8_t appdata[] = {0x17, 0x03, 0x03, 0x00, 0x01, 0x00};
    n = build_rev_pkt(pkt, 47801, 0x18, appdata, sizeof appdata);
    d2k_session_packet(s, pkt, n, 2000, buf, sizeof buf, &r);
    CHECK(count_kind(s, D2K_JRN_EXCHANGE) == 1,
          "TLS app-data не записаны до позднего RST");

    n = build_rev_pkt(pkt, 47801, 0x14, NULL, 0);
    d2k_session_packet(s, pkt, n, 3000, buf, sizeof buf, &r);
    const d2k_jrn_entry *e = last_suspect(s);
    CHECK(e != NULL, "поздний RST после TLS app-data не замечен");
    CHECK(e && e->code == D2K_SUSPECT_RST_AFTER_APP,
          "поздний RST смешан с ранним RST до ответа");
    d2k_session_free(s);

    /* Если браузер закрывает зависшую загрузку сам, его поздний RST тоже
       должен инициировать только парное измерение RX-объёма. Входящий
       ClientHello и обычное число исходящих пакетов попадают в узкое окно;
       firewall отдельно пропускает сюда поздний RST. */
    s = d2k_session_new(64, 64);
    CHECK(s != NULL, "сессия позднего клиентского RST не создалась");
    if (!s) { return; }
    n = build_pkt(pkt, 47803, 0x18, hello, hlen);
    d2k_session_packet(s, pkt, n, 3100, buf, sizeof buf, &r);
    n = build_rev_pkt(pkt, 47803, 0x18, appdata, sizeof appdata);
    d2k_session_packet(s, pkt, n, 3200, buf, sizeof buf, &r);
    n = build_pkt(pkt, 47803, 0x14, NULL, 0);
    d2k_session_packet(s, pkt, n, 3300, buf, sizeof buf, &r);
    e = last_suspect(s);
    CHECK(e != NULL && e->code == D2K_SUSPECT_RST_AFTER_APP,
          "клиентский RST после TLS app-data не дал узкий RX-volume-сигнал");
    d2k_session_free(s);

    /* The protective drop must preserve the measurement trigger: an alien
       RST after response data is still a residual RX suspicion, not proof. */
    s = d2k_session_new(64, 64);
    CHECK(s != NULL, "guarded late-RST session allocation failed");
    if (!s) return;
    d2k_plan *guard = NULL;
    char err[200];
    CHECK(d2k_plan_load(plan_guard, sizeof plan_guard, &guard, err, sizeof err) == 0,
          "guarded late-RST plan failed");
    d2k_session_set_plan(s, guard);
    n = build_pkt(pkt, 47804, 0x18, hello, hlen);
    d2k_session_packet(s, pkt, n, 3400, buf, sizeof buf, &r);
    n = build_rev_pkt(pkt, 47804, 0x18, appdata, sizeof appdata);
    pkt[8] = 53;
    d2k_session_packet(s, pkt, n, 3500, buf, sizeof buf, &r);
    n = build_rev_pkt(pkt, 47804, 0x14, NULL, 0);
    pkt[8] = 127;
    d2k_session_packet(s, pkt, n, 3600, buf, sizeof buf, &r);
    e = last_suspect(s);
    CHECK(r.verdict == D2K_VERDICT_DROP && e && e->code == D2K_SUSPECT_RST_AFTER_APP,
          "alien RST drop hid residual RX measurement trigger");
    d2k_session_free(s);

    s = d2k_session_new(64, 64);
    guard = NULL;
    CHECK(d2k_plan_load(plan_guard, sizeof plan_guard, &guard, err, sizeof err) == 0,
          "FIN retry plan fixture failed");
    d2k_session_set_plan(s, guard);
    n = build_pkt(pkt, 47805, 0x18, hello, hlen);
    d2k_session_packet(s, pkt, n, 3700, buf, sizeof buf, &r);
    n = build_rev_pkt(pkt, 47805, 0x18, appdata, sizeof appdata);
    d2k_session_packet(s, pkt, n, 3800, buf, sizeof buf, &r);
    n = build_pkt(pkt, 47805, 0x11, NULL, 0);
    d2k_session_packet(s, pkt, n, 3900, buf, sizeof buf, &r);
    CHECK(!last_suspect(s) && r.verdict == D2K_VERDICT_ACCEPT,
          "first FIN triggered RX or was intercepted");
    d2k_session_packet(s, pkt, n, 4000, buf, sizeof buf, &r);
    e = last_suspect(s);
    CHECK(e && e->code == D2K_SUSPECT_FIN_RETRY && r.verdict == D2K_VERDICT_ACCEPT,
          "unanswered FIN retry under plan did not trigger narrow RX measurement");
    d2k_session_free(s);

    /* A handshake/ServerHello response followed by RST is not enough to
       start an RX-volume search: application-data must have been observed. */
    s = d2k_session_new(64, 64);
    CHECK(s != NULL, "контрольная сессия late-RST не создалась");
    if (!s) { return; }
    const uint8_t handshake[] = {0x16, 0x03, 0x03, 0x00, 0x01, 0x00};
    n = build_pkt(pkt, 47802, 0x18, hello, hlen);
    d2k_session_packet(s, pkt, n, 4000, buf, sizeof buf, &r);
    n = build_rev_pkt(pkt, 47802, 0x18, handshake, sizeof handshake);
    d2k_session_packet(s, pkt, n, 5000, buf, sizeof buf, &r);
    n = build_rev_pkt(pkt, 47802, 0x14, NULL, 0);
    d2k_session_packet(s, pkt, n, 6000, buf, sizeof buf, &r);
    CHECK(d2k_session_suspects(s) == 0,
          "late-RST measurement trigger fired before TLS app-data");
    d2k_session_free(s);
}

/* ГЛУХОЙ ОБРЫВ ОТВЕТА БЕЗ RST/FIN (задача 50, поле 03.10.2026, rua.gr).
 *
 * Коробка молча перестаёт пропускать ответ сервера после ~20 КБ: ни RST, ни
 * FIN, ни повторов с той стороны. Клиент по таймауту шлёт FIN и повторяет его
 * с тем же номером — подтверждения нет. Очередь видит только первые восемь
 * ответных пакетов (connbytes 0:8): ServerHello-полёт TLS 1.3 и чистые ACK,
 * ни одного пакета, НАЧИНАЮЩЕГОСЯ с записи 0x17. Что ответ шёл дальше, видно
 * по подтверждению в самом FIN клиента: оно ушло далеко за байты, которые
 * видела очередь. Плана для цели нет (поиск ещё не запускался).
 *
 * Пара исходов: повтор FIN без ответа — подозрение FIN_RETRY (только узкий
 * RX-замер в контроллере, с повторяемостью); обычное закрытие, на которое
 * сервер ответил своим FIN, и закрытие после одного рукопожатия — не
 * подозрение. */
static size_t cut_seq(uint8_t *pkt, size_t n, uint32_t seq, uint32_t ack) {
    wr32(pkt + 24, seq);
    wr32(pkt + 28, ack);
    return n;
}

/* isn — начальный номер СЕРВЕРА (данные идут с isn + 1); t0 — время SYN,
   rtt — от SYN до SYN-ACK. Остальные пакеты рукопожатия — сразу после. */
static void cut_handshake_at(d2k_session *s, uint16_t port, const uint8_t *hello,
                             size_t hlen, uint8_t *pkt, uint8_t *buf, size_t cap,
                             d2k_result *r, uint32_t isn, uint64_t t0, uint64_t rtt) {
    /* ServerHello: запись 0x16, тело 40 байт (минимум 38), и продолжение
       зашифрованной записи без заголовка — ровно как в поле. */
    uint8_t sh[49];
    memset(sh, 0, sizeof sh);
    sh[0] = 0x16; sh[1] = 0x03; sh[2] = 0x03; sh[3] = 0x00; sh[4] = 44;
    sh[5] = 0x02; sh[6] = 0x00; sh[7] = 0x00; sh[8] = 40;
    uint8_t cont[100];
    memset(cont, 0x5a, sizeof cont);
    size_t n = cut_seq(pkt, build_pkt(pkt, port, 0x02, NULL, 0), 999, 0);
    d2k_session_packet(s, pkt, n, t0, buf, cap, r);
    n = cut_seq(pkt, build_rev_pkt(pkt, port, 0x12, NULL, 0), isn, 1000);
    d2k_session_packet(s, pkt, n, t0 + rtt, buf, cap, r);
    n = cut_seq(pkt, build_pkt(pkt, port, 0x18, hello, hlen), 1000, isn + 1);
    d2k_session_packet(s, pkt, n, t0 + rtt + 100, buf, cap, r);
    n = cut_seq(pkt, build_rev_pkt(pkt, port, 0x18, sh, sizeof sh), isn + 1,
                1000 + (uint32_t)hlen);
    d2k_session_packet(s, pkt, n, t0 + rtt + 200, buf, cap, r);
    n = cut_seq(pkt, build_rev_pkt(pkt, port, 0x10, cont, sizeof cont),
                isn + 1 + (uint32_t)sizeof sh, 1000 + (uint32_t)hlen);
    d2k_session_packet(s, pkt, n, t0 + rtt + 300, buf, cap, r);
}

static void cut_handshake(d2k_session *s, uint16_t port, const uint8_t *hello,
                          size_t hlen, uint8_t *pkt, uint8_t *buf, size_t cap,
                          d2k_result *r) {
    cut_handshake_at(s, port, hello, hlen, pkt, buf, cap, r, 4999, 1000, 100);
}

static void test_silent_cut_fin_retry(void) {
    uint8_t hello[512], pkt[1024], buf[8192];
    size_t hlen = build_hello(hello);
    d2k_result r;
    const uint32_t fin_seq = 1000 + (uint32_t)hlen + 24;
    const uint32_t seen = 49 + 100;

    /* Обрыв: клиент подтвердил 19 923 байта ответа, очередь видела 149. */
    d2k_session *s = d2k_session_new(64, 64);
    CHECK(s != NULL, "сессия глухого обрыва не создалась");
    if (!s) { return; }
    cut_handshake(s, 47820, hello, hlen, pkt, buf, sizeof buf, &r);
    CHECK(d2k_session_suspects(s) == 0, "рукопожатие с ответом объявлено подозрением");
    size_t n = cut_seq(pkt, build_pkt(pkt, 47820, 0x11, NULL, 0), fin_seq, 5000 + 19923);
    d2k_session_packet(s, pkt, n, 40000, buf, sizeof buf, &r);
    CHECK(!last_suspect(s) && r.verdict == D2K_VERDICT_ACCEPT,
          "первый FIN после обрыва уже подозрение или задержан");
    /* Повтор — FIN с нагрузкой close_notify, конец тот же. */
    const uint8_t alert[24] = {0x17, 0x03, 0x03, 0x00, 0x13};
    n = cut_seq(pkt, build_pkt(pkt, 47820, 0x19, alert, sizeof alert), fin_seq - 24,
                5000 + 19923);
    d2k_session_packet(s, pkt, n, 40440, buf, sizeof buf, &r);
    const d2k_jrn_entry *e = last_suspect(s);
    CHECK(e && e->code == D2K_SUSPECT_FIN_RETRY && r.verdict == D2K_VERDICT_ACCEPT,
          "повтор FIN без ответа после глухого обрыва (без плана) не дал узкого RX-сигнала");
    CHECK(e && e->d_planned == D2K_PLANNED_NO,
          "подозрение глухого обрыва без плана объявлено плановым");
    d2k_session_free(s);

    /* Обычное закрытие: сервер ответил своим FIN — поток отпущен, повтора нет. */
    s = d2k_session_new(64, 64);
    CHECK(s != NULL, "контрольная сессия закрытия не создалась");
    if (!s) { return; }
    cut_handshake(s, 47821, hello, hlen, pkt, buf, sizeof buf, &r);
    n = cut_seq(pkt, build_pkt(pkt, 47821, 0x11, NULL, 0), fin_seq, 5000 + 19923);
    d2k_session_packet(s, pkt, n, 40000, buf, sizeof buf, &r);
    n = cut_seq(pkt, build_rev_pkt(pkt, 47821, 0x11, NULL, 0), 5000 + 19923, fin_seq + 1);
    d2k_session_packet(s, pkt, n, 40050, buf, sizeof buf, &r);
    CHECK(d2k_session_suspects(s) == 0, "обычное закрытие долгого ответа стало подозрением");
    CHECK(d2k_session_flows_tcp(s) == 0, "закрытый с обеих сторон поток не отпущен");
    d2k_session_free(s);

    /* Закрытие после одного рукопожатия: подтверждение не ушло за видимое —
       об обрыве ОТВЕТА говорить не из чего, даже если FIN повторён. */
    s = d2k_session_new(64, 64);
    CHECK(s != NULL, "контрольная сессия рукопожатия не создалась");
    if (!s) { return; }
    cut_handshake(s, 47822, hello, hlen, pkt, buf, sizeof buf, &r);
    n = cut_seq(pkt, build_pkt(pkt, 47822, 0x11, NULL, 0), fin_seq, 5000 + seen);
    d2k_session_packet(s, pkt, n, 40000, buf, sizeof buf, &r);
    d2k_session_packet(s, pkt, n, 40440, buf, sizeof buf, &r);
    CHECK(d2k_session_suspects(s) == 0,
          "повтор FIN без ответа сверх рукопожатия принят за обрыв ответа");
    d2k_session_free(s);
}

/* Задача 50, раунд правок 1.
 *
 * (1) Тот же глухой обрыв, но клиент кончает ожидание RST. Раунд 2 (поле
 *     04.10): RST без пакета 0x17 подозрением НЕ становится — у него нет
 *     повтора в тишину, а обычные RST ложатся в тот же объём. Контроли:
 *     после одного рукопожатия и RST сервера — тоже ничего.
 * (2) Поток под планом: повтор FIN после того же глухого обрыва (без пакета
 *     0x17 в окне) — FIN_RETRY с planned=YES.
 * (3) Запись, оставленная после FIN клиента, живёт ровно окно повтора FIN
 *     (RFC 6298: RTO = 3R, не меньше 1 с; окно — первый повтор и ещё один
 *     после удвоения, 3 RTO), а не 120 с молчания.
 * (4) Номера сервера через 2^32. */
static void test_silent_cut_round1(void) {
    uint8_t hello[512], pkt[1024], buf[8192];
    size_t hlen = build_hello(hello);
    d2k_result r;
    const uint32_t fin_seq = 1000 + (uint32_t)hlen + 24;
    const uint64_t S = 1000000000ull;

    /* (1) RST клиента после глухого обрыва без пакета 0x17 в окне — НЕ
       сигнал (решение раунда 2: у RST нет повтора в тишину, и обычные RST
       клиентов ложатся в тот же объём, см. session.c). Сигналом остаётся
       повтор FIN. */
    d2k_session *s = d2k_session_new(64, 64);
    CHECK(s != NULL, "сессия RST после обрыва не создалась");
    if (!s) { return; }
    cut_handshake(s, 47830, hello, hlen, pkt, buf, sizeof buf, &r);
    size_t n = cut_seq(pkt, build_pkt(pkt, 47830, 0x14, NULL, 0), fin_seq, 5000 + 19923);
    d2k_session_packet(s, pkt, n, 40000, buf, sizeof buf, &r);
    const d2k_jrn_entry *e = last_suspect(s);
    CHECK(d2k_session_suspects(s) == 0,
          "RST клиента по одному подтверждению за видимым стал подозрением");
    d2k_session_free(s);

    /* RST клиента после одного рукопожатия — не обрыв ответа. */
    s = d2k_session_new(64, 64);
    if (!s) { return; }
    cut_handshake(s, 47831, hello, hlen, pkt, buf, sizeof buf, &r);
    n = cut_seq(pkt, build_pkt(pkt, 47831, 0x14, NULL, 0), fin_seq, 5000 + 149);
    d2k_session_packet(s, pkt, n, 40000, buf, sizeof buf, &r);
    CHECK(d2k_session_suspects(s) == 0,
          "RST клиента без ответа сверх рукопожатия принят за обрыв ответа");
    d2k_session_free(s);

    /* RST сервера: его подтверждение — про байты клиента, не про ответ. */
    s = d2k_session_new(64, 64);
    if (!s) { return; }
    cut_handshake(s, 47832, hello, hlen, pkt, buf, sizeof buf, &r);
    n = cut_seq(pkt, build_rev_pkt(pkt, 47832, 0x14, NULL, 0), 5000 + 149, 5000 + 19923);
    d2k_session_packet(s, pkt, n, 40000, buf, sizeof buf, &r);
    CHECK(d2k_session_suspects(s) == 0,
          "подтверждение в RST сервера принято за свидетельство ответа");
    d2k_session_free(s);

    /* (2) Под планом: тот же обрыв, повтор FIN — сигнал с planned=YES. */
    s = d2k_session_new(64, 64);
    if (!s) { return; }
    d2k_plan *guard = NULL;
    char err[200];
    CHECK(d2k_plan_load(plan_guard, sizeof plan_guard, &guard, err, sizeof err) == 0,
          "план для планового обрыва не загрузился");
    d2k_session_set_plan(s, guard);
    cut_handshake(s, 47833, hello, hlen, pkt, buf, sizeof buf, &r);
    n = cut_seq(pkt, build_pkt(pkt, 47833, 0x11, NULL, 0), fin_seq, 5000 + 19923);
    d2k_session_packet(s, pkt, n, 40000, buf, sizeof buf, &r);
    CHECK(!last_suspect(s), "первый FIN планового потока уже подозрение");
    d2k_session_packet(s, pkt, n, 40440, buf, sizeof buf, &r);
    e = last_suspect(s);
    CHECK(e && e->code == D2K_SUSPECT_FIN_RETRY && e->d_planned == D2K_PLANNED_YES,
          "повтор FIN под планом после глухого обрыва TLS 1.3 не дал сигнала с planned=YES");
    d2k_session_free(s);

    /* (3) Окно удержания после FIN: RTT 100 нс -> пол 1 с -> окно 3 с. */
    s = d2k_session_new(64, 64);
    if (!s) { return; }
    cut_handshake_at(s, 47834, hello, hlen, pkt, buf, sizeof buf, &r, 4999, S, 100);
    n = cut_seq(pkt, build_pkt(pkt, 47834, 0x11, NULL, 0), fin_seq, 5000 + 19923);
    d2k_session_packet(s, pkt, n, 2 * S, buf, sizeof buf, &r);
    d2k_session_expire(s, 2 * S + 3 * S - 1, 120 * S);
    CHECK(d2k_session_flows_tcp(s) == 1, "запись после FIN снята раньше окна повтора");
    d2k_session_expire(s, 2 * S + 3 * S, 120 * S);
    CHECK(d2k_session_flows_tcp(s) == 0,
          "запись после FIN без повтора держит место дольше окна повтора FIN");
    d2k_session_free(s);

    /* Измеренный RTT 1 с: первый RTO 3 с, окно 9 с; повтор на 8-й секунде
       ещё ловится. */
    s = d2k_session_new(64, 64);
    if (!s) { return; }
    cut_handshake_at(s, 47835, hello, hlen, pkt, buf, sizeof buf, &r, 4999, S, S);
    n = cut_seq(pkt, build_pkt(pkt, 47835, 0x11, NULL, 0), fin_seq, 5000 + 19923);
    d2k_session_packet(s, pkt, n, 3 * S, buf, sizeof buf, &r);
    d2k_session_expire(s, 11 * S, 120 * S);
    CHECK(d2k_session_flows_tcp(s) == 1, "окно повтора FIN не учло измеренный RTT");
    d2k_session_packet(s, pkt, n, 11 * S, buf, sizeof buf, &r);
    e = last_suspect(s);
    CHECK(e && e->code == D2K_SUSPECT_FIN_RETRY,
          "повтор FIN в окне медленной линии потерян");
    d2k_session_expire(s, 12 * S, 120 * S);
    CHECK(d2k_session_flows_tcp(s) == 0, "запись после FIN пережила окно повтора");
    d2k_session_free(s);

    /* (4) Сервер начал у самого 2^32: подтверждение переходит через ноль. */
    s = d2k_session_new(64, 64);
    if (!s) { return; }
    const uint32_t isn = 0xFFFFFF00u;
    cut_handshake_at(s, 47836, hello, hlen, pkt, buf, sizeof buf, &r, isn, 1000, 100);
    n = cut_seq(pkt, build_pkt(pkt, 47836, 0x11, NULL, 0), fin_seq, isn + 1 + 19923);
    d2k_session_packet(s, pkt, n, 40000, buf, sizeof buf, &r);
    d2k_session_packet(s, pkt, n, 40440, buf, sizeof buf, &r);
    e = last_suspect(s);
    CHECK(e && e->code == D2K_SUSPECT_FIN_RETRY,
          "обрыв не замечен, когда номера сервера перешли через 2^32");
    d2k_session_free(s);

    s = d2k_session_new(64, 64);
    if (!s) { return; }
    cut_handshake_at(s, 47837, hello, hlen, pkt, buf, sizeof buf, &r, isn, 1000, 100);
    n = cut_seq(pkt, build_pkt(pkt, 47837, 0x11, NULL, 0), fin_seq, isn + 1 + 149);
    d2k_session_packet(s, pkt, n, 40000, buf, sizeof buf, &r);
    d2k_session_packet(s, pkt, n, 40440, buf, sizeof buf, &r);
    CHECK(d2k_session_suspects(s) == 0,
          "переход через 2^32 превратил закрытие после рукопожатия в обрыв ответа");
    d2k_session_free(s);
}

/* --- ОТВЕТ, КОТОРЫЙ СПРЯТАЛ УСКОРИТЕЛЬ -----------------------------------
 *
 * Keenetic (MediaTek PPE, fastnat) уводит транзитный поток в аппаратный путь
 * мимо netfilter: очередь видит приветствие, но не ответ сервера (полевое
 * сообщение 02.10.2026). Снаружи это неотличимо от молчащей коробки — если
 * смотреть только на обратную сторону.
 *
 * Отличие видно с ПРЯМОЙ стороны: клиент, получивший данные сервера,
 * подтверждает их — номер подтверждения после приветствия растёт. Растущее
 * подтверждение при нуле увиденных ответных пакетов значит «ответ был, но
 * очередь его не видела». Повтор приветствия с тем же подтверждением —
 * молчание, и в этот счётчик он не попадает. Счётчик — диагностика
 * видимости, а не вердикт о блокировке. */
static void test_reply_hidden_by_accelerator(void) {
    uint8_t hello[512], pkt[1024], buf[8192];
    size_t hlen = build_hello(hello);
    d2k_result r;

    /* Ответ скрыт: приветствие, затем чистое ACK клиента с подвинутым
       подтверждением, обратных пакетов ноль. Второй такой пакет поток
       повторно не считает. */
    d2k_session *s = d2k_session_new(64, 64);
    CHECK(s != NULL, "сессия скрытого ответа не создалась");
    if (!s) { return; }
    CHECK(d2k_session_reply_hidden(s) == 0, "счётчик скрытого ответа не с нуля");
    size_t n = build_pkt(pkt, 47901, 0x18, hello, hlen);
    d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
    n = build_pkt(pkt, 47901, 0x10, NULL, 0);
    wr32(pkt + 24, 1000 + (uint32_t)hlen);
    wr32(pkt + 28, 0x11223344u + 1400u);
    d2k_session_packet(s, pkt, n, 2000, buf, sizeof buf, &r);
    CHECK(r.verdict == D2K_VERDICT_ACCEPT, "диагностика видимости тронула пакет");
    wr32(pkt + 28, 0x11223344u + 2800u);
    d2k_session_packet(s, pkt, n, 3000, buf, sizeof buf, &r);
    CHECK(d2k_session_reply_hidden(s) == 1,
          "подтверждение данных сервера без единого ответа в очереди не учтено");
    CHECK(d2k_session_tcp_hello_flows(s) == 1,
          "знаменатель скрытых ответов — не потоки TCP с приветствием");
    CHECK(d2k_session_suspects(s) == 0,
          "скрытый ответ выдан за подозрение на блокировку");
    d2k_session_free(s);

    /* Ответ виден: тот же порядок, но сервер ответил в очередь. */
    s = d2k_session_new(64, 64);
    CHECK(s != NULL, "контрольная сессия видимого ответа не создалась");
    if (!s) { return; }
    n = build_pkt(pkt, 47902, 0x18, hello, hlen);
    d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
    const uint8_t handshake[] = {0x16, 0x03, 0x03, 0x00, 0x01, 0x00};
    n = build_rev_pkt(pkt, 47902, 0x18, handshake, sizeof handshake);
    d2k_session_packet(s, pkt, n, 1500, buf, sizeof buf, &r);
    n = build_pkt(pkt, 47902, 0x10, NULL, 0);
    wr32(pkt + 28, 0x11223344u + 1400u);
    d2k_session_packet(s, pkt, n, 2000, buf, sizeof buf, &r);
    CHECK(d2k_session_reply_hidden(s) == 0,
          "поток с увиденным ответом посчитан скрытым");
    d2k_session_free(s);

    /* Зонд контроллера — не пользовательский поток: ни в числителе, ни в
       знаменателе. */
    s = d2k_session_new(64, 64);
    CHECK(s != NULL, "сессия зонда не создалась");
    if (!s) { return; }
    n = build_pkt(pkt, 47904, 0x18, hello, hlen);
    d2k_session_packet_probe(s, pkt, n, 1000, buf, sizeof buf, &r);
    n = build_pkt(pkt, 47904, 0x10, NULL, 0);
    wr32(pkt + 28, 0x11223344u + 1400u);
    d2k_session_packet_probe(s, pkt, n, 2000, buf, sizeof buf, &r);
    CHECK(d2k_session_reply_hidden(s) == 0 && d2k_session_tcp_hello_flows(s) == 0,
          "зонд контроллера попал в счёт скрытых ответов");
    d2k_session_free(s);

    /* Молчание: повторы приветствия с прежним подтверждением. Это не
       невидимый ответ, а отсутствие ответа. */
    s = d2k_session_new(64, 64);
    CHECK(s != NULL, "контрольная сессия молчания не создалась");
    if (!s) { return; }
    n = build_pkt(pkt, 47903, 0x18, hello, hlen);
    d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
    d2k_session_packet(s, pkt, n, 2000, buf, sizeof buf, &r);
    d2k_session_packet(s, pkt, n, 3000, buf, sizeof buf, &r);
    CHECK(d2k_session_reply_hidden(s) == 0,
          "повтор приветствия без ответа посчитан скрытым ответом");
    d2k_session_free(s);
}

/* ЗАДАЧА 47, п. 1: ПЛАНУ НА ПРИВЕТСТВИИ НЕ НУЖНО ЧИТАТЬ ТАБЛИЦУ CONNTRACK,
 * если ответ сервера (SYN-ACK) уже прошёл через ядро: ответ возвращается
 * только по подтверждённой записи, и её трансляция уже есть. Полное чтение
 * /proc/net/nf_conntrack стоит на роутере ~14 мс перед каждым ClientHello.
 * Без увиденного ответа (нет обратного правила, лаборатория) проверка
 * остаётся. */
static void test_tcp_plan_skips_conntrack_read(void) {
    d2k_nat_fn saved = d2k_nat_hook;
    d2k_nat_hook = nat_stub;
    uint8_t hello[512], pkt[1024], buf[8192];
    char err[128];
    size_t hlen = build_hello(hello);
    d2k_result r;

    d2k_session *g = d2k_session_new(8, 4);
    d2k_plan *gp = NULL;
    CHECK(d2k_plan_load(plan_bytes, sizeof plan_bytes, &gp, err, sizeof err) == 0, "plan");
    d2k_session_set_plan(g, gp);
    nat_calls = 0;
    nat_miss_first_n = 1000;   /* the table would say "absent": it must not be asked */
    size_t n = build_pkt(pkt, 41300, 0x02, NULL, 0);           /* SYN */
    d2k_session_packet(g, pkt, n, 1000, buf, sizeof buf, &r);
    n = build_rev_pkt(pkt, 41300, 0x12, NULL, 0);              /* SYN-ACK */
    d2k_session_packet(g, pkt, n, 2000, buf, sizeof buf, &r);
    n = build_pkt(pkt, 41300, 0x18, hello, hlen);
    d2k_session_packet(g, pkt, n, 3000, buf, sizeof buf, &r);
    CHECK(r.n_out > 0 && r.skipped == NULL, "plan applied on the ClientHello");
    CHECK(nat_calls == 0, "a reply already proved the conntrack entry: no table read");
    d2k_session_free(g);

    /* No reply seen: the entry is still proven by the table. */
    g = d2k_session_new(8, 4);
    gp = NULL;
    CHECK(d2k_plan_load(plan_bytes, sizeof plan_bytes, &gp, err, sizeof err) == 0, "plan");
    d2k_session_set_plan(g, gp);
    nat_calls = 0;
    nat_miss_first_n = 0;
    n = build_pkt(pkt, 41301, 0x18, hello, hlen);
    d2k_session_packet(g, pkt, n, 1000, buf, sizeof buf, &r);
    CHECK(r.n_out > 0 && nat_calls >= 1, "without a reply the table is still read");
    d2k_session_free(g);
    d2k_nat_hook = saved;
}

/* ЗАДАЧА 47, п. 0: КЛИЕНТ С МЕТКОЙ МАРШРУТИЗАЦИИ ПЛАНА НЕ ПОЛУЧАЕТ.
 * Keenetic метит пакеты клиента с маршрутом по политике/доменам (0xffffaaa ->
 * таблица 4096, VPN) до нашей очереди; сырые посылки d2k идут с меткой 0x2d
 * мимо этой таблицы — через провайдера. Поток идёт ядром без вмешательства и
 * без наблюдения: его поведение — свойство чужого пути, не коробки. */
static void test_routed_client_gets_no_plan_tcp(void) {
    uint8_t hello[512], pkt[1024], buf[8192];
    char err[128];
    size_t hlen = build_hello(hello);
    d2k_result r;
    d2k_session *g = d2k_session_new(8, 8);
    d2k_plan *gp = NULL;
    CHECK(d2k_plan_load(plan_bytes, sizeof plan_bytes, &gp, err, sizeof err) == 0, "plan");
    d2k_session_set_plan(g, gp);

    d2k_session_set_route_mark(g, 0xffffaaa);
    size_t n = build_pkt(pkt, 41400, 0x02, NULL, 0);
    d2k_session_packet(g, pkt, n, 1000, buf, sizeof buf, &r);
    CHECK(r.routed_first && r.routed_mark == 0xffffaaa, "first packet of a routed flow reported");
    d2k_session_set_route_mark(g, 0);           /* replies carry no client mark */
    n = build_rev_pkt(pkt, 41400, 0x12, NULL, 0);
    d2k_session_packet(g, pkt, n, 2000, buf, sizeof buf, &r);
    CHECK(!r.routed_first && r.skipped != NULL, "the flow's replies are left alone too");
    d2k_session_set_route_mark(g, 0xffffaaa);
    n = build_pkt(pkt, 41400, 0x18, hello, hlen);
    CHECK(d2k_session_hold_candidate(g, pkt, n) == 0, "a routed flow is never held");
    d2k_session_packet(g, pkt, n, 3000, buf, sizeof buf, &r);
    CHECK(r.n_out == 0 && !r.applied && r.verdict == D2K_VERDICT_ACCEPT,
          "routed client: no plan, kernel path");
    CHECK(!r.routed_first, "reported once per flow");
    CHECK(count_kind(g, D2K_JRN_HELLO_SNI) == 0 && count_plan_refused(g) == 0,
          "nothing about a foreign path reaches the controller");
    CHECK(d2k_session_routed_flows(g) == 1, "counted once");

    /* The same session still plans an unmarked client. */
    d2k_session_set_route_mark(g, 0);
    n = build_pkt(pkt, 41401, 0x18, hello, hlen);
    d2k_session_packet(g, pkt, n, 4000, buf, sizeof buf, &r);
    CHECK(r.n_out > 0, "unmarked client still planned");
    d2k_session_free(g);
}

/* ЗАДАЧА 47, ревью I1: метка одного пакета не переходит на другой. Отпуск
 * удержанного сегмента (observe_tcp из release_original) шёл сразу после
 * пакета клиента с меткой и метил ЧУЖОЙ поток. Воспроизведение ревьюера:
 * «routed flows after release: 2 (expect 1)». */
static void test_route_mark_does_not_leak(void) {
    uint8_t hello[512], pkt[1024], buf[8192];
    char err[128];
    size_t hlen = build_hello(hello);
    d2k_result r;
    d2k_session *g = d2k_session_new(8, 8);
    d2k_plan *gp = NULL;
    CHECK(d2k_plan_load(plan_bytes, sizeof plan_bytes, &gp, err, sizeof err) == 0, "plan");
    d2k_session_set_plan(g, gp);
    size_t n = build_pkt(pkt, 41500, 0x02, NULL, 0);
    d2k_session_packet(g, pkt, n, 1000, buf, sizeof buf, &r);   /* A, unmarked */
    d2k_session_set_route_mark(g, 0xffffaaa);
    n = build_pkt(pkt, 41600, 0x02, NULL, 0);
    d2k_session_packet(g, pkt, n, 1100, buf, sizeof buf, &r);   /* B, marked */
    /* A's held segment is released (no mark is set for it). */
    n = build_pkt(pkt, 41500, 0x10, hello, 100);
    d2k_session_observe_tcp(g, pkt, n, 1200);
    CHECK(d2k_session_routed_flows(g) == 1, "routed flows after release: 1");
    d2k_session_set_route_mark(g, 0);           /* d2kd sets it per packet */
    n = build_pkt(pkt, 41500, 0x18, hello, hlen);
    d2k_session_packet(g, pkt, n, 1300, buf, sizeof buf, &r);
    CHECK(!r.routed_first && (r.skipped == NULL || strstr(r.skipped, "меткой") == NULL),
          "A is not treated as a routed flow");
    d2k_session_free(g);
}

/* ЗАДАЧА 47, ревью M1: новый SYN на том же кортеже — новое соединение; флаг
 * «с меткой» прежнего не переживает его. */
static void test_routed_flag_reset_on_new_syn(void) {
    uint8_t hello[512], pkt[1024], buf[8192];
    char err[128];
    size_t hlen = build_hello(hello);
    d2k_result r;
    d2k_session *g = d2k_session_new(8, 8);
    d2k_plan *gp = NULL;
    CHECK(d2k_plan_load(plan_bytes, sizeof plan_bytes, &gp, err, sizeof err) == 0, "plan");
    d2k_session_set_plan(g, gp);
    d2k_session_set_route_mark(g, 0xffffaaa);
    size_t n = build_pkt(pkt, 41700, 0x02, NULL, 0);
    d2k_session_packet(g, pkt, n, 1000, buf, sizeof buf, &r);
    CHECK(r.routed_first, "first connection routed");
    /* Policy changed; the client reuses the port for a new connection. */
    d2k_session_set_route_mark(g, 0);
    n = build_pkt(pkt, 41700, 0x02, NULL, 0);
    d2k_session_packet(g, pkt, n, 2000, buf, sizeof buf, &r);
    CHECK(r.skipped == NULL || strstr(r.skipped, "меткой") == NULL,
          "an unmarked SYN starts a new, unrouted connection");
    n = build_pkt(pkt, 41700, 0x18, hello, hlen);
    d2k_session_packet(g, pkt, n, 3000, buf, sizeof buf, &r);
    CHECK(r.n_out > 0, "the new connection is planned");
    d2k_session_free(g);
}

/* ЗАДАЧА 56. TCP ВСТАЛ НА БЮДЖЕТЕ КОРОБКИ, КЛИЕНТ НЕ ЗАКРЫВАЕТ (поле 04.10,
 * Safari, пустой каталог). mailsuite.com (AWS 54.77.225.34): 20 пакетов
 * данных вниз, 26 с данными в обе стороны, затем 42 с тишины; www.romfea.gr
 * (Cloudflare): 25 с данными в обе стороны, 41 с тишины. Safari держит
 * соединение открытым: ни RST, ни FIN — ни один из детекторов позднего
 * закрытия не срабатывает, d2kc молчал.
 *
 * Очередь видит первые ~8 пакетов каждой стороны; дальше — счётчики
 * conntrack по кортежу (тот же ctnetlink, что у QUIC). Подменяем запрос. */
static struct { uint16_t cport; d2k_ct_info info; int answer; } tcp_ct;
static unsigned tcp_ct_queries;
static int fake_tcp_ct(void *ctx, const d2k_ct_tuple *t, d2k_ct_info *out) {
    (void)ctx;
    tcp_ct_queries++;
    static const uint8_t cli[4] = {192, 168, 1, 67}, srv[4] = {1, 2, 3, 4};
    uint16_t sp = (uint16_t)(t->sport_be[0] << 8 | t->sport_be[1]);
    uint16_t dp = (uint16_t)(t->dport_be[0] << 8 | t->dport_be[1]);
    /* Прямой кортеж — клиент → сервер, TCP. */
    if (t->family != 4 || t->proto != 6 || memcmp(t->src, cli, 4) || memcmp(t->dst, srv, 4) ||
        dp != 443 || sp != tcp_ct.cport || !tcp_ct.answer) return -1;
    *out = tcp_ct.info;
    return 0;
}
static void tcp_ct_set(uint16_t cport, uint64_t orig, uint64_t reply, int established) {
    tcp_ct.cport = cport;
    tcp_ct.answer = 1;
    tcp_ct.info.orig_pkts = orig;
    tcp_ct.info.reply_pkts = reply;
    tcp_ct.info.tcp_state_known = 1;
    tcp_ct.info.tcp_state = established ? D2K_CT_TCP_ESTABLISHED : 5 /* CLOSE_WAIT */;
}

/* Окно очереди одного потока: SYN, SYN-ACK через rtt, приветствие, затем
   fwd_data-1 пакетов данных клиента и fwd_acks чистых ACK, rev_data пакетов
   данных сервера и rev_acks чистых ACK сервера (кроме SYN-ACK). Номера
   последовательности честные: повтор номера приветствия — другая улика. */
static d2k_session *tcp_window(uint16_t port, uint64_t t0, uint64_t rtt,
                               int fwd_data, int fwd_acks, int rev_data, int rev_acks) {
    d2k_session *s = d2k_session_new(64, 64);
    if (!s) return NULL;
    d2k_session_set_ct_query(s, fake_tcp_ct, NULL);
    uint8_t hello[512], pkt[2048], buf[8192], junk[1440];
    memset(junk, 0x5a, sizeof junk);
    junk[0] = 0x17; junk[1] = 0x03; junk[2] = 0x03;   /* запись app-data */
    size_t hlen = build_hello(hello);
    d2k_result r;
    uint32_t cseq = 1000, sseq = 5000;
    uint64_t t = t0;
    size_t n = cut_seq(pkt, build_pkt(pkt, port, 0x02, NULL, 0), cseq - 1, 0);
    d2k_session_packet(s, pkt, n, t, buf, sizeof buf, &r);
    t += rtt;
    n = cut_seq(pkt, build_rev_pkt(pkt, port, 0x12, NULL, 0), sseq - 1, cseq);
    d2k_session_packet(s, pkt, n, t, buf, sizeof buf, &r);
    n = cut_seq(pkt, build_pkt(pkt, port, 0x18, hello, hlen), cseq, sseq);
    d2k_session_packet(s, pkt, n, t + 1000, buf, sizeof buf, &r);
    cseq += (uint32_t)hlen;
    for (int i = 0; i < rev_data; i++) {
        size_t len = i == 0 ? 1440 : 900;
        n = cut_seq(pkt, build_rev_pkt(pkt, port, 0x18, junk, len), sseq, cseq);
        d2k_session_packet(s, pkt, n, t + 2000 + (uint64_t)i, buf, sizeof buf, &r);
        sseq += (uint32_t)len;
    }
    for (int i = 0; i < rev_acks; i++) {
        n = cut_seq(pkt, build_rev_pkt(pkt, port, 0x10, NULL, 0), sseq, cseq);
        d2k_session_packet(s, pkt, n, t + 3000 + (uint64_t)i, buf, sizeof buf, &r);
    }
    for (int i = 1; i < fwd_data; i++) {
        n = cut_seq(pkt, build_pkt(pkt, port, 0x18, junk, 64), cseq, sseq);
        d2k_session_packet(s, pkt, n, t + 4000 + (uint64_t)i, buf, sizeof buf, &r);
        cseq += 64;
    }
    for (int i = 0; i < fwd_acks; i++) {
        n = cut_seq(pkt, build_pkt(pkt, port, 0x10, NULL, 0), cseq, sseq);
        d2k_session_packet(s, pkt, n, t + 5000 + (uint64_t)i, buf, sizeof buf, &r);
    }
    return s;
}

static void test_tcp_stall(void) {
    const uint64_t S = 1000000000ull, MS = 1000000ull;

    /* Ничего не наблюдается — ядро не спрашивается вовсе. */
    {
        d2k_session *s = d2k_session_new(64, 64);
        d2k_session_set_ct_query(s, fake_tcp_ct, NULL);
        tcp_ct_queries = 0;
        d2k_session_sweep(s, 5 * S);
        /* Поток без ответа сервера после приветствия — не этот детектор. */
        uint8_t hello[512], pkt[1024], buf[8192];
        size_t hlen = build_hello(hello);
        d2k_result r;
        size_t n = cut_seq(pkt, build_pkt(pkt, 47900, 0x02, NULL, 0), 999, 0);
        d2k_session_packet(s, pkt, n, 6 * S, buf, sizeof buf, &r);
        n = cut_seq(pkt, build_rev_pkt(pkt, 47900, 0x12, NULL, 0), 4999, 1000);
        d2k_session_packet(s, pkt, n, 6 * S + 80 * MS, buf, sizeof buf, &r);
        n = cut_seq(pkt, build_pkt(pkt, 47900, 0x18, hello, hlen), 1000, 5000);
        d2k_session_packet(s, pkt, n, 6 * S + 81 * MS, buf, sizeof buf, &r);
        d2k_session_sweep(s, 7 * S);
        CHECK(tcp_ct_queries == 0, "TCP: conntrack спрошен, хотя сервер ещё не отвечал данными");
        d2k_session_free(s);
    }

    /* mailsuite.com, поле 04.10 (s2-mailsuite.pcap): RTT 81 мс; очередь
       видела клиента S . 1536 1536 . . . 64 (3 с данными) и сервера
       S. . . 1440 1440 1440 1099 . (4 с данными); conntrack к тишине:
       прямой 19, обратный 25. Оценка: 3 + 4 + (25 - 8) = 24 при бюджете 25.
       Клиент 39 с молчит — подозрения нет (обрыв от простоя не отличить);
       на 40-й секунде Safari шлёт пять записей по 35 байт за 2 с, ни одна
       не подтверждена — третья даёт подозрение. */
    {
        tcp_ct_queries = 0;
        d2k_session *s = tcp_window(47901, 1 * S, 81 * MS, 3, 4, 4, 3);
        tcp_ct_set(47901, 19, 25, 1);
        d2k_session_sweep(s, 2 * S);
        d2k_session_sweep(s, 3 * S);
        CHECK(d2k_session_suspects(s) == 0, "mailsuite: секунда тишины уже объявлена обрывом");
        for (uint64_t k = 4; k <= 40; k++) d2k_session_sweep(s, k * S);
        CHECK(d2k_session_suspects(s) == 0,
              "mailsuite: тишина при молчащем клиенте объявлена обрывом");
        tcp_ct_set(47901, 21, 25, 1);
        d2k_session_sweep(s, 41 * S);
        CHECK(d2k_session_suspects(s) == 0, "mailsuite: два пакета клиента в тишину уже обрыв");
        tcp_ct_set(47901, 22, 25, 1);
        d2k_session_sweep(s, 42 * S);
        const d2k_jrn_entry *e = last_suspect(s);
        CHECK(e && e->code == D2K_SUSPECT_TCP_STALL,
              "mailsuite: поток встал на бюджете, клиент не закрывает — подозрения нет");
        CHECK(e && e->num == 24, "mailsuite: в подозрении не та оценка пакетов с данными (ждали 24)");
        CHECK(e && e->d_planned == D2K_PLANNED_NO, "mailsuite: поток без плана объявлен плановым");
        tcp_ct_set(47901, 30, 25, 1);
        d2k_session_sweep(s, 50 * S);
        d2k_session_sweep(s, 60 * S);
        CHECK(d2k_session_suspects(s) == 1, "mailsuite: один поток дал больше одного подозрения");
        d2k_session_free(s);
    }

    /* mailsuite.com повторно, замер 04.10 11:13 на роутере: Safari сразу
       продолжает слать по вставшему соединению (прямой 17 → 20 → 21 за 3 с,
       обратный стоит на 25) — подозрение через RTO. */
    {
        d2k_session *s = tcp_window(47915, 1 * S, 81 * MS, 3, 4, 4, 3);
        tcp_ct_set(47915, 17, 25, 1);
        d2k_session_sweep(s, 2 * S);
        tcp_ct_set(47915, 20, 25, 1);
        d2k_session_sweep(s, 3 * S);
        CHECK(d2k_session_suspects(s) == 0, "mailsuite-2: тишина короче RTO объявлена обрывом");
        tcp_ct_set(47915, 21, 25, 1);
        d2k_session_sweep(s, 4 * S + 100 * MS);
        CHECK(last_suspect(s) && last_suspect(s)->code == D2K_SUSPECT_TCP_STALL,
              "mailsuite-2: клиент говорит в тишину на бюджете — подозрения нет");
        d2k_session_free(s);
    }

    /* Ложные полосы (замер 04.10: 15 из 21): keep-alive после полного ответа
       на 22–28 пакетах. Клиент подтвердил последние данные (один пакет) и
       молчит; потом шлёт PING HTTP/2 — сервер отвечает. Подозрения нет. */
    {
        d2k_session *s = tcp_window(47916, 1 * S, 50 * MS, 3, 4, 4, 3);
        tcp_ct_set(47916, 14, 22, 1);
        d2k_session_sweep(s, 2 * S);
        tcp_ct_set(47916, 15, 22, 1);
        for (uint64_t k = 3; k <= 16; k++) d2k_session_sweep(s, k * S);
        tcp_ct_set(47916, 16, 23, 1);
        for (uint64_t k = 17; k <= 31; k++) d2k_session_sweep(s, k * S);
        tcp_ct_set(47916, 17, 24, 1);
        for (uint64_t k = 32; k <= 60; k++) d2k_session_sweep(s, k * S);
        CHECK(d2k_session_suspects(s) == 0,
              "keep-alive на бюджете с отвечающим сервером объявлен обрывом");
        d2k_session_free(s);
    }

    /* www.romfea.gr, поле 04.10 (s2-romfea.pcap): RTT 62 мс; клиент
       S . hello . . . 80 348 (3), сервер S. . . 1440 1440 993 544 31 (5);
       обратный 25 к тишине, клиент ещё шлёт ACK (прямой растёт). 3+5+17 = 25. */
    {
        d2k_session *s = tcp_window(47902, 1 * S, 62 * MS, 3, 5, 5, 2);
        tcp_ct_set(47902, 19, 25, 1);
        d2k_session_sweep(s, 2 * S);
        tcp_ct_set(47902, 22, 25, 1);
        d2k_session_sweep(s, 3 * S);
        tcp_ct_set(47902, 24, 25, 1);
        d2k_session_sweep(s, 4 * S + 100 * MS);
        const d2k_jrn_entry *e = last_suspect(s);
        CHECK(e && e->code == D2K_SUSPECT_TCP_STALL && e->num == 25,
              "romfea: поток встал на 25 пакетах — подозрения нет");
        d2k_session_free(s);
    }

    /* Простаивающее keep-alive после ПОЛНОГО ответа, число пакетов вне
       полосы: ни сразу, ни через минуту. Выше полосы поток больше не
       спрашивается — в неё уже не вернуться. */
    {
        d2k_session *s = tcp_window(47903, 1 * S, 50 * MS, 3, 4, 4, 3);
        tcp_ct_set(47903, 30, 60, 1);
        tcp_ct_queries = 0;
        for (uint64_t k = 2; k <= 60; k++) d2k_session_sweep(s, k * S);
        CHECK(d2k_session_suspects(s) == 0, "keep-alive после полного ответа (60 пакетов) объявлен обрывом");
        CHECK(tcp_ct_queries == 1, "поток выше полосы продолжают спрашивать каждую секунду");
        d2k_session_free(s);
        /* Маленький полный ответ ниже полосы. */
        s = tcp_window(47904, 1 * S, 50 * MS, 3, 4, 4, 3);
        tcp_ct_set(47904, 12, 12, 1);
        d2k_session_sweep(s, 2 * S);
        tcp_ct_set(47904, 20, 12, 1);   /* даже если клиент говорит в тишину */
        for (uint64_t k = 3; k <= 60; k++) d2k_session_sweep(s, k * S);
        CHECK(d2k_session_suspects(s) == 0, "keep-alive после маленького ответа (12 пакетов) объявлен обрывом");
        d2k_session_free(s);
    }

    /* Медленный сервер, который продолжает: пауза на бюджете короче RTO,
       затем ответ идёт дальше — подозрения нет. С измеренным RTT 1 с RTO —
       3 с, и пауза 2,5 с тоже не обрыв. */
    {
        d2k_session *s = tcp_window(47905, 1 * S, 50 * MS, 3, 4, 4, 3);
        tcp_ct_set(47905, 19, 25, 1);
        d2k_session_sweep(s, 2 * S);
        tcp_ct_set(47905, 23, 25, 1);   /* клиент шлёт, сервер думает */
        d2k_session_sweep(s, 3 * S + 500 * MS);
        tcp_ct_set(47905, 30, 70, 1);
        d2k_session_sweep(s, 4 * S);
        for (uint64_t k = 5; k <= 20; k++) d2k_session_sweep(s, k * S);
        CHECK(d2k_session_suspects(s) == 0, "медленный сервер, продолживший ответ, объявлен обрывом");
        d2k_session_free(s);

        s = tcp_window(47906, 1 * S, 1 * S, 3, 4, 4, 3);
        tcp_ct_set(47906, 19, 25, 1);
        d2k_session_sweep(s, 3 * S);
        tcp_ct_set(47906, 23, 25, 1);
        d2k_session_sweep(s, 4 * S);
        d2k_session_sweep(s, 5 * S + 500 * MS);
        CHECK(d2k_session_suspects(s) == 0, "пауза 2,5 с при RTT 1 с (RTO 3 с) объявлена обрывом");
        tcp_ct_set(47906, 40, 90, 1);
        d2k_session_sweep(s, 6 * S);
        CHECK(d2k_session_suspects(s) == 0, "медленный сервер с RTT 1 с объявлен обрывом");
        d2k_session_free(s);

        /* Медленный первый байт: тишина ниже полосы, потом полный ответ. */
        s = tcp_window(47907, 1 * S, 50 * MS, 3, 4, 2, 3);
        tcp_ct_set(47907, 8, 9, 1);
        d2k_session_sweep(s, 2 * S);
        tcp_ct_set(47907, 12, 9, 1);
        for (uint64_t k = 3; k <= 10; k++) d2k_session_sweep(s, k * S);
        tcp_ct_set(47907, 40, 120, 1);
        for (uint64_t k = 11; k <= 20; k++) d2k_session_sweep(s, k * S);
        CHECK(d2k_session_suspects(s) == 0, "медленный первый байт объявлен обрывом");
        d2k_session_free(s);
    }

    /* Соединение уже не установлено (клиент закрыл: CLOSE_WAIT и дальше) —
       это дело детекторов закрытия, не этого. Нет ответа ядра — не знаем. */
    {
        d2k_session *s = tcp_window(47908, 1 * S, 50 * MS, 3, 4, 4, 3);
        tcp_ct_set(47908, 19, 25, 0);
        d2k_session_sweep(s, 2 * S);
        tcp_ct_set(47908, 25, 25, 0);
        for (uint64_t k = 3; k <= 10; k++) d2k_session_sweep(s, k * S);
        CHECK(d2k_session_suspects(s) == 0, "закрывающееся соединение объявлено обрывом");
        d2k_session_free(s);
        s = tcp_window(47909, 1 * S, 50 * MS, 3, 4, 4, 3);
        tcp_ct_set(47909, 19, 25, 1);
        tcp_ct.answer = 0;
        for (uint64_t k = 2; k <= 10; k++) d2k_session_sweep(s, k * S);
        CHECK(d2k_session_suspects(s) == 0, "без ответа ядра поток объявлен обрывом");
        tcp_ct.info.tcp_state_known = 0;
        tcp_ct.info.orig_pkts = 30;
        tcp_ct.answer = 1;
        for (uint64_t k = 11; k <= 20; k++) d2k_session_sweep(s, k * S);
        CHECK(d2k_session_suspects(s) == 0, "без состояния TCP поток объявлен обрывом");
        d2k_session_free(s);
    }

    /* ИЗМЕРЕННЫЙ БЮДЖЕТ (контроллер передаёт бюджеты коробок): поток на 24
       пакетах при единственном бюджете 16 не в полосе; при 16 и 25 — в ней;
       поток на 17 при бюджете 16 — в полосе. */
    {
        const uint16_t b16[] = {16}, b16_25[] = {16, 25};
        d2k_session *s = tcp_window(47910, 1 * S, 50 * MS, 3, 4, 4, 3);
        d2k_session_set_stall_budgets(s, b16, 1);
        tcp_ct_set(47910, 19, 25, 1);
        d2k_session_sweep(s, 2 * S);
        tcp_ct_set(47910, 22, 25, 1);
        for (uint64_t k = 3; k <= 6; k++) d2k_session_sweep(s, k * S);
        CHECK(d2k_session_suspects(s) == 0, "24 пакета при бюджете коробки 16 объявлены обрывом");
        d2k_session_free(s);
        s = tcp_window(47911, 1 * S, 50 * MS, 3, 4, 4, 3);
        d2k_session_set_stall_budgets(s, b16_25, 2);
        tcp_ct_set(47911, 19, 25, 1);
        d2k_session_sweep(s, 2 * S);
        tcp_ct_set(47911, 22, 25, 1);
        for (uint64_t k = 3; k <= 6; k++) d2k_session_sweep(s, k * S);
        CHECK(d2k_session_suspects(s) == 1, "24 пакета при бюджетах 16 и 25 не стали подозрением");
        d2k_session_free(s);
        s = tcp_window(47912, 1 * S, 50 * MS, 3, 4, 4, 3);
        d2k_session_set_stall_budgets(s, b16, 1);
        tcp_ct_set(47912, 12, 18, 1);
        d2k_session_sweep(s, 2 * S);
        tcp_ct_set(47912, 15, 18, 1);
        for (uint64_t k = 3; k <= 6; k++) d2k_session_sweep(s, k * S);
        CHECK(d2k_session_suspects(s) == 1, "17 пакетов при бюджете 16 не стали подозрением");
        d2k_session_free(s);
        /* Пустой список — снова поле 04.10 (25). */
        s = tcp_window(47913, 1 * S, 50 * MS, 3, 4, 4, 3);
        d2k_session_set_stall_budgets(s, b16, 1);
        d2k_session_set_stall_budgets(s, NULL, 0);
        tcp_ct_set(47913, 19, 25, 1);
        d2k_session_sweep(s, 2 * S);
        tcp_ct_set(47913, 22, 25, 1);
        for (uint64_t k = 3; k <= 6; k++) d2k_session_sweep(s, k * S);
        CHECK(d2k_session_suspects(s) == 1, "сброс бюджетов не вернул полевой бюджет 25");
        d2k_session_free(s);
    }

    /* Цикл очереди не ждёт: запрос — один на наблюдаемый поток за обход,
       а поток после FIN клиента (ждёт повтора FIN) не наблюдается. */
    {
        d2k_session *s = tcp_window(47914, 1 * S, 50 * MS, 3, 4, 4, 3);
        tcp_ct_set(47914, 19, 21, 1);
        tcp_ct_queries = 0;
        d2k_session_sweep(s, 2 * S);
        d2k_session_sweep(s, 3 * S);
        CHECK(tcp_ct_queries == 2, "наблюдаемый поток спрошен не по разу за обход");
        uint8_t pkt[256], buf[4096];
        d2k_result r;
        size_t n = cut_seq(pkt, build_pkt(pkt, 47914, 0x11, NULL, 0), 3000, 5000 + 30000);
        d2k_session_packet(s, pkt, n, 3 * S + 1, buf, sizeof buf, &r);
        tcp_ct_queries = 0;
        d2k_session_sweep(s, 4 * S);
        CHECK(tcp_ct_queries == 0, "поток после FIN клиента всё ещё спрашивается");
        d2k_session_free(s);
    }
}

/* ЗАМЫСЕЛ 23.10.2026, п. 5.3: ПЛАН ВЕЗЁТ СВОИ ТРЕБОВАНИЯ К ПОТОКУ.
 *
 * Поле issue #7 (22.10.2026): план tcp-template-v1 с порчей «метка времени
 * назад» подтверждён зондом, а с ПК репортёра — 13 из 13 «план не применён».
 * Профиль копирует опции потока клиента и сдвигает в них метку; у клиента
 * метки нет, и d2k_wire_build возвращал 0 — тот же ноль, что «не поместилось»,
 * с текстом «буфер отправки кончился» и без кода. Контроллер читал это как
 * «план подтверждён, датапат его не применял» и ничего не перемерял.
 *
 * Требование: датапат проверяет требования плана к потоку ДО сборки и
 * отказывает своей причиной и своим кодом (D2K_REFUSE_FLOW_UNFIT); поток с
 * меткой времени план исполняет как прежде. */
static void put_rec(uint8_t *b, size_t *n, uint16_t type, const uint8_t *v, uint16_t len) {
    b[(*n)++] = (uint8_t)(type >> 8); b[(*n)++] = (uint8_t)type;
    b[(*n)++] = (uint8_t)(len >> 8);  b[(*n)++] = (uint8_t)len;
    if (len) { memcpy(b + *n, v, len); }
    *n += len;
}

static size_t build_pkt_ts(uint8_t *o, uint16_t sport, uint8_t flags,
                           const uint8_t *pay, size_t paylen) {
    static const uint8_t ts[12] = {1, 1, 8, 10, 0x00, 0x12, 0x34, 0x56, 0, 0, 0, 0};
    size_t n = build_pkt_opt(o, sport, flags, pay, paylen, sizeof ts);
    memcpy(o + 40, ts, sizeof ts);
    return n;
}

static size_t template_ts_plan(uint8_t *plan, size_t cap) {
    uint8_t hello[512];
    size_t hlen = build_hello(hello);
    size_t n = 0;
    if (cap < 64 + hlen) { return 0; }
    memcpy(plan, "D2KP", 4);
    plan[4] = 0; plan[5] = 1;             /* версия 1 */
    plan[6] = 0; plan[7] = 8;             /* minexec 8: tcp-template-v1 */
    plan[8] = 0; plan[9] = 0; plan[10] = 0; plan[11] = 8;
    n = 12;
    uint8_t id[16] = {0x7A, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    put_rec(plan, &n, 0x0001, id, sizeof id);
    uint8_t proto[2] = {6, 1};
    put_rec(plan, &n, 0x0002, proto, sizeof proto);
    put_rec(plan, &n, 0x010a, NULL, 0);   /* input tls-sni */
    uint8_t wire = 2;                     /* tcp-template-v1 */
    put_rec(plan, &n, 0x0109, &wire, 1);
    uint8_t payload[2 + 512];
    payload[0] = 0; payload[1] = 1;
    memcpy(payload + 2, hello, hlen);
    put_rec(plan, &n, 0x0010, payload, (uint16_t)(2 + hlen));
    uint8_t poison[8] = {0, 1, 0, D2K_POISON_TCPTS_BACK, 0, 0, 0, 0};
    put_rec(plan, &n, 0x0011, poison, sizeof poison);
    uint8_t fake[11] = {0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 3};
    put_rec(plan, &n, 0x0101, fake, sizeof fake);
    uint8_t order = 0;
    put_rec(plan, &n, 0x0103, &order, 1);
    return n;
}

static size_t count_refused_code(const d2k_journal *j, uint8_t code) {
    size_t n = d2k_journal_count(j), k = 0;
    for (size_t i = 0; i < n; i++) {
        const d2k_jrn_entry *e = d2k_journal_at(j, i);
        if (e && e->kind == D2K_JRN_PLAN_REFUSED && e->code == code) { k++; }
    }
    return k;
}

static void test_template_plan_needs_client_timestamp(void) {
    d2k_nat_fn saved = d2k_nat_hook;
    d2k_nat_hook = nat_stub;
    uint8_t hello[512], pkt[1024], buf[8192], plan[1024];
    char err[128];
    size_t hlen = build_hello(hello);
    size_t plen = template_ts_plan(plan, sizeof plan);
    d2k_result r;

    d2k_session *g = d2k_session_new(8, 8);
    d2k_plan *p = NULL;
    CHECK(plen > 0 && d2k_plan_load(plan, plen, &p, err, sizeof err) == 0,
          "план tcp-template-v1 с меткой времени не разобран");
    if (!p) { fprintf(stderr, "  %s\n", err); d2k_session_free(g); d2k_nat_hook = saved; return; }
    d2k_session_set_plan(g, p);
    nat_calls = 0;
    nat_miss_first_n = 0;

    /* --- клиент без метки времени (ПК репортёра #7) ---------------------- */
    size_t n = build_pkt(pkt, 41400, 0x02, NULL, 0);
    d2k_session_packet(g, pkt, n, 1000, buf, sizeof buf, &r);
    n = build_rev_pkt(pkt, 41400, 0x12, NULL, 0);
    d2k_session_packet(g, pkt, n, 2000, buf, sizeof buf, &r);
    n = build_pkt(pkt, 41400, 0x18, hello, hlen);
    d2k_session_packet(g, pkt, n, 3000, buf, sizeof buf, &r);
    CHECK(r.n_out == 0 && r.verdict == D2K_VERDICT_ACCEPT,
          "поток без метки: план частично собран или оригинал снят");
    CHECK(r.skipped != NULL && strstr(r.skipped, "метк") != NULL,
          "поток без метки: отказ не назван требованием плана к потоку");
    CHECK(r.skipped == NULL || strstr(r.skipped, "буфер") == NULL,
          "поток без метки: отказ выдан за нехватку буфера");
    CHECK(count_refused_code(d2k_session_journal(g), D2K_REFUSE_FLOW_UNFIT) == 1,
          "поток без метки: отказ не записан кодом «поток не несёт требуемого»");
    CHECK(d2k_session_applied(g) == 0, "поток без метки: счётчик применений сдвинулся");

    /* --- клиент с меткой времени: план исполняется ----------------------- */
    n = build_pkt_ts(pkt, 41401, 0x02, NULL, 0);
    d2k_session_packet(g, pkt, n, 4000, buf, sizeof buf, &r);
    n = build_rev_pkt(pkt, 41401, 0x12, NULL, 0);
    d2k_session_packet(g, pkt, n, 5000, buf, sizeof buf, &r);
    n = build_pkt_ts(pkt, 41401, 0x18, hello, hlen);
    d2k_session_packet(g, pkt, n, 6000, buf, sizeof buf, &r);
    CHECK(r.n_out > 0 && r.skipped == NULL, "поток с меткой: план не исполнен");
    CHECK(count_refused_code(d2k_session_journal(g), D2K_REFUSE_FLOW_UNFIT) == 1,
          "поток с меткой: отказ «не несёт требуемого» записан зря");
    d2k_session_free(g);
    d2k_nat_hook = saved;
}

/* ЗАМЫСЕЛ 2026-10-23, п. 5.1: СНИМОК ПРИВЕТСТВИЯ НЕСЁТ НАБОР ОПЦИЙ TCP КЛИЕНТА.
 * Датапат уже снимает приветствие по запросу (ARM_SHAPE); набор опций TCP того
 * же пакета (тот, что профиль tcp-template-v1 копирует в фальшивки) отдаётся
 * рядом, чтобы зонд здоровался этим набором, а не литералом. Пустой набор —
 * честный профиль клиента без опций (ПК репортёра #7), не «нет данных». */
static void test_shape_carries_client_tcp_options(void) {
    uint8_t hello[512], pkt[1024], buf[4096];
    size_t hlen = build_hello(hello);
    const uint8_t name[] = "hetzner.com";
    d2k_result r;
    size_t olen = 77;

    /* Снимка ещё нет — набора тоже. */
    d2k_session *g = d2k_session_new(8, 8);
    CHECK(d2k_session_shape_tcp_options_family(g, 4, &olen) == NULL && olen == 0,
          "опции без снимка: не NULL");

    /* Ловушка взведена, приветствие с меткой времени: набор 12 байт, вид 8. */
    CHECK(d2k_session_want_shape(g, name, sizeof name - 1, 6) == 0, "ловушка не взвелась");
    size_t n = build_pkt_ts(pkt, 41500, 0x18, hello, hlen);
    d2k_session_packet(g, pkt, n, 1000, buf, sizeof buf, &r);
    CHECK(d2k_session_shape(g, 6, &olen) != NULL, "снимок с меткой не снят");
    const uint8_t *o = d2k_session_shape_tcp_options_family(g, 4, &olen);
    CHECK(o != NULL && olen == 12 && o[2] == 8 && o[3] == 10,
          "опции снимка с меткой: не те байты");
    d2k_session_free(g);

    /* Приветствие без опций: набор известен и пуст. */
    g = d2k_session_new(8, 8);
    CHECK(d2k_session_want_shape(g, name, sizeof name - 1, 6) == 0, "ловушка не взвелась");
    n = build_pkt(pkt, 41501, 0x18, hello, hlen);
    d2k_session_packet(g, pkt, n, 1000, buf, sizeof buf, &r);
    CHECK(d2k_session_shape(g, 6, &olen) != NULL, "снимок без опций не снят");
    olen = 77;
    o = d2k_session_shape_tcp_options_family(g, 4, &olen);
    CHECK(o != NULL && olen == 0, "опции снимка без опций: не пустой известный набор");
    d2k_session_free(g);

    /* Снимок отдан из последнего приветствия (ловушка после пакета): набор с ним. */
    g = d2k_session_new(8, 8);
    n = build_pkt_ts(pkt, 41502, 0x18, hello, hlen);
    d2k_session_packet(g, pkt, n, 1000, buf, sizeof buf, &r);
    CHECK(d2k_session_want_shape(g, name, sizeof name - 1, 6) == 1, "последнее приветствие не отдано");
    olen = 77;
    o = d2k_session_shape_tcp_options_family(g, 4, &olen);
    CHECK(o != NULL && olen == 12 && o[2] == 8, "опции последнего приветствия не отданы со снимком");
    /* IPv6-слот чужой: там ничего нет. */
    CHECK(d2k_session_shape_tcp_options_family(g, 6, &olen) == NULL, "IPv6-слот отдал чужие опции");
    d2k_session_free(g);
}

int main(void) {
    D2K_TEST_NAT_NO_TABLE();
    test_template_plan_needs_client_timestamp();
    test_shape_carries_client_tcp_options();
    test_tcp_stall();
    test_route_mark_does_not_leak();
    test_routed_flag_reset_on_new_syn();
    test_tcp_plan_skips_conntrack_read();
    test_routed_client_gets_no_plan_tcp();
    test_reply_hidden_by_accelerator();
    {
        d2k_session *v6 = d2k_session_new(32, 32);
        uint8_t hello6[512], ip4[1024], ip6[1044] = {0}, output6[8192];
        size_t h6 = build_hello(hello6);
        size_t n4 = build_pkt(ip4, 47701, 0x18, hello6, h6);
        size_t n6 = n4 + 20;
        ip6[0] = 0x60; wr16(ip6 + 4, (uint16_t)(n4 - 20));
        ip6[6] = 6; ip6[7] = 64;
        ip6[8] = ip6[24] = 0x20; ip6[9] = ip6[25] = 1;
        ip6[23] = 1; ip6[39] = 2;
        memcpy(ip6 + 40, ip4 + 20, n4 - 20);
        d2k_result r6;
        d2k_session_want_shape_family(v6, NULL, 0, 6, 6);
        d2k_session_packet(v6, ip6, n6, 1, output6, sizeof output6, &r6);
        CHECK(r6.verdict == D2K_VERDICT_ACCEPT, "IPv6 observation dropped traffic");
        CHECK(count_kind(v6, D2K_JRN_HELLO_SNI) == 1, "IPv6 TLS hello not observed");
        size_t snaplen = 0;
        const uint8_t *snap = d2k_session_shape_family(v6, 6, 6, &snaplen);
        CHECK(snap && snaplen == h6 && !memcmp(snap, hello6, h6), "IPv6 live snapshot missing");
        CHECK(d2k_session_shape(v6, 6, &snaplen) == NULL, "IPv6 polluted IPv4 snapshot");
        d2k_plan *p6 = NULL; char why6[128];
        CHECK(d2k_plan_load(plan_owns_payload, sizeof plan_owns_payload, &p6,
                             why6, sizeof why6) == 0, "IPv6 execution fixture plan");
        CHECK(d2k_plantab_set_addr_family(d2k_session_plans(v6), ip6 + 24, 6, 2, p6) == 0,
              "IPv6 execution address binding");
        wr16(ip6 + 40, 47702);
        d2k_session_packet(v6, ip6, n6, 3, output6, sizeof output6, &r6);
        CHECK(r6.applied && r6.n_out > 0 && (output6[0] >> 4) == 6,
              "IPv6 plan did not produce native IPv6 packets");
        d2k_session_free(v6);
    }
    test_suspect_tells_planned();
    test_late_rst_after_tls_appdata();
    test_silent_cut_fin_retry();
    test_silent_cut_round1();
    d2k_session *s = d2k_session_new(64, 32);
    CHECK(s != NULL, "сессия не создалась");
    if (!s) {
        return 1;
    }

    d2k_plan *p = NULL;
    char err[160];
    CHECK(d2k_plan_load(plan_bytes, sizeof plan_bytes, &p, err, sizeof err) == 0,
          "план не загрузился");
    d2k_session_set_plan(s, p);

    uint8_t hello[512];
    size_t hlen = build_hello(hello);
    uint8_t pkt[1024], buf[4096];
    d2k_result r;

    /* --- СБОРКА НЕ ВЛЕЗЛА: отказ целиком, оригинал нетронут -------------
     *
     * 0009, U3. Буфер результата даётся заведомо маленький — первая же
     * посылка в него не поместится. Это происходит на СБОРКЕ, до единой
     * отправки, и значит чистый выход есть: воздействия не было, поток не
     * испорчен, оригинал обязан пройти.
     *
     * Раньше исполнителю сообщалось число уже СОБРАННЫХ посылок как число
     * ушедших: с ним он объявлял поток испорченным и снимал оригинал из-за
     * байт, которых на проводе не было. Проверяется именно это: ноль посылок
     * и проход оригинала. */
    {
        uint8_t tiny[8];
        size_t nn = build_pkt(pkt, 40001, 0x18, hello, hlen);
        d2k_result rt;
        d2k_session_packet(s, pkt, nn, 900, tiny, sizeof tiny, &rt);
        CHECK(rt.n_out == 0, "несобранный план выдан как частично исполненный");
        CHECK(rt.verdict == D2K_VERDICT_ACCEPT,
              "оригинал снят, хотя на провод не ушло ни байта");
        CHECK(rt.skipped != NULL, "отказ сборки не назван причиной");
    }

    /* --- ClientHello: план применяется ---------------------------------- */
    size_t n = build_pkt(pkt, 40000, 0x18, hello, hlen);
    d2k_session_packet(s, pkt, n, 1000, buf, sizeof buf, &r);
    CHECK(r.n_out == 2, "ожидались две копии фальшивки");
    CHECK(r.skipped == NULL, "план не применён, хотя должен был");
    CHECK(r.verdict == D2K_VERDICT_ACCEPT, "оригинал обязан пройти: нагрузку не трогали");
    if (r.n_out == 2) {
        CHECK(r.out[0].delay_us == 0, "первая копия не должна ждать");
        CHECK(r.out[1].delay_us == 78000, "пауза между копиями потеряна");
        CHECK(r.out[0].len == 20 + 20 + 3, "длина собранного пакета неверна");
    }
    CHECK(d2k_session_applied(s) == 1, "счётчик применений не сдвинулся");

    /* --- тот же поток второй раз: план НЕ применяется -------------------- */
    d2k_session_packet(s, pkt, n, 2000, buf, sizeof buf, &r);
    CHECK(r.n_out == 0, "план применён к потоку повторно");
    CHECK(r.skipped != NULL, "повторное применение не объяснено");
    CHECK(d2k_session_applied(s) == 1, "счётчик применений вырос повторно");

    /* --- не ClientHello: пропускаем -------------------------------------- */
    {
        uint8_t junk[] = {'G', 'E', 'T', ' ', '/', '\r', '\n'};
        n = build_pkt(pkt, 40001, 0x18, junk, sizeof junk);
        d2k_session_packet(s, pkt, n, 3000, buf, sizeof buf, &r);
        CHECK(r.n_out == 0, "план применён к не-TLS");
        CHECK(r.verdict == D2K_VERDICT_ACCEPT, "не-TLS обязан пройти как есть");
    }

    /* --- пустая нагрузка --------------------------------------------------- */
    n = build_pkt(pkt, 40002, 0x10, NULL, 0);
    d2k_session_packet(s, pkt, n, 4000, buf, sizeof buf, &r);
    CHECK(r.n_out == 0, "план применён к пакету без нагрузки");

    /* --- сброс убирает поток ---------------------------------------------- */
    {
        size_t before = d2k_session_flows(s);
        n = build_pkt(pkt, 40001, 0x14, NULL, 0);  /* RST|ACK */
        d2k_session_packet(s, pkt, n, 5000, buf, sizeof buf, &r);
        CHECK(d2k_session_flows(s) < before, "сброс не освободил поток");
    }

    /* --- мусор вместо пакета: пропускаем и объясняем ------------------------ */
    {
        uint8_t garbage[8];
        memset(garbage, 0xFF, sizeof garbage);
        d2k_session_packet(s, garbage, sizeof garbage, 6000, buf, sizeof buf, &r);
        CHECK(r.verdict == D2K_VERDICT_ACCEPT, "мусор обязан проходить как есть");
        CHECK(r.skipped != NULL, "пропуск мусора не объяснён");
    }

    /* --- врущее поле длины --------------------------------------------------- */
    {
        n = build_pkt(pkt, 40010, 0x18, hello, hlen);
        wr16(pkt + 2, (uint16_t)(n + 500));   /* объявляем больше, чем есть */
        d2k_session_packet(s, pkt, n, 7000, buf, sizeof buf, &r);
        CHECK(r.n_out == 0, "пакет с врущей длиной обработан");
        CHECK(r.verdict == D2K_VERDICT_ACCEPT, "пакет с врущей длиной обязан пройти");
    }

    /* --- крошечный буфер отправки ------------------------------------------- */
    {
        n = build_pkt(pkt, 40011, 0x18, hello, hlen);
        d2k_session_packet(s, pkt, n, 8000, buf, 10, &r);
        CHECK(r.n_out == 0, "в крошечный буфер что-то поместилось");
        CHECK(r.verdict == D2K_VERDICT_ACCEPT,
              "ничего не выпустив, оригинал обязаны пропустить");
        CHECK(r.skipped != NULL, "нехватка буфера не объяснена");
    }

    /* --- подозрения ---------------------------------------------------------
     * Три улики, доступные в направлении, которое и так наблюдается, плюс
     * одна, доступная только в момент забвения потока. Все три — НАБЛЮДЕНИЯ:
     * §2.4 запрещает выводить из них устройство механизма, и ни одна на диск
     * не идёт (§2.3).                                                       */
    {
        d2k_session *z = d2k_session_new(64, 64);

        /* 1. Сброс в ответ на приветствие. */
        n = build_pkt(pkt, 41000, 0x18, hello, hlen);
        d2k_session_packet(z, pkt, n, 1000, buf, sizeof buf, &r);
        CHECK(d2k_session_suspects(z) == 0, "приветствие само по себе — подозрение");
        n = build_rev_pkt(pkt, 41000, 0x14, NULL, 0);   /* RST|ACK от сервера */
        d2k_session_packet(z, pkt, n, 2000, buf, sizeof buf, &r);
        CHECK(d2k_session_suspects(z) == 1, "сброс после приветствия не замечен");

        /* Сброс БЕЗ предшествующего приветствия подозрением не является:
           соединение могло закрыться по любой причине. */
        n = build_pkt(pkt, 41001, 0x02, NULL, 0);       /* SYN */
        d2k_session_packet(z, pkt, n, 3000, buf, sizeof buf, &r);
        n = build_rev_pkt(pkt, 41001, 0x14, NULL, 0);
        d2k_session_packet(z, pkt, n, 3100, buf, sizeof buf, &r);
        CHECK(d2k_session_suspects(z) == 1, "сброс без приветствия сочтён подозрением");

        /* 2. Повтор приветствия. Один повтор — ещё не улика: пакет мог
           потеряться на линии. */
        n = build_pkt(pkt, 41002, 0x18, hello, hlen);
        d2k_session_packet(z, pkt, n, 4000, buf, sizeof buf, &r);
        d2k_session_packet(z, pkt, n, 4500, buf, sizeof buf, &r);
        CHECK(d2k_session_suspects(z) == 1, "один повтор уже объявлен подозрением");
        d2k_session_packet(z, pkt, n, 5000, buf, sizeof buf, &r);
        CHECK(d2k_session_suspects(z) == 2, "два повтора не замечены");

        /* Тот же поток дальше не должен множить подозрения. */
        d2k_session_packet(z, pkt, n, 5500, buf, sizeof buf, &r);
        CHECK(d2k_session_suspects(z) == 2, "подозрение отмечено по одному потоку дважды");

        /* 3. Ответа не было вовсе — видно только при забвении потока. */
        n = build_pkt(pkt, 41003, 0x18, hello, hlen);
        d2k_session_packet(z, pkt, n, 6000, buf, sizeof buf, &r);
        uint64_t before = d2k_session_suspects(z);
        d2k_session_expire(z, 6000 + 100000, 50000);
        CHECK(d2k_session_suspects(z) > before,
              "молчание в ответ на приветствие не замечено при уборке");

        /* Поток, на приветствие которого ответили, подозрения не вызывает. */
        d2k_session *w = d2k_session_new(64, 64);
        n = build_pkt(pkt, 41004, 0x18, hello, hlen);
        d2k_session_packet(w, pkt, n, 1000, buf, sizeof buf, &r);
        {
            uint8_t data[8] = {0x16, 0x03, 0x03, 0, 3, 2, 0, 0};
            n = build_rev_pkt(pkt, 41004, 0x18, data, sizeof data);
            d2k_session_packet(w, pkt, n, 1100, buf, sizeof buf, &r);
        }
        d2k_session_expire(w, 1100 + 100000, 50000);
        CHECK(d2k_session_suspects(w) == 0,
              "поток с ответом на приветствие сочтён подозрительным");
        d2k_session_free(w);
        d2k_session_free(z);
    }

    /* --- защита от чужого сброса ------------------------------------------
     * Ориентир берётся из САМОГО потока: TTL первого пакета, пришедшего с той
     * стороны. Сброс с другим TTL послан не тем, кто до этого отвечал.       */
    {
        d2k_session *g = d2k_session_new(64, 64);
        d2k_plan *gp = NULL;
        CHECK(d2k_plan_load(plan_guard, sizeof plan_guard, &gp, err, sizeof err) == 0,
              "план с защитой не загрузился");
        d2k_session_set_plan(g, gp);

        /* Рукопожатие: SYN клиента, затем SYN-ACK сервера с TTL 124 —
           он и задаёт ориентир для защиты. */
        n = build_pkt(pkt, 42000, 0x02, NULL, 0);
        d2k_session_packet(g, pkt, n, 900, buf, sizeof buf, &r);
        n = build_rev_pkt_ttl(pkt, 42000, 0x12, NULL, 0, 124);
        d2k_session_packet(g, pkt, n, 1000, buf, sizeof buf, &r);

        /* Приветствие: план применяется, защита назначается потоку. */
        n = build_pkt(pkt, 42000, 0x18, hello, hlen);
        d2k_session_packet(g, pkt, n, 1100, buf, sizeof buf, &r);
        CHECK(d2k_session_applied(g) == 1, "план с защитой не применился");

        /* Сброс с ЧУЖИМ TTL — снимается. */
        n = build_rev_pkt_ttl(pkt, 42000, 0x14, NULL, 0, 127);
        d2k_session_packet(g, pkt, n, 1200, buf, sizeof buf, &r);
        CHECK(r.verdict == D2K_VERDICT_DROP, "чужой сброс не снят");
        CHECK(d2k_session_rst_dropped(g) == 1, "снятый сброс не посчитан");
        CHECK(d2k_session_flows(g) > 0,
              "поток удалён вместе со снятым сбросом: сервер ещё отвечает");

        /* Сброс с ТЕМ ЖЕ TTL — настоящий, проходит и закрывает поток.
           Это и есть цена ошибки в обратную сторону, и она обязана быть
           маленькой: настоящий сброс мы не трогаем. */
        size_t before_flows = d2k_session_flows(g);
        n = build_rev_pkt_ttl(pkt, 42000, 0x14, NULL, 0, 124);
        d2k_session_packet(g, pkt, n, 1300, buf, sizeof buf, &r);
        CHECK(r.verdict == D2K_VERDICT_ACCEPT, "настоящий сброс снят защитой");
        CHECK(d2k_session_rst_dropped(g) == 1, "настоящий сброс посчитан снятым");
        CHECK(d2k_session_flows(g) < before_flows, "настоящий сброс не закрыл поток");

        d2k_session_free(g);
    }

    /* --- план выбирается по цели, а не один на всех ------------------------
     * §2.6: план закрепляется за контекстом, на котором подтверждён. Имя
     * точнее адреса, поэтому ищется первым.                                  */
    {
        d2k_session *g = d2k_session_new(64, 64);
        d2k_plan *by_name = NULL, *by_addr = NULL;
        d2k_plan_load(plan_bytes, sizeof plan_bytes, &by_name, err, sizeof err);
        d2k_plan_load(plan_guard, sizeof plan_guard, &by_addr, err, sizeof err);

        /* Приветствие в наших пакетах несёт имя hetzner.com, а адрес цели —
           1.2.3.4. Ставим планы на оба ключа и проверяем, что берётся тот,
           что по имени. */
        uint8_t dst[4] = {1, 2, 3, 4};
        uint32_t dst_be;
        memcpy(&dst_be, dst, 4);
        d2k_plantab_set_addr(d2k_session_plans(g), dst_be, 1, by_addr);
        d2k_plantab_set_name(d2k_session_plans(g),
                             (const uint8_t *)"hetzner.com", 11, 1, by_name);

        n = build_pkt(pkt, 43000, 0x18, hello, hlen);
        d2k_session_packet(g, pkt, n, 1000, buf, sizeof buf, &r);
        CHECK(r.n_out == 2, "план по имени не применился");
        CHECK(d2k_session_applied(g) == 1, "применение не посчитано");

        /* Цель без своего плана и без запасного — пропуск с объяснением. */
        d2k_session *w = d2k_session_new(64, 64);
        n = build_pkt(pkt, 43001, 0x18, hello, hlen);
        d2k_session_packet(w, pkt, n, 1000, buf, sizeof buf, &r);
        CHECK(r.n_out == 0, "план взялся ниоткуда");
        CHECK(r.verdict == D2K_VERDICT_ACCEPT, "цель без плана не пропущена");
        CHECK(d2k_session_hellos(w) == 1,
              "приветствие не узнано из-за отсутствия плана");
        d2k_session_free(w);
        d2k_session_free(g);
    }

    /* --- одно имя, две формы: клиент TLS 1.2 получает план своей формы ----
     * Поле 04.10.2026, updates.discord.com: приложение шлёт приветствие
     * TLS 1.2 одним сегментом, а привязка легла только формой TLS 1.3 —
     * «отказов по форме приветствия» росло, обход не применялся. План формы
     * 1.2 рядом с планом 1.3 того же имени достаётся именно ему.            */
    {
        const uint8_t *nm = (const uint8_t *)"hetzner.com";
        for (int with_legacy = 0; with_legacy <= 1; with_legacy++) {
            d2k_session *g = d2k_session_new(64, 64);
            d2k_plan *modern = NULL, *legacy = NULL;
            d2k_plan_load(plan_bytes, sizeof plan_bytes, &modern, err, sizeof err);
            CHECK(modern && d2k_plantab_set_name_family(d2k_session_plans(g), nm, 11, 1,
                      modern, D2K_PLAN_SHAPE_MODERN, 0, 4) == 0, "две формы: план TLS 1.3");
            if (with_legacy) {
                d2k_plan_load(plan_bytes, sizeof plan_bytes, &legacy, err, sizeof err);
                CHECK(legacy && d2k_plantab_set_name_family(d2k_session_plans(g), nm, 11, 1,
                          legacy, D2K_PLAN_SHAPE_LEGACY, 0, 4) == 0, "две формы: план TLS 1.2");
            }
            n = build_pkt(pkt, (uint16_t)(43010 + with_legacy), 0x18, hello, hlen);
            d2k_session_packet(g, pkt, n, 1000, buf, sizeof buf, &r);
            if (with_legacy) {
                CHECK(r.n_out == 2 && d2k_session_applied(g) == 1,
                      "две формы: клиенту TLS 1.2 не применён план его формы");
                CHECK(d2k_plantab_shape_misses(d2k_session_plans(g)) == 0,
                      "две формы: приветствие TLS 1.2 посчитано отказом по форме");
            } else {
                CHECK(r.n_out == 0 && d2k_session_applied(g) == 0,
                      "одна форма: клиенту TLS 1.2 применён план формы TLS 1.3");
                CHECK(d2k_plantab_shape_misses(d2k_session_plans(g)) >= 1,
                      "одна форма: отказ по форме не посчитан");
            }
            d2k_session_free(g);
        }
    }

    /* --- ПРИВЕТСТВИЕ КРУПНЕЕ ПРЕЖНЕГО БУФЕРА СБОРКИ, ИМЯ В ХВОСТЕ ---------
     * Поле 13.10.2026, forum.ru-board.com. Chrome шлёт приветствие 2118-2214
     * байт (постквантовый key_share плюс перемешанный порядок расширений), и
     * у части соединений имя уезжает в самый хвост: в снятом приветствии 2182
     * байта имя лежит на смещении 2129, то есть во ВТОРОМ сегменте. Датапат
     * обязан собрать голову с хвостом — иначе имени он не узнает, плана не
     * поставит, а коробка после СВОЕЙ пересборки имя видит и глушит поток
     * молча (в браузере это ERR_TIMED_OUT на картинках: из 23 потоков план
     * получили 5, у остальных 18 не было ни ответа, ни сброса).
     *
     * Упиралось это в потолок снимка: приветствие длиннее него отвергалось
     * целиком (capture.c, «total > D2K_CAPTURE_BYTES»), и сборка не
     * начиналась вовсе. */
    {
        const char *bnm = "hetzner.com";
        static uint8_t big[8192];
        size_t blen = 0, bo;
        {   /* Приветствие с НАБИВКОЙ ПЕРЕД ИМЕНЕМ: имя — последнее расширение. */
            static uint8_t body[8192];
            size_t b = 0, e = 0;
            static uint8_t ext[8192];
            body[b++] = 0x03; body[b++] = 0x03;
            for (int i = 0; i < 32; i++) { body[b++] = (uint8_t)i; }
            body[b++] = 0;
            body[b++] = 0x00; body[b++] = 0x02; body[b++] = 0x13; body[b++] = 0x01;
            body[b++] = 0x01; body[b++] = 0x00;
            const size_t pad = 2048;                 /* набивка впереди имени */
            ext[e++] = 0x00; ext[e++] = 0x15;
            ext[e++] = (uint8_t)(pad >> 8); ext[e++] = (uint8_t)pad;
            memset(ext + e, 0, pad); e += pad;
            size_t nl = strlen(bnm);
            ext[e++] = 0x00; ext[e++] = 0x00;
            ext[e++] = 0x00; ext[e++] = (uint8_t)(5 + nl);
            ext[e++] = 0x00; ext[e++] = (uint8_t)(3 + nl);
            ext[e++] = 0x00;
            ext[e++] = 0x00; ext[e++] = (uint8_t)nl;
            memcpy(ext + e, bnm, nl); e += nl;
            body[b++] = (uint8_t)(e >> 8); body[b++] = (uint8_t)e;
            memcpy(body + b, ext, e); b += e;
            bo = 0;
            big[bo++] = 0x16; big[bo++] = 0x03; big[bo++] = 0x01;
            big[bo++] = (uint8_t)((b + 4) >> 8); big[bo++] = (uint8_t)(b + 4);
            big[bo++] = 0x01;
            big[bo++] = (uint8_t)(b >> 16); big[bo++] = (uint8_t)(b >> 8); big[bo++] = (uint8_t)b;
            memcpy(big + bo, body, b); bo += b;
            blen = bo;
        }
        const size_t SEG = 1452;
        CHECK(blen > 2048 && blen < sizeof big,
              "крупное приветствие не той длины");
        /* Имя обязано лежать ЗА первым сегментом — иначе опыт не про то. */
        {
            size_t at = 0, i;
            for (i = 0; i + strlen(bnm) <= blen; i++) {
                if (!memcmp(big + i, bnm, strlen(bnm))) { at = i; break; }
            }
            CHECK(at > SEG, "имя попало в первый сегмент — опыт не про это");
        }
        /* План с входом по имени: такой и ставится цели в поле. */
        static const uint8_t named_plan[] = {
            'D','2','K','P', 0,1, 0,5, 0,0, 0,5,
            0,2, 0,2, 6,1,                 /* TCP/TLS */
            1,10, 0,0,                     /* input tls-sni */
            1,0, 0,4, 0,5, 0,0,            /* split sni_middle */
            1,8, 0,4, 0,0,5,120,           /* segment 1400 */
            1,9, 0,1, 1                    /* detect-tcp-v1 */
        };
        d2k_session *g = d2k_session_new(64, 64);
        d2k_hold *bh = d2k_hold_new();
        d2k_plan *bp = NULL;
        CHECK(g && bh && d2k_plan_load(named_plan, sizeof named_plan, &bp,
                                       err, sizeof err) == 0,
              "крупное приветствие: план не разобран");
        CHECK(bp && d2k_plantab_set_name_family(d2k_session_plans(g),
                  (const uint8_t *)bnm, 11, 1, bp,
                  D2K_PLAN_SHAPE_GRANDFATHER, 0, 4) == 0,
              "крупное приветствие: привязка не встала");
        static uint8_t bpkt[8192], bbuf[65536];
        size_t bn = build_pkt(bpkt, 43060, 0x02, NULL, 0);
        d2k_session_packet(g, bpkt, bn, 1000, bbuf, sizeof bbuf, &r);
        bn = build_pkt(bpkt, 43060, 0x10, big, SEG);
        wr32(bpkt + 24, 1001);
        int allow = d2k_session_hold_candidate(g, bpkt, bn);
        CHECK(allow, "крупное приветствие: голову удержать не разрешили");
        d2k_hold_batch bb;
        memset(&bb, 0, sizeof bb);
        CHECK(d2k_hold_feed(bh, 200, bpkt, bn, 2000, d2k_session_plan_revision(g),
                            allow, 1001, 1, hold_release, g, &bb) == 1,
              "крупное приветствие: голова не удержана — потолок снимка мал");
        bn = build_pkt(bpkt, 43060, 0x18, big + SEG, blen - SEG);
        wr32(bpkt + 24, 1001 + (uint32_t)SEG);
        CHECK(d2k_hold_feed(bh, 201, bpkt, bn, 2100, d2k_session_plan_revision(g),
                            0, 1001, 1, hold_release, g, &bb) == 2 && bb.count == 2,
              "крупное приветствие: хвост не присоединился к голове");
        if (bb.count == 2) {
            d2k_session_packet(g, bb.packet, bb.len, 2200, bbuf, sizeof bbuf, &r);
            CHECK(r.applied == 1 && r.n_out > 0,
                  "крупное приветствие: собрано, а план не применён");
        }
        d2k_hold_free(bh);
        d2k_session_free(g);
    }

    /* --- ОТКАЗ ИСПОЛНИТЕЛЯ НА ПОТОКЕ СВОЕГО ЗОНДА ВИДЕН КОНТРОЛЛЕРУ -------
     * Поле 13.10.2026, forum.ru-board.com. Пробная запись стоит под портом
     * зонда, план найден, но исполнитель его отвергает (здесь — приветствие
     * с несходящимися объявленными длинами, план считает от имени). Зонд
     * уходит голым, коробка срезает его как без обхода, и контроллер обязан
     * узнать, что плана на проводе НЕ БЫЛО: иначе наш отказ записывается в
     * вину кандидату. Прежде refuse() молчал о любом зондовом потоке, и
     * такого события не появлялось вовсе (в поле 10 отказов за 15 минут — ни
     * одного события), а контроллер после одного повтора судил кандидата.
     *
     * Код обязан быть D2K_REFUSE_NOT_APPLIED, а не ноль: ноль значит «плана
     * для цели нет», случается на каждом транзитном потоке, и контроллер его
     * намеренно пропускает (on_refused). Запись GRANDFATHER — чтобы в опыте
     * проверялся отказ исполнителя, а не подбор формы. */
    {
        static const uint8_t anchored_plan[] = {
            'D','2','K','P', 0,1, 0,5, 0,0, 0,5,
            0,2, 0,2, 6,1,                 /* TCP/TLS */
            1,10, 0,0,                     /* input tls-sni */
            1,0, 0,4, 0,5, 0,0,            /* split sni_middle */
            1,8, 0,4, 0,0,5,120,           /* segment 1400 */
            1,9, 0,1, 1                    /* detect-tcp-v1 */
        };
        const uint8_t *nm = (const uint8_t *)"hetzner.com";
        d2k_session *g = d2k_session_new(64, 64);
        d2k_plan *ap = NULL;
        CHECK(g && d2k_plan_load(anchored_plan, sizeof anchored_plan, &ap,
                                 err, sizeof err) == 0 && ap,
              "отказ зонда: план с якорем по имени не разобран");
        uint16_t pport = 43040;
        CHECK(ap && d2k_plantab_set_name_probe(d2k_session_plans(g), nm, 11, 1, ap,
                  D2K_PLAN_SHAPE_GRANDFATHER, htons16(pport)) == 0,
              "отказ зонда: пробная запись не встала");
        uint8_t bad[2048];
        memcpy(bad, hello, hlen);
        /* Объявленная длина записи больше объявленной длины рукопожатия:
           имя читается, а исполнитель такой вход не берёт. */
        bad[3] = (uint8_t)((hlen - 5 + 7) >> 8);
        bad[4] = (uint8_t)(hlen - 5 + 7);
        n = build_pkt(pkt, pport, 0x02, NULL, 0);
        d2k_session_packet_probe(g, pkt, n, 1000, buf, sizeof buf, &r);
        n = build_pkt(pkt, pport, 0x18, bad, hlen);
        d2k_session_packet_probe(g, pkt, n, 1100, buf, sizeof buf, &r);
        CHECK(r.applied == 0 && r.n_out == 0,
              "отказ зонда: план всё-таки применился — проверять нечего");
        CHECK(r.skipped != NULL && strstr(r.skipped, "не сходятся") != NULL,
              "отказ зонда: причина отказа не названа дословно");
        const d2k_journal *jr = d2k_session_journal(g);
        size_t jn = d2k_journal_count(jr), coded = 0;
        for (size_t i = 0; i < jn; i++) {
            const d2k_jrn_entry *e = d2k_journal_at(jr, i);
            if (e && e->kind == D2K_JRN_PLAN_REFUSED &&
                e->code == D2K_REFUSE_NOT_APPLIED) { coded++; }
        }
        CHECK(coded == 1,
              "отказ исполнителя на потоке зонда не уехал контроллеру с кодом");
        d2k_session_free(g);
    }

    /* --- постквантовое приветствие в двух сегментах -------------------------
     * Поле 13.10.2026, forum.ru-board.com: план подтверждён собственным
     * зондом на TLS 1.3, а к браузеру не применялся. Приветствие 1541 байт,
     * key_share с X25519MLKEM768, supported_versions за ним — во втором
     * сегменте. По первому сегменту форма была «неизвестна», и привязка
     * TLS 1.3 отказывала по форме. key_share есть только в TLS 1.3 — по нему
     * форма известна уже в первом сегменте, и план применяется к нему.
     * Контроль: на месте key_share набивка — признака нет, форма неизвестна,
     * отказ по форме как прежде (не догадываемся).                         */
    {
        const uint8_t *nm = (const uint8_t *)"hetzner.com";
        for (int with_key_share = 1; with_key_share >= 0; with_key_share--) {
            uint8_t pq[2048];
            size_t b = 0, e0;
            pq[b++] = 0x16; pq[b++] = 0x03; pq[b++] = 0x01; b += 2;
            pq[b++] = 0x01; b += 3;
            pq[b++] = 0x03; pq[b++] = 0x03;
            for (int i = 0; i < 32; i++) { pq[b++] = (uint8_t)i; }
            pq[b++] = 0;
            pq[b++] = 0x00; pq[b++] = 0x02; pq[b++] = 0x13; pq[b++] = 0x01;
            pq[b++] = 0x01; pq[b++] = 0x00;
            e0 = b; b += 2;
            const uint8_t sni[] = {0,0,0,16, 0,14, 0, 0,11, 'h','e','t','z','n','e','r','.','c','o','m'};
            memcpy(pq + b, sni, sizeof sni); b += sizeof sni;
            /* key_share (51) или набивка (21) той же длины: 1258 байт. */
            pq[b++] = 0x00; pq[b++] = with_key_share ? 0x33 : 0x15;
            pq[b++] = (uint8_t)(1258 >> 8); pq[b++] = (uint8_t)1258;
            memset(pq + b, 0, 1258);
            if (with_key_share) {
                pq[b] = (uint8_t)(1256 >> 8); pq[b + 1] = (uint8_t)1256;
                pq[b + 2] = 0x11; pq[b + 3] = 0xec; pq[b + 4] = 0x04; pq[b + 5] = 0xc0;
            }
            b += 1258;
            const uint8_t sv[] = {0,0x2b,0,3, 2,3,4};
            memcpy(pq + b, sv, sizeof sv); b += sizeof sv;
            wr16(pq + e0, (uint16_t)(b - e0 - 2));
            wr16(pq + 3, (uint16_t)(b - 5));
            pq[6] = 0; wr16(pq + 7, (uint16_t)(b - 9));

            d2k_session *g = d2k_session_new(64, 64);
            d2k_plan *modern = NULL;
            d2k_plan_load(plan_bytes, sizeof plan_bytes, &modern, err, sizeof err);
            CHECK(modern && d2k_plantab_set_name_family(d2k_session_plans(g), nm, 11, 1,
                      modern, D2K_PLAN_SHAPE_MODERN, 0, 4) == 0, "PQ: план TLS 1.3");
            /* Первый сегмент: обрыв посреди тела key_share. */
            n = build_pkt(pkt, (uint16_t)(43020 + with_key_share), 0x18, pq, 600);
            d2k_session_packet(g, pkt, n, 1000, buf, sizeof buf, &r);
            if (with_key_share) {
                CHECK(r.n_out > 0 && d2k_session_applied(g) == 1,
                      "PQ: план TLS 1.3 не применён к приветствию с key_share в первом сегменте");
                CHECK(d2k_plantab_shape_misses(d2k_session_plans(g)) == 0,
                      "PQ: приветствие с key_share посчитано отказом по форме");
            } else {
                CHECK(r.n_out == 0 && d2k_session_applied(g) == 0,
                      "PQ-контроль: без признака TLS 1.3 применён план TLS 1.3");
                CHECK(d2k_plantab_shape_misses(d2k_session_plans(g)) >= 1,
                      "PQ-контроль: отказ по форме не посчитан");
            }
            d2k_session_free(g);
        }
    }

    /* --- SYN-ACK обогнал SYN: направление всё равно верное -----------------
     * Два направления приходят из ДВУХ правил firewall, и порядок между ними
     * не гарантирован. Раньше такой поток получал направления наоборот, и
     * приветствие клиента не разбиралось вовсе.                             */
    {
        d2k_session *g = d2k_session_new(64, 64);
        n = build_rev_pkt_ttl(pkt, 42002, 0x12, NULL, 0, 124);   /* SYN-ACK первым */
        d2k_session_packet(g, pkt, n, 900, buf, sizeof buf, &r);
        n = build_pkt(pkt, 42002, 0x18, hello, hlen);
        d2k_session_packet(g, pkt, n, 1000, buf, sizeof buf, &r);
        CHECK(d2k_session_hellos(g) == 1,
              "приветствие потеряно, когда SYN-ACK пришёл раньше SYN");
        d2k_session_free(g);
    }

    /* --- без защиты чужой сброс проходит ------------------------------------
     * Проверка, что защита не включается сама собой: план без guard обязан
     * оставлять поведение прежним.                                          */
    {
        d2k_session *g = d2k_session_new(64, 64);
        d2k_plan *gp = NULL;
        d2k_plan_load(plan_bytes, sizeof plan_bytes, &gp, err, sizeof err);
        d2k_session_set_plan(g, gp);
        n = build_pkt(pkt, 42001, 0x02, NULL, 0);
        d2k_session_packet(g, pkt, n, 900, buf, sizeof buf, &r);
        n = build_rev_pkt_ttl(pkt, 42001, 0x12, NULL, 0, 124);
        d2k_session_packet(g, pkt, n, 1000, buf, sizeof buf, &r);
        n = build_pkt(pkt, 42001, 0x18, hello, hlen);
        d2k_session_packet(g, pkt, n, 1100, buf, sizeof buf, &r);
        n = build_rev_pkt_ttl(pkt, 42001, 0x14, NULL, 0, 127);
        d2k_session_packet(g, pkt, n, 1200, buf, sizeof buf, &r);
        CHECK(r.verdict == D2K_VERDICT_ACCEPT, "защита сработала без плана с защитой");
        CHECK(d2k_session_rst_dropped(g) == 0, "снятие посчитано там, где защиты нет");
        d2k_session_free(g);
    }

    /* Segmented measured fake: 7 * ceil(4096/1400) + truth = 22 packets.
     * Check the real session output and an all-or-nothing small-buffer refusal. */
    {
        uint8_t tlv[4200] = {'D','2','K','P',0,1,0,3,0,0,0,5,0,2,0,2,6,1};
        size_t z = 18;
        wr16(tlv + z, 0x0010); wr16(tlv + z + 2, 4098); wr16(tlv + z + 4, 1);
        memset(tlv + z + 6, 0x0f, 4096); z += 4102;
        const uint8_t tail[] = {
            0x01,0x01,0,10, 0,1,0,0,7,0,0,0,0,0,
            0x01,0x07,0,4, 0,0,0x3a,0x98,
            0x01,0x08,0,4, 0,0,0x05,0x78
        };
        memcpy(tlv + z, tail, sizeof tail); z += sizeof tail;
        uint8_t bigbuf[D2K_RESULT_MAX * 1600];
        d2k_session *g = d2k_session_new(64, 64);
        d2k_plan *gp = NULL;
        CHECK(d2k_plan_load(tlv, z, &gp, err, sizeof err) == 0, "segmented plan rejected");
        CHECK(d2k_plan_max_emit(gp) == 1440, "MTU check ignores segmentation");
        d2k_session_set_plan(g, gp);
        n = build_pkt(pkt, 43098, 0x18, hello, hlen);
        d2k_session_packet(g, pkt, n, 1000, buf, sizeof buf, &r);
        CHECK(r.n_out == 0 && !r.applied && r.verdict == D2K_VERDICT_ACCEPT,
              "small buffer produced partial measured execution");
        n = build_pkt(pkt, 43099, 0x18, hello, hlen);
        d2k_session_packet(g, pkt, n, 2000, bigbuf, sizeof bigbuf, &r);
        CHECK(r.n_out == 22 && r.applied && r.verdict == D2K_VERDICT_DROP,
              "long measured fake does not fit real session");
        if (r.n_out == 22) {
            for (size_t k = 0; k < 21; k++) {
                CHECK(r.out[k].len == (k % 3 == 2 ? 1336u : 1440u), "segment length changed");
                CHECK(r.out[k].delay_us == 0, "segment gained delay");
            }
            CHECK(r.out[21].delay_us == 15000, "settle delay lost");
            CHECK(r.out[21].len == hlen + 40, "truth length changed");
            CHECK(memcmp(bigbuf + r.out[21].off + 40, hello, hlen) == 0, "truth bytes changed");
        }
        d2k_session_free(g);
    }

    /* --- план с repeats больше вместимости out[] отвергается целиком -------
       Ревью задачи 4, круг 2: repeats берётся из TLV байтом без потолка (до
       255), d2k_result.out[] ограничен D2K_RESULT_MAX. Раньше n тихо
       обрезался до 16, на провод уходило меньше посылок, чем описывал план,
       а plan_done/applied++/PLAN_APPLIED ставились как за полное исполнение.
       Честный исход — отказ целиком: ни одной посылки, план не применён. */
    {
        d2k_session *g = d2k_session_new(64, 64);
        d2k_plan *gp = NULL;
        CHECK(d2k_plan_load(plan_too_many_repeats, sizeof plan_too_many_repeats, &gp, err, sizeof err) == 0,
              "план с лишним повтором не загрузился");
        d2k_session_set_plan(g, gp);
        n = build_pkt(pkt, 43100, 0x18, hello, hlen);
        d2k_session_packet(g, pkt, n, 1000, buf, sizeof buf, &r);
        CHECK(r.n_out == 0, "план с лишним повтором отправил посылку вместо отказа");
        CHECK(r.verdict == D2K_VERDICT_ACCEPT, "ничего не отправив, оригинал обязаны пропустить");
        CHECK(r.skipped != NULL, "отказ по переполнению out[] не объяснён вызывающему");
        CHECK(d2k_session_applied(g) == 0, "план с лишним повтором засчитан применённым");
        d2k_session_free(g);
    }

    /* --- молчание замечается по измеренному RTT, а не через две минуты ---
     *
     * Полевой прогон 06.09.2026: цель молчала в ответ на приветствие, и поиск
     * не начинался вовсе — подозрение рождалось только при забвении потока, а
     * это 120 секунд. Человек перед пустой страницей столько не ждёт. */
    {
        d2k_session *q = d2k_session_new(16, 32);
        CHECK(q != NULL, "сессия для молчания не создалась");
        const uint64_t ms = 1000000ull;
        uint8_t qp[1024], qb[4096];
        d2k_result qr;

        /* SYN и SYN-ACK с интервалом 20 мс — вот и измеренный RTT. */
        size_t qn = build_pkt(qp, 41000, 0x02, NULL, 0);
        d2k_session_packet(q, qp, qn, 0, qb, sizeof qb, &qr);
        qn = build_rev_pkt(qp, 41000, 0x12, NULL, 0);
        d2k_session_packet(q, qp, qn, 20 * ms, qb, sizeof qb, &qr);

        uint8_t qh[512];
        size_t qhl = build_hello(qh);
        qn = build_pkt(qp, 41000, 0x18, qh, qhl);
        d2k_session_packet(q, qp, qn, 30 * ms, qb, sizeof qb, &qr);
        CHECK(d2k_session_suspects(q) == 0, "подозрение сразу после приветствия");

        CHECK(d2k_session_sweep(q, 530 * ms) == 0,
              "полсекунды молчания объявлены блокировкой");
        CHECK(d2k_session_sweep(q, 1530 * ms) == 1,
              "молчание не замечено на второй секунде");
        CHECK(d2k_session_suspects(q) == 1, "подозрение о молчании не отмечено");
        CHECK(d2k_session_sweep(q, 9000 * ms) == 0, "подозрение продублировано");
        d2k_session_free(q);
    }

    /* --- без видимости обратной стороны молчания не бывает ---------------
     *
     * Правило на обратное направление ставится не всегда. Без него сервер
     * невидим, и каждый поток выглядел бы молчащим: это подмена «не смотрели»
     * на «нет ответа». */
    {
        d2k_session *q = d2k_session_new(16, 32);
        const uint64_t ms = 1000000ull;
        uint8_t qp[1024], qb[4096];
        d2k_result qr;

        /* Только исходящее: SYN и приветствие. Ответов не видим вовсе. */
        size_t qn = build_pkt(qp, 43000, 0x02, NULL, 0);
        d2k_session_packet(q, qp, qn, 0, qb, sizeof qb, &qr);
        uint8_t qh[512];
        size_t qhl = build_hello(qh);
        qn = build_pkt(qp, 43000, 0x18, qh, qhl);
        d2k_session_packet(q, qp, qn, 30 * ms, qb, sizeof qb, &qr);

        CHECK(d2k_session_sweep(q, 9000 * ms) == 0,
              "невидимая обратная сторона объявлена молчащей");
        d2k_session_free(q);
    }

    /* --- ответивший сервер не молчит, сколько ни выжидай ----------------- */
    {
        d2k_session *q = d2k_session_new(16, 32);
        const uint64_t ms = 1000000ull;
        uint8_t qp[1024], qb[4096];
        d2k_result qr;

        size_t qn = build_pkt(qp, 42000, 0x02, NULL, 0);
        d2k_session_packet(q, qp, qn, 0, qb, sizeof qb, &qr);
        qn = build_rev_pkt(qp, 42000, 0x12, NULL, 0);
        d2k_session_packet(q, qp, qn, 20 * ms, qb, sizeof qb, &qr);

        uint8_t qh[512];
        size_t qhl = build_hello(qh);
        qn = build_pkt(qp, 42000, 0x18, qh, qhl);
        d2k_session_packet(q, qp, qn, 30 * ms, qb, sizeof qb, &qr);

        uint8_t sh[8] = { 0x16, 0x03, 0x03, 0x00, 0x03, 0x02, 0x00, 0x00 };
        qn = build_rev_pkt(qp, 42000, 0x18, sh, sizeof sh);
        d2k_session_packet(q, qp, qn, 50 * ms, qb, sizeof qb, &qr);

        CHECK(d2k_session_sweep(q, 9000 * ms) == 0, "ответивший сервер объявлен молчащим");
        d2k_session_free(q);
    }

    /* --- отказ «плана для этой цели нет» доходит до журнала и не чаще
     * одного раза на поток (ревью, пункт 3) ---------------------------------
     *
     * Раньше session.c просто выставлял out->skipped и возвращался: refuse()
     * не звался, в журнал ничего не попадало, на провод ничего не уходило —
     * единственным следом оставался счётчик в сводке d2kd. Управляющий сокет
     * — единственное, что видит контроллер, а вытеснение из таблицы планов
     * теперь штатный путь (см. d2k_plans.h): однажды выпавшая подтверждённая
     * цель терялась бы НАВСЕГДА без единого сигнала об этом.
     *
     * Ловушка, которую эта проверка обязана ловить: наивная правка звала бы
     * refuse() там же, где стоит "плана для этой цели нет", — а это условие
     * ложно совпадает с «пакет вообще не приветствие» (use остаётся NULL,
     * потому что tls.is_client_hello ложно, а не потому, что план искали и не
     * нашли). На потоке без всякого плана КАЖДЫЙ пакет после SYN подпадал бы
     * под то же условие — событие на каждый пакет вместо события на промах. */
    {
        d2k_session *g = d2k_session_new(64, 64);
        /* Ни глобального плана (d2k_session_set_plan не звался), ни записи в
           таблице планов — это и есть «плана для этой цели нет» по-настоящему. */
        uint8_t pkt[1024], buf[4096];
        d2k_result r;

        /* Мусор вместо приветствия на СВОЁМ потоке, план для которого тоже
           не встал: use == NULL здесь по причине "не приветствие", а не
           "искали план и не нашли". Событие отказа плана не обязано
           появиться ложно. */
        uint8_t junk[] = {'G', 'E', 'T', ' ', '/', '\r', '\n'};
        size_t n = build_pkt(pkt, 45000, 0x18, junk, sizeof junk);
        d2k_session_packet(g, pkt, n, 1000, buf, sizeof buf, &r);
        CHECK(count_plan_refused(g) == 0,
              "не-приветствие без всякого плана ложно засчитано отказом плана");

        /* Настоящее приветствие на ДРУГОМ потоке: d2k_plantab_find и s->plan
           оба ничего не дают — вот теперь это по-настоящему «плана для этой
           цели нет», и событие обязано дойти до журнала. */
        uint8_t hello[512];
        size_t hlen = build_hello(hello);
        n = build_pkt(pkt, 45001, 0x18, hello, hlen);
        d2k_session_packet(g, pkt, n, 2000, buf, sizeof buf, &r);
        CHECK(r.n_out == 0, "план взялся ниоткуда для цели без плана");
        size_t after_hello = count_plan_refused(g);
        CHECK(after_hello == 1,
              "отказ «плана для этой цели нет» не ушёл в журнал");

        /* Тот же поток дальше: пакет с нагрузкой, но не приветствием. После
           рукопожатия tls.is_client_hello уже не взводится вовсе — saw_hello
           взведён первым же пакетом приветствия (session.c) и держит эту
           дверь закрытой до конца потока. Событие не обязано прибавиться —
           сравниваем с after_hello, а не с литералом 1, чтобы эта проверка
           отвечала за СВОЙ факт (пакет ничего не добавил), а не дублировала
           провал предыдущей, если та уже упала. */
        uint8_t appdata[] = {0x17, 0x03, 0x03, 0x00, 0x01, 0xAA};
        n = build_pkt(pkt, 45001, 0x18, appdata, sizeof appdata);
        d2k_session_packet(g, pkt, n, 3000, buf, sizeof buf, &r);
        CHECK(count_plan_refused(g) == after_hello,
              "пакет после рукопожатия на том же потоке размножил отказ плана");

        d2k_session_free(g);
    }

    /* --- результат исполнения доезжает до контроллера ---------------------
     *
     * Разрыв, ради которого заведён этот блок (docs/decisions/0006, «Что
     * по-прежнему НЕ доказано»): APPLIED писался при ПОСТРОЕНИИ результата, до
     * отправки, и ошибка отправки его не отзывала. На живой пробе 12.09.2026
     * «sendto: Message too large» шло ОДНОВРЕМЕННО с ростом «план применён».
     * Отрицательный исход становился неотличим от неотправленного зонда.
     *
     * Проверяется тройка: (1) ключ потока и идентификатор плана доезжают до
     * точки отправки в самом результате; (2) когда все посылки ушли, журнал
     * получает «план доисполнен»; (3) когда хоть одна не ушла — «план не
     * доисполнен» с кодом причины, и поздняя удача остатка НЕ превращает это
     * обратно в «доисполнен». */
    {
        d2k_session *g = d2k_session_new(64, 64);
        d2k_plan *gp = NULL;
        CHECK(d2k_plan_load(plan_with_send_id, sizeof plan_with_send_id, &gp,
                            err, sizeof err) == 0,
              "план с идентификатором не загрузился");
        d2k_session_set_plan(g, gp);

        n = build_pkt(pkt, 46000, 0x18, hello, hlen);
        d2k_session_packet(g, pkt, n, 1000, buf, sizeof buf, &r);
        CHECK(r.n_out == 2, "план с идентификатором не дал двух посылок");
        CHECK(r.applied == 1, "результат не объявил план применённым");
        /* Ключ канонический: низкий конец пары — не обязательно клиент.
           Сверяем то, что не зависит от порядка: транспорт и оба порта. */
        CHECK(r.key.proto == 6, "в результате нет транспорта ключа потока");
        CHECK((r.key.low_port == htons16(46000) || r.key.high_port == htons16(46000)),
              "ключ потока в результате не про этот поток");
        CHECK(memcmp(r.plan_id, want_send_id, 16) == 0,
              "идентификатор плана не доехал до точки отправки");

        /* Все посылки ушли — «план доисполнен». */
        CHECK(count_kind(g, D2K_JRN_PLAN_DONE) == 0,
              "«доисполнен» записан до единой отправки");
        d2k_session_sent(g, 1100, &r.key, r.execution_id);
        CHECK(count_kind(g, D2K_JRN_PLAN_DONE) == 0,
              "«доисполнен» записан на половине посылок");
        d2k_session_sent(g, 1200, &r.key, r.execution_id);
        CHECK(count_kind(g, D2K_JRN_PLAN_DONE) == 0,
              "отправки завершены, но судьба оригинала ещё не подтверждена");
        d2k_session_sent(g, 1250, &r.key, r.execution_id);
        CHECK(count_kind(g, D2K_JRN_PLAN_DONE) == 1,
              "все посылки ушли, а «доисполнен» не записан");
        CHECK(count_kind(g, D2K_JRN_PLAN_UNSENT) == 0,
              "успешная отправка записана недоисполнением");

        d2k_session_free(g);
    }

    /* --- ДЛИНА ПОСЫЛКИ И ОБЪЯВЛЕННАЯ В НЕЙ ДЛИНА — ОДНО ЧИСЛО -----------
     *
     * Приёмка U3 просит опыт на разных опциях TCP и на перекрытии ПОЛНОГО
     * сегмента. Проверяемое утверждение здесь одно, зато оно держит всю
     * проверку предела отправки: число, по которому d2kd сверяет посылку с
     * пределом (out[].len), обязано совпадать с числом, по которому её
     * нарежет ядро (поле длины в заголовке IPv4). Разойдись они — проверка
     * предела сверяла бы не то, и EMSGSIZE приходил бы посреди исполнения,
     * где чистого выхода нет.
     *
     * Опции — NOP'ы: их содержимое не предмет опыта, предмет — смещение
     * данных, от которого зависит всё, что собирается из пакета. Нагрузка —
     * приветствие, добитое до полутора килобайт: на коротком приветствии
     * расхождение статической и настоящей длины не видно. */
    for (size_t oi = 0; oi < 3; oi++) {
        static const size_t opts[] = { 0, 12, 20 };
        static const size_t sizes[] = { 0, 700, 1400 };
        /* Свои буферы: общие на функцию рассчитаны на короткое приветствие, а
           здесь нагрузка нарочно полноразмерная, и посылок из неё выходит
           больше её самой. */
        uint8_t big[2048], bpkt[2048], bbuf[16384];
        size_t blen = build_hello_pad(big, sizes[oi]);
        d2k_session *g = d2k_session_new(64, 64);
        d2k_plan *gp = NULL;
        CHECK(d2k_plan_load(plan_owns_payload, sizeof plan_owns_payload, &gp,
                            err, sizeof err) == 0, "план для опыта с опциями");
        d2k_session_set_plan(g, gp);
        n = build_pkt_opt(bpkt, (uint16_t)(46200 + oi), 0x18, big, blen, opts[oi]);
        d2k_session_packet(g, bpkt, n, 1000, bbuf, sizeof bbuf, &r);
        CHECK(r.applied == 1, "план не применился при опциях TCP");
        CHECK(r.n_out > 0, "посылок не собралось — сверять нечего");
        for (size_t k = 0; k < r.n_out; k++) {
            const uint8_t *e = bbuf + r.out[k].off;
            CHECK(r.out[k].len >= 20, "посылка короче заголовка IPv4");
            size_t decl = (size_t)e[2] << 8 | e[3];
            CHECK(decl == r.out[k].len,
                  "объявленная длина посылки расходится с её размером — "
                  "предел отправки сверяется не по тому числу");
        }
        d2k_session_free(g);
    }

    /* --- ОБЩИЙ ИСХОД ОТКАЗА ИСПОЛНЕНИЯ (0009, U3) ----------------------
     *
     * Пять веток отказа у отправляющего вели себя по-разному: учёт повреждения
     * стоял ровно в одной, а обещание «оригинал пройдёт» не выполнялось
     * нигде — вердикт оставался DROP, и ClientHello клиента не уходил на
     * провод вовсе из-за НАШЕЙ внутренней ошибки.
     *
     * Чистый выход существует ровно в одном случае: ни один кусок нагрузки не
     * ушёл И вердикт ещё не отправлен. */
    {
        d2k_session *g = d2k_session_new(64, 64);
        d2k_plan *gp = NULL;
        CHECK(d2k_plan_load(plan_owns_payload, sizeof plan_owns_payload, &gp,
                            err, sizeof err) == 0, "план для проверки отказа");
        d2k_session_set_plan(g, gp);
        n = build_pkt(pkt, 46010, 0x18, hello, hlen);
        d2k_session_packet(g, pkt, n, 1000, buf, sizeof buf, &r);
        CHECK(r.applied == 1, "план не применился");
        d2k_key key0 = r.key;
        uint64_t exec0 = r.execution_id;

        /* Нагрузка не ушла, вердикт не отправлен — оригинал ещё наш. */
        CHECK(d2k_session_exec_failed(g, 1100, &r.key, r.plan_id, D2K_REFUSE_QUEUE,
                                      r.execution_id, 0, 0) == 1,
              "оригинал не отпущен, хотя на провод не ушло ни байта нагрузки");
        CHECK(count_kind(g, D2K_JRN_PLAN_UNSENT) == 1, "отказ не записан");

        /* Вторая неудача той же попытки не удваивает запись: «ошибка посылки,
           затем ошибка вердикта» — один несостоявшийся опыт, а не два. */
        CHECK(d2k_session_exec_failed(g, 1150, &r.key, r.plan_id, D2K_REFUSE_SEND,
                                      r.execution_id, 0, 1) == 0,
              "вердикт уже ушёл, а оригинал объявлен отпускаемым");
        CHECK(count_kind(g, D2K_JRN_PLAN_UNSENT) == 1,
              "двойной отказ одной попытки записан дважды");

        /* Защиты сняты вместе с планом: держать испорченный поток живым,
           снимая подделанный сброс, значит заставлять человека ждать таймаута
           вместо быстрой переустановки соединения клиентом. */
        CHECK(d2k_session_guards(g, &key0) == 0,
              "защиты остались на испорченном потоке");

        /* Факт повреждения записан В МОМЕНТ установления, а не при следующем
           пакете: замолчавший поток второго пакета мог бы и не прислать. */
        CHECK(count_kind(g, D2K_JRN_PLAN_DAMAGED) == 1,
              "повреждение не записано в момент установления");
        CHECK(d2k_session_exec_failed(g, 1160, &key0, r.plan_id, D2K_REFUSE_SEND,
                                      exec0, 1, 0) == 0,
              "повторный отказ той же попытки вернул «оригинал ещё наш»");
        CHECK(count_kind(g, D2K_JRN_PLAN_DAMAGED) == 1,
              "повреждение записано дважды за одну попытку");

        /* Повреждение стало НАБЛЮДАЕМЫМ: следующее приветствие того же потока
           получает именно его, а не «план уже применён». */
        /* Другой ПОРТ — тот же поток? Нет: ключ другой. Берём тот же порт,
           но проверяем через send_pending, что поток жив и это он. */
        CHECK(!d2k_session_send_pending(g, &key0, exec0),
              "после отказа поток всё ещё принимает посылки этой попытки");
        n = build_pkt(pkt, 46010, 0x18, hello, hlen);
        d2k_session_packet(g, pkt, n, 1200, buf, sizeof buf, &r);
        CHECK(r.skipped != NULL && strstr(r.skipped, "испорчен") != NULL,
              "повреждение потока не наблюдаемо — флаг остался write-only");
        d2k_session_free(g);
    }

    {
        /* План ИЗ ОДНИХ ФАЛЬШИВОК оригинал не забирает. Отказ отложенной
           посылки по такому плану поток НЕ портит: байты клиента целы, и
           единственный факт — воздействие неполно. Слишком широкая политика
           «отложенный отказ = всегда порча» этот случай завалит. */
        d2k_session *g = d2k_session_new(64, 64);
        d2k_plan *gp = NULL;
        CHECK(d2k_plan_load(plan_bytes, sizeof plan_bytes, &gp, err, sizeof err) == 0,
              "план из одних фальшивок не загрузился");
        d2k_session_set_plan(g, gp);
        n = build_pkt(pkt, 46011, 0x18, hello, hlen);
        d2k_session_packet(g, pkt, n, 1000, buf, sizeof buf, &r);
        CHECK(r.applied == 1 && r.verdict == D2K_VERDICT_ACCEPT,
              "план из одних фальшивок забрал оригинал");
        CHECK(r.first_payload == 0xFF, "у плана без нагрузки объявлен номер её посылки");

        CHECK(d2k_session_exec_failed(g, 1100, &r.key, r.plan_id, D2K_REFUSE_SEND,
                                      r.execution_id, 0, 1) == 1,
              "поток объявлен испорченным, хотя оригинал не наш и байты клиента целы");
        n = build_pkt(pkt, 46011, 0x18, hello, hlen);
        d2k_session_packet(g, pkt, n, 1200, buf, sizeof buf, &r);
        CHECK(r.skipped != NULL && strstr(r.skipped, "испорчен") == NULL,
              "целый поток объявлен испорченным");
        d2k_session_free(g);
    }

    /* A new SYN must not erase the binding of still queued old sends. */
    {
        d2k_session *g = d2k_session_new(64, 64);
        d2k_plan *gp = NULL;
        CHECK(!d2k_plan_load(plan_with_send_id, sizeof plan_with_send_id, &gp,
                            err, sizeof err), "pending SYN fixture plan");
        CHECK(!d2k_plantab_set_name(d2k_session_plans(g),
            (const uint8_t *)"hetzner.com", 11, 1, gp), "pending SYN binding");
        n = build_pkt(pkt, 46003, 0x18, hello, hlen);
        d2k_session_packet(g, pkt, n, 1000, buf, sizeof buf, &r);
        d2k_result pending = r;
        CHECK(pending.applied && pending.binding.generation,
              "pending SYN fixture did not select a binding");
        n = build_pkt(pkt, 46003, 0x02, NULL, 0);
        d2k_session_packet(g, pkt, n, 1100, buf, sizeof buf, &r);
        CHECK(!r.applied, "bare SYN unexpectedly applied a plan");
        for (size_t i = 0; i <= pending.n_out; i++)
            d2k_session_sent(g, 1200 + i, &pending.key, pending.execution_id);
        const d2k_jrn_entry *e = last_of_kind(g, D2K_JRN_PLAN_DONE);
        CHECK(e && e->execution_id == pending.execution_id &&
              !memcmp(&e->binding, &pending.binding, sizeof e->binding),
              "new SYN erased the binding of pending execution DONE");
        d2k_session_free(g);
    }

    /* One 5-tuple may be reused while old delayed packets still exist. */
    {
        d2k_session *g = d2k_session_new(64, 64);
        d2k_plan *gp = NULL;
        CHECK(d2k_plan_load(plan_with_send_id, sizeof plan_with_send_id, &gp,
                            err, sizeof err) == 0, "план для повторного ключа");
        CHECK(!d2k_plantab_set_name(d2k_session_plans(g),
            (const uint8_t *)"hetzner.com", 11, 1, gp), "bound execution fixture");
        n = build_pkt(pkt, 46002, 0x18, hello, hlen);
        d2k_session_packet(g, pkt, n, 1000, buf, sizeof buf, &r);
        uint64_t old = r.execution_id;
        d2k_key key = r.key;
        n = build_pkt(pkt, 46002, 0x11, NULL, 0);
        d2k_session_packet(g, pkt, n, 1100, buf, sizeof buf, &r);
        n = build_pkt(pkt, 46002, 0x18, hello, hlen);
        d2k_session_packet(g, pkt, n, 1200, buf, sizeof buf, &r);
        d2k_binding_context selected = r.binding;
        CHECK(selected.generation && selected.kind == D2K_BIND_NAME,
              "execution lost selected binding identity");
        d2k_plan *replacement = NULL;
        CHECK(!d2k_plan_load(plan_with_send_id, sizeof plan_with_send_id, &replacement,
                            err, sizeof err), "same-hash replacement fixture");
        CHECK(!d2k_plantab_set_name(d2k_session_plans(g),
            (const uint8_t *)"hetzner.com", 11, 1201, replacement), "same-hash replace while sends pending");
        d2k_binding_context current = {0};
        CHECK(d2k_plantab_binding(d2k_session_plans(g), replacement, &current) &&
              current.generation != selected.generation, "replacement has a new generation");
        CHECK(r.applied && r.execution_id != old, "повторный поток наследовал номер исполнения");
        CHECK(!d2k_session_send_pending(g, &key, old), "старый пакет разрешён к отправке");
        d2k_session_sent(g, 1300, &key, old);
        d2k_session_unsent(g, 1301, &key, NULL, D2K_REFUSE_SEND, old);
        CHECK(d2k_session_send_pending(g, &r.key, r.execution_id), "старый отказ отменил новое исполнение");
        for (size_t i = 0; i < r.n_out; i++) {
            d2k_session_sent(g, 1400 + i, &r.key, r.execution_id);
        }
        CHECK(count_kind(g, D2K_JRN_PLAN_DONE) == 0, "чужая отправка зачтена новому потоку");
        d2k_session_sent(g, 1500, &r.key, r.execution_id);
        const d2k_jrn_entry *e = last_of_kind(g, D2K_JRN_PLAN_DONE);
        CHECK(e && memcmp(e->plan_id, want_send_id, 16) == 0, "DONE потерял ID плана");
        CHECK(e && e->execution_id == r.execution_id &&
              e->binding.generation == selected.generation && e->binding.generation != current.generation,
              "late DONE borrowed the replacement binding instead of its snapshot");
        d2k_session_free(g);
    }

    /* Отказ отправки: «план не доисполнен» с кодом, и поздняя удача остатка
       не отменяет отказ. Отдельная сессия — иначе счётчики предыдущей
       смешались бы с этими. */
    {
        d2k_session *g = d2k_session_new(64, 64);
        d2k_plan *gp = NULL;
        CHECK(d2k_plan_load(plan_with_send_id, sizeof plan_with_send_id, &gp,
                            err, sizeof err) == 0,
              "план с идентификатором не загрузился (вторая сессия)");
        d2k_session_set_plan(g, gp);

        n = build_pkt(pkt, 46001, 0x18, hello, hlen);
        d2k_session_packet(g, pkt, n, 1000, buf, sizeof buf, &r);
        CHECK(r.applied == 1, "план не применился во второй сессии");

        d2k_session_unsent(g, 1100, &r.key, r.plan_id, D2K_REFUSE_TOO_LONG, r.execution_id);
        CHECK(count_kind(g, D2K_JRN_PLAN_UNSENT) == 1,
              "отказ отправки не записан в журнал");
        {
            const d2k_jrn_entry *e = last_of_kind(g, D2K_JRN_PLAN_UNSENT);
            CHECK(e != NULL && e->code == D2K_REFUSE_TOO_LONG,
                  "у недоисполнения нет кода причины");
            CHECK(e != NULL && memcmp(e->plan_id, want_send_id, 16) == 0,
                  "недоисполнение не названо идентификатором плана");
            CHECK(e != NULL && e->key.proto == 6,
                  "недоисполнение не названо ключом потока");
        }

        /* Остаток плана уходит успешно — «доисполнен» всё равно не пишется:
           план исполнен НЕ полностью, и поздняя удача этого не меняет. */
        d2k_session_sent(g, 1200, &r.key, r.execution_id);
        d2k_session_sent(g, 1300, &r.key, r.execution_id);
        CHECK(count_kind(g, D2K_JRN_PLAN_DONE) == 0,
              "поздняя удача остатка объявила недоисполненный план доисполненным");

        d2k_session_free(g);
    }

    d2k_session_free(s);

    /* Snapshot assembly is observation, never a packet verdict/byte change.
       SNI can cross a boundary or be in the first segment. Neither case may
       publish a truncated SHAPE or duplicate the target event. */
    {
        uint8_t whole[2048], part[2100], saved[2100];
        size_t whole_len = build_hello_pad(whole, 1544);
        /* РЕЖЕМ ДО ИМЕНИ. Удержание существует ровно для куска, в котором
           имени ещё нет: когда имя в первом сегменте, план применяется к нему
           сразу и ждать остатка незачем (см. d2k_session_hold_candidate).
           Сорок байт — заведомо меньше, чем смещение server_name у любого
           приветствия: до него одних только записи, заголовка, версии и
           random больше сорока. */
        const uint32_t HEAD1 = 40;
        const size_t cuts[] = {1, 4, 8, 60, 64, 70, 1448, 1544};
        const uint8_t name[] = "hetzner.com";
        for (size_t j = 0; j < sizeof cuts / sizeof cuts[0]; j++) {
            d2k_session *g = d2k_session_new(64, 64);
            CHECK(g != NULL, "capture session allocation");
            if (!g) { continue; }
            CHECK(d2k_session_want_shape(g, name, sizeof name - 1, 6) == 0,
                  "empty capture was ready");
            size_t cut = cuts[j];
            size_t pn = build_pkt(part, 47000, 0x18, whole, cut);
            memcpy(saved, part, pn);
            d2k_session_packet(g, part, pn, 1, buf, sizeof buf, &r);
            CHECK(r.verdict == D2K_VERDICT_ACCEPT && !r.applied && !r.n_out,
                  "capture changed first packet verdict");
            CHECK(!memcmp(saved, part, pn), "capture changed first packet bytes");
            size_t got_len = 0;
            if (cut < whole_len) {
                CHECK(d2k_session_shape(g, 6, &got_len) == NULL,
                      "partial hello published as SHAPE");
                CHECK(count_kind(g, D2K_JRN_SHAPE) == 0, "partial SHAPE event");
                CHECK(count_kind(g, D2K_JRN_HELLO_NONAME) == 0,
                      "incomplete SNI was called nameless");
                pn = build_pkt(part, 47000, 0x18, whole + cut, whole_len - cut);
                wr32(part + 24, 1000 + (uint32_t)cut);
                memcpy(saved, part, pn);
                d2k_session_packet(g, part, pn, 2, buf, sizeof buf, &r);
                CHECK(r.verdict == D2K_VERDICT_ACCEPT && !r.applied && !r.n_out,
                      "capture changed tail verdict");
                CHECK(!memcmp(saved, part, pn), "capture changed tail bytes");
            }
            const uint8_t *got = d2k_session_shape(g, 6, &got_len);
            CHECK(got && got_len == whole_len && !memcmp(got, whole, whole_len),
                  "assembled snapshot differs from original hello");
            CHECK(count_kind(g, D2K_JRN_SHAPE) == 1, "expected one SHAPE event");
            CHECK(count_kind(g, D2K_JRN_HELLO_SNI) == 1, "expected one SNI event");
            CHECK(d2k_session_want_shape(g, name, sizeof name - 1, 6) == 1,
                  "full hello not available to later search");
            CHECK(d2k_session_shape(g, 17, &got_len) == NULL, "TCP polluted QUIC snapshot");
            CHECK(d2k_session_want_shape_family(g, name, sizeof name - 1, 6, 6) == 0,
                  "IPv6 request reused IPv4 snapshot");
            CHECK(d2k_session_shape_family(g, 6, 6, &got_len) == NULL,
                  "IPv6 snapshot contains IPv4 hello");
            CHECK(d2k_session_shape_family(g, 6, 4, &got_len) != NULL,
                  "IPv6 request destroyed IPv4 snapshot");
            pn = build_pkt(part, 47000, 0x18, whole, whole_len);
            d2k_session_packet(g, part, pn, 3, buf, sizeof buf, &r);
            d2k_payload_stats ps;
            d2k_session_payload_stats(g, &ps);
            CHECK(ps.capture_complete == 1, "retransmit duplicated completed capture");
            d2k_session_free(g);
        }
        /* Fast successful flows must release slots, not fill all 64 slots
           for five seconds and starve the next incomplete ClientHello. */
        {
            d2k_session *g = d2k_session_new(256, 64);
            CHECK(g != NULL, "capture pressure allocation");
            if (g) {
                for (uint16_t port = 48000; port < 48080; port++) {
                    size_t pn = build_pkt(part, port, 0x18, whole, whole_len);
                    d2k_session_packet(g, part, pn, 1, buf, sizeof buf, &r);
                }
                d2k_payload_stats ps;
                d2k_session_payload_stats(g, &ps);
                CHECK(ps.capture_complete == 80 && ps.capture_full == 0,
                      "completed captures starved new flows");
                d2k_session_free(g);
            }
        }
        {
            /* ПЕРВЫЙ СЕГМЕНТ ПРИВЕТСТВИЯ — ЗАКОННЫЙ ВХОД ПЛАНА, а вот сборка,
               завершившаяся на ХВОСТЕ, разрешением послать пересобранное
               приветствие не является: голова уже ушла на провод. */
            static const uint8_t strict_plan[] = {
                'D','2','K','P', 0,1, 0,5, 0,0, 0,8,
                0,2, 0,2, 6,1,                 /* TCP/TLS */
                1,10, 0,0,                     /* input tls-sni */
                1,0, 0,4, 0,0, 0,1,           /* split payload_start+1 */
                1,0, 0,4, 0,5, 0,0,           /* split sni_middle */
                1,8, 0,4, 0,0,5,120,           /* segment 1400 */
                1,3, 0,1, 1,                   /* reverse */
                1,5, 0,4, 0,0,46,224,          /* pace 12000 */
                1,9, 0,1, 1                    /* detect-tcp-v1 */
            };
            d2k_session *g = d2k_session_new(64, 64);
            d2k_plan *gp = NULL;
            CHECK(g != NULL, "strict capture allocation");
            CHECK(d2k_plan_load(strict_plan, sizeof strict_plan, &gp,
                                err, sizeof err) == 0, "strict capture plan parse");
            if (g && gp) {
                d2k_session_set_plan(g, gp);
                gp = NULL;
                size_t pn = build_pkt(part, 47500, 0x18, whole, 1448);
                d2k_session_packet(g, part, pn, 1, buf, sizeof buf, &r);
                /* Имя в сегменте есть — план применяется к нему, а остаток
                   уйдёт следом сам. Ждать остаток нельзя: пока сегмент лежит
                   в очереди без вердикта, ядро его не выпускает (поле
                   18.09.2026). */
                CHECK(r.applied && r.n_out > 0 && r.verdict == D2K_VERDICT_DROP,
                      "план не применён к первому сегменту составного приветствия");
                pn = build_pkt(part, 47500, 0x18, whole + 1448, whole_len - 1448);
                wr32(part + 24, 2448);
                d2k_session_packet(g, part, pn, 2, buf, sizeof buf, &r);
                CHECK(!r.applied && !r.n_out && r.verdict == D2K_VERDICT_ACCEPT,
                      "observation executed full plan on passed-through tail");
                pn = build_pkt(part, 47501, 0x18, whole, whole_len);
                d2k_session_packet(g, part, pn, 3, buf, sizeof buf, &r);
                CHECK(r.applied && r.n_out > 0 && r.verdict == D2K_VERDICT_DROP,
                      "capture prevented whole-packet plan execution");

                /* Port 80 does not turn TLS into HTTP, in either arrival order. */
                for (int tail_first = 0; tail_first < 2; tail_first++) {
                    d2k_hold *hp = d2k_hold_new();
                    d2k_hold_batch bp;
                    uint16_t port = (uint16_t)(47800 + tail_first);
                    pn = build_pkt(part, port, 0x02, NULL, 0);
                    wr16(part + 22, 80);
                    d2k_session_packet(g, part, pn, 4, buf, sizeof buf, &r);
                    for (int step = 0; step < 2; step++) {
                        int tail = step ^ tail_first;
                        pn = build_pkt(part, port, 0x18, whole + (tail ? HEAD1 : 0),
                                       tail ? whole_len - HEAD1 : HEAD1);
                        wr16(part + 22, 80); wr32(part + 24, 1001 + (tail ? HEAD1 : 0));
                        int mode = d2k_session_hold_candidate(g, part, pn);
                        if (!step) CHECK(mode == D2K_HOLD_TLS,
                            "TLS on port 80 retains TLS readiness, including tail-first");
                        int rc = d2k_hold_feed(hp, 100 + (uint32_t)step, part, pn, 5 + step,
                            d2k_session_plan_revision(g), mode, 1001, 1, hold_release, g, &bp);
                        CHECK(rc == (step ? 2 : 1), "split TLS on port 80 is assembled");
                        if (rc == 2) {
                            CHECK(bp.count == 2 && bp.len == 40 + whole_len &&
                                  !memcmp(bp.packet + 40, whole, whole_len),
                                  "TLS on port 80 preserves full assembled bytes");
                            d2k_session_packet(g, bp.packet, bp.len, 8, buf, sizeof buf, &r);
                            CHECK(r.applied, "assembled TLS on port 80 executes its TLS plan");
                        }
                    }
                    d2k_hold_flush(hp, 9, d2k_session_plan_revision(g), 1, hold_release, g);
                    d2k_hold_free(hp);
                }

                /* ХВОСТ ПРИВЕТСТВИЯ ПРИШЁЛ ПЕРВЫМ — ЕГО ТОЖЕ НАДО УДЕРЖАТЬ.
                 *
                 * Поле 17.09.2026, живая линия, зонд подтверждения d2k:
                 *   пакет 51359->443 seq=3909908605 нагрузка=146   <- ХВОСТ
                 *   пакет 51359->443 seq=3909907217 нагрузка=1388  <- голова
                 * Разница ровно 1388 — второй сегмент пришёл раньше первого.
                 *
                 * Удержание начиналось только с сегмента сразу за SYN, и хвост
                 * уходил на провод ГОЛЫМ, прямо в коробку. Потом приходила
                 * голова, заводила удержание и ждала хвоста, которого уже нет:
                 * таймаут, план не применён, рабочий обход выброшен
                 * собственным подтверждением. Сборка по смещениям у датапата
                 * есть (capture.c собирает по seq) — не хватало права НАЧАТЬ
                 * удержание не с первого куска. */
                {
                    d2k_hold *h2 = d2k_hold_new();
                    d2k_hold_batch b2;
                    CHECK(h2 != NULL, "hold allocation for out-of-order case");
                    if (h2) {
                        pn = build_pkt(part, 47503, 0x02, NULL, 0);
                        d2k_session_packet(g, part, pn, 7, buf, sizeof buf, &r);

                        /* Хвост. Записи TLS он не начинает (первый байт не 22)
                           и стоит не сразу за SYN — по прежнему правилу не
                           кандидат. */
                        pn = build_pkt(part, 47503, 0x18, whole + HEAD1, whole_len - HEAD1);
                        wr32(part + 24, 1001 + HEAD1);
                        int a2 = d2k_session_hold_candidate(g, part, pn);
                        CHECK(a2, "хвост приветствия, пришедший первым, не удержан — "
                                  "он уйдёт голым в коробку");
                        CHECK(d2k_hold_feed(h2, 90, part, pn, 8,
                                            d2k_session_plan_revision(g), a2, 1001, 1,
                                            hold_release, g, &b2) == 1,
                              "хвост не взят в удержание");

                        /* Голова. Слот уже есть, и она обязана его дособрать. */
                        pn = build_pkt(part, 47503, 0x18, whole, HEAD1);
                        wr32(part + 24, 1001);
                        CHECK(d2k_hold_feed(h2, 91, part, pn, 9,
                                            d2k_session_plan_revision(g), 0, 1001, 1,
                                            hold_release, g, &b2) == 2,
                              "приветствие не собралось из кусков, пришедших в обратном порядке");
                        CHECK(b2.count == 2,
                              "собраны не оба куска — один ушёл бы на провод без плана");
                        /* НОМЕР ПОСЛЕДОВАТЕЛЬНОСТИ — ГОЛОВЫ, А НЕ ПЕРВОГО
                           ПРИШЕДШЕГО. Содержимое собрано верно, но заголовок
                           брался у первого пришедшего пакета — у ХВОСТА. План
                           ушёл бы верными байтами на неверные позиции потока,
                           и сервер выбросил бы их как уже полученные. */
                        CHECK(rd32(b2.packet + 24) == 1001,
                              "в собранном пакете номер последовательности хвоста, а не головы");
                        d2k_hold_free(h2);
                    }
                }

                /* ТРИ КУСКА В ОБРАТНОМ ПОРЯДКЕ И ХВОСТ, НАЧИНАЮЩИЙСЯ С 0x16.
                 *
                 * Начало приветствия определялось по первому байту куска
                 * (0x16 — тип записи TLS). Это догадка по содержимому, и она
                 * неверна дважды: третий кусок, пришедший первым, головой не
                 * является, а хвост вполне может начинаться с 0x16 случайно —
                 * это просто байт данных. Начало обязано браться из известной
                 * позиции потока (сразу за SYN), а не угадываться. */
                {
                    d2k_hold *h3 = d2k_hold_new();
                    d2k_hold_batch b3;
                    CHECK(h3 != NULL, "hold allocation for permutation case");
                    if (h3) {
                        pn = build_pkt(part, 47504, 0x02, NULL, 0);
                        d2k_session_packet(g, part, pn, 10, buf, sizeof buf, &r);
                        size_t a = 600, b = 1200;   /* три куска: 0..a, a..b, b..конец */
                        int rc3 = 0;
                        /* третий */
                        pn = build_pkt(part, 47504, 0x18, whole + b, whole_len - b);
                        wr32(part + 24, (uint32_t)(1001 + b));
                        rc3 = d2k_hold_feed(h3, 92, part, pn, 11,
                                            d2k_session_plan_revision(g),
                                            d2k_session_hold_candidate(g, part, pn), 1001, 1,
                                            hold_release, g, &b3);
                        CHECK(rc3 == 1, "третий кусок, пришедший первым, не удержан");
                        /* второй */
                        pn = build_pkt(part, 47504, 0x18, whole + a, b - a);
                        wr32(part + 24, (uint32_t)(1001 + a));
                        rc3 = d2k_hold_feed(h3, 93, part, pn, 12,
                                            d2k_session_plan_revision(g), 0, 1001, 1,
                                            hold_release, g, &b3);
                        CHECK(rc3 == 1, "средний кусок не принят");
                        /* первый */
                        pn = build_pkt(part, 47504, 0x18, whole, a);
                        wr32(part + 24, 1001);
                        rc3 = d2k_hold_feed(h3, 94, part, pn, 13,
                                            d2k_session_plan_revision(g), 0, 1001, 1,
                                            hold_release, g, &b3);
                        CHECK(rc3 == 2, "три куска в обратном порядке не собрались");
                        CHECK(b3.count == 3, "собраны не все три куска");
                        CHECK(rd32(b3.packet + 24) == 1001,
                              "номер последовательности взят не у головы");
                        d2k_hold_free(h3);
                    }
                }

                /* Хвост, случайно начинающийся с 0x16. Головой он не является,
                   и принять его за голову значит собрать приветствие со
                   сдвигом — то есть отправить мусор. */
                {
                    d2k_hold *h4 = d2k_hold_new();
                    d2k_hold_batch b4;
                    CHECK(h4 != NULL, "hold allocation for 0x16 tail case");
                    if (h4) {
                        static uint8_t tricky[2048];
                        size_t tw = whole_len;
                        memcpy(tricky, whole, tw);
                        tricky[1448] = 0x16;   /* хвост теперь начинается с 0x16 */
                        pn = build_pkt(part, 47505, 0x02, NULL, 0);
                        d2k_session_packet(g, part, pn, 14, buf, sizeof buf, &r);
                        pn = build_pkt(part, 47505, 0x18, tricky + 1448, tw - 1448);
                        /* Здесь разрез свой, 1448: набор про БАЙТ 0x16 в
                           начале хвоста, а не про место имени. */
                        wr32(part + 24, 1001 + 1448);
                        int a4 = d2k_session_hold_candidate(g, part, pn);
                        int rc4 = d2k_hold_feed(h4, 95, part, pn, 15,
                                                d2k_session_plan_revision(g), a4, 1001, 1,
                                                hold_release, g, &b4);
                        CHECK(rc4 == 1, "хвост с байтом 0x16 не удержан");
                        pn = build_pkt(part, 47505, 0x18, tricky, 1448);
                        wr32(part + 24, 1001);
                        rc4 = d2k_hold_feed(h4, 96, part, pn, 16,
                                            d2k_session_plan_revision(g), 0, 1001, 1,
                                            hold_release, g, &b4);
                        CHECK(rc4 == 2,
                              "хвост с 0x16 принят за голову — приветствие собрано со сдвигом");
                        CHECK(rd32(b4.packet + 24) == 1001,
                              "номер последовательности взят у хвоста с 0x16");
                        d2k_hold_free(h4);
                    }
                }

                /* КУСКИ ПРИВЕТСТВИЯ В ЛЮБОМ ПОРЯДКЕ, И ЗАГОЛОВОК — У ГОЛОВЫ.
                 *
                 * Живая линия 18.09, зонд подтверждения d2k. На проводе оба
                 * сегмента, а в датапат попадал только первый: он уходил в
                 * удержание и ТУТ ЖЕ разбирался сессией как приветствие, на
                 * потоке взводился saw_hello — и второй кусок отсекался
                 * раньше всех проверок. Сборка не завершалась, удержание
                 * отпускало взятое по таймауту, план не применялся, и рабочий
                 * обход выбрасывался собственным подтверждением. */
                {
                    d2k_hold *h2 = d2k_hold_new();
                    d2k_hold_batch b2;
                    CHECK(h2 != NULL, "hold allocation for out-of-order case");
                    if (h2) {
                        pn = build_pkt(part, 47503, 0x02, NULL, 0);
                        d2k_session_packet(g, part, pn, 7, buf, sizeof buf, &r);

                        /* Голова уходит в удержание — и сессии НЕ отдаётся:
                           d2kd на удержанном пакете обрывает обработку
                           (hr == 1 → continue). Отдать его здесь значило бы
                           проверять поведение, которого у службы нет. */
                        pn = build_pkt(part, 47503, 0x18, whole, HEAD1);
                        wr32(part + 24, 1001);
                        int a1 = d2k_session_hold_candidate(g, part, pn);
                        CHECK(a1, "голова составного приветствия не удержана");
                        CHECK(d2k_hold_feed(h2, 90, part, pn, 8,
                                            d2k_session_plan_revision(g), a1, 1001, 1,
                                            hold_release, g, &b2) == 1,
                              "голова не взята в удержание");

                        /* Хвост. НОВОГО удержания он не открывает — попытку по
                           этому потоку уже сделала голова, и второй слот на
                           тот же поток был бы ошибкой. Но к УЖЕ открытому
                           слоту он обязан попасть: allow_start решает только
                           «заводить ли слот». */
                        pn = build_pkt(part, 47503, 0x18, whole + HEAD1, whole_len - HEAD1);
                        wr32(part + 24, 1001 + HEAD1);
                        int a2 = d2k_session_hold_candidate(g, part, pn);
                        CHECK(!a2, "хвост открыл ВТОРОЕ удержание того же потока");
                        CHECK(d2k_hold_feed(h2, 91, part, pn, 9,
                                            d2k_session_plan_revision(g), a2, 1001, 1,
                                            hold_release, g, &b2) == 2,
                              "приветствие не собралось из двух кусков");
                        CHECK(b2.count == 2,
                              "собраны не оба куска — один ушёл бы на провод без плана");
                        /* Номер последовательности — ГОЛОВЫ: верные байты на
                           неверных позициях потока сервер выбросит как уже
                           полученные. */
                        CHECK(rd32(b2.packet + 24) == 1001,
                              "в собранном пакете номер последовательности не головы");
                        d2k_hold_free(h2);
                    }
                }

                /* Тот же поток, но куски приходят В ОБРАТНОМ ПОРЯДКЕ. */
                {
                    d2k_hold *h3 = d2k_hold_new();
                    d2k_hold_batch b3;
                    CHECK(h3 != NULL, "hold allocation for reversed case");
                    if (h3) {
                        pn = build_pkt(part, 47504, 0x02, NULL, 0);
                        d2k_session_packet(g, part, pn, 10, buf, sizeof buf, &r);
                        pn = build_pkt(part, 47504, 0x18, whole + HEAD1, whole_len - HEAD1);
                        wr32(part + 24, 1001 + HEAD1);
                        int a3 = d2k_session_hold_candidate(g, part, pn);
                        CHECK(a3, "хвост, пришедший первым, не удержан — он уйдёт голым");
                        CHECK(d2k_hold_feed(h3, 92, part, pn, 11,
                                            d2k_session_plan_revision(g), a3, 1001, 1,
                                            hold_release, g, &b3) == 1,
                              "хвост не взят в удержание");
                        pn = build_pkt(part, 47504, 0x18, whole, HEAD1);
                        wr32(part + 24, 1001);
                        CHECK(d2k_hold_feed(h3, 93, part, pn, 12,
                                            d2k_session_plan_revision(g), 0, 1001, 1,
                                            hold_release, g, &b3) == 2,
                              "приветствие не собралось из кусков в обратном порядке");
                        CHECK(b3.count == 2 && rd32(b3.packet + 24) == 1001,
                              "обратный порядок: собрано не всё или номер не головы");
                        d2k_hold_free(h3);
                    }
                }

                /* КУСОК С ИМЕНЕМ НЕ УДЕРЖИВАЕТСЯ, ХОТЯ ЗАПИСЬ И НЕ ЦЕЛАЯ.
                   Ждать остаток незачем: план по имени выбирается уже сейчас.
                   А на живой линии ожидание ещё и невыполнимо — пока голова
                   без вердикта, ядро остатка не выпускает (замер 18.09,
                   «добавлено к голове=0»). */
                {
                    pn = build_pkt(part, 47511, 0x02, NULL, 0);
                    d2k_session_packet(g, part, pn, 13, buf, sizeof buf, &r);
                    pn = build_pkt(part, 47511, 0x18, whole, 1448);
                    wr32(part + 24, 1001);
                    d2k_tls_info t1;
                    d2k_tls_parse(whole, 1448, &t1);
                    CHECK(t1.have_sni && !t1.have_record_end,
                          "набор испорчен: в голове 1448 байт нет имени или запись целая");
                    CHECK(!d2k_session_hold_candidate(g, part, pn),
                          "кусок с именем ушёл в удержание — остаток за ним не выйдет");
                }

                /* НОВОЕ СОЕДИНЕНИЕ НА ТОЙ ЖЕ ПЯТЁРКЕ — НОВОЕ НАЧАЛО ПОТОКА.
                   Запись потока живёт дольше соединения: порт возвращается в
                   оборот, и следующее соединение попадает в ТУ ЖЕ ячейку. Всё,
                   что запомнено о прошлом (начало потока, приветствие было,
                   попытку удержания уже делали), к новому отношения не имеет:
                   якорь показывал бы на чужой ISN, а удержание было закрыто
                   навсегда. */
                pn = build_pkt(part, 47504, 0x02, NULL, 0);
                wr32(part + 24, 5000);
                d2k_session_packet(g, part, pn, 13, buf, sizeof buf, &r);
                pn = build_pkt(part, 47504, 0x18, whole, HEAD1);
                wr32(part + 24, 5001);
                uint32_t anc = 0;
                CHECK(d2k_session_stream_anchor(g, part, pn, &anc) && anc == 5001,
                      "новое соединение взяло начало потока от прошлого");
                CHECK(d2k_session_hold_candidate(g, part, pn),
                      "новое соединение закрыто отметками прошлого");

                /* The explicit owning path is allowed to execute the WHOLE
                   held hello, once, using its first seq/ACK and normal NAT. */
                d2k_hold *h = d2k_hold_new();
                d2k_hold_batch batch;
                CHECK(h != NULL, "owning hold allocation");
                if (h) {
                    pn = build_pkt(part, 47502, 0x02, NULL, 0);
                    d2k_session_packet(g, part, pn, 4, buf, sizeof buf, &r);
                    pn = build_pkt(part, 47502, 0x18, whole, HEAD1);
                    wr32(part + 24, 1001);
                    int allow = d2k_session_hold_candidate(g, part, pn);
                    CHECK(allow, "installed measured plan did not enable hold");
                    CHECK(d2k_hold_feed(h, 80, part, pn, 5, d2k_session_plan_revision(g),
                        allow, 0, 0, hold_release, g, &batch) == 1, "first piece not owned");
                    pn = build_pkt(part, 47502, 0x18, whole + HEAD1, whole_len - HEAD1);
                    wr32(part + 24, 1001 + HEAD1);
                    CHECK(d2k_hold_feed(h, 81, part, pn, 6, d2k_session_plan_revision(g),
                        0, 0, 0, hold_release, g, &batch) == 2, "held hello not completed");
                    CHECK(batch.count == 2 && batch.ids[0] == 80 && batch.ids[1] == 81,
                          "original ownership lost");
                    d2k_session_packet(g, batch.packet, batch.len, 7, buf, sizeof buf, &r);
                    CHECK(r.applied && r.verdict == D2K_VERDICT_DROP && r.n_out == 4,
                          "whole held disorder was not applied");
                    d2k_tls_info ti;
                    d2k_tls_parse(whole, whole_len, &ti);
                    size_t middle = ti.sni_off + ti.sni_len / 2;
                    size_t offsets[] = {middle, middle + 1400, 1, 0};
                    size_t lengths[] = {1400, whole_len - middle - 1400, middle - 1, 1};
                    for (size_t k = 0; k < r.n_out && k < 4; k++) {
                        const uint8_t *wire = buf + r.out[k].off;
                        size_t ihl = (wire[0] & 15u) * 4;
                        const uint8_t *tcp = wire + ihl;
                        size_t hdr = ihl + (tcp[12] >> 4) * 4;
                        uint8_t want_seq[4]; wr32(want_seq, 1001 + (uint32_t)offsets[k]);
                        CHECK(!memcmp(tcp + 4, want_seq, 4), "held disorder sequence differs");
                        CHECK(r.out[k].len == hdr + lengths[k] &&
                              !memcmp(wire + hdr, whole + offsets[k], lengths[k]),
                              "held disorder payload differs");
                        CHECK(r.out[k].delay_us == (k < 2 ? 0u : 12000u),
                              "held disorder timing differs");
                        d2k_session_sent(g, 8 + k, &r.key, r.execution_id);
                    }
                    size_t done = count_kind(g, D2K_JRN_PLAN_DONE);
                    CHECK(done == 0, "DONE before all originals acknowledged");
                    /* One logical acknowledgement, only AFTER both IDs. */
                    d2k_session_sent(g, 12, &r.key, r.execution_id);
                    CHECK(count_kind(g, D2K_JRN_PLAN_DONE) == done + 1,
                          "group acknowledgement failed to finish Plan");

                    /* Change/delete the installed plan while waiting: release
                       unmodified originals, no synthetic application. */
                    pn = build_pkt(part, 47503, 0x02, NULL, 0);
                    d2k_session_packet(g, part, pn, 13, buf, sizeof buf, &r);
                    pn = build_pkt(part, 47503, 0x18, whole, HEAD1);
                    wr32(part + 24, 1001);
                    allow = d2k_session_hold_candidate(g, part, pn);
                    CHECK(allow, "second hold not enabled");
                    CHECK(d2k_hold_feed(h, 82, part, pn, 14, d2k_session_plan_revision(g),
                        allow, 0, 0, hold_release, g, &batch) == 1, "revision test not held");
                    d2k_session_set_plan(g, NULL);
                    d2k_hold_flush(h, 15, d2k_session_plan_revision(g), 0, hold_release, g);
                    CHECK(hold_released == 1 && d2k_hold_next(h) == 0,
                          "plan revision did not release originals");
                    CHECK(count_kind(g, D2K_JRN_PLAN_DONE) == done + 1,
                          "rollback observation acknowledged a plan");
                    CHECK(!d2k_session_hold_candidate(g, part, pn),
                          "released head was eligible to hold again");
                    d2k_hold_free(h);
                }
                /* A probe plan never causes a different source port to be
                   held, even when SNI is still in a later segment. */
                /* Safari puts supported_versions after a large key_share:
                   SNI in the head is not sufficient to choose a shaped plan.
                   Own probes know their shape, while client traffic must wait
                   for the bounded owning assembly (never guess MODERN). */
                /* Issue #2: scenario 9 has an ECH/GREASE hello but only a
                   learned MODERN suffix, including segmented ClientHello. */
                for (int scenario = 0; scenario < 10; scenario++) {
                    uint8_t late[2048];
                    memcpy(late, whole, whole_len);
                    size_t late_len = whole_len;
                    if (scenario != 1 && scenario != 7) {
                        const uint8_t versions[] = {0,43,0,3,2,3,4};
                        size_t q = 5 + 4 + 2 + 32;
                        q += 1 + late[q];
                        q += 2 + ((size_t)late[q] << 8 | late[q + 1]);
                        q += 1 + late[q];
                        if (scenario == 4 || scenario == 5 || scenario == 8) {
                            memmove(late + q + 2 + sizeof versions, late + q + 2, late_len - q - 2);
                            memcpy(late + q + 2, versions, sizeof versions);
                        } else memcpy(late + late_len, versions, sizeof versions);
                        late_len += sizeof versions;
                        wr16(late + q, (uint16_t)(((unsigned)late[q] << 8 | late[q + 1]) + sizeof versions));
                        wr16(late + 7, (uint16_t)(((unsigned)late[7] << 8 | late[8]) + sizeof versions));
                        wr16(late + 3, (uint16_t)(((unsigned)late[3] << 8 | late[4]) + sizeof versions));
                        if (scenario == 4 || scenario >= 8) {
                            const uint8_t ech[] = {0xfe,0x0d,0,11, 0,0,1,0,1,7,0,0,0,1,42};
                            memcpy(late + late_len, ech, sizeof ech); late_len += sizeof ech;
                            wr16(late + q, (uint16_t)(((unsigned)late[q] << 8 | late[q + 1]) + sizeof ech));
                            wr16(late + 7, (uint16_t)(((unsigned)late[7] << 8 | late[8]) + sizeof ech));
                            wr16(late + 3, (uint16_t)(((unsigned)late[3] << 8 | late[4]) + sizeof ech));
                        }
                    }
                    d2k_session *v = d2k_session_new(64, 64);
                    d2k_hold *vh = d2k_hold_new();
                    CHECK(v && vh, "late TLS version fixture allocation");
                    if (!v || !vh) { d2k_session_free(v); d2k_hold_free(vh); continue; }
                    uint16_t port = (uint16_t)(47540 + scenario);
                    d2k_plan *vp = NULL;
                    if (scenario != 3) {
                        CHECK(d2k_plan_load(strict_plan, sizeof strict_plan, &vp,
                                            err, sizeof err) == 0, "late version plan parse");
                        if (scenario >= 6) {
                            CHECK(d2k_plantab_set_suffix_family(d2k_session_plans(v), name,
                                sizeof name - 1, 1, vp, scenario == 7 ? D2K_PLAN_SHAPE_LEGACY :
                                scenario == 8 ? D2K_PLAN_SHAPE_ECH_TCP : D2K_PLAN_SHAPE_MODERN, 4) == 0,
                                "fragmented learned area install");
                            CHECK(d2k_plantab_count(d2k_session_plans(v)) == 0, "area creates no exact host");
                        } else CHECK(d2k_plantab_set_name_probe(d2k_session_plans(v), name,
                            sizeof name - 1, 1, vp, scenario >= 4 ? D2K_PLAN_SHAPE_ECH_TCP : D2K_PLAN_SHAPE_MODERN,
                            scenario == 2 ? htons16(port) : 0) == 0, "late version plan install");
                    }
                    pn = build_pkt(part, port, 0x02, NULL, 0);
                    if (scenario == 2) d2k_session_packet_probe(v, part, pn, 1, buf, sizeof buf, &r);
                    else d2k_session_packet(v, part, pn, 1, buf, sizeof buf, &r);
                    d2k_tls_info prefix;
                    d2k_tls_parse(late, 1388, &prefix);
                    CHECK(prefix.have_sni && prefix.exts_truncated &&
                          prefix.is_tls13 == (scenario == 4 || scenario == 5 || scenario == 8) && !prefix.ech_offer,
                          "late TLS version not hidden in tail");
                    pn = build_pkt(part, port, 0x18, late, 1388);
                    wr32(part + 24, 1001);
                    int owns = d2k_session_hold_candidate(v, part, pn);
                    CHECK(owns == (scenario < 2 || scenario >= 4), "named partial TLS shape released or own probe held");
                    if (owns) {
                        d2k_hold_batch vb;
                        CHECK(d2k_hold_feed(vh, 100, part, pn, 2,
                            d2k_session_plan_revision(v), owns, 1001, 1,
                            hold_release, v, &vb) == 1, "ambiguous head not owned");
                        pn = build_pkt(part, port, 0x18, late + 1388, late_len - 1388);
                        wr32(part + 24, 2389);
                        CHECK(d2k_hold_feed(vh, 101, part, pn, 3,
                            d2k_session_plan_revision(v), 0, 1001, 1,
                            hold_release, v, &vb) == 2 && vb.count == 2,
                            "late version assembly lost original IDs");
                        d2k_session_packet(v, vb.packet, vb.len, 4, buf, sizeof buf, &r);
                        CHECK(r.applied == (scenario == 0 || scenario == 4 || scenario >= 6), "late version/ECH applied wrong TLS plan");
                        CHECK(scenario != 0 || r.verdict == D2K_VERDICT_DROP,
                              "assembled modern hello sent unchanged");
                        CHECK(scenario != 1 || r.verdict == D2K_VERDICT_ACCEPT,
                              "legacy hello received modern plan");
                    }
                    d2k_hold_free(vh); d2k_session_free(v);
                }
                /* ПОЛЕ 17.10.2026, LR-rx1/rx2: Chrome переставляет расширения,
                   и ECH уезжает во второй сегмент. Без планов голова идёт
                   быстрым путём с догадкой MODERN; целый снимок того же потока
                   несёт ECH, но подозрение уходило с формой 1, и контроллер
                   мерил cloudflare-ech.com обычным приветствием («проходит»,
                   покой 10 мин). Собранное целое приветствие — факт формы. */
                for (int installed = 0; installed < 2; installed++) {
                    uint8_t late[2048];
                    memcpy(late, whole, whole_len);
                    size_t late_len = whole_len;
                    const uint8_t versions[] = {0,43,0,3,2,3,4};
                    const uint8_t ech[] = {0xfe,0x0d,0,11, 0,0,1,0,1,7,0,0,0,1,42};
                    size_t q = 5 + 4 + 2 + 32;
                    q += 1 + late[q];
                    q += 2 + ((size_t)late[q] << 8 | late[q + 1]);
                    q += 1 + late[q];
                    memmove(late + q + 2 + sizeof versions, late + q + 2, late_len - q - 2);
                    memcpy(late + q + 2, versions, sizeof versions);
                    late_len += sizeof versions;
                    memcpy(late + late_len, ech, sizeof ech); late_len += sizeof ech;
                    size_t grow = sizeof versions + sizeof ech;
                    wr16(late + q, (uint16_t)(((unsigned)late[q] << 8 | late[q + 1]) + grow));
                    wr16(late + 7, (uint16_t)(((unsigned)late[7] << 8 | late[8]) + grow));
                    wr16(late + 3, (uint16_t)(((unsigned)late[3] << 8 | late[4]) + grow));
                    d2k_session *v = d2k_session_new(64, 64);
                    CHECK(v != NULL, "не выделена сессия для проверки формы ECH");
                    if (v) {
                        if (installed) {
                            d2k_plan *selected = NULL;
                            CHECK(d2k_plan_load(plan_bytes, sizeof plan_bytes, &selected,
                                               err, sizeof err) == 0, "разбор плана для позднего ECH");
                            CHECK(selected && d2k_plantab_set_name_family(d2k_session_plans(v),
                                name, sizeof name - 1, 1, selected,
                                D2K_PLAN_SHAPE_MODERN, 0, 4) == 0, "не удалось установить план MODERN для позднего ECH");
                        }
                        uint16_t port = 47560;
                        pn = build_pkt(part, port, 0x02, NULL, 0);
                        d2k_session_packet(v, part, pn, 1, buf, sizeof buf, &r);
                        pn = build_pkt(part, port, 0x18, late, 1388);
                        wr32(part + 24, 1001);
                        d2k_session_packet(v, part, pn, 2, buf, sizeof buf, &r);
                        CHECK(d2k_session_applied(v) == (unsigned)installed,
                              "план не применился к первому сегменту ECH");
                        d2k_key fk;
                        CHECK(d2k_key_make(&fk, 6, part + 12, part + 16, part + 20, part + 22) == 0,
                              "не извлечён ключ потока с фрагментированным ECH");
                        CHECK(d2k_session_client_shape(v, &fk) == D2K_PLAN_SHAPE_MODERN,
                              "первый фрагмент ECH не получил быструю предварительную форму MODERN");
                        pn = build_pkt(part, port, 0x18, late + 1388, late_len - 1388);
                        wr32(part + 24, 2389);
                        d2k_session_packet(v, part, pn, 3, buf, sizeof buf, &r);
                        CHECK(d2k_session_client_shape(v, &fk) == D2K_PLAN_SHAPE_ECH_TCP,
                              "полный ClientHello с ECH не заменил предварительную форму MODERN");
                        CHECK(d2k_session_applied(v) == (unsigned)installed && !r.applied,
                              "исправление формы ECH повторно применило план");
                        d2k_session_free(v);
                    }
                }
                CHECK(d2k_plan_load(strict_plan, sizeof strict_plan, &gp,
                                    err, sizeof err) == 0, "probe hold plan parse");
                CHECK(d2k_plantab_set_name_probe(d2k_session_plans(g), name,
                        sizeof name - 1, 30, gp, D2K_PLAN_SHAPE_LEGACY,
                        htons16(47504)) == 0, "probe hold plan install");
                gp = NULL;
                for (uint16_t port = 47504; port <= 47505; port++) {
                    pn = build_pkt(part, port, 0x02, NULL, 0);
                    d2k_session_packet_probe(g, part, pn, 31, buf, sizeof buf, &r);
                    pn = build_pkt(part, port, 0x18, whole, 1);
                    wr32(part + 24, 1001);
                    CHECK(d2k_session_hold_candidate(g, part, pn) == (port == 47504),
                          "probe hold source-port isolation failed");
                }
            }
            d2k_plan_free(gp);
            d2k_session_free(g);
        }

        /* Reset between pieces: neither FIN nor SYN can join two incarnations. */
        const uint8_t reset_flags[] = {0x11, 0x14, 0x02};
        for (size_t j = 0; j < sizeof reset_flags; j++) {
            d2k_session *g = d2k_session_new(64, 64);
            CHECK(g != NULL, "reset capture session allocation");
            if (!g) { continue; }
            d2k_session_want_shape(g, name, sizeof name - 1, 6);
            size_t pn = build_pkt(part, 47000, 0x18, whole, 1448);
            d2k_session_packet(g, part, pn, 1, buf, sizeof buf, &r);
            pn = build_pkt(part, 47000, reset_flags[j], NULL, 0);
            d2k_session_packet(g, part, pn, 2, buf, sizeof buf, &r);
            pn = build_pkt(part, 47000, 0x18, whole + 1448, whole_len - 1448);
            wr32(part + 24, 2448);
            d2k_session_packet(g, part, pn, 3, buf, sizeof buf, &r);
            size_t got_len = 0;
            CHECK(d2k_session_shape(g, 6, &got_len) == NULL, "reset mixed captures");
            d2k_session_free(g);
        }
    }

    /* --- ПРОМАХ CONNTRACK (см. пояснение у nat_stub) --------------------- */
    {
        d2k_nat_fn saved = d2k_nat_hook;
        d2k_nat_hook = nat_stub;

        /* ГОНКА: первый ответ «нет», сразу следом «есть». План обязан
           примениться — запись существует, её просто не увидели с первого
           раза. Без перепроверки здесь теряется и клиент, и зонд. */
        {
            d2k_session *g = d2k_session_new(8, 4);
            d2k_plan *gp = NULL;
            CHECK(d2k_plan_load(plan_bytes, sizeof plan_bytes, &gp, err, sizeof err) == 0,
                  "план гонки не загрузился");
            d2k_session_set_plan(g, gp);
            nat_calls = 0;
            nat_miss_first_n = 1;
            size_t nn = build_pkt(pkt, 41100, 0x18, hello, hlen);
            d2k_result rr;
            d2k_session_packet(g, pkt, nn, 1000, buf, sizeof buf, &rr);
            CHECK(rr.skipped == NULL,
                  "промах conntrack принят с первого ответа — клиент и зонд остаются без обхода");
            CHECK(rr.n_out > 0, "план не исполнен, хотя запись conntrack существует");
            CHECK(nat_calls >= 2, "перепроверки не было вовсе");
            d2k_session_free(g);
        }

        /* ЗАПИСИ ДЕЙСТВИТЕЛЬНО НЕТ: сколько ни спрашивай, ответ один. План
           обязан быть отвергнут — иначе посылки уйдут с локальным адресом
           мимо NAT, и это ровно тот дефект, ради которого проверка заведена. */
        {
            d2k_session *g = d2k_session_new(8, 4);
            d2k_plan *gp = NULL;
            CHECK(d2k_plan_load(plan_bytes, sizeof plan_bytes, &gp, err, sizeof err) == 0,
                  "план отсутствия не загрузился");
            d2k_session_set_plan(g, gp);
            nat_calls = 0;
            nat_miss_first_n = 1000;
            size_t nn = build_pkt(pkt, 41200, 0x18, hello, hlen);
            d2k_result rr;
            d2k_session_packet(g, pkt, nn, 1000, buf, sizeof buf, &rr);
            CHECK(rr.skipped != NULL,
                  "план применён без записи conntrack — посылки уйдут мимо NAT");
            CHECK(rr.n_out == 0, "посылки собраны, хотя уйдут с локальным адресом");
            /* Перепроверка не должна превращаться в бесконечный опрос: цена
               каждой — чтение таблицы в сотни строк, и платит за неё пакетный
               путь. */
            CHECK(nat_calls <= 8, "перепроверок слишком много — цена каждой чтение всей таблицы");
            d2k_session_free(g);
        }

        d2k_nat_hook = saved;
    }

    if (fails) {
        printf("ПРОВАЛОВ: %d\n", fails);
        return 1;
    }
    printf("сессия: все проверки прошли\n");
    return 0;
}
