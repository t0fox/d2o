/* Contract tests for the production scheduler adapter, without network.
 * The classifier itself is exercised by test_tree; here its input/output
 * is intercepted so a correct classifier cannot hide a broken adapter. */
#include "d2k_detect.h"
#include "d2k_verdict.h"
#include <stdio.h>
#include <string.h>

/* Объявление обязано совпадать с bridge.c: без последнего параметра (stop)
   x86-64 передавал мусор из регистра, и мост падал (CI 06.10.2026). */
d2k_vres d2k_detect_sched_tcp(const char *, uint16_t, d2k_hello, d2k_hello,
                             uint32_t, int, uint32_t, uint32_t,
                             const volatile sig_atomic_t *);
d2k_vres d2k_detect_sched_tcp_base(const char *, uint16_t, d2k_hello, d2k_hello,
                                  uint32_t, int, uint32_t, uint32_t,
                                  const volatile sig_atomic_t *);
d2k_vres d2k_detect_sched_tcp_seeded(const char *, uint16_t, d2k_hello, d2k_hello,
                                    uint32_t, int, uint32_t, uint32_t,
                                    const volatile sig_atomic_t *, const d2k_base_seed *);
int d2k_arm_from_poison(const d2k_poison *, d2k_arm *, char *, size_t);
int d2k_detect_sched_tcp_ack(const char *, uint16_t, uint32_t,
                             const volatile sig_atomic_t *, int *);

static d2k_opts seen;
static const char *const *sweep_pass;
static d2k_result answer;
static int failures;
static char seen_name[D2K_TRIGGER_NAME_MAX];
static int rule_failed;
static int base_stop_before, base_stop_other, base_stop_after;

/* raw.o is not linked here: the adapter only asks whether the kernel-RST
 * suppression rule ever failed in this process. */
unsigned long d2k_raw_rst_fail_count(void) { return (unsigned long)rule_failed; }
/* Сырые соединения потока: по умолчанию прогон ходил сырым слоем. */
static int dialled = 1;
unsigned long d2k_raw_dial_count(void) { return (unsigned long)dialled; }

/* Ход измерителя (задача 48): sched.o здесь не линкуется, приёмник
 * планировщика подменён записью вызовов. */
static int progress_calls, progress_probes;
static char progress_last[160];
void d2k_sched_progress_note(const char *question, int pass, int fail)
{
    progress_calls++;
    progress_probes += pass + fail;
    snprintf(progress_last, sizeof progress_last, "%s", question);
}
static void progress_reset(void)
{
    progress_calls = progress_probes = 0;
    progress_last[0] = '\0';
}
#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "bridge:%d: %s\n", __LINE__, #c); failures++; \
} } while (0)

/* Задача 54: нейтральный байт подменён сценарием по вызовам. */
static const char *ack_pat = "-";
static int ack_calls;
static char ack_host[64], ack_port[16];
static uint32_t ack_mark;
static int ack_timeout;
void d2k_opts_defaults(d2k_opts *o)
{
    if (o->repeats <= 0) o->repeats = 3;
    if (o->timeout_ms <= 0) o->timeout_ms = 6000;
}
int d2k_probe_data_ack(const char *host, const char *port, const d2k_opts *opt,
                       char *err, size_t errcap)
{
    size_t n = strlen(ack_pat);
    char c = ack_pat[(size_t)ack_calls < n ? (size_t)ack_calls : n - 1];
    ack_calls++;
    snprintf(ack_host, sizeof ack_host, "%s", host);
    snprintf(ack_port, sizeof ack_port, "%s", port);
    ack_mark = opt->mark;
    ack_timeout = opt->timeout_ms;
    if (c == 'e') { snprintf(err, errcap, "dial"); return -1; }
    if (c == 'u') { snprintf(err, errcap, "unobservable"); return -2; }
    return c == '+' ? 1 : 0;
}

void d2k_classify_run(const char *addr, const d2k_trigger *tr,
                      d2k_opts *opt, d2k_result *res)
{
    CHECK(strcmp(addr, "192.0.2.1:443") == 0);
    CHECK(tr->len >= 2 && tr->payload[0] == 0x16);
    snprintf(seen_name, sizeof seen_name, "%s", tr->name);
    seen = *opt;
    *res = answer;
    /* ПЕРЕБОР ОТРАВ НАСТОЯЩЕГО СПИСКА (поле 04.10, rutracker.org/discord.com).
       Коробка «глотает» гипотезы из sweep_pass; дерево идёт по d2k_poisons()
       в его порядке и, как classify.c, отдаёт первую единогласную находку,
       которую принял фильтр opt->accept. */
    if (sweep_pass) {
        int n, i, k;
        const d2k_poison *l = d2k_poisons(&n);
        res->has_hit = 0;
        /* Худший исход дерева без находки: контроль молчит, без поручительства. */
        res->verdict = D2K_DV_INCONCLUSIVE;
        snprintf(res->reason, sizeof res->reason,
                 "контроль не ответил и отравить не удалось: базы нет");
        for (i = 0; i < n && !res->has_hit; i++) {
            for (k = 0; sweep_pass[k]; k++) {
                if (strcmp(sweep_pass[k], l[i].name)) continue;
                if (opt->accept && !opt->accept(&l[i], opt->accept_ctx)) break;
                res->has_hit = 1;
                res->hit = l[i];
                snprintf(res->path, sizeof res->path, "перебор");
                res->verdict = D2K_DV_POISONABLE;
                snprintf(res->reason, sizeof res->reason,
                         "поток пересобирается, но буфер травится: коробка глотает «%s», "
                         "сервер выбрасывает", l[i].name);
                break;
            }
        }
    }
    /* Базовый вопрос (задача 32): остановка взводится ровно наблюдением
       "whole" — до него дерево не бросается, после — бросается. */
    if (opt->on_obs) {
        d2k_obs other, whole;
        memset(&other, 0, sizeof other); memset(&whole, 0, sizeof whole);
        snprintf(other.probe, sizeof other.probe, "split");
        snprintf(whole.probe, sizeof whole.probe, "whole");
        other.fail = 3;
        whole.pass = 1; whole.fail = 2;
        base_stop_before = opt->cancel.fn(opt->cancel.ctx);
        opt->on_obs(opt->on_obs_ctx, &other);
        base_stop_other = opt->cancel.fn(opt->cancel.ctx);
        opt->on_obs(opt->on_obs_ctx, &whole);
        base_stop_after = opt->cancel.fn(opt->cancel.ctx);
    }
}

static size_t build_hello(uint8_t *o, const char *sni);

static d2k_vres measure_base(int pass, int fail, const char *err)
{
    uint8_t hello[300], ctl[] = {0x16, 0x03, 0x01};
    d2k_hello tr = {hello, build_hello(hello, "base.example")}, control = {ctl, sizeof ctl};
    memset(&answer, 0, sizeof answer);
    answer.verdict = D2K_DV_PREFIX; /* дальше дерево не идёт — вердикт не берётся */
    answer.repeats = 2;
    answer.ntrace = 2;
    snprintf(answer.trace[0].probe, sizeof answer.trace[0].probe, "whole");
    answer.trace[0].pass = pass;
    answer.trace[0].fail = fail;
    snprintf(answer.trace[0].err, sizeof answer.trace[0].err, "%s", err);
    snprintf(answer.trace[1].probe, sizeof answer.trace[1].probe, "split");
    base_stop_before = base_stop_other = base_stop_after = -1;
    return d2k_detect_sched_tcp_base("192.0.2.1", 443, tr, control, 0x2d, 2, 12000, 321, NULL);
}

static d2k_vres measure(void)
{
    uint8_t hello[] = {0x16, 0x03};
    uint8_t ctl[] = {0x16, 0x03, 0x01};
    d2k_hello tr = {hello, sizeof hello}, control = {ctl, sizeof ctl};
    return d2k_detect_sched_tcp("192.0.2.1", 443, tr, control,
                                0x2d, 2, 12000, 321, NULL);
}

static size_t build_hello(uint8_t *o, const char *sni)
{
    size_t n = strlen(sni), p = 0, ext = 9 + n, body = 2 + 32 + 1 + 4 + 2 + 2 + ext;
    const uint8_t a[] = {0x16, 0x03, 0x01};
    memcpy(o, a, 3); p = 3;
    o[p++] = (body + 4) >> 8; o[p++] = (body + 4) & 255;
    o[p++] = 1; o[p++] = 0; o[p++] = body >> 8; o[p++] = body & 255;
    o[p++] = 3; o[p++] = 3;
    memset(o + p, 7, 32); p += 32;
    o[p++] = 0;
    o[p++] = 0; o[p++] = 2; o[p++] = 0; o[p++] = 0x2f;
    o[p++] = 1; o[p++] = 0;
    o[p++] = ext >> 8; o[p++] = ext & 255;
    o[p++] = 0; o[p++] = 0; o[p++] = (n + 5) >> 8; o[p++] = (n + 5) & 255;
    o[p++] = (n + 3) >> 8; o[p++] = (n + 3) & 255;
    o[p++] = 0; o[p++] = n >> 8; o[p++] = n & 255;
    memcpy(o + p, sni, n); p += n;
    return p;
}

int main(void)
{
    d2k_vres r;
    d2k_arm arm;
    d2k_poison p;
    char why[160];
    {
        d2k_hello empty = {0};
        r = d2k_detect_sched_tcp("192.0.2.1", 443, empty, empty, 0x2d, 2, 12000, 321, NULL);
        CHECK(r.owns_search && !r.have_arm && r.verdict == D2K_V_FLAKY);
    }
    {
        /* The response-direction probe takes its SNI from tr.name; it must be
         * the client's name, never the address being measured. */
        uint8_t h[300], c[] = {0x16, 0x03, 0x01};
        d2k_hello tr, ctl = {c, sizeof c};
        tr.bytes = h;
        tr.len = build_hello(h, "blocked.example");
        answer.verdict = D2K_DV_INCONCLUSIVE; answer.has_hit = 0;
        d2k_detect_sched_tcp("192.0.2.1", 443, tr, ctl, 0x2d, 2, 12000, 321, NULL);
        CHECK(strcmp(seen_name, "tls:blocked.example") == 0);
        /* Real hello, no server_name extension. */
        {
            uint8_t g[300];
            size_t n = build_hello(g, "x.example");
            /* turn server_name (type 0) into an unknown extension type */
            g[n - strlen("x.example") - 9 + 0] = 0xff;
            g[n - strlen("x.example") - 9 + 1] = 0xff;
            tr.bytes = g; tr.len = n;
            seen_name[0] = 'Z';
            d2k_detect_sched_tcp("192.0.2.1", 443, tr, ctl, 0x2d, 2, 12000, 321, NULL);
            CHECK(seen_name[0] == '\0');
        }
        /* Max-length SNI is held whole. */
        {
            char big[254], want[300];
            uint8_t g[600];
            memset(big, 'a', 253); big[253] = 0;
            tr.bytes = g; tr.len = build_hello(g, big);
            seen_name[0] = 'Z';
            d2k_detect_sched_tcp("192.0.2.1", 443, tr, ctl, 0x2d, 2, 12000, 321, NULL);
            snprintf(want, sizeof want, "tls:%s", big);
            CHECK(strcmp(seen_name, want) == 0);
        }
        /* Embedded NUL: no name. */
        {
            uint8_t g[300];
            size_t n = build_hello(g, "ab.example");
            g[n - 5] = 0;
            tr.bytes = g; tr.len = n;
            seen_name[0] = 'Z';
            d2k_detect_sched_tcp("192.0.2.1", 443, tr, ctl, 0x2d, 2, 12000, 321, NULL);
            CHECK(seen_name[0] == '\0');
        }
    }
    answer.verdict = D2K_DV_INCONCLUSIVE;
    r = measure();
    CHECK(seen.control.len == 3);
    CHECK(seen.control_vouched == 0); /* automatic control != operator promise */
    CHECK(seen.mark == 0x2d && seen.repeats == 2);
    CHECK(seen.write_gap_ms == 12 && seen.timeout_ms == 321);
    CHECK(r.verdict == D2K_V_INCONCLUSIVE);
    CHECK(r.owns_search && r.split_gap_us == 12000);

    answer.verdict = D2K_DV_POISONABLE;
    answer.has_hit = 1;
    strcpy(answer.hit.name, "seqovl-1");
    answer.hit.seqovl = 1;
    r = measure();
    CHECK(r.have_arm && r.arm.seqovl == 1);
    CHECK(strcmp(r.arm_name, "seqovl-1") == 0);
    CHECK(r.arm_path[0] == '\0'); /* дерево пути не назвало — мост не выдумывает */
    /* d2k_vres is returned and repeatedly copied by value. No pointer into
     * the adapter's dead stack frame may escape with the result. */
    CHECK(r.arm.name == NULL);
    CHECK(r.arm_input.trigger_len == 2);
    {
        uint8_t decoy[] = {0xa1, 0, 0x7f};
        answer.hit.decoy = decoy;
        answer.hit.decoy_len = sizeof decoy;
        r = measure();
        decoy[0] = 0xff;
        CHECK(r.arm_input.decoy_len == 3 && r.arm_input.decoy[0] == 0xa1);
        CHECK(r.arm_input.decoy[1] == 0); /* binary, not a C string */
        d2k_vres copied = r;
        memset(&r, 0, sizeof r);
        CHECK(copied.arm_input.decoy[0] == 0xa1);
        answer.hit.decoy_len = D2K_ARM_DECOY_MAX + 1;
        r = measure();
        CHECK(!r.have_arm); /* fail before dereferencing an oversized prefix */
        answer.hit.decoy = NULL; answer.hit.decoy_len = 0;
    }

    /* A raw layer that failed its own self-check is a LOCAL defect, not a
     * DPI property (spec §9.9): the original search did not run, so the
     * adapter must not claim it, and the scheduler may ask its datapath
     * questions instead of failing the task. */
    memset(&answer, 0, sizeof answer);
    answer.verdict = D2K_DV_OPAQUE;
    answer.raw_selftest_failed = 1;
    r = measure();
    CHECK(r.verdict == D2K_V_OPAQUE && !r.have_arm && !r.owns_search);
    answer.raw_selftest_failed = 0;
    answer.raw_usable = 1;
    r = measure();
    CHECK(r.verdict == D2K_V_OPAQUE && r.owns_search); /* search ran, found nothing */
    /* nft-only router: no RST rule, the self-check (handshake only) passes,
     * every poison probe is cut by OUR kernel's RST. That empty search is a
     * local limitation (donor note 04.09), never «nothing to bypass». */
    rule_failed = 1;
    snprintf(answer.reason, sizeof answer.reason, "содержимое важно");
    r = measure();
    CHECK(r.verdict == D2K_V_OPAQUE && !r.have_arm && !r.owns_search);
    CHECK(strstr(r.reason, "RST") != NULL && strstr(r.reason, "не подавлен") != NULL);
    answer.verdict = D2K_DV_POISONABLE;
    answer.has_hit = 1;
    strcpy(answer.hit.name, "seqovl-1");
    answer.hit.seqovl = 1;
    r = measure();
    CHECK(r.have_arm && r.owns_search); /* a hit is a finished search */
    rule_failed = 0;
    memset(&answer, 0, sizeof answer);
    /* Отказ правила случился ДО этого прогона (счётчик на старте уже 1): пустой
       поиск этого прогона честный и владеет поиском — прошлый отказ не метит
       прогоны навсегда (ревью задачи 49). */
    rule_failed = 1;
    answer.rst_fail_base = 1;
    answer.raw_usable = 1;
    snprintf(answer.reason, sizeof answer.reason, "содержимое важно");
    r = measure();
    CHECK(r.owns_search && strstr(r.reason, "не подавлен") == NULL);
    rule_failed = 0;
    memset(&answer, 0, sizeof answer);
    /* Финальное ревью detect, I1: прогон, который сырым слоем не ходил вовсе,
       пометку «RST не подавлен» не получает и владения поиском не теряет —
       даже если счётчик отказов потока почему-то сдвинулся. */
    rule_failed = 1;
    dialled = 0;
    answer.raw_usable = 1;
    snprintf(answer.reason, sizeof answer.reason, "содержимое важно");
    r = measure();
    CHECK(r.owns_search && strstr(r.reason, "не подавлен") == NULL);
    rule_failed = 0;
    dialled = 1;
    memset(&answer, 0, sizeof answer);

    /* ОТВЕТЫ TCP-ВОПРОСОВ О СВОЙСТВАХ — В ТРАССУ ВЕРДИКТА (поле 10.10.2026).
       QUIC пишет каждый вопрос в qtrace, и журнал печатает «вопрос «…»: N/M»;
       у TCP трасса дерева до планировщика не доходила, и промах «метка
       времени» на rutracker.org пришлось выводить из порядка дерева.
       Копируются только вопросы о свойствах: база, разрез и гипотезы
       перебора — не вопросы о свойствах. Ярлык — целиком, не обрубок. */
    {
        answer.verdict = D2K_DV_OPAQUE;
        answer.raw_usable = 1;
        answer.repeats = 2;
        answer.ntrace = 6;
        snprintf(answer.trace[0].probe, sizeof answer.trace[0].probe, "whole");
        answer.trace[0].fail = 2;
        snprintf(answer.trace[1].probe, sizeof answer.trace[1].probe, "свойство:перекрытие слева");
        answer.trace[1].fail = 1;
        snprintf(answer.trace[2].probe, sizeof answer.trace[2].probe, "свойство:метка времени");
        answer.trace[2].pass = 2;
        snprintf(answer.trace[3].probe, sizeof answer.trace[3].probe, "свойство:сверка MD5");
        answer.trace[3].fail = 1;
        snprintf(answer.trace[3].err, sizeof answer.trace[3].err, "sendto: Operation not permitted");
        snprintf(answer.trace[4].probe, sizeof answer.trace[4].probe, "свойство:перекрытие до конца имени");
        answer.trace[4].fail = 1;
        snprintf(answer.trace[5].probe, sizeof answer.trace[5].probe, "poison:seqovl-16");
        answer.trace[5].fail = 1;
        r = measure();
        CHECK(strcmp(r.qtrace[0].label, "перекрытие слева") == 0);
        CHECK(r.qtrace[0].sent == 1 && r.qtrace[0].answered == 0 && r.qtrace[0].outcome == D2K_PROP_NO);
        CHECK(strcmp(r.qtrace[1].label, "метка времени") == 0);
        CHECK(r.qtrace[1].sent == 2 && r.qtrace[1].answered == 2 && r.qtrace[1].outcome == D2K_PROP_YES);
        CHECK(strcmp(r.qtrace[2].label, "сверка MD5") == 0);
        CHECK(r.qtrace[2].outcome == D2K_PROP_UNKNOWN); /* локальная ошибка зонда — не измерено */
        CHECK(strcmp(r.qtrace[3].label, "перекрытие до конца имени") == 0);
        CHECK(r.qtrace[4].label[0] == '\0'); /* whole и poison:* — не вопросы о свойствах */
        /* Все вопросы каталога свойств обязаны помещаться в трассу. */
        CHECK(D2K_QTRACE_MAX >= 11);
        memset(&answer, 0, sizeof answer);
    }

    /* Базовый вопрос донора отдельно (задача 32): тот же измеритель, та же
       метка/повторы/контроль, но без ответного направления и сырого слоя;
       блокировка — ни одного прохода и ни одной ошибки транспорта. */
    progress_reset();
    r = measure_base(0, 2, "");
    CHECK(r.base_blocked && r.verdict == D2K_V_INCONCLUSIVE && r.probes == 2);
    CHECK(seen_name[0] == '\0' && seen.no_raw == 1);
    CHECK(seen.mark == 0x2d && seen.repeats == 2 && seen.control.len == 3);
    CHECK(base_stop_before == 0 && base_stop_other == 0 && base_stop_after == 1);
    /* Базовый вопрос тоже отдаёт ход, не теряя своей остановки на "whole". */
    CHECK(progress_calls == 2 && progress_probes == 6 && strcmp(progress_last, "whole") == 0);
    r = measure_base(2, 0, "");
    CHECK(!r.base_blocked && r.verdict == D2K_V_CLEAR);
    r = measure_base(1, 1, "");
    CHECK(!r.base_blocked && r.verdict == D2K_V_FLAKY);
    CHECK(r.base.valid && r.base.repeats == 2 && r.base.pass == 1 && r.base.fail == 1);
    r = measure_base(0, 2, "connect: refused");
    CHECK(!r.base_blocked && r.verdict == D2K_V_UNREACHABLE);
    CHECK(r.base.valid && strcmp(r.base.err, "connect: refused") == 0);
    r = measure_base(0, 2, "dial tcp 192.0.2.1:443: i/o timeout");
    CHECK(!r.base.valid && !r.base_blocked && r.verdict == D2K_V_UNREACHABLE);
    r = measure_base(0, 2, "context canceled");
    CHECK(r.base.valid); /* no fresh measurement on local/cancel failure */
    r = measure_base(0, 1, ""); /* брошен на втором повторе */
    CHECK(!r.base_blocked && r.verdict == D2K_V_INCONCLUSIVE && !r.base.valid);
    {
        /* Полный прогон с ответом базы: подсказка доходит до измерителя. */
        uint8_t hello[] = {0x16, 0x03};
        d2k_hello tr = {hello, sizeof hello}, none = {0};
        d2k_base_seed seed;
        memset(&seed, 0, sizeof seed);
        seed.valid = 1; seed.repeats = 2; seed.pass = 0; seed.fail = 2;
        memset(&answer, 0, sizeof answer);
        answer.verdict = D2K_DV_PREFIX;
        progress_reset();
        r = d2k_detect_sched_tcp_seeded("192.0.2.1", 443, tr, none, 0x2d, 2, 12000, 321, NULL, &seed);
        CHECK(seen.seed_whole == 1 && seen.seed_repeats == 2 && seen.seed_pass == 0 &&
              seen.seed_fail == 2 && r.verdict == D2K_V_PREFIX);
        snprintf(seed.err, sizeof seed.err, "dial tcp 192.0.2.1:443: i/o timeout");
        r = d2k_detect_sched_tcp_seeded("192.0.2.1", 443, tr, none, 0x2d, 2, 12000, 321, NULL, &seed);
        CHECK(!seen.seed_whole); /* even an old valid timeout seed must be remeasured */
        snprintf(seed.err, sizeof seed.err, "context canceled");
        r = d2k_detect_sched_tcp_seeded("192.0.2.1", 443, tr, none, 0x2d, 2, 12000, 321, NULL, &seed);
        CHECK(seen.seed_whole);
        seed.err[0] = 0;
        progress_reset();
        r = d2k_detect_sched_tcp_seeded("192.0.2.1", 443, tr, none, 0x2d, 2, 12000, 321, NULL, &seed);
        /* Полный прогон отдаёт ход планировщику: каждый вопрос с его зондами. */
        CHECK(seen.on_obs != NULL);
        /* Задача 49: "whole" с ответом базы — без зондов (они прошлого прогона). */
        CHECK(progress_calls == 2 && progress_probes == 3 && strcmp(progress_last, "whole") == 0);
        progress_reset();
        r = d2k_detect_sched_tcp("192.0.2.1", 443, tr, none, 0x2d, 2, 12000, 321, NULL);
        CHECK(seen.seed_whole == 0);
        CHECK(progress_calls == 2 && progress_probes == 6 && strcmp(progress_last, "whole") == 0);
    }
    memset(&answer, 0, sizeof answer);

    memset(&p, 0, sizeof p);
    p.ttl = 8;
    CHECK(d2k_arm_from_poison(&p, &arm, why, sizeof why) == 0);
    CHECK(arm.repeats == 1 && arm.ttl == 8); /* TTL-only poison still emits a fake */
    p.ttl = 0;
    p.seq_shift = -66000;
    CHECK(d2k_arm_from_poison(&p, &arm, why, sizeof why) == 0);
    CHECK(arm.repeats == 1 && arm.seq_out);
    p.seq_shift = -123;
    CHECK(d2k_arm_from_poison(&p, &arm, why, sizeof why) != 0);
    p.seq_shift = 0;
    p.disorder = 1; p.disorder_pos = 2;
    CHECK(d2k_arm_from_poison(&p, &arm, why, sizeof why) == 0);
    CHECK(arm.disorder && arm.disorder_pos == 2);
    p.disorder = 0; p.disorder_pos = 0;
    p.syn_data = 1;
    CHECK(d2k_arm_from_poison(&p, &arm, why, sizeof why) != 0);
    p.syn_data = 0; p.oob = 1;
    /* oob БОЛЬШЕ НЕ ОТКАЗ (поле 10.10.2026): срочный байт выражается планом
       «oob sni_middle 0f» и исполняется датапатом — мост его принимает. */
    CHECK(d2k_arm_from_poison(&p, &arm, why, sizeof why) == 0);
    CHECK(arm.oob);
    p.oob = 0; p.md5 = 1;
    CHECK(d2k_arm_from_poison(&p, &arm, why, sizeof why) == 0);
    CHECK(arm.md5 && arm.repeats == 1);
    /* СЕМЕЙСТВО C ЧЕРЕЗ МОСТ (поле 10.10.2026). Составной приём замера —
       фальшивое ECH-приветствие под меткой времени, серия ×8, разрез настоящего
       приветствия +2 — ОБЯЗАН быть выразим планом: мост несёт метку времени,
       серию и ПРЯМОЙ разрез отдельным полем (split_pos), не путая его с обратным
       disorder_pos. Так находка замера становится планом plan-680fbe00, а не
       теряется как невыразимая. Падает на main до правки: там split_pos у плеча
       нет, и прямой разрез настоящего приветствия мост выразить не мог. */
    memset(&p, 0, sizeof p);
    p.tcp_ts = 1; p.decoy_hello = 1; p.repeats = 8; p.split_pos = 2;
    CHECK(d2k_arm_from_poison(&p, &arm, why, sizeof why) == 0);
    CHECK(arm.tcpts && arm.decoy_hello && arm.repeats == 8 && arm.split_pos == 2);
    CHECK(!arm.disorder && !arm.disorder_pos); /* прямой разрез, не обратный */
    {
        /* ПОЛЕ 04.10, ЧИСТЫЙ КАТАЛОГ: rutracker.org и discord.com. Перебор
           отрав дошёл до невыразимой гипотезы (теперь это syndata — oob стал
           выразим) — коробку он берёт, но планом не задаётся, — и перебор
           обязан продолжиться к следующей гипотезе, которую датапат исполнит,
           а о невыразимой — сказать в причине. */
        static const char *const box_takes[] = {"syndata", "ttl-8", NULL};
        static const char *const only_unexpr[] = {"syndata", NULL};
        static const char *const box_oob[] = {"oob", NULL};
        uint8_t h[300], c[] = {0x16, 0x03, 0x01};
        d2k_hello tr = {h, 0}, ctl = {c, sizeof c};
        tr.len = build_hello(h, "rutracker.org");
        memset(&answer, 0, sizeof answer);
        sweep_pass = box_takes;
        r = d2k_detect_sched_tcp("192.0.2.1", 443, tr, ctl, 0x2d, 2, 12000, 321, NULL);
        CHECK(seen.accept != NULL);
        CHECK(r.verdict == D2K_V_OPAQUE && r.have_arm && r.owns_search);
        CHECK(r.arm.ttl == 8 && r.arm.repeats == 1 && strcmp(r.arm_name, "ttl-8") == 0);
        CHECK(strcmp(r.arm_path, "перебор") == 0); /* §0.1: путь находки доходит до журнала */
        CHECK(strstr(r.reason, "«syndata»") != NULL && strstr(r.reason, "SYN") != NULL);
        /* oob теперь ВЫРАЗИМ: перебор берёт его как найденный план. */
        sweep_pass = box_oob;
        r = d2k_detect_sched_tcp("192.0.2.1", 443, tr, ctl, 0x2d, 2, 12000, 321, NULL);
        CHECK(r.verdict == D2K_V_OPAQUE && r.have_arm && r.owns_search);
        CHECK(r.arm.oob && strcmp(r.arm_name, "oob") == 0);
        CHECK(strcmp(r.arm_path, "перебор") == 0);
        /* Выразимого нет вовсе: плана нет, но взятая отрава всё равно
           доказала «решает содержимое» — вердикт тот же, что и до правки,
           даже если без неё дерево не нашло бы базы (контроль молчал). */
        sweep_pass = only_unexpr;
        r = d2k_detect_sched_tcp("192.0.2.1", 443, tr, ctl, 0x2d, 2, 12000, 321, NULL);
        CHECK(r.verdict == D2K_V_OPAQUE && !r.have_arm && r.owns_search);
        CHECK(strstr(r.reason, "буфер травится") != NULL);
        CHECK(strstr(r.reason, "«syndata»") != NULL);
        CHECK(strstr(r.reason, "SYN") != NULL);
        /* Счёт зондов и точка разреза доходят до планировщика (поле 04.10
           после 06cb9fd: «за 268 с и 0 зондов замера» — правка фильтра
           выронила out.probes и out.split_pos). */
        sweep_pass = NULL;
        memset(&answer, 0, sizeof answer);
        answer.verdict = D2K_DV_PREFIX; answer.split_pos = 5; answer.probes = 17;
        r = d2k_detect_sched_tcp("192.0.2.1", 443, tr, ctl, 0x2d, 2, 12000, 321, NULL);
        CHECK(r.verdict == D2K_V_PREFIX && r.split_pos == 5 && r.probes == 17);
        dialled = 0;
        r = d2k_detect_sched_tcp("192.0.2.1", 443, tr, ctl, 0x2d, 2, 12000, 321, NULL);
        CHECK(r.verdict == D2K_V_FLAKY && r.split_pos == 0 && !r.have_arm && r.owns_search);
        dialled = 1;
        memset(&answer, 0, sizeof answer);
        answer.verdict = D2K_DV_FLAKY; answer.dial_deadline = 1;
        r = d2k_detect_sched_tcp("192.0.2.1", 443, tr, ctl, 0x2d, 2, 12000, 321, NULL);
        CHECK(r.verdict == D2K_V_FLAKY && r.dial_deadline == 1);
        memset(&answer, 0, sizeof answer);
        sweep_pass = box_takes;
        r = d2k_detect_sched_tcp("192.0.2.1", 443, tr, ctl, 0x2d, 2, 12000, 321, NULL);
        CHECK(r.have_arm);
        /* Фильтр пропускает всё, что план выражает. */
        memset(&p, 0, sizeof p);
        p.badsum = 1; p.repeats = 7;
        CHECK(seen.accept(&p, seen.accept_ctx) == 1);
        sweep_pass = NULL;
        memset(&answer, 0, sizeof answer);
    }
    {
        /* Задача 54: вопрос перепроверки мёртвого адреса. */
        int probes = -1, rc;
        ack_pat = "-"; ack_calls = 0;
        rc = d2k_detect_sched_tcp_ack("192.0.2.1", 443, 0x2f, NULL, &probes);
        CHECK(rc == 0 && ack_calls == 3 && probes == 3);
        CHECK(strcmp(ack_host, "192.0.2.1") == 0 && strcmp(ack_port, "443") == 0);
        CHECK(ack_mark == 0x2f && ack_timeout > 0);
        ack_pat = "-+"; ack_calls = 0;
        rc = d2k_detect_sched_tcp_ack("2001:db8::1", 443, 0x2f, NULL, &probes);
        CHECK(rc == 1 && ack_calls == 2 && probes == 2);
        CHECK(strcmp(ack_host, "2001:db8::1") == 0);
        ack_pat = "e"; ack_calls = 0;
        rc = d2k_detect_sched_tcp_ack("192.0.2.1", 443, 0x2f, NULL, &probes);
        CHECK(rc < 0 && ack_calls == 1 && probes == 1);
        ack_pat = "u"; ack_calls = 0;
        rc = d2k_detect_sched_tcp_ack("192.0.2.1", 443, 0x2f, NULL, &probes);
        CHECK(rc < 0 && probes == 0);
        {
            volatile sig_atomic_t stop = 1;
            ack_pat = "-"; ack_calls = 0;
            rc = d2k_detect_sched_tcp_ack("192.0.2.1", 443, 0x2f, &stop, &probes);
            CHECK(rc < 0 && ack_calls == 0);
        }
    }
    if (failures) { return 1; }
    puts("bridge: scheduler adapter contracts passed");
    return 0;
}
