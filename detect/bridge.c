/* bridge.c — переходник: планировщик d2k зовёт ПЕРЕНЕСЁННЫЙ измеритель.
 *
 * ЧТО ЗДЕСЬ МЕНЯЕТСЯ ПО СУЩЕСТВУ. Прежнее дерево d2k (core/verdict.c) отвечало
 * на вопрос «какого класса блокировка» и на этом кончалось: чем именно брать
 * коробку, выяснял уже планировщик — отдельными вопросами, которые ставят план
 * командой и ждут события обмена через датапат. Перенесённый измеритель
 * отвечает на оба вопроса СРАЗУ и своими сокетами: его фаза свойств и его
 * перебор отравлений живут в том же блокирующем вызове, что и дерево. Поэтому
 * он возвращает не только вердикт, но и НАЙДЕННОЕ ПЛЕЧО (d2k_vres.have_arm).
 *
 * ПОЧЕМУ ПЕРЕХОДНИК, А НЕ ПРЯМАЯ ЗАМЕНА. Планировщик держит один крючок на
 * транспорт (d2k_sched_tcp_hook) с фиксированной сигнатурой, и её же подменяют
 * тесты, чтобы утверждать развилку по транспорту, не выходя в сеть. Ломать эту
 * точку ради переноса нельзя: тогда вместе с измерителем пришлось бы менять и
 * то, чем он проверяется.
 *
 * ЧЕГО ЗДЕСЬ НЕТ. Транспорт QUIC идёт своим путём (d2k_quic_classify) и этого
 * переходника не касается вовсе: дерево разреза потока к датаграмме
 * неприменимо — см. шапку d2k_quicprobe.h. Перенос вопросника QUIC — отдельная
 * работа, и молчать об этом нельзя: молчание читалось бы как «перенесено всё».
 */
#include "d2k_detect.h"

#include "d2k_arm.h"
#include "d2k_hello.h"
#include "d2k_verdict.h"
#include "d2k_sched.h"

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ОСТАНОВКА СЛУЖБЫ НЕ ЖДЁТ ОКОНЧАНИЯ ЗАМЕРА.
 *
 * Один зонд стоит до шести секунд, полный перебор — десятки минут, и всё это
 * время служба не выходила по сигналу: главный цикл флаг видел, а join
 * рабочего потока досиживал замер до конца. Стенд транзита 17.09 повис на
 * `wait` ровно так.
 *
 * Флаг взводится один раз и не снимается: см. требование липкости в шапке
 * d2k_detect.h — на нём держится пометка «замер брошен». */
static volatile sig_atomic_t g_stop_all;

void d2k_detect_stop_all(void) { g_stop_all = 1; }

/* Две причины бросить, и обе обязаны читаться: флаг ЭТОЙ задачи (у неё истёк
 * срок) и общий флаг остановки службы. Задачный важнее по смыслу — чужой
 * замер от чужого срока бросать нельзя, — но проверяются оба. */
static int stop_asked(void *ctx)
{
    const volatile sig_atomic_t *task_stop = ctx;
    if (g_stop_all) { return 1; }
    return task_stop && *task_stop;
}

/* НАХОДКА, КОТОРУЮ НЕЛЬЗЯ ПОСТАВИТЬ, ДЛЯ ПЛАНА — НЕ НАХОДКА.
 *
 * Поле 04.10, чистый каталог: rutracker.org и discord.com. Перебор отрав
 * дошёл до «oob» (срочный байт), коробка его взяла — и перебор на этом
 * кончился. Языком плана URG не выражается (d2k_arm_from_poison), поиск
 * принадлежит замеру, и итог — «кандидатов 0», цель отдыхает, хотя
 * следующие гипотезы того же списка, которые датапат исполняет, так и не
 * были заданы. Фильтр находок дерева (d2k_opts.accept) ровно для этого:
 * невыразимое — «как будто не сработало», перебор идёт дальше. Это не
 * подмена похожим: следующий кандидат — тоже измеренный ответ коробки.
 * Взятое, но невыразимое, не теряется — оно названо в причине, а первое
 * из него ещё и доказывает «решает содержимое», если дальше не взяло
 * ничего (см. sched_tcp). */
typedef struct {
    char first[64];     /* d2k_poison.name */
    char why[120];      /* почему не выражается первое */
    char others[96];    /* остальные взятые невыразимые — только имена */
} unplannable;

static int plannable_hit(const d2k_poison *p, void *ctx)
{
    unplannable *u = ctx;
    d2k_arm a;
    char why[120];
    size_t n;
    if (d2k_arm_from_poison(p, &a, why, sizeof why) == 0) { return 1; }
    if (!u->first[0]) {
        snprintf(u->first, sizeof u->first, "%s", p->name);
        snprintf(u->why, sizeof u->why, "%s", why);
        return 0;
    }
    n = strlen(u->others);
    if (n + 1 < sizeof u->others) {
        snprintf(u->others + n, sizeof u->others - n, "%s«%s»", n ? ", " : "", p->name);
    }
    return 0;
}

static d2k_verdict map_verdict(d2k_verdict_t v)
{
    switch (v) {
    case D2K_DV_CLEAR:        return D2K_V_CLEAR;
    case D2K_DV_PREFIX:       return D2K_V_PREFIX;
    case D2K_DV_WHOLE_PACKET: return D2K_V_WHOLE;
    case D2K_DV_OPAQUE:       return D2K_V_OPAQUE;
    /* Отравимая коробка — это ТОТ ЖЕ класс «решает содержимое»: разрез её не
     * берёт. Отличие не в классе, а в том, что мы знаем, чем её брать, и это
     * едет отдельным полем, а не подменой вердикта. */
    case D2K_DV_POISONABLE:   return D2K_V_OPAQUE;
    case D2K_DV_ADDRESS:      return D2K_V_ADDRESS;
    case D2K_DV_RESPONSE:     return D2K_V_RESPONSE;
    case D2K_DV_UNREACHABLE:  return D2K_V_UNREACHABLE;
    case D2K_DV_FLAKY:        return D2K_V_FLAKY;
    default:                  return D2K_V_INCONCLUSIVE;
    }
}

/* Вход измерителя из аргументов крючка — общий у полного прогона и у его
 * базового вопроса. 0 — готово; -1 — мерить нечем, out заполнен. */
static int bridge_input(const char *ip, uint16_t port,
                        d2k_hello trigger, d2k_hello control, d2k_hello white,
                        uint32_t mark, int repeats,
                        uint32_t gap_us, uint32_t wait_ms,
                        const volatile sig_atomic_t *stop,
                        d2k_trigger *trp, d2k_opts *optp, char addr[96], d2k_vres *outp)
{
    size_t off = 0, len = 0;

    memset(outp, 0, sizeof(*outp));
    /* Provider capability, including early input errors: failure to start
     * the original tool must not authorize a different legacy search. */
    outp->owns_search = 1;
    memset(optp, 0, sizeof(*optp));
    memset(trp, 0, sizeof(*trp));

    if (!ip || !trigger.bytes || trigger.len < 2 || trigger.len > D2K_TRIGGER_MAX) {
        outp->verdict = D2K_V_FLAKY;
        snprintf(outp->reason, sizeof(outp->reason),
                 "мерить нечем: снятого приветствия нет или оно не по размеру");
        return -1;
    }

    /* ТРИГГЕР — СНЯТОЕ ПРИВЕТСТВИЕ, ПОБАЙТНО. Ни пересборки, ни подстановки
     * имени: форма приветствия и есть измерительный инструмент, и самодельная
     * мерила бы другую коробку, чем видит клиент (см. d2k_meas.h). */
    memcpy(trp->payload, trigger.bytes, trigger.len);
    trp->len = trigger.len;
    trp->accept = D2K_ACCEPT_SERVERHELLO;
    /* Набор опций TCP клиента — вместе с его приветствием: зонд здоровается
     * им, а не литералом (замысел 2026-10-23, п. 5.1). */
    if (trigger.tcp_known && trigger.tcp_options_len <= sizeof trp->client_tcp_options) {
        trp->client_tcp_known = 1;
        trp->client_tcp_options_len = trigger.tcp_options_len;
        if (trigger.tcp_options_len) {
            memcpy(trp->client_tcp_options, trigger.tcp_options, trigger.tcp_options_len);
        }
    }
    if (d2k_hello_sni(trp->payload, trp->len, &off, &len) == 0) {
        trp->sni_off = (int)off;
        trp->sni_len = (int)len;
        /* Имя триггера = настоящее SNI клиента (как у донора: "tls:"+sni):
         * по нему проверяется ОТВЕТНОЕ направление. IP вместо имени дал бы
         * ложное «чисто». Без SNI имени нет — ответ не проверяется. */
        if (len > 0 && len <= 253 && len <= sizeof(trp->name) - 5 && !memchr(trp->payload + off, 0, len)) {
            memcpy(trp->name, "tls:", 4);
            memcpy(trp->name + 4, trp->payload + off, len);
            trp->name[4 + len] = '\0';
        }
    }

    if (control.bytes && control.len >= 2 && control.len <= D2K_TRIGGER_MAX) {
        memcpy(optp->control.payload, control.bytes, control.len);
        optp->control.len = control.len;
        optp->control.accept = D2K_ACCEPT_TLSRECORD;
        snprintf(optp->control.name, sizeof(optp->control.name), "control");
        /* Scheduler builds this automatically (currently disk.rzd.ru).
         * Supplying bytes does NOT promise that this target serves that
         * name. Match the original's automatic ControlTrigger path: a
         * silent unvouched control cannot prove an address block. The
         * scheduler hook carries no explicit operator-vouch argument. */
        optp->control_vouched = 0;
    }
    /* ПРИМАНКА — КЛОН ПРИВЕТСТВИЯ КЛИЕНТА С БЕЗОБИДНЫМ ИМЕНЕМ.
     *
     * Документированный механизм zapret2 (bol-van, docs/manual.md):
     * `tls_client_hello_clone` «подготавливает blob… заполненный результатом
     * модификации текущего reasm», умеет операции со SNI (`sni_del`,
     * `sni_first`, `sni_snt_new`) и принимает `fallback` — блоб, который
     * копируется в результат, «если пейлоад неверного типа или невалидный».
     * Дальше этот блоб уходит телом `fake`. Мы переносили только fallback:
     * приманка всегда была чужой формой (шаблон, снятый с www.microsoft.com)
     * с безобидным именем внутри, а коробка, разбирающая L7, смотрит именно
     * В приманку.
     *
     * Имя берётся у контроля: его подбирает планировщик (белое имя сети), и
     * менять эту ось здесь нечего. Байты — снятого приветствия, и ТОЛЬКО
     * снятого: заготовка холодного старта такой же синтетикой и осталась бы.
     *
     * Отличие от документированной функции названо честно: она удаляет все
     * хосты и добавляет свой первым (`sni_del` + `sni_first`), а
     * d2k_hello_rename подменяет значение имеющегося SNI. Для приветствия с
     * одним хостом — обычного случая — это то же самое; приветствие с
     * несколькими хостами мы так не трогаем.
     *
     * Зондов не добавляется: это другой ИСТОЧНИК тех же байт в тех же
     * вопросах, а не новая ось перебора. */
    if (trigger.snapped && trigger.len > 5 && trigger.bytes[0] == 0x16 &&
        control.bytes && control.len >= 2) {
        size_t coff = 0, clen = 0;
        char benign[256];
        if (d2k_hello_sni(optp->control.payload, optp->control.len, &coff, &clen) == 0 &&
            clen > 0 && clen < sizeof benign &&
            !memchr(optp->control.payload + coff, 0, clen)) {
            size_t out_len = 0;
            memcpy(benign, optp->control.payload + coff, clen);
            benign[clen] = '\0';
            /* d2k_hello_rename работает с рукопожатием, обёртка записи своя. */
            if (d2k_hello_rename(trigger.bytes + 5, trigger.len - 5, benign,
                                 optp->decoy.payload + 5,
                                 sizeof optp->decoy.payload - 5, &out_len) == 0 &&
                out_len <= 0xffff) {
                memcpy(optp->decoy.payload, trigger.bytes, 3);
                optp->decoy.payload[3] = (uint8_t)(out_len >> 8);
                optp->decoy.payload[4] = (uint8_t)out_len;
                optp->decoy.len = out_len + 5;
                optp->decoy.accept = D2K_ACCEPT_TLSRECORD;
                snprintf(optp->decoy.name, sizeof optp->decoy.name, "clone");
            } else {
                optp->decoy.len = 0;   /* fallback, как в документации */
            }
        }
    }
    /* Белое имя сети приманкой для вопроса «приветствие под меткой» (поле
       10.10.2026): полный ClientHello-record, не имя контроля. Пусто —
       вопрос не задаётся. Планировщик строит его из подтверждённого имени. */
    if (white.bytes && white.len >= 2 && white.len <= D2K_TRIGGER_MAX) {
        memcpy(optp->white.payload, white.bytes, white.len);
        optp->white.len = white.len;
        optp->white.accept = D2K_ACCEPT_TLSRECORD;
        snprintf(optp->white.name, sizeof(optp->white.name), "white");
    }

    optp->repeats = repeats;
    optp->write_gap_ms = gap_us > 0 ? (int)(gap_us / 1000u) : 0;
    optp->timeout_ms = wait_ms > 0 ? (int)wait_ms : 0;
    /* МЕТКА — ОТ ВЫЗЫВАЮЩЕГО, а не зашитая. У z2k мимо очереди пропускает
     * 0x40000000, у d2k — своя (её задаёт --mark датапату, у владельца 0x2d).
     * Зашитая константа означала бы, что зонд идёт ЧЕРЕЗ наш же обход и мерит
     * его, а не коробку провайдера. */
    optp->mark = mark;
    optp->cancel.fn = stop_asked;
    /* const снимается намеренно и только для передачи: обратно указатель
     * читается через const-указатель внутри stop_asked, писать по нему
     * измеритель не может и не пытается. */
    optp->cancel.ctx = (void *)(uintptr_t)stop;

    snprintf(addr, 96, strchr(ip, ':') ? "[%s]:%u" : "%s:%u", ip, (unsigned)port);
    return 0;
}

/* ХОД — ПЛАНИРОВЩИКУ (задача 48). Каждый заданный вопрос с его зондами
 * уходит в d2k_sched_progress_note: полный прогон на трудной цели идёт
 * минутами, и без этого панель видит «0 зондов» и ни одного вопроса.
 * Наблюдение то же, что печатает --progress, ни на что в дереве не влияет. */
static void progress_seen(void *ctx, const d2k_obs *o)
{
    /* С ответом базы (seeded) наблюдение "whole" несёт счёт ПРОШЛОГО
       прогона, зондов в этом не было: вопрос виден, зонды — нет (задача 49:
       иначе ход обгонял итог, и карточка потом падала). */
    int *seeded_whole = ctx;
    if (seeded_whole && *seeded_whole && strcmp(o->probe, "whole") == 0) {
        *seeded_whole = 0;
        d2k_sched_progress_note(o->probe, 0, 0);
        return;
    }
    d2k_sched_progress_note(o->probe, o->pass, o->fail);
}

/* ОТВЕТЫ ВОПРОСОВ О СВОЙСТВАХ — ПЛАНИРОВЩИКУ (поле 10.10.2026). У QUIC каждый
 * вопрос лежит в d2k_vres.qtrace, и журнал печатает «вопрос «…»: N/M»; у TCP
 * трасса дерева дальше измерителя не шла, и промах вопроса «метка времени»
 * на rutracker.org пришлось выводить из порядка дерева. Копируются только
 * наблюдения «свойство:*»: база, разрез и гипотезы перебора — не вопросы о
 * свойствах. Исход: большинство повторов прошло — YES (props.c,
 * d2k_prop_majority), иначе — NO, локальная ошибка
 * зонда — UNKNOWN (сети зонд не достиг). Ярлык режется только по границе
 * символа UTF-8 (r-73.1). */
static void trace_questions(const d2k_result *res, int repeats, d2k_vres *out)
{
    static const char pfx[] = "свойство:";
    size_t qi = 0;
    int i;
    for (i = 0; i < res->ntrace && qi < D2K_QTRACE_MAX; i++) {
        const d2k_obs *o = &res->trace[i];
        d2k_quic_step *st;
        const char *label;
        size_t n;
        if (strncmp(o->probe, pfx, sizeof(pfx) - 1) != 0) { continue; }
        label = o->probe + sizeof(pfx) - 1;
        n = strlen(label);
        if (n > sizeof(st->label) - 1) {
            n = sizeof(st->label) - 1;
            while (n > 0 && ((unsigned char)label[n] & 0xC0) == 0x80) { n--; }
        }
        st = &out->qtrace[qi++];
        memcpy(st->label, label, n);
        st->label[n] = '\0';
        st->sent = (uint8_t)(o->pass + o->fail > 255 ? 255 : o->pass + o->fail);
        st->answered = (uint8_t)(o->pass > 255 ? 255 : o->pass);
        st->outcome = o->err[0] ? D2K_PROP_UNKNOWN
                    : d2k_prop_majority(o->pass, repeats) ? D2K_PROP_YES : D2K_PROP_NO;
    }
}

/* A dial timeout says nothing about the trigger. The full pass gets one
 * fresh baseline measurement (its existing repeat count), not a replay of
 * this transient transport failure. Local errors/cancellation are not retried. */
static int retry_base_timeout(const char *err) {
    return err && !strncmp(err, "dial tcp ", 9) && strstr(err, ": i/o timeout") != NULL;
}

/* Полный прогон; seed — ответ уже заданного базового вопроса тем же входом
 * (d2k_opts.seed_whole), NULL — прогон спрашивает базу сам. */
static d2k_vres sched_tcp(const char *ip, uint16_t port,
                          d2k_hello trigger, d2k_hello control, d2k_hello white,
                          uint32_t mark, int repeats,
                          uint32_t gap_us, uint32_t wait_ms,
                          const volatile sig_atomic_t *stop, const d2k_base_seed *seed)
{
    d2k_vres out;
    d2k_opts opt;
    d2k_trigger tr;
    d2k_result res;
    char addr[96];

    if (bridge_input(ip, port, trigger, control, white, mark, repeats, gap_us, wait_ms, stop,
                     &tr, &opt, addr, &out) != 0) {
        return out;
    }
    if (seed && seed->valid && !retry_base_timeout(seed->err)) {
        opt.seed_whole = 1;
        opt.seed_repeats = seed->repeats;
        opt.seed_pass = seed->pass;
        opt.seed_fail = seed->fail;
        snprintf(opt.seed_err, sizeof(opt.seed_err), "%s", seed->err);
    }
    int seeded_whole = opt.seed_whole;
    opt.on_obs = progress_seen;
    opt.on_obs_ctx = &seeded_whole;
    unplannable refused;
    memset(&refused, 0, sizeof refused);
    opt.accept = plannable_hit;
    opt.accept_ctx = &refused;
    d2k_classify_run(addr, &tr, &opt, &res);

    if (res.stopped) {
        /* БРОШЕННЫЙ ЗАМЕР НЕ ВЫДАЁТСЯ ЗА ИЗМЕРЕННЫЙ. Дерево пройдено не до
         * конца, и любой его вердикт утверждал бы больше, чем известно:
         * «чисто» сняло бы рабочий план, «режут адрес» закрыло бы цель. */
        out.verdict = D2K_V_INCONCLUSIVE;
        snprintf(out.reason, sizeof(out.reason),
                 "замер брошен по требованию остановки на %d-м зонде — о цели не сказано ничего",
                 res.probes);
        out.probes = res.probes;
        return out;
    }
    out.verdict = map_verdict(res.verdict);
    out.dial_deadline = res.dial_deadline;
    trace_questions(&res, opt.repeats, &out);
    out.split_gap_us = (uint32_t)opt.write_gap_ms * 1000u;
    snprintf(out.reason, sizeof(out.reason), "%.*s", (int)sizeof(out.reason) - 1, res.reason);
    out.split_pos = res.split_pos;
    out.probes = res.probes;
    /* Socket-only split diagnostics remain useful on unsupported hosts, but
       cannot arm a packet program that the measurement never executed. */
    if ((res.verdict == D2K_DV_PREFIX || res.verdict == D2K_DV_WHOLE_PACKET) &&
        d2k_raw_dial_count() == res.raw_dial_base) {
        out.verdict = D2K_V_FLAKY;
        out.split_pos = 0;
        snprintf(out.reason, sizeof out.reason,
                 "разрез проверен только записями сокета — общий пакетный исполнитель не участвовал");
        return out;
    }
    if (refused.first[0]) {
        size_t n;
        if (!res.has_hit) {
            /* Ни одной выразимой находки после невыразимой: взятая отрава
             * всё равно доказала, что решает содержимое, — тот же вердикт и
             * та же строка, что прежде давала она сама; молчание контроля
             * этого не отменяет. */
            out.verdict = D2K_V_OPAQUE;
            snprintf(out.reason, sizeof(out.reason),
                     "поток пересобирается, но буфер травится: коробка глотает «%s», "
                     "сервер выбрасывает", refused.first);
        }
        n = strlen(out.reason);
        snprintf(out.reason + n, sizeof(out.reason) - n,
                 "; приём «%s» сработал, но планом не задаётся: %s%s%s", refused.first,
                 refused.why, refused.others[0] ? "; также " : "", refused.others);
    }
    /* СЫРОЙ СЛОЙ НЕ ПОДНЯЛСЯ — ПОИСКА НЕ БЫЛО. Самопроверка не прошла ни
     * разу: отравление не проверено вовсе, и «решает содержимое» без плеча
     * — не итог поиска, а своя поломка (D2K_SPEC §9 п.9: локальная ошибка не
     * свойство DPI). Владеть поиском, которого не было, нельзя: иначе
     * планировщик снимает цель как «обойти нечем», хотя вопросы о свойствах
     * через датапат задать ещё можно. */
    if (res.raw_selftest_failed && !res.has_hit) {
        out.owns_search = 0;
    }
    /* ЯДЕРНЫЙ RST НЕ ПОДАВЛЕН — ПУСТОЙ ПОИСК НИЧЕГО НЕ ДОКАЗАЛ. Роутер без
     * iptables (только nft): правило не встало, самопроверка — одно
     * рукопожатие — проходит, а каждый зонд отравления обрывает RST нашего же
     * ядра. Ровно это вырождение донор описал (замер 04.09): «содержимое
     * важно, брать нечем» на любом домене. Находка остаётся находкой; пустой
     * итог — локальное ограничение, им владеть нельзя. */
    /* Счётчики — потока этого прогона (ревью detect, I1): отказ вставки в
     * соседнем рабочем потоке сюда не попадает, а пометка ставится, только
     * если прогон сам ходил сырым слоем. */
    if (d2k_raw_rst_fail_count() != res.rst_fail_base &&
        d2k_raw_dial_count() != res.raw_dial_base && !res.has_hit) {
        /* Пометка — В НАЧАЛО: причина вердикта ограничена D2K_REASON_MAX, и
         * приписка в хвост срезалась бы первой, а она здесь главное. */
        static const char note[] =
            "ядерный RST не подавлен (нет правила iptables) — пустой поиск "
            "недостоверен, локальное ограничение; ";
        size_t room = sizeof(out.reason) - (sizeof(note) - 1) - 1;
        size_t keep = strlen(res.reason);
        if (keep > room) { keep = room; }
        out.owns_search = 0;
        memcpy(out.reason, note, sizeof(note) - 1);
        memcpy(out.reason + sizeof(note) - 1, res.reason, keep);
        out.reason[sizeof(note) - 1 + keep] = '\0';
    }
    /* Метку измеритель ставит всегда и на всех сокетах, но ПОДТВЕРЖДЕНИЯ, что
     * ядро её приняло, у него нет — в отличие от d2k_meas с его крючком. Врать
     * «подтверждена» нельзя: на непомеченном зонде «обходить нечего» было бы
     * самоподтверждающимся (см. d2k_verdict.h). */
    out.marked = 0;
    if (res.has_hit) {
        char why[160];
        int converted = d2k_arm_from_poison(&res.hit, &out.arm, why, sizeof(why));
        if (converted == 0 && (res.hit.decoy_len > sizeof out.arm_input.decoy ||
                              (res.hit.decoy_len && !res.hit.decoy))) {
            snprintf(why, sizeof why, "приманку найденного приёма нельзя сохранить целиком");
            converted = -1;
        }
        if (converted == 0) {
            out.arm_input.trigger_len = tr.len;
            out.arm_input.sni_off = (size_t)tr.sni_off;
            out.arm_input.sni_len = (size_t)tr.sni_len;
            out.arm_input.decoy_len = res.hit.decoy_len;
            if (res.hit.decoy_len) {
                memcpy(out.arm_input.decoy, res.hit.decoy, res.hit.decoy_len);
            }
            snprintf(out.arm_name, sizeof(out.arm_name), "%s", res.hit.name);
            snprintf(out.arm_path, sizeof(out.arm_path), "%s", res.path);
            out.have_arm = 1;
        } else {
            /* Молчать об этом нельзя: иначе «плана нет» читается как «коробку
             * не взяли», а коробку как раз взяли — не выразили. */
            size_t n = strlen(out.reason);
            snprintf(out.reason + n, sizeof(out.reason) - n,
                     "; приём «%s» сработал, но планом не задаётся: %s", res.hit.name, why);
        }
    }
    return out;
}

/* Крючок планировщика. Сигнатура — d2k_sched_tcp_fn, менять её нельзя. */
d2k_vres d2k_detect_sched_tcp(const char *ip, uint16_t port,
                              d2k_hello trigger, d2k_hello control,
                              uint32_t mark, int repeats,
                              uint32_t gap_us, uint32_t wait_ms,
                              const volatile sig_atomic_t *stop)
{
    d2k_hello none = {0};
    return sched_tcp(ip, port, trigger, control, none, mark, repeats, gap_us, wait_ms, stop, NULL);
}

/* Тот же прогон, но с белым именем сети приманкой (d2k_sched_tcp_white_fn,
   поле 10.10.2026): планировщик зовёт его, когда имя подобрано. */
d2k_vres d2k_detect_sched_tcp_white(const char *ip, uint16_t port,
                                    d2k_hello trigger, d2k_hello control, d2k_hello white,
                                    uint32_t mark, int repeats,
                                    uint32_t gap_us, uint32_t wait_ms,
                                    const volatile sig_atomic_t *stop)
{
    return sched_tcp(ip, port, trigger, control, white, mark, repeats, gap_us, wait_ms, stop, NULL);
}

/* Тот же прогон с ответом базового вопроса (d2k_sched_tcp_seeded_fn). */
d2k_vres d2k_detect_sched_tcp_seeded(const char *ip, uint16_t port,
                                     d2k_hello trigger, d2k_hello control,
                                     uint32_t mark, int repeats,
                                     uint32_t gap_us, uint32_t wait_ms,
                                     const volatile sig_atomic_t *stop,
                                     const d2k_base_seed *seed)
{
    d2k_hello none = {0};
    return sched_tcp(ip, port, trigger, control, none, mark, repeats, gap_us, wait_ms, stop, seed);
}

/* Тот же прогон С ОТВЕТОМ БАЗЫ И ECH-ПРИМАНКОЙ (d2k_sched_tcp_seeded_white_fn,
   поле 10.10.2026). У целей семейства C профильный замер идёт SEEDED (снятыми
   байтами клиента), и без этого крючка приманка туда не доходила — составной
   ECH-вопрос не задавался. sched_tcp уже умеет и seed, и white сразу. */
d2k_vres d2k_detect_sched_tcp_seeded_white(const char *ip, uint16_t port,
                                           d2k_hello trigger, d2k_hello control,
                                           d2k_hello white, uint32_t mark, int repeats,
                                           uint32_t gap_us, uint32_t wait_ms,
                                           const volatile sig_atomic_t *stop,
                                           const d2k_base_seed *seed)
{
    return sched_tcp(ip, port, trigger, control, white, mark, repeats, gap_us, wait_ms, stop, seed);
}

/* БАЗОВЫЙ ВОПРОС ДОНОРА ОТДЕЛЬНО (задача 32 d2k, d2k_sched_tcp_base_hook).
 *
 * Не новый зонд «по мотивам», а тот же d2k_classify_run, остановленный на
 * границе сразу после первого вопроса: триггер целиком, одной записью, теми
 * же повторами, тем же критерием прохода. Наблюдение "whole" отдаётся
 * on_obs, и с этой минуты просьба бросить взведена — следующий вопрос
 * дерева бросается до первого зонда. Ответное направление не спрашивается
 * (имя триггера пусто), сырой слой не поднимается: это вопросы полного
 * прогона, и он задаст их сам, если до него дойдёт.
 *
 * base_blocked — ни одного прохода из всех повторов и ни одной ошибки
 * транспорта: блокировка на рукопожатии подтверждена. Это не вердикт дерева
 * и в него не идёт: полный прогон потом спрашивает базу заново. */
typedef struct {
    const volatile sig_atomic_t *task_stop;
    int base_done;
} base_ctx;

static void base_seen(void *ctx, const d2k_obs *o)
{
    progress_seen(NULL, o);
    if (strcmp(o->probe, "whole") == 0) { ((base_ctx *)ctx)->base_done = 1; }
}

static int base_stop(void *ctx)
{
    const base_ctx *b = ctx;
    return b->base_done || stop_asked((void *)(uintptr_t)b->task_stop);
}

/* ПЕРЕПРОВЕРКА МЁРТВОГО АДРЕСА (задача 54, fix round 1 I2): тот же вопрос,
 * что в дереве (neutral-ack), но отдельно и ПЕРВЫМ — до любого триггера.
 * До первого подтверждения из repeats (умолчание измерителя); тишина на всех
 * — 0, подтверждение — 1, локальная ошибка/ненаблюдаемо/отмена — -1.
 * probes — сколько соединений стоил вопрос. */
int d2k_detect_sched_tcp_ack(const char *ip, uint16_t port, uint32_t mark,
                             const volatile sig_atomic_t *stop, int *probes)
{
    d2k_opts opt;
    char ports[16], err[160];
    int i;
    if (probes) { *probes = 0; }
    if (!ip || !ip[0] || port == 0) { return -1; }
    memset(&opt, 0, sizeof opt);
    d2k_opts_defaults(&opt);
    opt.mark = mark;
    opt.cancel.fn = stop_asked;
    opt.cancel.ctx = (void *)(uintptr_t)stop;
    snprintf(ports, sizeof ports, "%u", (unsigned)port);
    for (i = 0; i < opt.repeats; i++) {
        int rc;
        if (stop_asked((void *)(uintptr_t)stop)) { return -1; }
        err[0] = '\0';
        rc = d2k_probe_data_ack(ip, ports, &opt, err, sizeof err);
        if (rc == -2) { return -1; }
        if (probes) { (*probes)++; }
        if (rc < 0) { return -1; }
        if (rc > 0) { return 1; }
    }
    return 0;
}

d2k_vres d2k_detect_sched_tcp_base(const char *ip, uint16_t port,
                                   d2k_hello trigger, d2k_hello control,
                                   uint32_t mark, int repeats,
                                   uint32_t gap_us, uint32_t wait_ms,
                                   const volatile sig_atomic_t *stop)
{
    d2k_vres out;
    d2k_opts opt;
    d2k_trigger tr;
    d2k_result res;
    char addr[96];
    base_ctx bc;
    d2k_hello none = {0};

    if (bridge_input(ip, port, trigger, control, none, mark, repeats, gap_us, wait_ms, stop,
                     &tr, &opt, addr, &out) != 0) {
        return out;
    }
    tr.name[0] = '\0';
    opt.no_raw = 1;
    bc.task_stop = stop;
    bc.base_done = 0;
    opt.cancel.fn = base_stop;
    opt.cancel.ctx = &bc;
    opt.on_obs = base_seen;
    opt.on_obs_ctx = &bc;
    d2k_classify_run(addr, &tr, &opt, &res);

    const d2k_obs *b = res.ntrace > 0 && strcmp(res.trace[0].probe, "whole") == 0
                       ? &res.trace[0] : NULL;
    int asked = b ? b->pass + b->fail : 0;
    out.probes = asked;
    if (b && res.repeats > 0 && asked >= res.repeats && !retry_base_timeout(b->err)) {
        /* Вопрос задан целиком — его ответ годится полному прогону. */
        out.base.valid = 1;
        out.base.repeats = res.repeats;
        out.base.pass = b->pass;
        out.base.fail = b->fail;
        snprintf(out.base.err, sizeof(out.base.err), "%s", b->err);
    }
    if (!b) {
        /* До зонда не дошло: цель не разобрана (вердикт дерева тот же). */
        out.verdict = map_verdict(res.verdict);
        snprintf(out.reason, sizeof(out.reason), "%.300s", res.reason);
    } else if (asked < res.repeats || res.repeats <= 0) {
        out.verdict = D2K_V_INCONCLUSIVE;
        snprintf(out.reason, sizeof(out.reason),
                 "базовый вопрос брошен по требованию остановки — о цели не сказано ничего");
    } else if (b->err[0] && b->pass == 0) {
        out.verdict = D2K_V_UNREACHABLE;
        snprintf(out.reason, sizeof(out.reason), "нет TCP до цели: %.300s", b->err);
    } else if (b->pass == res.repeats) {
        out.verdict = D2K_V_CLEAR;
        snprintf(out.reason, sizeof(out.reason),
                 "база проходит: %d из %d (только базовый вопрос)", b->pass, res.repeats);
    } else if (b->pass > 0) {
        out.verdict = D2K_V_FLAKY;
        snprintf(out.reason, sizeof(out.reason),
                 "база не воспроизводится: %d прошло из %d", b->pass, res.repeats);
    } else {
        out.verdict = D2K_V_INCONCLUSIVE;
        out.base_blocked = 1;
        snprintf(out.reason, sizeof(out.reason),
                 "база не проходит: 0 из %d — триггер целиком режется", res.repeats);
    }
    return out;
}
