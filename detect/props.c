/* props.c — свойства сперва, стратегия — из них.
 *
 * Перенос internal/classify/compose.go эталона (propProbes, composeFromProps,
 * runProperties).
 *
 * ЧЕМ ЭТО ОТЛИЧАЕТСЯ ОТ ПЕРЕБОРА. Раньше свойства коробки записывались как
 * побочный продукт перебора: гоняли девяносто гипотез, а из исходов задним
 * числом узнавали, что коробка умеет. Порядок был обратный правильному, и
 * держался он на том, что список отсортирован по замеренной частоте попаданий
 * — то есть на подгонке под статистику, а не на выводе.
 *
 * Здесь сперва задаются ВОПРОСЫ, по одному на свойство, а стратегия
 * СОБИРАЕТСЯ из ответов. Перебор остаётся, но уже запасным путём.
 */
#include "d2k_detect.h"

#include <stdio.h>
#include <string.h>

/* Какое поле вектора заполняет исход вопроса. В эталоне это замыкание set;
 * здесь — перечисление, потому что каждый случай записан явным литералом и
 * читать их полезнее списком, чем через указатель на функцию. */
typedef enum {
    SET_LEFT_OVERLAP,   /* проход → не терпит перекрытие; промах → терпит */
    SET_REORDER,        /* проход → не терпит порядок;     промах → терпит */
    SET_CHECKSUM,       /* ТОЛЬКО по проходу */
    SET_PARSES_L7,      /* ТОЛЬКО по проходу */
    SET_DUPLICATES,     /* ТОЛЬКО по проходу */
    SET_SYN,            /* ТОЛЬКО по проходу */
    SET_MD5,            /* ТОЛЬКО по проходу */
    SET_SEQ_WINDOW,     /* ТОЛЬКО по проходу */
    SET_TIMESTAMPS,     /* ТОЛЬКО по проходу */
    SET_OVERLAP_SNI,    /* ТОЛЬКО по проходу */
    SET_DUP_DENSE,      /* ТОЛЬКО по проходу, то же поле, что SET_DUPLICATES */
    SET_WHITE_TS        /* проход → не сверяет метку И разбирает L7 (белое имя) */
} prop_set;

typedef struct {
    const char *label;
    d2k_poison  p;
    prop_set    set;
} prop_probe;

/* СКОЛЬКО ВОПРОСОВ О СВОЙСТВАХ. Одна константа на массив, его обнуление и
   вызов: прежде число 12 стояло в четырёх местах, и добавление вопроса писало
   за границу массива молча. */
#define PROP_QUESTIONS 12

static int prop_probes(prop_probe *out, int cap)
{
    int k = 0;
    if (cap < PROP_QUESTIONS) {
        return 0;
    }
    memset(out, 0, sizeof(*out) * PROP_QUESTIONS);

    out[k].label = "перекрытие слева";
    snprintf(out[k].p.name, sizeof(out[k].p.name), "seqovl-1");
    out[k].p.seqovl = 1;
    out[k].set = SET_LEFT_OVERLAP;
    k++;

    out[k].label = "порядок сегментов";
    snprintf(out[k].p.name, sizeof(out[k].p.name), "disorder");
    out[k].p.disorder = 1;
    out[k].set = SET_REORDER;
    k++;

    /* Пишем ТОЛЬКО по проходу. Проход однозначен: коробка проглотила фальшивку
     * с битой суммой, значит сумму не сверяет. Промах объясняется и разбором
     * L7, и чем угодно ещё, поэтому поле остаётся неизмеренным. */
    out[k].label = "контрольная сумма";
    snprintf(out[k].p.name, sizeof(out[k].p.name), "badsum");
    out[k].p.badsum = 1;
    out[k].set = SET_CHECKSUM;
    k++;

    /* Сюда доходим только после промаха зонда выше: набивку коробка не взяла.
     * Если теперь взяла ПРИВЕТСТВИЕ — значит разбирает L7, а заодно доказано,
     * что сумму она не сверяет. Предусловия «ValidatesChecksum == true» здесь
     * нет: оно было тавтологией с перевёрнутым знаком и заставляло отчёт
     * печатать «разбирает протокол: да» рядом с ложным «сумму проверяет: да». */
    out[k].label = "разбор протокола";
    snprintf(out[k].p.name, sizeof(out[k].p.name), "badsum+hello");
    out[k].p.badsum = 1;
    out[k].p.decoy_hello = 1;
    out[k].set = SET_PARSES_L7;
    k++;

    out[k].label = "повтор как ретрансмит";
    snprintf(out[k].p.name, sizeof(out[k].p.name), "badsum-x2-g20");
    out[k].p.badsum = 1;
    out[k].p.repeats = 2;
    out[k].p.gap_ms = 20;
    out[k].set = SET_DUPLICATES;
    k++;

    /* ПОЛЯ, КОТОРЫЕ УЗНАВАЛ ТОЛЬКО ПЕРЕБОР (§0.1 ТЗ, 07.10.2026). По вопросу
     * на поле и БЕЗ битой суммы: с ней проход значил бы лишь «сумму не
     * сверяет» (вопрос выше), а не ответ о самом поле. IP ID отдельно не
     * спрашивается: пакет с нулевым IP ID сервер принимает — это не приём. */
    out[k].label = "сверка MD5";
    snprintf(out[k].p.name, sizeof(out[k].p.name), "md5");
    out[k].p.md5 = 1;
    out[k].set = SET_MD5;
    k++;

    out[k].label = "окно seq";
    snprintf(out[k].p.name, sizeof(out[k].p.name), "seq-out-of-window");
    out[k].p.seq_shift = -66000;
    out[k].set = SET_SEQ_WINDOW;
    k++;

    out[k].label = "метка времени";
    snprintf(out[k].p.name, sizeof(out[k].p.name), "ts");
    out[k].p.tcp_ts = 1;
    out[k].set = SET_TIMESTAMPS;
    k++;

    /* ОСИ `tcp_ts_up` И `ip_autottl` СПРАШИВАЛИСЬ ЗДЕСЬ И СНЯТЫ ПОЛЕМ.
     * Прогон 23.10.2026 `ttl-ae30825-1`: 12 провалов контроля из 56 против 10
     * у выпуска, и ни одного исполнения новых осей — все находки пути
     * «свойство» в раунде пришлись на ПЕРВЫЙ вопрос списка (`seqovl-1`), до
     * восьмого замер не дошёл ни на одной из 22 целей. Вопрос в конце списка
     * на этой линии стоит 2–4 зонда у глубоких целей и ответа не даёт.
     * Снят ВОПРОС, механизм остался: `ip_autottl` — запись языка плана
     * (REC_AUTOTTL, minexec 13), её выбирает RX-лестница для клиента без
     * метки времени (issue #7); `tcp_ts_up` — бит порчи. Вернуть вопрос,
     * когда поле покажет цель, доходящую до конца списка.
     * Регрессия: test_unreachable_axes_not_asked (detect/test_repeats.c). */

    /* Размер перекрытия не перебирается (прежде seqovl 2…681): длина —
     * до конца имени в приветствии, её задаёт run_properties по триггеру. */
    out[k].label = "перекрытие до конца имени";
    snprintf(out[k].p.name, sizeof(out[k].p.name), "seqovl-sni");
    out[k].set = SET_OVERLAP_SNI;
    k++;

    /* Порог дубликатов: вопрос выше — две копии с паузой 20 мс; здесь —
     * плотная семёрка без паузы, а не сетка 4×4 копий и пауз. */
    out[k].label = "плотная серия";
    snprintf(out[k].p.name, sizeof(out[k].p.name), "badsum-x7");
    out[k].p.badsum = 1;
    out[k].p.repeats = 7;
    out[k].set = SET_DUP_DENSE;
    k++;

    /* СОСТАВНОЙ ВОПРОС СЕМЕЙСТВА C: ECH-ПРИВЕТСТВИЕ ПОД МЕТКОЙ ВРЕМЕНИ, СЕРИЯ,
     * РАЗРЕЗ (поле 10.10.2026, разбор 2026-10-10-tcp-block-analysis.md, раздел
     * «Предложение»; уточнение владельца по ECH).
     *
     * КОРЕНЬ ДЫРЫ: коробка этих целей (rutracker.org и прочие за Cloudflare,
     * рукопожатие 0/3) поддаётся только ПРОИЗВЕДЕНИЮ множителей, а отдельные
     * вопросы «метка времени», «плотная серия», «разбор протокола» мерят каждый
     * ОТДЕЛЬНО и каждый промах. Этот вопрос мерит ВСЁ ВМЕСТЕ, одним приёмом:
     *   fake ECH-приветствие (opt->white — шаблон cloudflare-ech / fake_default_tls
     *     с ECH-расширением; коробка не читает в нём имя и не режет по нему)
     *   + poison tcpts (TS−1000, сервер отбросит по PAWS, коробка разберёт)
     *   + серия ×8 (одной копии мало — замерено полем)
     *   + split настоящего приветствия +2 (прямой порядок).
     * Это ровно рабочий plan-680fbe00 (ступень 0 RX-лестницы). Проход при
     * промахе «метки времени» значит: коробка принимает пакет со старой меткой
     * (метку не сверяет) И разбирает фальшивое ECH-приветствие (разбирает L7),
     * цепляясь за ECH-поток вместо имени. План из того же воздействия выразим
     * через мост (fake+tcpts, серия, split +2) — путь находки «свойство».
     *
     * Приманка — ECH-шаблон, а НЕ имя контроля: имя контроля коробка прочитает
     * и срежет. opt->white всегда несёт ECH-шаблон (планировщик строит его из
     * net.name либо из семени hcaptcha.com, см. core/sched.c, d2k_white_decoy_hello),
     * поэтому вопрос работает и с пустым каталогом. Задаётся ТОЛЬКО при наличии
     * ECH-приманки (opt->white). Это СЛОЙ РУКОПОЖАТИЯ; объёмный слой 16 КБ
     * (SNI-whitelist, «белое имя сети») снимает отдельный путь — RX-лестница,
     * здесь он не мерится и не предполагается снятым. Место — после «плотной
     * серии», перед «данными в SYN» (решение владельца 09.10: syndata последним). */
    out[k].label = "ECH-приветствие под меткой";
    snprintf(out[k].p.name, sizeof(out[k].p.name), "white-hello-ts");
    out[k].p.tcp_ts = 1;
    out[k].p.decoy_hello = 1;
    out[k].p.repeats = 8;    /* серия: одной копии мало (поле 10.10) */
    out[k].p.split_pos = 2;  /* разрез настоящего приветствия +2, прямой порядок */
    out[k].set = SET_WHITE_TS;
    k++;

    /* SYN precedes the observed name in a live flow. Ask all questions
     * whose successful send can become a datapath plan before syndata
     * (owner decision 09.10.2026, plan items 2–3). */
    out[k].label = "данные в SYN";
    snprintf(out[k].p.name, sizeof(out[k].p.name), "syndata");
    out[k].p.syn_data = 1;
    out[k].set = SET_SYN;
    k++;

    /* Если вопрос добавили, а константу забыли — ломаемся здесь, а не молча
       за границей массива. */
    return k <= PROP_QUESTIONS ? k : 0;
}

static void apply_set(d2k_dprops *pr, prop_set s, int ok, const d2k_poison *p)
{
    switch (s) {
    case SET_LEFT_OVERLAP:
        pr->tolerates_left_overlap = ok ? D2K_TRI_FALSE : D2K_TRI_TRUE;
        break;
    case SET_REORDER:
        pr->tolerates_reorder = ok ? D2K_TRI_FALSE : D2K_TRI_TRUE;
        break;
    case SET_CHECKSUM:
        if (ok) {
            pr->validates_checksum = D2K_TRI_FALSE;
        }
        break;
    case SET_PARSES_L7:
        if (ok) {
            pr->parses_l7 = D2K_TRI_TRUE;
            pr->validates_checksum = D2K_TRI_FALSE;
        }
        break;
    case SET_DUPLICATES:
        if (ok) {
            pr->counts_duplicates = D2K_TRI_TRUE;
        }
        break;
    case SET_SYN:
        if (ok) {
            pr->inspects_syn = D2K_TRI_FALSE;
        }
        break;
    case SET_MD5:
        if (ok) { pr->validates_md5 = D2K_TRI_FALSE; }
        break;
    case SET_SEQ_WINDOW:
        if (ok) { pr->validates_seq_window = D2K_TRI_FALSE; }
        break;
    case SET_TIMESTAMPS:
        if (ok) { pr->validates_timestamps = D2K_TRI_FALSE; }
        break;
    case SET_OVERLAP_SNI:
        if (ok) { pr->overlap_covers_sni = D2K_TRI_TRUE; }
        break;
    case SET_DUP_DENSE:
        if (ok) { pr->counts_duplicates = D2K_TRI_TRUE; }
        break;
    case SET_WHITE_TS:
        /* Проход: коробка разобрала фальшивое ECH-приветствие (разбирает L7),
         * зацепившись за ECH-поток вместо имени. Про ПОРЧУ утверждаем только
         * то, что в этом вопросе действительно было: у клиента без метки
         * времени её в зонде нет, и «метку не сверяет» по такому проходу —
         * выдумка о коробке (§2.4, замысел 2026-10-23 п. 5.2). Все выводы —
         * только по проходу. */
        if (ok) {
            pr->parses_l7 = D2K_TRI_TRUE;
            if (p && p->tcp_ts) { pr->validates_timestamps = D2K_TRI_FALSE; }
            if (p && p->badsum) { pr->validates_checksum = D2K_TRI_FALSE; }
        }
        break;
    }
}

/* runProperties задаёт вопросы и заполняет вектор. Возвращает первую
 * гипотезу, которая сама по себе сработала, если такая была. */
int d2k_run_properties(const uint8_t ip4[4], uint16_t port,
    const d2k_trigger *tr, const d2k_opts *opt, d2k_result *res, d2k_poison *hit)
{
    return d2k_run_properties_family(ip4, 4, port, tr, opt, res, hit);
}

int d2k_run_properties_family(const uint8_t *ip4, uint8_t family, uint16_t port,
                       const d2k_trigger *tr, const d2k_opts *opt,
                       d2k_result *res, d2k_poison *hit)
{
    prop_probe pp[PROP_QUESTIONS];
    int n = prop_probes(pp, PROP_QUESTIONS);
    int i, j;
    char err[160];

    for (i = 0; i < n; i++) {
        d2k_poison p = pp[i].p;
        d2k_obs *obs;
        char label[200];
        int pass = 0, done = 0, local_err = 0, got;
        int decoy_cloned = 0;

        if (d2k_detect_stopped(&opt->cancel)) {
            break;
        }
        if (d2k_opts_skipped(opt, p.name)) {
            continue;
        }
        /* ВОПРОС ЗАДАЁТСЯ КАК КЛИЕНТ (замысел 2026-10-23, п. 5.1 и 5.2).
         *
         * Порча «метка времени назад» исполнима только на потоке, который
         * метку предлагает: датапат копирует опции потока и сдвигает метку в
         * них (datapath/wire.c, профиль tcp-template-v1). Клиенту без метки
         * одиночный вопрос о метке не задаётся вовсе — его «нет» говорило бы
         * о нашем зонде, а не о коробке.
         *
         * СОСТАВНОЙ ВОПРОС СЕМЕЙСТВА C при этом НЕ ПРОПАДАЕТ, А СОБИРАЕТСЯ:
         * множители (приманка ECH, серия ×8, разрез +2) остаются, а порча
         * берётся из того, что уже измерено, — тем же правилом, которым
         * d2k_compose_from_props берёт битую сумму (пробуем, пока коробка не
         * доказала, что сумму сверяет): нечем сделать фальшивку отвергаемой
         * сервером — вопрос не задаётся, потому что приём, который примет и
         * сервер, обходом не является.
         *
         * Оговорка про «доказала» сегодня не срабатывает ни разу: TRI_TRUE в
         * validates_checksum не пишет никто — по §2.4 свойство ставится только
         * по ПРОХОДУ, а проход доказывает обратное (сумму НЕ сверяет). Условие
         * оставлено как страховка на случай, когда появится источник такого
         * доказательства; сегодня подстановка битой суммы безусловна, и это
         * безопасно: сервер такую фальшивку бракует по построению. */
        if (p.tcp_ts && !d2k_trigger_offers_ts(tr)) {
            if (pp[i].set != SET_WHITE_TS) {
                continue;
            }
            p.tcp_ts = 0;
            if (res->props.validates_checksum == D2K_TRI_TRUE) {
                continue;
            }
            p.badsum = 1;
        }
        if (pp[i].set == SET_OVERLAP_SNI) {
            /* До конца имени: без имени в приветствии вопрос не задаётся. */
            if (tr->sni_len <= 0 || tr->sni_off <= 0 ||
                (size_t)(tr->sni_off + tr->sni_len) >= tr->len) {
                continue;
            }
            p.seqovl = tr->sni_off + tr->sni_len;
        }
        if (pp[i].set == SET_WHITE_TS) {
            /* Приманка — ECH-ПРИВЕТСТВИЕ (opt->white), не имя контроля: имя
             * контроля коробка прочитает и срежет, а имя в ECH-приветствии она
             * не читает и цепляется за поток. Нет ECH-приманки — нет вопроса
             * (планировщик всегда её даёт, с пустым каталогом — семя hcaptcha.com;
             * уточнение владельца по ECH, поле 10.10.2026). */
            if (opt->white.len < 2) {
                continue;
            }
            p.decoy = opt->white.payload;
            p.decoy_len = opt->white.len;
        } else if (p.decoy_hello) {
            const d2k_trigger *d = d2k_opts_decoy(opt);
            p.decoy = d->payload;
            p.decoy_len = d->len;
            decoy_cloned = d == &opt->decoy;
        }
        /* Паузу и число копий кладём в наблюдение явно: без этого трасса
         * показывала «пауза=0мс» у зонда, который её честно выдерживает, и
         * читалась как поломка механизма. */
        /* ЯРЛЫК НАЗЫВАЕТ ТО, ЧТО УШЛО НА ПРОВОД (ревью ветки, находка 9).
         * Составной вопрос клиента без метки собран без неё: писать в трассу
         * «под меткой» значило бы назвать в журнале опыта воздействие,
         * которого не было. Имя гипотезы (p.name) при этом НЕ меняется — по
         * нему ведётся учёт заданных и пропущенных вопросов. */
        if (pp[i].set == SET_WHITE_TS && !p.tcp_ts) {
            snprintf(label, sizeof(label), "свойство:ECH-приветствие под битой суммой");
        } else if (decoy_cloned) {
            /* КАКОЙ ПРИМАНКОЙ ЗАДАН ВОПРОС — В ЗАПИСЬ ОПЫТА. Клон приветствия
             * клиента и встроенный шаблон (fallback) — разные стимулы для
             * коробки, разбирающей L7, и в журнале их обязано быть видно:
             * иначе два разных опыта выглядят одинаково (ТЗ §5). */
            snprintf(label, sizeof(label), "свойство:%s (приманка — клон клиента)",
                     pp[i].label);
        } else {
            snprintf(label, sizeof(label), "свойство:%s", pp[i].label);
        }
        obs = d2k_trace_add(res, label);
        obs->delay_ms = p.gap_ms;
        /* ОТВЕТ — БОЛЬШИНСТВОМ ПОВТОРОВ (поле 14.10.2026, fost.club с роутера,
         * d2k-detect с меткой замера): «ECH-приветствие под меткой» к одному
         * адресу дало 3/3, 0/1, 2/3, 1/2 — приём срабатывает в ~2 попытках из
         * 3 при любой приманке, и тот же план (680fbe00) через датапат сайт
         * открывал весь день. Прежнее единогласие с выходом на первом провале
         * делало из такого приёма «нет» в ~7 случаях из 10. Вопросы о свойствах
         * задаются при режущейся базе (0/N), так что проход приёма — эффект
         * приёма, а не случайность сервера. Повторы кончаются, как только исход
         * решён: большинство набрано или уже недостижимо. */
        for (j = 0; j < opt->repeats; j++) {
            int rc = d2k_raw_probe_poison_family(ip4, family, port, tr, &p, opt->timeout_ms, opt->mark,
                                          &opt->cancel, err, sizeof(err));
            res->probes++;
            done++;
            d2k_raw_note_rc(res, family, rc);
            if (rc < 0) {
                local_err = 1;
                /* Локальная ошибка — в трассу: иначе «0/3» читается как
                 * ответ сети, а сети зонд не достиг (поле 10.10.2026). */
                if (obs->err[0] == '\0') {
                    snprintf(obs->err, sizeof(obs->err), "%s", err);
                }
                break;
            }
            if (rc > 0) { pass++; }
            if (d2k_prop_majority(pass, opt->repeats) ||
                !d2k_prop_majority(pass + (opt->repeats - done), opt->repeats)) {
                break;
            }
        }
        if (!local_err && res->nanswered < D2K_ANSWERED_MAX) {
            res->answered[res->nanswered++] = p;
        }
        obs->pass = pass;
        obs->fail = done - pass;
        if (opt->on_obs) { opt->on_obs(opt->on_obs_ctx, obs); }
        got = d2k_prop_majority(pass, opt->repeats);
        /* A local compile/apply/send refusal is not an answer from the box. */
        if (!local_err) apply_set(&res->props, pp[i].set, got, &p);
        /* Находку, которую план не выражает (фильтр дерева, d2k_opts.accept),
         * не берём и не останавливаемся: ответ уже в векторе, а следующие
         * вопросы могут найти выразимый приём — в переборе их может не быть. */
        if (got && d2k_opts_acceptable(opt, &p)) {
            *hit = p;
            return 1;
        }
    }
    return 0;
}

static int tri_no(d2k_tri t)  { return t == D2K_TRI_FALSE; }
static int tri_yes(d2k_tri t) { return t == D2K_TRI_TRUE; }

/* composeFromProps строит кандидатов ИЗ ВЕКТОРА, а не берёт из списка.
 *
 * Правила размещения взяты из дампов боевых плеч, а не из головы: фальшивка
 * идёт отдельной посылкой ПЕРЕД перекрытием, приманкой служит целое
 * приветствие, а не огрызок, и число копий имеет порог. */
int d2k_compose_from_props(const d2k_dprops *pr, const uint8_t *ctl, size_t ctl_len,
                           d2k_poison *out, int cap)
{
    d2k_poison base;
    int n = 0, i;

    memset(&base, 0, sizeof(base));
    /* Битую сумму пробуем и когда свойство НЕ ИЗМЕРЕНО: раньше здесь стояло
     * «нет», которое при «не измерено» давало ложь и выключало единственный
     * признак, работающий на коробках, не сверяющих сумму. */
    base.badsum = !tri_yes(pr->validates_checksum);
    if (tri_yes(pr->parses_l7)) {
        base.decoy_hello = 1;
    }

    /* Дубликаты считаются как ретрансмиты — значит серия работает там, где
     * одиночная копия нет. Порог замерен: семь вплотную либо два с паузой. */
    if (tri_yes(pr->counts_duplicates) && n + 2 <= cap) {
        out[n] = base;
        snprintf(out[n].name, sizeof(out[n].name), "СОБРАНО: серия с паузой");
        out[n].repeats = 2;
        out[n].gap_ms = 20;
        n++;
        out[n] = base;
        snprintf(out[n].name, sizeof(out[n].name), "СОБРАНО: плотная серия");
        out[n].repeats = 7;
        n++;
    }

    /* Левое перекрытие не подрезается — добавляем его к фальшивке. Длину
     * берём равной приманке: в неё ложится целое приветствие. */
    if (tri_no(pr->tolerates_left_overlap) && n < cap) {
        out[n] = base;
        snprintf(out[n].name, sizeof(out[n].name), "СОБРАНО: фальшивка + перекрытие");
        out[n].seqovl_exact = 1;
        out[n].decoy_hello = 1;
        out[n].repeats = 7;
        n++;
    }

    /* Порядок не держит — добавляем сбитый порядок к тому же. */
    if (tri_no(pr->tolerates_reorder) && n < cap) {
        out[n] = base;
        snprintf(out[n].name, sizeof(out[n].name), "СОБРАНО: фальшивка + порядок");
        out[n].disorder = 1;
        out[n].repeats = 7;
        n++;
    }

    /* Ничего одиночного не сработало — пробуем всё вместе. Это последний
     * собранный кандидат перед падением в перебор. */
    if (n == 0 && cap > 0) {
        memset(&out[0], 0, sizeof(out[0]));
        snprintf(out[0].name, sizeof(out[0].name), "СОБРАНО: всё сразу");
        out[0].badsum = 1;
        out[0].decoy_hello = 1;
        out[0].seqovl_exact = 1;
        out[0].disorder = 1;
        out[0].repeats = 7;
        n = 1;
    }

    for (i = 0; i < n; i++) {
        if (out[i].decoy_hello) {
            out[i].decoy = ctl;
            out[i].decoy_len = ctl_len;
            if (out[i].seqovl_exact) {
                out[i].seqovl = (int)ctl_len;
            }
        }
    }
    return n;
}
