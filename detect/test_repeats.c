/* test_repeats.c — повторы, которые не меняют исход, не тратятся.
 *
 * Стенд: классификатор и свойства собраны в ЭТОМ же модуле (#include .c),
 * а сырой слой подменён сценарием ответов — как test_raw.c подменяет сокеты.
 * Сокетные зонды (база, разрез, контроль) идут на настоящую петлю: коробка
 * «решает по содержимому» — пропускает только контрольную нагрузку.
 *
 * Эквивалентность «до/после»: подписи вердиктов ниже СНЯТЫ с кода ДО правки
 * (те же сценарии, те же ответы, все повторы). Совпадение подписи значит, что
 * вердикт, путь, находка, стратегия и вектор свойств не изменились; меняется
 * только число зондов. */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1
#include <sys/socket.h>
#include <netdb.h>
static int transport_getaddrinfo(const char *, const char *, const struct addrinfo *, struct addrinfo **);
static int transport_setsockopt(int, int, int, const void *, socklen_t);
#define getaddrinfo transport_getaddrinfo
#define setsockopt transport_setsockopt
#define d2k_raw_probe_handshake_as     fake_handshake
#define d2k_raw_probe_poison_family    fake_poison
#define d2k_raw_supported              fake_raw_supported
#define d2k_raw_rst_fail_count         fake_rst_fail_count
/* Настоящий вопрос определён в самом classify.c, поэтому подменяется место
 * вызова, а не имя функции. */
#define D2K_DATA_ACK_PROBE             fake_data_ack
#include "classify.c"
#include "props.c"
#undef getaddrinfo
#undef setsockopt
static int transport_dns_calls, transport_fail_mark;
static int transport_getaddrinfo(const char *host, const char *port,
                                const struct addrinfo *hints, struct addrinfo **ai) {
    if (!strcmp(host, "transport-switch.test"))
        host = transport_dns_calls++ == 0 ? "127.0.0.2" : "127.0.0.1";
    return getaddrinfo(host, port, hints, ai);
}
static int transport_setsockopt(int fd, int level, int name, const void *value, socklen_t len) {
    /* Loopback tests model the Linux-only bypass mark; no host routing rule
     * or privilege is required. Other socket operations remain real. */
    if (level == SOL_SOCKET && name == SO_MARK) {
        if (transport_fail_mark) { errno = EPERM; return -1; }
        return 0;
    }
    return setsockopt(fd, level, name, value, len);
}

#include <pthread.h>

static int fails;
#define CHECK(c, ...) do { if (!(c)) { printf("  ПРОВАЛ %d: ", __LINE__); \
    printf(__VA_ARGS__); printf("\n"); fails++; } } while (0)

/* --- сценарий сырого слоя ------------------------------------------------ */
/* Шаблон: по символу на ПОВТОР одного вопроса, последний символ тянется.
 * '+' прошло, '-' нет, 'e' локальная ошибка зонда (rc<0). Счёт повторов
 * начинается заново у каждого вопроса (каждой строки трассы): один и тот же
 * вопрос, заданный дважды (свойство и затем перебор), получает одинаковые
 * ответы, а не продолжение чужого счётчика — иначе ранняя остановка сдвинула
 * бы ответы следующего вопроса и «одинаковые ответы» перестали бы быть
 * одинаковыми. */
typedef struct { const char *name; const char *pat; } script_ent;

static const script_ent *g_script;
static const char *g_default = "-";
static const char *g_selftest = "+";
static const d2k_result *g_res;   /* чей прогон идёт: номер строки трассы = вопрос */
static int g_ask = -1, g_rep;     /* текущий вопрос сырого слоя и номер его повтора */
static int g_hs_calls;
static int g_poison_calls;
static int g_split_success, g_split_calls, g_split_gaps;
static int g_split_connect_failures, g_split_response_failures;

static int pat_rc(const char *pat, int idx)
{
    size_t n = strlen(pat);
    char c = pat[(size_t)idx < n ? (size_t)idx : n - 1];
    return c == '+' ? 1 : c == 'e' ? -1 : 0;
}

static int next_rep(void)
{
    if (g_res->ntrace != g_ask) {
        g_ask = g_res->ntrace;
        g_rep = 0;
    }
    return g_rep++;
}

int fake_raw_supported(void) { return 1; }
unsigned long fake_rst_fail_count(void) { return 0; }

/* Самопроверка слоя зовётся тем же набором опций, что и вопросы (ревью ветки,
   находка 7): стенд запоминает, предлагалась ли метка времени. */
static int g_hs_offer_ts = -1;
int fake_handshake(const uint8_t *ip, uint8_t family, uint16_t port, int timeout_ms,
                   uint32_t mark, const d2k_detect_stop *cancel, int offer_ts,
                   char *err, size_t errcap)
{
    int rc;
    (void)ip; (void)family; (void)port; (void)timeout_ms; (void)mark; (void)cancel;
    g_hs_offer_ts = offer_ts;
    g_hs_calls++;
    rc = pat_rc(g_selftest, next_rep());
    if (rc < 0) { snprintf(err, errcap, "classify: SYN-ACK не пришёл"); }
    return rc;
}

int fake_poison(const uint8_t *ip, uint8_t family, uint16_t port, const d2k_trigger *tr,
                const d2k_poison *p, int timeout_ms, uint32_t mark,
                const d2k_detect_stop *cancel, char *err, size_t errcap)
{
    const char *pat = g_default;
    int i, rc;
    (void)ip; (void)family; (void)port; (void)tr; (void)timeout_ms; (void)mark; (void)cancel;
    if (!strcmp(p->name, "tcp-split")) {
        g_split_calls++;
        if (g_split_connect_failures > 0) {
            g_split_connect_failures--;
            snprintf(err, errcap, "raw connect timeout");
            return -2;
        }
        if (g_split_response_failures > 0) { g_split_response_failures--; return 0; }
        if (p->gap_ms == 2) g_split_gaps |= 1;
        if (p->gap_ms == 10) g_split_gaps |= 2;
        if (g_split_success < 0) snprintf(err, errcap, "raw split: local send failure");
        return g_split_success;
    }
    g_poison_calls++;
    for (i = 0; g_script && g_script[i].name; i++) {
        if (strcmp(g_script[i].name, p->name) == 0) { pat = g_script[i].pat; break; }
    }
    rc = pat_rc(pat, next_rep());
    if (rc < 0) { snprintf(err, errcap, "sendto: Operation not permitted"); }
    return rc;
}

/* Вопрос «принимает ли адрес данные вообще» (задача 54). Петля ядра
 * подтверждает любой байт мгновенно, поэтому тишину адреса на ней не
 * изобразить — ответ подменён сценарием: '+' байт подтверждён, '-' тишина,
 * 'e' локальная ошибка, 'u' подтверждение на платформе не наблюдается. */
static const char *g_ack_pat = "+";
static int g_ack_calls;

int fake_data_ack(const char *host, const char *port, const d2k_opts *opt,
                  char *err, size_t errcap)
{
    size_t n = strlen(g_ack_pat);
    char c = g_ack_pat[(size_t)g_ack_calls < n ? (size_t)g_ack_calls : n - 1];
    (void)host; (void)port; (void)opt;
    g_ack_calls++;
    if (c == 'e') { snprintf(err, errcap, "dial tcp: i/o timeout"); return -1; }
    if (c == 'u') { snprintf(err, errcap, "подтверждение не наблюдается"); return -2; }
    return c == '+' ? 1 : 0;
}

/* --- коробка на петле ---------------------------------------------------- */
static const char CTL[] = "BENIGN-CONTROL-PAYLOAD";
static const char *g_ctl_pat = "+"; /* ответ на контрольную нагрузку по вызовам */
static int g_ctl_calls;
static int g_srv_fd, g_silent, g_timeout_seed;
static void *quiet_connection(void *arg) {
    struct timespec pause={0,450000000};
    nanosleep(&pause,NULL);
    close((int)(intptr_t)arg);
    return NULL;
}

static void *srv_thread(void *arg)
{
    (void)arg;
    for (;;) {
        uint8_t buf[256];
        ssize_t n;
        int c = accept(g_srv_fd, NULL, NULL);
        if (c < 0) { return NULL; }
        n = recv(c, buf, sizeof buf, 0);
        if (n == (ssize_t)(sizeof(CTL) - 1) && memcmp(buf, CTL, (size_t)n) == 0 &&
            pat_rc(g_ctl_pat, g_ctl_calls++) > 0) {
            (void)send(c, "OK", 2, 0);
        }
        if(g_silent && !(n==(ssize_t)(sizeof CTL-1) && !memcmp(buf,CTL,(size_t)n))) {
            pthread_t th; pthread_create(&th,NULL,quiet_connection,(void *)(intptr_t)c);
            pthread_detach(th);
        } else close(c); /* baseline scenarios use immediate close */
    }
}

static char g_addr[64];

static void srv_start(void)
{
    struct sockaddr_in sa;
    socklen_t sl = sizeof sa;
    pthread_t th;
    int one = 1;
    g_srv_fd = socket(AF_INET, SOCK_STREAM, 0);
    (void)setsockopt(g_srv_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(0x7f000001u);
    if (bind(g_srv_fd, (struct sockaddr *)&sa, sizeof sa) != 0 || listen(g_srv_fd, 64) != 0 ||
        getsockname(g_srv_fd, (struct sockaddr *)&sa, &sl) != 0) {
        printf("стенд не поднялся\n");
        exit(1);
    }
    snprintf(g_addr, sizeof g_addr, "127.0.0.1:%u", (unsigned)ntohs(sa.sin_port));
    pthread_create(&th, NULL, srv_thread, NULL);
    pthread_detach(th);
}

/* --- прогон -------------------------------------------------------------- */
static const char PAY[] = "WA\x06\x03SIGNATURE-AND-THEN-SOME-PAYLOAD-BYTES";

typedef struct {
    const char       *name;
    const script_ent *script;
    const char       *dflt;
    const char       *selftest;
    const char       *ctl;
    int               vouched;
    const char       *ack;
    int               white;   /* 1 — задать opt.white (белое имя сети приманкой) */
    int               no_ts;   /* 1 — клиент триггера метку времени НЕ предлагает */
} scenario;

/* Фильтр находок, как plannable_hit в bridge.c: NULL — берётся любая. */
static int (*g_accept)(const d2k_poison *p, void *ctx);

static void run(const scenario *s, d2k_result *res)
{
    d2k_opts opt;
    d2k_trigger t;
    memset(&opt, 0, sizeof opt);
    opt.allow_loopback = 1;
    opt.repeats = 3;
    opt.timeout_ms = 400;
    opt.write_gap_ms = 2;
    opt.long_gap_ms = 10;
    opt.control_vouched = s->vouched;
    if(g_timeout_seed) {
        opt.seed_whole=1; opt.seed_repeats=3; opt.seed_fail=3;
        snprintf(opt.seed_err,sizeof opt.seed_err,"dial tcp 127.0.0.1:443: i/o timeout");
    }
    opt.accept = g_accept;
    memset(&opt.control, 0, sizeof opt.control);
    snprintf(opt.control.name, sizeof opt.control.name, "control");
    memcpy(opt.control.payload, CTL, sizeof(CTL) - 1);
    opt.control.len = sizeof(CTL) - 1;
    opt.control.accept = D2K_ACCEPT_ANY;
    memset(&opt.white, 0, sizeof opt.white);
    if (s->white) {
        /* Белое имя сети приманкой: содержимое для стенда неважно (fake_poison
           его игнорирует), важно, что len>=2 — иначе вопрос пропускается. */
        static const uint8_t wrec[] = {0x16, 0x03, 0x01, 0x00, 0x05, 1, 0, 0, 1, 0};
        memcpy(opt.white.payload, wrec, sizeof wrec);
        opt.white.len = sizeof wrec;
        opt.white.accept = D2K_ACCEPT_TLSRECORD;
        snprintf(opt.white.name, sizeof opt.white.name, "white");
    }
    memset(&t, 0, sizeof t);
    /* Набор опций TCP клиента (замысел 2026-10-23, п. 5.1): известный пустой
       набор — клиент без метки времени. */
    t.client_tcp_known = s->no_ts;
    t.client_tcp_options_len = 0;
    snprintf(t.name, sizeof t.name, "test");
    memcpy(t.payload, PAY, sizeof(PAY) - 1);
    t.len = sizeof(PAY) - 1;
    t.accept = D2K_ACCEPT_ANY;

    g_script = s->script;
    g_default = s->dflt ? s->dflt : "-";
    g_selftest = s->selftest ? s->selftest : "+";
    g_ctl_pat = s->ctl ? s->ctl : "+";
    g_ctl_calls = 0;
    g_ack_pat = s->ack ? s->ack : "+";
    g_ack_calls = 0;
    g_res = res;
    g_ask = -1;
    g_hs_calls = 0;
    g_poison_calls = 0;
    d2k_classify_run(g_addr, &t, &opt, res);
}

/* Подпись исхода: всё, что уходит наружу, кроме числа зондов и трассы. */
static void sig(const d2k_result *r, char *out, size_t cap)
{
    const d2k_dprops *p = &r->props;
    /* Подпись для сравнения исходов: обрезка по буферу допустима. */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
#endif
    snprintf(out, cap, "%s|%s|%s|%s|%d%d%d%d%d%d%d|%d|u%d|f%d|%s",
             d2k_verdict_name(r->verdict), r->path, r->has_hit ? r->hit.name : "-",
             r->strategy, p->reassembles, p->parses_l7, p->validates_checksum,
             p->tolerates_reorder, p->tolerates_left_overlap, p->counts_duplicates,
             p->inspects_syn, p->hop_ttl, r->raw_usable, r->raw_selftest_failed, r->reason);
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
}

static void dump(const d2k_result *r)
{
    int i;
    for (i = 0; i < r->ntrace; i++) {
        printf("    %-40s прошло=%d не прошло=%d %s\n", r->trace[i].probe, r->trace[i].pass,
               r->trace[i].fail, r->trace[i].err);
    }
}

/* Сценарии. Имена гипотез перебора берутся из списка по номеру ниже. */
static const script_ent S_YOUTUBE[] = {
    {"seqovl-1", "-"}, {"disorder", "+"}, {NULL, NULL}};
static script_ent S_RUTRACKER[] = {{NULL, "+"}, {NULL, NULL}};
static script_ent S_FLAKY[] = {
    {"seqovl-1", "+-"}, {"disorder", "-+"}, {"badsum", "++-"},
    {NULL, "++-"}, {NULL, "+"}, {NULL, NULL}};
static const script_ent S_PROPHIT_L7[] = {{"badsum+hello", "+"}, {NULL, NULL}};

static scenario SC[] = {
    {"youtube", S_YOUTUBE, NULL, NULL, NULL, 0, NULL, 0, 0},
    {"rutracker", S_RUTRACKER, NULL, NULL, NULL, 0, NULL, 0, 0},
    {"flaky", S_FLAKY, NULL, NULL, NULL, 0, NULL, 0, 0},
    {"prop-l7", S_PROPHIT_L7, NULL, NULL, NULL, 0, NULL, 0, 0},
    {"none-pass", NULL, "-", NULL, NULL, 0, NULL, 0, 0},
    {"selftest-fail", NULL, "-", "e", NULL, 0, NULL, 0, 0},
    {"selftest-late", S_YOUTUBE, NULL, "-e+", NULL, 0, NULL, 0, 0},
    {"ctl-late", S_YOUTUBE, NULL, NULL, "-+", 0, NULL, 0, 0},
    {"ctl-dead", NULL, "-", NULL, "-", 0, NULL, 0, 0},
    {"ctl-dead-vouched", NULL, "-", NULL, "-", 1, NULL, 0, 0},
    {"ctl-dead-hit", S_YOUTUBE, NULL, NULL, "-", 1, NULL, 0, 0},
    {"errors", NULL, "e", NULL, NULL, 0, NULL, 0, 0},
    /* Задача 54 (поле 04.10, cdn.cookielaw.org, 104.18.86.0/24): рукопожатие
     * проходит, а сервер не подтверждает ни одного байта данных — ни
     * приветствия, ни контроля, ни одного нейтрального байта. */
    {"addr-silent", NULL, "-", NULL, "-", 0, "-", 0, 0},
    {"addr-silent-late", NULL, "-", NULL, "-", 0, "-+", 0, 0},
    {"addr-ack-unseen", NULL, "-", NULL, "-", 0, "u", 0, 0},
    {"addr-ack-err", NULL, "-", NULL, "-", 0, "e", 0, 0},
};
#define NSC ((int)(sizeof SC / sizeof SC[0]))

static void bind_list_names(void)
{
    int n;
    const d2k_poison *l = d2k_poisons(&n);
    /* rutracker: сорок первая гипотеза перебора срабатывает. */
    S_RUTRACKER[0].name = l[40].name;
    /* flaky: 2 из 3 на одной, единогласие на следующей. */
    S_FLAKY[3].name = l[10].name;
    S_FLAKY[4].name = l[11].name;
}

/* Подписи СНЯТЫ с кода до правки (все повторы на каждом вопросе), прогон
 * с чистым процессом. before — сколько зондов стоил тот прогон; сколько
 * обязан стоить теперь — в after_count. */
typedef struct { const char *name; int before; const char *sig; } golden;
static const golden GOLD[] = {
{"youtube", 18, "poisonable|свойство|disorder|--lua-desync=multidisorder:payload=tls_client_hello:dir=out:pos=1,midsld|0001200|0|u1|f0|поток пересобирается, но буфер травится: коробка глотает «disorder», сервер выбрасывает"},
{"rutracker", 156, "poisonable|перебор|seqovl-16|--lua-desync=multisplit:payload=tls_client_hello:dir=out:pos=1:seqovl=16|0002100|0|u1|f0|поток пересобирается, но буфер травится: коробка глотает «seqovl-16», сервер выбрасывает"},
{"flaky", 69, "poisonable|свойство|disorder|--lua-desync=multidisorder:payload=tls_client_hello:dir=out:pos=1,midsld|0001200|0|u1|f0|поток пересобирается, но буфер травится: коробка глотает «disorder», сервер выбрасывает"},
{"prop-l7", 24, "poisonable|свойство|badsum+hello|--lua-desync=fake:payload=tls_client_hello:dir=out:blob=fake_default_tls:tls_mod=rnd,dupsid,sni=www.google.com:badsum|0212200|0|u1|f0|поток пересобирается, но буфер травится: коробка глотает «badsum+hello», сервер выбрасывает"},
{"none-pass", 297, "opaque||-||0002200|0|u1|f0|разрез не помогает, контроль проходит, отравить буфер не удалось — содержимое важно, но чем брать, зондами не нашли"},
{"selftest-fail", 12, "opaque||-||0000000|0|u0|f1|разрез не помогает, контроль проходит; сырые зонды НЕ РАБОТАЮТ (самопроверка не прошла) — про отравление вывода нет"},
{"selftest-late", 18, "poisonable|свойство|disorder|--lua-desync=multidisorder:payload=tls_client_hello:dir=out:pos=1,midsld|0001200|0|u1|f0|поток пересобирается, но буфер травится: коробка глотает «disorder», сервер выбрасывает"},
{"ctl-late", 18, "poisonable|свойство|disorder|--lua-desync=multidisorder:payload=tls_client_hello:dir=out:pos=1,midsld|0001200|0|u1|f0|поток пересобирается, но буфер травится: коробка глотает «disorder», сервер выбрасывает"},
{"ctl-dead", 297, "inconclusive||-||0002200|0|u1|f0|контроль не ответил и отравить не удалось: базы нет, отличить блок по адресу от нехватки гипотез нельзя"},
{"ctl-dead-vouched", 297, "address||-||0002200|0|u1|f0|молчит и контроль на имени, за которое ручается оператор, и ни одна гипотеза не сработала — похоже на блок по адресу"},
{"ctl-dead-hit", 18, "poisonable|свойство|disorder|--lua-desync=multidisorder:payload=tls_client_hello:dir=out:pos=1,midsld|0001200|0|u1|f0|поток пересобирается, но буфер травится: коробка глотает «disorder», сервер выбрасывает"},
{"errors", 297, "opaque||-||0002200|0|u1|f0|разрез не помогает, контроль проходит, отравить буфер не удалось — содержимое важно, но чем брать, зондами не нашли"},
/* Задача 54: снято не с кода до правки — нового вопроса там не было. Тишина
 * адреса — свой вердикт; остальные три обязаны совпасть с ctl-dead. */
{"addr-silent", 0, "address||-||0000000|0|u0|f0|рукопожатие проходит, но сервер не подтвердил ни одного нейтрального байта (0 из 3): данные к адресу режутся целиком, содержимое ни при чём — обходить содержимым нечего"},
{"addr-silent-late", 297, "inconclusive||-||0002200|0|u1|f0|контроль не ответил и отравить не удалось: базы нет, отличить блок по адресу от нехватки гипотез нельзя"},
{"addr-ack-unseen", 297, "inconclusive||-||0002200|0|u1|f0|контроль не ответил и отравить не удалось: базы нет, отличить блок по адресу от нехватки гипотез нельзя"},
{"addr-ack-err", 297, "inconclusive||-||0002200|0|u1|f0|контроль не ответил и отравить не удалось: базы нет, отличить блок по адресу от нехватки гипотез нельзя"},
};

static int after_count(const char *name)
{
    /* Полный перебор — на 3 зонда дешевле (задача 49): три точных дубля
       донора (badsum-x2-g20, badsum-x2-g80, badsum-x7-g0) больше не
       спрашиваются второй раз.
       §0.1 ТЗ (07.10.2026): ещё четыре вопроса о свойствах — сверка MD5,
       окно seq, метка времени, плотная серия — задаются после шести прежних
       и, как они, до первого прохода. Где свойство не нашло приём, это +4
       зонда (перекрытие до конца имени у приветствия без SNI не задаётся).
       План 09.10.2026: перебор не спрашивает второй раз девять гипотез, на
       которые вопрос о свойствах уже получил ответ сети (−8…−11 зондов там,
       где свойство не нашло приём; при локальных ошибках — без изменений).
       Порядок 10.10: syndata последний. Для этих сценариев число зондов
       неизменно: находки раньше прежнего места SYN либо все вопросы заданы.
       Снижение на один для MD5/seq/TS проверяется в test_props_fields. */
    /* 14.10.2026: вопрос о свойствах отвечает БОЛЬШИНСТВОМ (props.c,
       d2k_prop_majority): промах стоит два зонда вместо одного, проход —
       два вместо трёх; «flaky» (приём через раз) берётся вопросом, а не
       перебором. */
    /* 23.10.2026: вопросы «TTL по пути» (ip_autottl) и «метка первой в
       опциях» (tcp_ts_up) добавлялись в конец списка и СНЯТЫ прогоном
       `ttl-ae30825-1` того же дня: ни одного исполнения, +4 зонда у целей,
       доходящих до конца списка. Числа ниже — те же, что до их появления.
       Механизм остался в языке плана, см. test_unreachable_axes_not_asked. */
    static const struct { const char *n; int a; } A[] = {
        {"youtube", 12}, {"rutracker", 64}, {"flaky", 14}, {"prop-l7", 16},
        {"none-pass", 105}, {"selftest-fail", 10}, {"selftest-late", 14},
        {"ctl-late", 13}, {"ctl-dead", 108}, {"ctl-dead-vouched", 108},
        {"ctl-dead-hit", 15}, {"errors", 104},
        /* Задача 54: молчащий контроль добавляет ОДИН вопрос — нейтральный
         * байт; подтверждённый с первого раза, он стоит один зонд. Молчание
         * адреса стоит три (единогласие) и снимает весь перебор отравлений. */
        {"addr-silent", 12}, {"addr-silent-late", 109},
        {"addr-ack-unseen", 107}, {"addr-ack-err", 108}};
    size_t i;
    for (i = 0; i < sizeof A / sizeof A[0]; i++) {
        if (strcmp(A[i].n, name) == 0) { return A[i].a; }
    }
    return -1;
}

static const scenario *find_sc(const char *name)
{
    int i;
    for (i = 0; i < NSC; i++) {
        if (strcmp(SC[i].name, name) == 0) { return &SC[i]; }
    }
    return NULL;
}

static const golden *find_gold(const char *name)
{
    size_t i;
    for (i = 0; i < sizeof GOLD / sizeof GOLD[0]; i++) {
        if (strcmp(GOLD[i].name, name) == 0) { return &GOLD[i]; }
    }
    return NULL;
}

/* Чистый процесс: кэша самопроверки нет, счёт ошибок пуст. */
static void fresh_process(void)
{
    pthread_mutex_lock(&g_selftest_mu);
    memset(g_selftest_ok, 0, sizeof g_selftest_ok);
    memset(g_selftest_at, 0, sizeof g_selftest_at);
    memset(g_raw_err_streak, 0, sizeof g_raw_err_streak);
    pthread_mutex_unlock(&g_selftest_mu);
}

static const d2k_obs *find_obs(const d2k_result *r, const char *probe)
{
    int i;
    for (i = 0; i < r->ntrace; i++) {
        if (strcmp(r->trace[i].probe, probe) == 0) { return &r->trace[i]; }
    }
    return NULL;
}

/* Трасса честна: сумма pass+fail по строкам = число сделанных зондов. */
static int trace_probes(const d2k_result *r)
{
    int i, n = 0;
    for (i = 0; i < r->ntrace; i++) { n += r->trace[i].pass + r->trace[i].fail; }
    return n;
}

static void test_equivalence(void)
{
    int i;
    printf("до/после: одинаковые ответы — одинаковый исход\n");
    for (i = 0; i < NSC; i++) {
        const golden *g = find_gold(SC[i].name);
        d2k_result r;
        char s[1400];
        fresh_process();
        run(&SC[i], &r);
        sig(&r, s, sizeof s);
        CHECK(g && strcmp(s, g->sig) == 0, "%s: исход разошёлся\n    было  %s\n    стало %s",
              SC[i].name, g ? g->sig : "?", s);
        CHECK(r.probes == after_count(SC[i].name), "%s: зондов %d, ждали %d (было %d)",
              SC[i].name, r.probes, after_count(SC[i].name), g ? g->before : -1);
        CHECK(trace_probes(&r) == r.probes, "%s: трасса показывает %d зондов, сделано %d",
              SC[i].name, trace_probes(&r), r.probes);
        printf("  %-18s зондов %3d -> %3d\n", SC[i].name, g ? g->before : -1, r.probes);
        if (getenv("DUMP")) { dump(&r); }
    }
}

static void test_counts_per_question(void)
{
    d2k_result r;
    const d2k_obs *o;
    printf("повторы по вопросам\n");
    fresh_process();
    run(find_sc("youtube"), &r);
    o = find_obs(&r, "control");
    CHECK(o && o->pass == 1 && o->fail == 0, "(a) контроль: ждали 1 зонд до первого прохода");
    o = find_obs(&r, "raw-selftest");
    CHECK(o && o->pass == 1 && o->fail == 0, "самопроверка: ждали 1 зонд до первого успеха");
    o = find_obs(&r, "свойство:перекрытие слева");
    CHECK(o && o->pass == 0 && o->fail == 2, "(b) промах: два провала из трёх решают «нет»");
    o = find_obs(&r, "свойство:порядок сегментов");
    CHECK(o && o->pass == 2 && o->fail == 0, "(c) проход: два прохода из трёх решают «да»");
    o = find_obs(&r, "whole");
    CHECK(o && o->pass + o->fail == 3, "база: все повторы");
    o = find_obs(&r, "split");
    CHECK(o && o->pass + o->fail == 3, "разрез: все повторы");
    fresh_process();
    run(find_sc("ctl-dead"), &r);
    o = find_obs(&r, "control");
    CHECK(o && o->pass == 0 && o->fail == 3, "контроль без прохода: все 3 повтора");
}

/* Поля подделки, которые прежде узнавал только перебор (§0.1 ТЗ, 07.10.2026).
 * Выразимые вопросы идут перед syndata и до первого прохода: каждый
 * ответ записывается в вектор только по проходу. */
static const script_ent S_FIELD_MD5[] = {{"md5", "+"}, {NULL, NULL}};
static const script_ent S_FIELD_SEQ[] = {{"seq-out-of-window", "+"}, {NULL, NULL}};
static const script_ent S_FIELD_TS[]  = {{"ts", "+"}, {NULL, NULL}};
static void test_syndata_last(void)
{
    /* Число берётся из той же константы, что и массив в props.c, через
       prop_probes: иначе список и тест расходятся молча. Вопросов снова 12 —
       оси `ip_autottl` и `tcp_ts_up` сняты полем 23.10.2026, см.
       test_unreachable_axes_not_asked. */
    prop_probe pp[16];
    int n = prop_probes(pp, 16);
    CHECK(n == 12 && pp[n - 1].p.syn_data,
          "syndata должен быть последним вопросом о свойствах");
    for (int i = 0; i < n - 1; i++) {
        CHECK(!pp[i].p.syn_data, "syndata перед выразимыми вопросами");
    }
    /* Вопрос «приветствие под меткой» — после «плотной серии», перед syndata
       (поле 10.10.2026, раздел «Предложение»). */
    int white_at = -1, dense_at = -1;
    for (int i = 0; i < n; i++) {
        if (pp[i].p.tcp_ts && pp[i].p.decoy_hello) { white_at = i; }
        if (!strcmp(pp[i].p.name, "badsum-x7")) { dense_at = i; }
    }
    CHECK(white_at == n - 2, "«приветствие под меткой» не предпоследний (перед syndata)");
    CHECK(dense_at >= 0 && dense_at < white_at,
          "«приветствие под меткой» не после «плотной серии»");
}

/* СОСТАВНОЙ ВОПРОС СЕМЕЙСТВА C «ECH-приветствие под меткой времени» (поле
   10.10.2026, уточнение владельца по ECH). Цель C-сигнатуры (рукопожатие 0/3,
   «решает содержимое») берётся ЗАМЕРОМ: при промахе «метки времени» составной
   приём проходит — коробка приняла пакет со старой меткой И разобрала фальшивое
   ECH-приветствие (validates_timestamps=нет, parses_l7=да). Находка — не огрызок
   на одну копию без разреза, а ВСЁ ПРОИЗВЕДЕНИЕ множителей рабочего плана
   plan-680fbe00: серия ×8 и разрез настоящего приветствия +2. Путь — «свойство»,
   НЕ перебор. Без ECH-приманки вопрос не задаётся.

   ПАДАЕТ НА main ДО ПРАВКИ: там вопрос слал одну копию без разреза (repeats=1,
   split_pos=0), и этот же приём не собирал семейство C — цель уходила в перебор
   (путь «перебор»/RX-лестница), а не бралась замером. */
static void test_white_ts(void)
{
    static const script_ent s_white[] = {
        {"ts", "-"}, {"white-hello-ts", "+"}, {NULL, NULL}};
    scenario sc = {"white-ts", s_white, "-", NULL, NULL, 0, NULL, 1, 0};
    d2k_result r;
    memset(&r, 0, sizeof r);
    run(&sc, &r);
    CHECK(r.has_hit && !strcmp(r.hit.name, "white-hello-ts"),
          "составной вопрос семейства C не стал находкой");
    CHECK(!strcmp(r.path, "свойство"), "путь находки «%s», ждали «свойство» (не перебор)", r.path);
    CHECK(r.props.validates_timestamps == D2K_TRI_FALSE,
          "проход составного вопроса не записал «метку не сверяет»");
    CHECK(r.props.parses_l7 == D2K_TRI_TRUE,
          "проход составного вопроса не записал «разбирает L7»");
    /* Находка несёт ВЕСЬ механизм семейства C, а не одиночную копию без разреза. */
    CHECK(r.hit.tcp_ts && r.hit.decoy_hello,
          "находка семейства C без метки времени или без фальшивого приветствия");
    CHECK(r.hit.repeats == 8, "находка семейства C без серии ×8 (repeats=%d)", r.hit.repeats);
    CHECK(r.hit.split_pos == 2, "находка семейства C без разреза +2 (split_pos=%d)", r.hit.split_pos);
    CHECK(find_obs(&r, "свойство:ECH-приветствие под меткой") != NULL,
          "составной вопрос семейства C не задан при наличии ECH-приманки");

    /* A timed-out earlier dial is not an answer to the content question.
       Fresh whole/split connections stay open silently after the trigger;
       control replies, and the exact measured C product must still win. */
    g_silent=1; g_timeout_seed=1;
    run(&sc,&r);
    CHECK(r.has_hit && !strcmp(r.hit.name,"white-hello-ts") && !strcmp(r.path,"свойство"),
          "timeout seed prevented fresh silent-trigger/control/C measurement");
    const d2k_obs *whole=find_obs(&r,"whole");
    CHECK(whole && whole->fail==3 && !whole->err[0],"fresh post-trigger silence must replace transport error");
    g_silent=g_timeout_seed=0;

    /* Без ECH-приманки вопрос пропускается: та же раскладка, white=0. */
    scenario sc0 = {"white-ts-none", s_white, "-", NULL, NULL, 0, NULL, 0, 0};
    memset(&r, 0, sizeof r);
    run(&sc0, &r);
    CHECK(find_obs(&r, "свойство:ECH-приветствие под меткой") == NULL,
          "составной вопрос семейства C задан без ECH-приманки");
    CHECK(!(r.has_hit && !strcmp(r.hit.name, "white-hello-ts")),
          "без ECH-приманки приём семейства C всё равно найден");
}

static const script_ent S_FIELD_SYN[] = {{"syndata", "+"}, {NULL, NULL}};
static void test_syndata_after_misses(void)
{
    static const scenario syn = {"props-syn-last", S_FIELD_SYN, NULL, NULL, NULL, 0, NULL, 0, 0};
    d2k_result r;
    fresh_process();
    run(&syn, &r);
    CHECK(r.has_hit && r.hit.syn_data, "последний вопрос syndata не задан");
    /* The fixture has no SNI: ten questions, nine misses (two probes each
     * under the majority rule) and two positive syndata repeats, plus eight
     * baseline/self-test probes = 28. The "TTL по пути" and "метка первой в
     * опциях" axes were asked here on 23.10.2026 and removed the same day:
     * the field round never reached them. */
    CHECK(r.probes == 28, "syndata: зондов %d, ждали 28", r.probes);
    CHECK(r.nanswered == 10 && r.answered[r.nanswered - 1].syn_data,
          "syndata не последний отвеченный вопрос");
    CHECK(r.props.inspects_syn == D2K_TRI_FALSE, "ответ SYN не записан");
}

/* ОСИ, КОТОРЫЕ ПОЛЕ ПРИЗНАЛО НЕДОСТИЖИМЫМИ, НЕ СПРАШИВАЮТСЯ.
 *
 * Прогон 23.10.2026 `ttl-ae30825-1` (t0 15:30:40) со сборкой
 * `lab-1023-ttlaxis-ae30825`: 12 провалов контроля из 56 против 10 у выпуска,
 * и НИ ОДНОГО исполнения новых осей — в журнале раунда ноль упоминаний
 * «TTL по пути», «метка первой», `autottl`, `ts-up`. Все находки пути
 * «свойство» в раунде — `seqovl-1`, ПЕРВЫЙ вопрос списка; до восьмого
 * (о метке) замер не дошёл ни на одной из 22 целей, значит и до девятого с
 * десятым тоже.
 *
 * Значит вопросы в КОНЦЕ списка на этой линии стоят 2–4 зонда у целей,
 * доходящих до конца, и не дают ответа. «Лишние зонды убирать по причине»
 * (решение владельца) — причина измерена, зонды снимаются.
 *
 * Снимается ВОПРОС, а не механизм: `ip_autottl` остаётся записью языка плана
 * (REC_AUTOTTL, minexec 13), исполняется датапатом и выбирается RX-лестницей
 * для клиента без метки времени — там он закрывает issue #7. `tcp_ts_up`
 * остаётся битом порчи. Вернуть вопрос можно, когда поле покажет цель,
 * доходящую до конца списка. */
static void test_unreachable_axes_not_asked(void)
{
    prop_probe pp[16];
    int n = prop_probes(pp, 16);
    for (int i = 0; i < n; i++) {
        CHECK(strcmp(pp[i].p.name, "ts-up") != 0,
              "вопрос «метка первой» снят полем: не спрашивать");
        CHECK(strcmp(pp[i].p.name, "autottl") != 0,
              "вопрос «TTL по пути» снят полем: не спрашивать");
        CHECK(!pp[i].p.autottl, "порча autottl в вопросе о свойствах");
        CHECK(!pp[i].p.tcp_ts_up, "порча tcp_ts_up в вопросе о свойствах");
    }
}

static void test_props_fields(void)
{
    static const scenario md5 = {"props-md5", S_FIELD_MD5, NULL, NULL, NULL, 0, NULL, 0, 0};
    static const scenario seq = {"props-seq", S_FIELD_SEQ, NULL, NULL, NULL, 0, NULL, 0, 0};
    static const scenario ts  = {"props-ts",  S_FIELD_TS,  NULL, NULL, NULL, 0, NULL, 0, 0};
    d2k_result r;
    printf("свойства: сверка полей подделки\n");
    fresh_process();
    run(&md5, &r);
    CHECK(r.props.validates_md5 == D2K_TRI_FALSE, "MD5: проход не записан");
    CHECK(r.has_hit && !strcmp(r.hit.name, "md5"), "MD5: приём не стал находкой");
    /* syndata stays last and unasked after these findings. Under the
     * majority rule each earlier miss costs two probes and the finding two:
     * MD5 20, seq 22, TS 24. */
    CHECK(r.probes == 20, "MD5: зондов %d, ждали 20", r.probes);
    CHECK(r.props.inspects_syn == D2K_TRI_UNSET, "SYN спросили до MD5");
    fresh_process();
    run(&seq, &r);
    CHECK(r.props.validates_seq_window == D2K_TRI_FALSE, "окно seq: проход не записан");
    CHECK(r.probes == 22, "seq: зондов %d, ждали 22", r.probes);
    CHECK(r.props.validates_md5 == D2K_TRI_UNSET, "MD5 записан без прохода");
    fresh_process();
    run(&ts, &r);
    CHECK(r.props.validates_timestamps == D2K_TRI_FALSE, "метка времени: проход не записан");
    CHECK(r.probes == 24, "TS: зондов %d, ждали 24", r.probes);
    CHECK(r.props.counts_duplicates == D2K_TRI_UNSET, "дубликаты записаны без прохода");
}

/* The real bridge still rejects syndata. This test additionally rejects
 * expressible MD5 through its explicit acceptance filter: a rejected hit
 * must not hide the later timestamp question. syndata is now last and is
 * never asked after a usable timestamp finding. */
static int no_syn_md5(const d2k_poison *p, void *ctx)
{
    (void)ctx;
    return !p->syn_data && !p->md5;
}
static const script_ent S_SYN_TS[] = {{"syndata", "+"}, {"md5", "+"}, {"ts", "+"}, {NULL, NULL}};
static void test_props_skip_unplannable(void)
{
    static const scenario sc = {"syn-ts", S_SYN_TS, "-", NULL, NULL, 0, NULL, 0, 0};
    d2k_result r;
    printf("свойства: невыразимая находка не останавливает вопросы\n");
    fresh_process();
    g_accept = no_syn_md5;
    run(&sc, &r);
    g_accept = NULL;
    CHECK(r.has_hit && !strcmp(r.hit.name, "ts"), "находка — не метка времени (%s)",
          r.has_hit ? r.hit.name : "нет");
    CHECK(!strcmp(r.path, "свойство"), "путь «%s», ждали «свойство»", r.path);
    CHECK(r.props.inspects_syn == D2K_TRI_UNSET, "SYN спросили раньше выразимой находки");
    CHECK(r.props.validates_md5 == D2K_TRI_FALSE, "ответ о MD5 не записан");
    CHECK(r.props.validates_timestamps == D2K_TRI_FALSE, "ответ о метке времени не записан");
    CHECK(find_obs(&r, "poison:syndata") == NULL, "перебор переспросил отвеченный syndata");
}

/* Перебор не спрашивает второй раз то, на что вопрос о свойствах уже получил
 * ответ сети: при единогласии исход повтора тот же (как задача 49, решение
 * владельца 03.10). Локальная ошибка зонда — не ответ сети: такую гипотезу
 * перебор спрашивает. */
static const script_ent S_MD5_ERR[] = {{"md5", "e"}, {NULL, NULL}};
static void test_sweep_skips_answered(void)
{
    static const char *const dup[] = {
        "seqovl-1", "disorder", "badsum", "badsum+hello", "badsum-x2-g20",
        "syndata", "md5", "seq-out-of-window", "badsum-x7"};
    static const scenario err = {"md5-err", S_MD5_ERR, "-", NULL, NULL, 0, NULL, 0, 0};
    d2k_result r;
    char nm[96];
    size_t i;
    printf("перебор: отвеченные свойства второй раз не спрашиваются\n");
    fresh_process();
    run(find_sc("none-pass"), &r);
    for (i = 0; i < sizeof dup / sizeof dup[0]; i++) {
        snprintf(nm, sizeof nm, "poison:%s", dup[i]);
        CHECK(find_obs(&r, nm) == NULL, "перебор повторил отвеченный вопрос «%s»", dup[i]);
    }
    CHECK(find_obs(&r, "poison:badsum-x2-g80") != NULL, "перебор пропустил неотвеченную гипотезу");
    fresh_process();
    run(&err, &r);
    CHECK(find_obs(&r, "poison:md5") != NULL, "локальная ошибка свойства сняла гипотезу с перебора");
}

/* ЗАДАЧА 54. Адрес, который после рукопожатия не принимает НИКАКИХ данных,
 * содержимым не обходится: десинк меняет то, как выглядят байты, но байты
 * всё равно должны дойти до сервера. Перебор девяноста гипотез по шесть
 * секунд тишины на каждой не укладывался в срок задачи (10 мин), замер
 * бросался без вердикта и через 10 мин начинался снова. */
static void test_address_silence(void)
{
    d2k_result r;
    const d2k_obs *o;
    printf("адрес не принимает данных\n");
    fresh_process();
    run(find_sc("addr-silent"), &r);
    CHECK(r.verdict == D2K_DV_ADDRESS, "вердикт %s, ждали address (%s)",
          d2k_verdict_name(r.verdict), r.reason);
    CHECK(strstr(r.reason, "нейтральн") != NULL, "причина не называет измерение: %s", r.reason);
    CHECK(r.strategy[0] == '\0', "для блока адреса предложена стратегия «%s»", r.strategy);
    CHECK(g_poison_calls == 0 && g_hs_calls == 0,
          "после доказанной тишины адреса шёл сырой перебор: отрав %d, самопроверок %d",
          g_poison_calls, g_hs_calls);
    o = find_obs(&r, "neutral-ack");
    CHECK(o && o->pass == 0 && o->fail == 3, "нейтральный байт: ждали 0 из 3 в трассе");

    /* Один подтверждённый байт — адрес данные принимает; дальше по-старому. */
    fresh_process();
    run(find_sc("addr-silent-late"), &r);
    CHECK(r.verdict == D2K_DV_INCONCLUSIVE, "подтверждённый байт: вердикт %s",
          d2k_verdict_name(r.verdict));
    CHECK(g_poison_calls > 0, "подтверждённый байт снял перебор");
    o = find_obs(&r, "neutral-ack");
    CHECK(o && o->pass == 1 && o->fail == 1, "нейтральный байт: ждали остановку на первом проходе");

    /* Не наблюдаемо или локальная ошибка — не свойство адреса. */
    fresh_process();
    run(find_sc("addr-ack-unseen"), &r);
    CHECK(r.verdict == D2K_DV_INCONCLUSIVE && g_poison_calls > 0,
          "ненаблюдаемое подтверждение выдано за тишину адреса: %s", d2k_verdict_name(r.verdict));
    fresh_process();
    run(find_sc("addr-ack-err"), &r);
    CHECK(r.verdict == D2K_DV_INCONCLUSIVE && g_poison_calls > 0,
          "локальная ошибка выдана за тишину адреса: %s", d2k_verdict_name(r.verdict));
}

static void test_selftest_cache(void)
{
    d2k_result r;
    char s[1400];
    const golden *g;
    printf("самопроверка сырого слоя: раз на процесс\n");

    /* (d) второй прогон в том же процессе самопроверку не повторяет. */
    fresh_process();
    run(find_sc("youtube"), &r);
    CHECK(g_hs_calls == 1, "первый прогон: самопроверок %d, ждали 1", g_hs_calls);
    run(find_sc("youtube"), &r);
    CHECK(g_hs_calls == 0, "второй прогон: самопроверок %d, ждали 0", g_hs_calls);
    CHECK(r.probes == 11, "второй прогон: зондов %d, ждали 11", r.probes);
    CHECK(find_obs(&r, "raw-selftest:кэш") != NULL, "трасса не говорит, что самопроверка из кэша");
    CHECK(find_obs(&r, "raw-selftest") == NULL, "в трассе зонд самопроверки, которого не было");
    CHECK(trace_probes(&r) == r.probes, "трасса показывает %d зондов, сделано %d",
          trace_probes(&r), r.probes);
    sig(&r, s, sizeof s);
    g = find_gold("youtube");
    CHECK(strcmp(s, g->sig) == 0, "исход из кэша разошёлся: %s", s);

    /* Подряд идущие локальные ошибки сырых зондов — самопроверка снова. */
    {
        d2k_result junk;
        memset(&junk, 0, sizeof junk);
        d2k_raw_note_rc(&junk, 4, -1);
        d2k_raw_note_rc(&junk, 4, -1);
        d2k_raw_note_rc(&junk, 4, -1);
    }
    run(find_sc("youtube"), &r);
    CHECK(g_hs_calls == 1, "после серии отказов: самопроверок %d, ждали 1", g_hs_calls);

    /* Удача сбрасывает счёт: две ошибки, удача, две ошибки — кэш жив. */
    {
        d2k_result junk;
        memset(&junk, 0, sizeof junk);
        d2k_raw_note_rc(&junk, 4, -1);
        d2k_raw_note_rc(&junk, 4, -1);
        d2k_raw_note_rc(&junk, 4, 0);
        d2k_raw_note_rc(&junk, 4, -1);
        d2k_raw_note_rc(&junk, 4, -1);
    }
    run(find_sc("youtube"), &r);
    CHECK(g_hs_calls == 0, "ошибки вперемешку с удачей: самопроверок %d, ждали 0", g_hs_calls);

    /* Кэш стареет. */
    pthread_mutex_lock(&g_selftest_mu);
    g_selftest_at[0] -= D2K_SELFTEST_TTL_MS + 1;
    pthread_mutex_unlock(&g_selftest_mu);
    run(find_sc("youtube"), &r);
    CHECK(g_hs_calls == 1, "кэш старше срока: самопроверок %d, ждали 1", g_hs_calls);

    /* Кэш есть, а сырой слой сломался: первые же отказы этого прогона
     * перепроверяют слой, и провал ведёт себя ровно как провал самопроверки. */
    {
        scenario broken = {"broken", NULL, "e", "e", NULL, 0, NULL, 0, 0};
        fresh_process();
        run(find_sc("youtube"), &r);
        run(&broken, &r);
        CHECK(g_hs_calls >= 1, "сломанный слой при кэше не перепроверен");
        sig(&r, s, sizeof s);
        g = find_gold("selftest-fail");
        CHECK(strcmp(s, g->sig) == 0, "сломанный слой при кэше:\n    ждали %s\n    стало %s",
              g->sig, s);
        CHECK(trace_probes(&r) == r.probes, "трасса показывает %d зондов, сделано %d",
              trace_probes(&r), r.probes);
        /* и следующий прогон снова мерит слой, а не верит кэшу */
        run(find_sc("youtube"), &r);
        CHECK(g_hs_calls == 1, "после провала перепроверки: самопроверок %d, ждали 1",
              g_hs_calls);
    }

    /* Кэш есть, сырые зонды отказывают, но слой исправен (цель не отвечает
     * сырому SYN): перепроверка проходит, исход тот же, что без кэша. */
    {
        fresh_process();
        run(find_sc("youtube"), &r);
        run(find_sc("errors"), &r);
        sig(&r, s, sizeof s);
        g = find_gold("errors");
        CHECK(strcmp(s, g->sig) == 0, "отказы при исправном слое:\n    ждали %s\n    стало %s",
              g->sig, s);
        CHECK(trace_probes(&r) == r.probes, "трасса показывает %d зондов, сделано %d",
              trace_probes(&r), r.probes);
    }
}

static void test_local_plan_error_is_not_a_property(void) {
    d2k_result r = {0}; d2k_opts opt = {0}; d2k_trigger tr = {0}; d2k_poison hit = {0};
    opt.repeats = 3; opt.white.len = 2;
    tr.len = 2049; tr.sni_off = 100; tr.sni_len = 11;
    g_script = NULL; g_default = "e"; g_res = &r; g_ask = -1;
    CHECK(d2k_run_properties((uint8_t[]){192,0,2,1}, 443, &tr, &opt, &r, &hit) == 0,
          "локальный отказ стал находкой");
    d2k_dprops expected = {0};
    CHECK(!memcmp(&r.props, &expected, sizeof expected), "локальный отказ изменил свойства коробки");
    CHECK(r.nanswered == 0, "локальный отказ стал ответом сети");
}

/* ЗАМЫСЕЛ 2026-10-23, п. 5.1 и 5.2: СОСТАВ ВОПРОСОВ ИДЁТ ОТ КЛИЕНТА.
   Одиночный вопрос о метке времени задаётся только клиенту, который метку
   предлагает: порча требует метки в потоке (datapath/wire.c), и у клиента без
   метки (ПК репортёра #7) её «нет» говорило бы о зонде, а не о коробке.
   Составной вопрос семейства C при этом задаётся обоим — у клиента без метки
   он собирается с порчей, которую поток несёт (см. тест ниже). Набор опций не
   снят — весь прежний состав вопросов, как раньше. */
static int trace_count(const d2k_result *r, const char *needle) {
    int n = 0;
    for (int i = 0; i < r->ntrace; i++) if (strstr(r->trace[i].probe, needle)) n++;
    return n;
}
static void test_timestamp_questions_follow_client_profile(void) {
    d2k_result r; d2k_opts opt; d2k_trigger tr; d2k_poison hit;
    for (int known = 0; known < 2; known++) {
        memset(&r, 0, sizeof r); memset(&opt, 0, sizeof opt); memset(&tr, 0, sizeof tr);
        memset(&hit, 0, sizeof hit);
        opt.repeats = 3; opt.white.len = 2;
        tr.len = 300; tr.sni_off = 100; tr.sni_len = 11;
        tr.client_tcp_known = known; tr.client_tcp_options_len = 0;
        g_script = NULL; g_default = "-"; g_res = &r; g_ask = -1;
        CHECK(d2k_run_properties((uint8_t[]){192,0,2,1}, 443, &tr, &opt, &r, &hit) == 0,
              "клиентский профиль: вопросы дали находку на стенде промахов");
        int ts = trace_count(&r, "метка времени");
        int white = trace_count(&r, "ECH-приветствие под");
        if (known) {
            /* Одиночный вопрос о метке — нет; составной (п. 5.2) — да, без метки. */
            CHECK(ts == 0 && white == 1,
                  "клиент без метки времени: не тот состав вопросов (ts=%d, white=%d)", ts, white);
        } else {
            CHECK(ts == 1 && white == 1,
                  "набор не снят: вопросы о метке не заданы (ts=%d, white=%d)", ts, white);
        }
        CHECK(trace_count(&r, "плотная серия") == 1, "клиентский профиль: прочие вопросы пропали");
    }
}

/* ЗАМЫСЕЛ 2026-10-23, п. 5.2: СОСТАВНОЙ ВОПРОС СОБИРАЕТСЯ, А НЕ ПРИВОЗИТСЯ.
   Клиент без метки времени (ПК репортёра #7): одиночный вопрос о метке ему не
   задаётся — его «нет» говорило бы о зонде, а не о коробке. Составной вопрос
   семейства C при этом НЕ пропадает: множители (приманка ECH, серия ×8, разрез
   +2) те же, а порча берётся из измеренного — битая сумма, пока коробка не
   доказала, что сумму сверяет. По такому проходу «метку не сверяет» НЕ
   записывается: метки в зонде не было. */
static void test_composite_assembled_for_client_without_ts(void) {
    static const script_ent s_white[] = {
        {"white-hello-ts", "+"}, {NULL, NULL}};
    scenario sc = {"white-ts-noopts", s_white, "-", NULL, NULL, 0, NULL, 1, 1};
    d2k_result r;
    memset(&r, 0, sizeof r);
    run(&sc, &r);
    CHECK(find_obs(&r, "свойство:метка времени") == NULL,
          "клиенту без метки задан одиночный вопрос о метке времени");
    CHECK(find_obs(&r, "свойство:ECH-приветствие под битой суммой") != NULL,
          "клиенту без метки составной вопрос семейства C не задан вовсе");
    CHECK(find_obs(&r, "свойство:ECH-приветствие под меткой") == NULL,
          "трасса называет метку времени, которой в зонде не было");
    CHECK(r.has_hit && !strcmp(r.hit.name, "white-hello-ts"),
          "составной вопрос без метки не стал находкой");
    CHECK(!r.hit.tcp_ts, "находка клиента без метки несёт метку времени");
    CHECK(r.hit.badsum, "порча составного вопроса не взята из измеренного (битая сумма)");
    CHECK(r.hit.decoy_hello && r.hit.repeats == 8 && r.hit.split_pos == 2,
          "множители составного вопроса потеряны (приманка/серия/разрез)");
    CHECK(r.props.parses_l7 == D2K_TRI_TRUE,
          "проход составного вопроса не записал «разбирает L7»");
    CHECK(r.props.validates_timestamps == D2K_TRI_UNSET,
          "по проходу без метки записано «метку не сверяет» — метки в зонде не было");
}

/* РЕВЬЮ ВЕТКИ, НАХОДКА 7: самопроверка сырого слоя ручается за ТУ форму
   потока, которой идут вопросы. Прежде она всегда предлагала метку времени, а
   вопросы клиента без метки — нет: путь, не отвечающий на SYN без метки, дал
   бы промахи во всех вопросах и живой слой в самопроверке, и промахи зачлись
   бы ответами коробки (запрет §2.4). */
static void test_selftest_uses_client_tcp_profile(void) {
    d2k_result r;
    scenario with_ts = {"selftest-ts", NULL, "-", NULL, NULL, 0, NULL, 0, 0};
    scenario no_ts   = {"selftest-no-ts", NULL, "-", NULL, NULL, 0, NULL, 0, 1};
    fresh_process();
    g_hs_offer_ts = -1;
    run(&with_ts, &r);
    CHECK(g_hs_offer_ts == 1, "клиент с меткой: самопроверка пошла без метки (%d)", g_hs_offer_ts);
    fresh_process();
    g_hs_offer_ts = -1;
    run(&no_ts, &r);
    CHECK(g_hs_offer_ts == 0, "клиент без метки: самопроверка пошла С меткой (%d)", g_hs_offer_ts);
}

static void test_split_uses_runtime(void) {
    scenario sc = {"split-runtime", NULL, "-", NULL, "+", 0, NULL, 0, 0};
    d2k_result r;
    g_split_success = 1; g_split_calls = g_split_gaps = 0;
    run(&sc, &r);
    CHECK(r.verdict == D2K_DV_WHOLE_PACKET && g_split_calls == 9 && g_split_gaps == 3,
          "split measurement bypassed the production packet runtime: verdict=%d calls=%d gaps=%d",
          r.verdict, g_split_calls, g_split_gaps);
    g_split_success = -1; g_split_calls = 0;
    run(&sc, &r);
    CHECK(r.verdict == D2K_DV_FLAKY && g_poison_calls == 0 && g_split_calls == 3,
          "failed raw split is a local failure, not a negative DPI property");
    g_split_success = 0;
}

static const char *transport_cancel_at;
static int transport_cancelled;
static int transport_is_cancelled(void *ctx) { (void)ctx; return transport_cancelled; }
static void transport_progress(void *ctx, const d2k_obs *o) {
    *(int *)ctx += o->pass + o->fail;
    if (transport_cancel_at && !strcmp(o->probe, transport_cancel_at)) transport_cancelled = 1;
}

static void test_split_recovers_only_unsent_transport_failure(void) {
    d2k_opts opt = {0}; d2k_trigger tr = {0}; d2k_result r = {0};
    int cut = 1, units = 0; const char *port = strrchr(g_addr, ':') + 1;
    opt.on_obs = transport_progress; opt.on_obs_ctx = &units;
    opt.repeats = 3; opt.timeout_ms = 100; opt.mark = 0;
    memcpy(tr.payload, PAY, sizeof PAY - 1); tr.len = sizeof PAY - 1;
    g_split_success = 1; g_split_calls = 0; g_split_connect_failures = 1;
    d2k_tally tally = measure("127.0.0.1", port, &tr, &opt, "split", &cut, 1, 0, &r, 0);
    CHECK(!tally.has_err && tally.pass == 3 && tally.fail == 0,
          "an unsent split prevents three actual successful trials");
    CHECK(r.probes == 5 && g_split_calls == 4 && units == 5,
          "missing raw attempt / fresh TCP control / retry accounting: %d", r.probes);

    memset(&r, 0, sizeof r); g_split_calls = 0; g_split_connect_failures = 10;
    tally = measure("127.0.0.1", port, &tr, &opt, "split", &cut, 1, 0, &r, 0);
    CHECK(tally.has_err && tally.pass == 0 && g_split_calls == 2 && r.probes == 3,
          "persistent raw failure must stop after the diagnostic pair");

    memset(&r, 0, sizeof r); g_split_calls = 0; g_split_connect_failures = 0;
    g_split_response_failures = 1;
    tally = measure("127.0.0.1", port, &tr, &opt, "split", &cut, 1, 0, &r, 0);
    CHECK(!tally.has_err && tally.pass == 2 && tally.fail == 1 && r.probes == 3 && g_split_calls == 3,
          "a failed trigger was retried into a false unanimous result");
    /* A fresh kernel control that cannot connect must not authorize a retry. */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {0}; socklen_t sl = sizeof sa;
    sa.sin_family = AF_INET; sa.sin_addr.s_addr = htonl(0x7f000001u);
    CHECK(fd >= 0 && bind(fd, (struct sockaddr *)&sa, sizeof sa) == 0 &&
          getsockname(fd, (struct sockaddr *)&sa, &sl) == 0, "transport control fixture");
    char closed_port[16]; snprintf(closed_port, sizeof closed_port, "%u", ntohs(sa.sin_port));
    memset(&r, 0, sizeof r); g_split_calls = 0; g_split_connect_failures = 1;
    units = 0;
    tally = measure("127.0.0.1", closed_port, &tr, &opt, "split", &cut, 1, 0, &r, 0);
    CHECK(tally.has_err && tally.pass == 0 && g_split_calls == 1 && r.probes == 2 && units == 2,
          "failed transport control authorized a split or hid its cost");
    close(fd);

    memset(&r, 0, sizeof r); g_split_calls = 0; g_split_connect_failures = 1;
    transport_dns_calls = 0;
    tally = measure("transport-switch.test", port, &tr, &opt, "split", &cut, 1, 0, &r, 0);
    CHECK(tally.has_err && tally.pass == 0 && g_split_calls == 1 && transport_dns_calls == 1,
          "transport recovery silently changed the target's resolved address");

    memset(&r, 0, sizeof r); g_split_calls = 0; g_split_connect_failures = 1;
    opt.mark = 0x2d; transport_fail_mark = 1;
    tally = measure("127.0.0.1", port, &tr, &opt, "split", &cut, 1, 0, &r, 0);
    CHECK(tally.has_err && tally.pass == 0 && g_split_calls == 1,
          "unmarked TCP control authorized raw recovery");
    transport_fail_mark = 0; opt.mark = 0;

    const char *cancel_stages[] = {"transport:raw-connect", "transport:tcp-control"};
    for (int stage = 0; stage < 2; stage++) {
        memset(&r, 0, sizeof r); g_split_calls = 0; g_split_connect_failures = 1;
        units = 0; transport_cancelled = 0; transport_cancel_at = cancel_stages[stage];
        opt.cancel.fn = transport_is_cancelled;
        tally = measure("127.0.0.1", port, &tr, &opt, "split", &cut, 1, 0, &r, 0);
        CHECK(tally.has_err && tally.pass == 0 && g_split_calls == 1 &&
              r.probes == stage + 1 && units == stage + 1,
              "cancellation allowed another transport experiment");
    }
    transport_cancel_at = NULL; transport_cancelled = 0; opt.cancel.fn = NULL;

    /* Exercise the complete classifier, not only its repeat helper. */
    scenario sc = {"split-recovered", NULL, "-", NULL, "+", 0, NULL, 0, 0};
    d2k_result before, after;
    g_split_connect_failures = 0; g_split_calls = 0;
    run(&sc, &before);
    g_split_connect_failures = 1; g_split_calls = 0;
    run(&sc, &after);
    CHECK(after.verdict == D2K_DV_WHOLE_PACKET && after.split_pos == before.split_pos &&
          after.probes == before.probes + 2 && g_split_calls == 10,
          "recovered classifier lost the measured split or entered fallback");
    g_split_success = 0;
}

int main(void)
{
    test_local_plan_error_is_not_a_property();
    test_timestamp_questions_follow_client_profile();
    srv_start();
    test_split_uses_runtime();
    test_split_recovers_only_unsent_transport_failure();
    bind_list_names();
    if (getenv("CAPTURE")) {
        int i;
        for (i = 0; i < NSC; i++) {
            d2k_result r;
            char s[1400];
            run(&SC[i], &r);
            sig(&r, s, sizeof s);
            printf("{\"%s\", %d, \"%s\"},\n", SC[i].name, r.probes, s);
        }
        return 0;
    }
    test_equivalence();
    test_counts_per_question();
    test_syndata_last();
    test_white_ts();
    test_composite_assembled_for_client_without_ts();
    test_selftest_uses_client_tcp_profile();
    test_syndata_after_misses();
    test_unreachable_axes_not_asked();
    test_props_fields();
    test_sweep_skips_answered();
    test_props_skip_unplannable();
    test_address_silence();
    test_selftest_cache();
    if (fails) {
        printf("повторы: ПРОВАЛОВ %d\n", fails);
        return 1;
    }
    printf("повторы: лишних нет, исходы совпадают\n");
    return 0;
}
