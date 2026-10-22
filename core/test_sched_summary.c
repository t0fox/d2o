/* Exercise production terminal/reset paths without creating a network worker. */
#define pthread_create summary_thread_create
#define d2k_verify_probe_ech_origin_on summary_ech_probe
#include "sched.c"
#undef d2k_verify_probe_ech_origin_on
#undef pthread_create
#include "d2k_quic_arms.h"
#include "d2k_plantlv.h"
#include "test_quic_pq.h"

static int capture_spawn;
int summary_thread_create(pthread_t *thread, const pthread_attr_t *attr,
                          void *(*start)(void *), void *arg) {
    (void)thread; (void)attr; (void)start; (void)arg;
    if (capture_spawn) { free(arg); return 0; }
    return EAGAIN;
}

/* Без сети (стенд Astra, ревью rx6): ECH-зонд свидетеля и HTTPS RR подменены. */
static char probed_origin[256];
static int probe_calls;
d2k_ver_result summary_ech_probe(int use_fd, const char *ip, uint16_t port,
    const char *outer, const char *origin, int deadline, size_t wire,
    uint32_t mark, const char *path) {
    (void)use_fd; (void)ip; (void)port; (void)outer;
    (void)deadline; (void)wire; (void)mark; (void)path;
    probe_calls++;
    snprintf(probed_origin, sizeof probed_origin, "%s", origin ? origin : "");
    d2k_ver_result r = {0}; r.fd = -1; return r;
}
static int rr_queries;
static int summary_resolve(const char *name, uint32_t mark, d2k_ech_config *cfg) {
    (void)mark;
    rr_queries++;
    if (!strcmp(name, "bad1.example") || !strcmp(name, "bad2.example")) return -1;
    memset(cfg, 0, sizeof *cfg);
    strcpy(cfg->public_name, "cloudflare-ech.com"); return 0;
}

static int fails;
static char rows[8192];
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"summary:%d: %s\n",__LINE__,#x); fails++; } } while (0)
static void collect(void *ctx, const char *line) {
    (void)ctx;
    size_t used = strlen(rows);
    snprintf(rows + used, sizeof rows - used, "%s\n", line);
}
/* ЗАДАЧА 26: подменённая проба объёма. Мерить по «/» (или по устаревшему
   свидетелю привязки) нечем — завершённый 403 на 243 байта; обрыв даёт ТОЛЬКО
   путь, который уже наблюдался у этой цели (vol_cut_path). Проба в сеть не
   ходит: предмет проверки — какой путь спрашивает планировщик. */
static const char *vol_cut_path;
static char vol_asked[4][512];
static int vol_asks;
static d2k_vol_result vol_answer_for(const char *path) {
    d2k_vol_result r;
    memset(&r, 0, sizeof r);
    if (vol_asks < 4) snprintf(vol_asked[vol_asks], sizeof vol_asked[0], "%s", path ? path : "");
    vol_asks++;
    r.verdict = D2K_VOL_PASSED;
    r.at_kb = 40;
    if (path && vol_cut_path && !strcmp(path, vol_cut_path)) {
        r.rx_cut = 1; r.rx_compressed_complete = 1; r.rx_at_kb = 15;
        snprintf(r.measured_path, sizeof r.measured_path, "%s", path);
        snprintf(r.rx_reason, sizeof r.rx_reason, "обрыв 15985/15968, gzip завершился");
    } else {
        /* МЕРИТЬ БЫЛО НЕЧЕМ: ответ завершён и меньше полосы. Это НЕ парное
           отрицательное измерение (см. rx_short в d2k_volume.h). */
        r.rx_short = 1; r.rx_short_bytes = 243;
        snprintf(r.rx_reason, sizeof r.rx_reason, "HTTP 403, тело 243/243, complete=1");
    }
    return r;
}
static d2k_vol_result stub_vol_path(const char *ip, uint16_t port, const char *sni,
    int plain, int tls12, size_t wire, uint32_t mark, const char *path) {
    (void)ip; (void)port; (void)sni; (void)plain; (void)tls12; (void)wire; (void)mark;
    return vol_answer_for(path);
}
static d2k_vol_result stub_vol_root(const char *ip, uint16_t port, const char *sni,
    int plain, int tls12, size_t wire, uint32_t mark) {
    (void)ip; (void)port; (void)sni; (void)plain; (void)tls12; (void)wire; (void)mark;
    return vol_answer_for("");
}

static task *fixture(d2k_sched *s) {
    task *t = &s->tasks[0];
    memset(t, 0, sizeof *t);
    t->prop_fd = t->prop_q = t->probe_fd = t->ver.fd = t->c_fd = -1;
    strcpy(t->name, "summary.example");
    strcpy(t->ip, "127.0.0.1");
    t->port = 443; t->transport = 6; t->family = 4;
    t->shape_armed = 1;
    t->report_id = ++s->report_sequence;
    t->report_admitted_ms = 100;
    t->state = T_QUEUED;
    t->queued_ms = 800;
    t->report_queue_ms = 50; /* an earlier queue, then shape wait */
    s->now_ms = 900; s->clock_seen = 1;
    rows[0] = 0;
    return t;
}
/* Поле 17.10.2026, router-round RR3-fix2-1: свидетель ECH romfea.gr стоит за
   Cloudflare challenge. Под планом рукопожатие с принятым ECH прошло, сервер
   свидетеля ответил своей challenge-страницей — и cloudflare-ech.com получил
   60-минутную антибот-паузу: Chrome с ECH не открыл ни одного CF-сайта.
   Свидетель доказывает только проход ECH через коробку; полный HTTP-ответ его
   сервера через принятый ECH — это доказательство, а не антибот цели. */
static void ech_witness_challenge_is_transport_proof(d2k_sched *s) {
    task *t = fixture(s);
    strcpy(t->name, "cloudflare-ech.com"); strcpy(t->ech_origin, "romfea.gr");
    t->transport = 6; t->ech_offer = 1; t->ech_replay = 0;
    memset(&t->ver, 0, sizeof t->ver);
    t->ver.level = D2K_VER_CHALLENGE; t->ver.cloudflare_challenge = 1;
    t->ver.ech_accepted = 1; t->ver.name_ok = 1; t->ver.body_complete = 1; t->ver.status = 403;
    CHECK(ech_witness_transport_proof(t) == 1);
    t->ver.ech_accepted = 0;
    CHECK(ech_witness_transport_proof(t) == 0);  /* ECH не принят — прохода нет */
    t->ver.ech_accepted = 1; t->ver.body_complete = 0;
    CHECK(ech_witness_transport_proof(t) == 0);  /* ответ не полный */
    t->ver.body_complete = 1; t->ver.name_ok = 0;
    CHECK(ech_witness_transport_proof(t) == 0);  /* чужое имя сертификата */
    t->ver.name_ok = 1; strcpy(t->ech_origin, "cloudflare-ech.com");
    CHECK(ech_witness_transport_proof(t) == 0);  /* без свидетеля challenge — цели */
    strcpy(t->ech_origin, "romfea.gr"); t->ech_offer = 0;
    CHECK(ech_witness_transport_proof(t) == 0);  /* не ECH — обычный challenge */
    t->ech_offer = 1; t->ech_replay = 1;
    CHECK(ech_witness_transport_proof(t) == 0);  /* повтор байтов клиента — иной путь */
    t->ech_replay = 0; t->ver.level = D2K_VER_HANDSHAKE; t->ver.cloudflare_challenge = 0;
    CHECK(ech_witness_transport_proof(t) == 0);  /* рукопожатие без ответа — не проход */
    task_reset(s, t);
}

/* Поле 17.10.2026, RR3-ech1-1: под планами из перебора рукопожатие с принятым
   ECH проходит, свидетель kinozal.me отвечает 200, а тело обрывается около
   21 КБ — объёмный обрыв. Его надо считать измеренным RX-обрывом и включать
   лестницу белого имени, иначе кандидаты кончаются без плана. */
static void ech_witness_body_cut_is_rx_cut(d2k_sched *s) {
    task *t = fixture(s);
    strcpy(t->name, "cloudflare-ech.com"); strcpy(t->ech_origin, "kinozal.me");
    t->transport = 6; t->ech_offer = 1; t->ech_replay = 0;
    memset(&t->ver, 0, sizeof t->ver);
    t->ver.level = D2K_VER_TRANSPORT; t->ver.ech_accepted = 1; t->ver.name_ok = 1;
    t->ver.status = 200; t->ver.body_bytes = 21300; t->ver.body_expected = 0;
    t->ver.body_complete = 0; t->ver.body_framing_valid = 1;
    CHECK(ech_witness_rx_cut(t) == 1);
    t->ver.body_complete = 1;
    CHECK(ech_witness_rx_cut(t) == 0);   /* тело целиком — обрыва нет */
    t->ver.body_complete = 0; t->ver.body_bytes = 900;
    CHECK(ech_witness_rx_cut(t) == 0);   /* 900 байт — не объёмный обрыв */
    t->ver.body_bytes = 21300; t->ver.ech_accepted = 0;
    CHECK(ech_witness_rx_cut(t) == 0);   /* ECH не принят */
    t->ver.ech_accepted = 1; t->ver.status = 0;
    CHECK(ech_witness_rx_cut(t) == 0);   /* HTTP не разобран */
    t->ver.status = 200; strcpy(t->ech_origin, "cloudflare-ech.com");
    CHECK(ech_witness_rx_cut(t) == 0);   /* без свидетеля */
    task_reset(s, t);
}

/* Поле 17.10.2026, LR-rx4-1: свидетель romfea.gr отвечает через принятый ECH
   страницей проверки Cloudflare (403, 3,6 КБ). Проход ECH она доказывает, а
   обрыв на ~16 КБ на ней не случится: план перебора, снимающий только
   рукопожатие, подтверждался, и Chrome резался у шести сайтов.
   mode 0 — в списке есть другой свидетель (kinozal.me): тот же кандидат,
   следующего свидетеля выберет рабочий поток VERIFY; отчёт поиска открыт,
   список и курсор кандидатов те же (ревью Astra п.1, п.3);
   mode 1 — другого нет; mode 2 — другой тоже отвечал проверкой: ни
   подтверждения, ни паузы, кандидат не измерен (ревью Astra п.2). */
static void ech_challenge_witness(d2k_sched *s, int mode) {
    task *t = fixture(s);
    strcpy(t->name, "cloudflare-ech.com"); strcpy(t->ech_origin, "romfea.gr");
    t->transport = 6; t->ech_offer = 1; t->ech_replay = 0;
    strcpy(t->ech_witnesses[t->ech_witness_count++], "romfea.gr");
    ech_rr_store(s, "romfea.gr", 1, "cloudflare-ech.com");
    if (mode != 1) {
        strcpy(t->ech_witnesses[t->ech_witness_count++], "kinozal.me");
        ech_rr_store(s, "kinozal.me", 1, "cloudflare-ech.com");
    }
    if (mode == 2) ech_chal_add(s, "kinozal.me");
    snprintf(t->plans[0], sizeof t->plans[0], "%s", "tcp split pos=1");
    snprintf(t->plans[1], sizeof t->plans[1], "%s", "tcp split pos=2");
    t->n_plans = 2; t->next_plan = 1;
    memset(&t->ver, 0, sizeof t->ver);
    t->ver.fd = -1;
    t->ver.level = D2K_VER_CHALLENGE; t->ver.cloudflare_challenge = 1;
    t->ver.ech_accepted = 1; t->ver.name_ok = 1; t->ver.body_complete = 1; t->ver.status = 403;
    t->state = T_VERIFY; t->res_ready = 1;
    s->sync_pending = 0;
    capture_spawn = 1;
    (void)d2k_sched_tick(s, 900);
    capture_spawn = 0;
    t->th_live = 0; /* подменённое создание: потока нет, не присоединять */
    CHECK(strstr(rows, "ПОДТВЕРЖДЕНО") == NULL);
    CHECK(strstr(rows, "проход ECH через коробку доказан") == NULL);
    CHECK(strstr(rows, "антибот-ответ") == NULL);
    CHECK(ech_chal_has(s, "romfea.gr"));
    if (mode == 0) {
        CHECK(strstr(rows, "тот же кандидат проверяю через другого свидетеля") != NULL);
        CHECK(t->ech_reselect == 1);
        /* Тот же кандидат: курсор вернулся на него, установка — следующим тактом. */
        CHECK(t->n_plans == 2 && t->next_plan == 0 && t->state == T_PLANNING);
        CHECK(!strcmp(t->plans[0], "tcp split pos=1") && !strcmp(t->plans[1], "tcp split pos=2"));
        CHECK(!t->report_closed);
        rows[0] = 0;
        search_report(s, t, 901, "probe-confirmed", "property");
        CHECK(strstr(rows, "outcome=probe-confirmed") != NULL);
    } else {
        CHECK(strstr(rows, "через другого свидетеля") == NULL);
        /* Проверять объём нечем: кандидаты не оцениваются, поиск закрыт
           неубедительным (ревью Astra R2), без паузы антибота. */
        CHECK(strstr(rows, "объём ответа измерить нечем") != NULL);
        CHECK(strstr(rows, "outcome=inconclusive") != NULL);
        CHECK(!t->ech_reselect);
    }
    if (fails) fprintf(stderr, "%s\n", rows);
    memset(s->ech_chal, 0, sizeof s->ech_chal);
    memset(s->ech_rr, 0, sizeof s->ech_rr); s->ech_rr_next = 0;
    task_reset(s, t);
}

/* Ревью Astra rx6: следующего свидетеля выбирает рабочий поток VERIFY по
   необходимости; исключение — по результату (RR не та, страница проверки),
   не по счёту. mode 0 — подходящий третий после двух неподходящих; mode 1 —
   подходящих не осталось: зонда нет, кандидат не измерен. */
static void verify_reselects_witness(d2k_sched *s, int mode) {
    task *t = fixture(s);
    strcpy(t->name, "cloudflare-ech.com"); strcpy(t->ech_origin, "primary.example");
    t->transport = 6; t->ech_offer = 1; t->ech_reselect = 1; t->job = JOB_VERIFY;
    strcpy(t->ech_witnesses[t->ech_witness_count++], "primary.example");
    ech_rr_store(s, "primary.example", 1, t->name);
    ech_chal_add(s, "primary.example");
    strcpy(t->ech_witnesses[t->ech_witness_count++], "bad1.example");
    strcpy(t->ech_witnesses[t->ech_witness_count++], "bad2.example");
    if (mode == 0) strcpy(t->ech_witnesses[t->ech_witness_count++], "third.example");
    rr_queries = 0; probe_calls = 0; probed_origin[0] = 0;
    d2k_sched_ech_resolve_hook = summary_resolve;
    worker_arg *arg = calloc(1, sizeof *arg);
    arg->s = s; arg->t = t; arg->use_fd = -1;
    worker_run(arg);
    CHECK(!t->ech_reselect);
    if (mode == 0) {
        CHECK(probe_calls == 1 && !strcmp(probed_origin, "third.example"));
        CHECK(!strcmp(t->ech_origin, "third.example"));
        CHECK(rr_queries == 3);
    } else {
        CHECK(probe_calls == 0);
        CHECK(!strcmp(t->ech_origin, "primary.example"));
        CHECK(t->ver.level == D2K_VER_HANDSHAKE && strstr(t->ver.reason, "не осталось"));
        /* Следующий кандидат относится к той же задаче, но не помечен для повторного выбора. */
        worker_arg *next = calloc(1, sizeof *next);
        next->s = s; next->t = t; next->use_fd = -1;
        worker_run(next);
        CHECK(probe_calls == 0);
        fprintf(stderr, "после исчерпания: зондов=%d, источник=%s\n", probe_calls, probed_origin);
    }
    if (fails) fprintf(stderr, "режим повтора=%d, источник=%s, проверен=%s, RR=%d\n%s\n",
        mode, t->ech_origin, probed_origin, rr_queries, rows);
    d2k_sched_ech_resolve_hook = d2k_ech_resolve;
    memset(s->ech_chal, 0, sizeof s->ech_chal);
    memset(s->ech_rr, 0, sizeof s->ech_rr); s->ech_rr_next = 0;
    task_reset(s, t);
}

/* Поле 17.10.2026, LR-rx5-2/rx6-1/rx6-2: у spzh.eu RX-проба получает 403
   (4540 Б), измерен только обрыв ИСХОДЯЩЕЙ лестницы ~19 КБ. Лестница белого
   имени открывалась только RX-обрывом: если spzh искался раньше, чем сеть
   подобрала 9gag.com на соседнем сайте, — перебор и «лучший частичный» план по
   403, Safari стоял; позже — свой план коробки, Safari открывался (rx5-1).
   Обрыв той же коробки в другую сторону — тот же вопрос имени. */
static void tx_cut_opens_white_ladder(d2k_sched *s, int known) {
    task *t = fixture(s);
    strcpy(t->name, "spzh.eu");
    CHECK(d2k_hello_from_profile(D2K_SHAPE_MODERN, "spzh.eu", t->trig, sizeof t->trig,
                                 &t->trig_len) == 0);
    t->vol.verdict = D2K_VOL_CUT; t->vol.at_kb = 19; t->vol.rx_cut = 0;
    snprintf(s->cat->net.name, sizeof s->cat->net.name, "%s", known ? "9gag.com" : "");
    s->cat->net.searched = known;
    d2k_vres r; memset(&r, 0, sizeof r); r.verdict = D2K_V_INCONCLUSIVE;
    verdict_to_plans(s, t, &r);
    char want[sizeof t->plans[0]];
    CHECK(d2k_rx_volume_plan_named(0, D2K_SHAPE_MODERN, s->send_cap,
                                   known ? "9gag.com" : d2k_net_whitelist_name(0),
                                   want, sizeof want) == 0);
    CHECK(t->n_plans > 0 && !strcmp(t->plans[0], want));
    if (!known) CHECK(t->net_probing);
    if (fails) fprintf(stderr, "%s\n", rows);
    s->cat->net.name[0] = 0; s->cat->net.searched = 0;
    task_reset(s, t);
}

static void challenge_exclusions_survive_cache_eviction(d2k_sched *s) {
    task *t = fixture(s);
    strcpy(t->name, "cloudflare-ech.com");
    int seen[10] = {0};
    for (int i = 0; i < 10; i++) {
        snprintf(t->ech_witnesses[i], sizeof t->ech_witnesses[i], "w%d.example", i);
        ech_rr_store(s, t->ech_witnesses[i], 1, t->name);
    }
    t->ech_witness_count = 10;
    for (int step = 0; step < 10; step++) {
        t->ech_origin[0] = 0;
        CHECK(ech_pick_witness(s, t, 1, 0));
        int chosen = -1;
        CHECK(sscanf(t->ech_origin, "w%d.example", &chosen) == 1);
        CHECK(chosen >= 0 && chosen < 10);
        if (chosen < 0 || chosen >= 10) break;
        fprintf(stderr, "шаг проверки=%d, выбран=%s, уже проверялся=%d\n", step, t->ech_origin, seen[chosen]);
        CHECK(!seen[chosen]);
        seen[chosen] = 1;
        ech_witness_reject(s, t); /* главный поток при ответе-проверке */
    }
    memset(s->ech_chal, 0, sizeof s->ech_chal); s->ech_chal_next = 0;
    memset(s->ech_rr, 0, sizeof s->ech_rr); s->ech_rr_next = 0;
    task_reset(s, t);
}

extern int pthread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
static void *finished_worker(void *arg) { return arg; }

static void tx_ladder_requires_volume_proof(int passed) {
    d2k_catalog cat = {0};
    d2k_sched *s = d2k_sched_new(&cat, -1, 0x2d);
    d2k_sched_set_say(s, collect, NULL);
    task *t = fixture(s);
    strcpy(t->name, "spzh.eu");
    CHECK(d2k_hello_from_profile(D2K_SHAPE_MODERN, t->name, t->trig,
        sizeof t->trig, &t->trig_len) == 0);
    t->trig_snapped = 1;
    t->vol.verdict = D2K_VOL_CUT; t->vol.at_kb = 19;
    d2k_vres r = {0}; r.verdict = D2K_V_INCONCLUSIVE;
    verdict_to_plans(s, t, &r);
    CHECK(t->n_plans > 0 && t->net_probing);
    t->next_plan = 1;
    t->state = T_VERIFY; t->res_ready = 1;
    memset(&t->ver, 0, sizeof t->ver); t->ver.fd = -1;
    t->ver.level = D2K_VER_APPLICATION; t->ver.name_ok = 1;
    t->ver.status = 403; t->ver.body_bytes = t->ver.body_expected = 4540;
    t->ver.body_complete = t->ver.body_framing_valid = 1;
    t->ver.budget = passed ? D2K_BUDGET_PASSED : D2K_BUDGET_NOT_APPLICABLE;
    t->ver.conn_close = !passed;
    t->ver.budget_packets = passed ? 51 : 6; t->ver.budget_need = 50;
    t->ver.local_port = 55001;
    inet_pton(AF_INET, "127.0.0.2", t->ver.local_ip4);
    /* Уже подтверждённый APPLIED сохранён именно для этого потока проверки. */
    t->ver_seen = 1;
    t->ver_early[0].family = 4; t->ver_early[0].transport = 6;
    memcpy(t->ver_early[0].a_ip, t->ver.local_ip4, 4);
    inet_pton(AF_INET, t->ip, t->ver_early[0].b_ip);
    t->ver_early[0].a_port = t->ver.local_port; t->ver_early[0].b_port = t->port;
    task *direct = &s->tasks[1];
    if (passed) {
        memset(direct, 0, sizeof *direct);
        direct->prop_fd = direct->prop_q = direct->probe_fd = direct->ver.fd = direct->c_fd = -1;
        strcpy(direct->name, "spzh.eu"); strcpy(direct->ip, "127.0.0.3");
        direct->transport=6; direct->family=4; direct->port=443;
        CHECK(d2k_hello_from_profile(D2K_SHAPE_MODERN, direct->name, direct->trig,
            sizeof direct->trig, &direct->trig_len)==0);
        direct->trig_snapped=1; direct->own_first=3; direct->state=T_ASKING;
        direct->res.verdict=D2K_V_CLEAR; direct->res_ready=1;
        direct->vol.verdict=D2K_VOL_PASSED; direct->vol.rx_direct_complete=1;
        /* Результат пришёл после предыдущего запроса уступить. Короткий полный
           ответ RX не означает измеренный обрыв: исходящая лестница и рукопожатие прошли. */
        if (getenv("REVIEW_SHORT_RX")) {
            direct->vol.rx_short=1;
            direct->vol.rx_short_bytes=243;
            direct->vol.rx_direct_complete=0;
        }
        direct->yield_to_own_plan=1;
        direct->stop=1;
        direct->report_id=++s->report_sequence; direct->report_admitted_ms=100;
        direct->started_ms=100;
        CHECK(pthread_create(&direct->th, NULL, finished_worker, NULL)==0);
        direct->th_live=1;
    }
    s->sync_pending = 0;
    (void)d2k_sched_tick(s, 900);
    if(passed) {
        fprintf(stderr, "после подтверждения соседней цели CLEAR: состояние=%d, свой план первым=%d, планов=%zu\n", direct->state,direct->own_first,direct->n_plans);
        CHECK(direct->state != T_PLANNING);
        CHECK(strstr(rows,"outcome=probe-direct") != NULL);
    }
    fprintf(stderr, "исходящий обрыв + короткий 403: бюджет пройден=%d, сеть=%s, поиск=%d\n%s\n", passed, cat.net.name, cat.net.searched, rows);
    CHECK((cat.net.name[0] != 0) == passed);
    CHECK((cat.net.searched != 0) == passed);
    CHECK((strstr(rows, "outcome=probe-confirmed") != NULL) == passed);
    d2k_sched_free(s); d2k_catalog_free(&cat);
}

static void measurement_absence_is_retryable(d2k_sched *s) {
    task *t = fixture(s);
    t->state = T_ASKING;
    t->res_ready = 1;
    t->res.verdict = D2K_V_FLAKY;
    t->res.dial_deadline = 1;
    snprintf(t->res.reason, sizeof t->res.reason, "замер не состоялся: адрес не принимал соединения");
    s->sync_pending = 0;
    (void)d2k_sched_tick(s, 900);
    int64_t left = 0;
    CHECK(strstr(rows, "outcome=unknown") != NULL);
    CHECK(!cooldown_blocks(s, t->name, t->transport, t->family, t->ip, t->port,
                           D2K_SUSPECT_RST, &left, NULL));
    task_reset(s, t);

    t = fixture(s);
    t->state = T_ASKING; t->res_ready = 1; t->res.verdict = D2K_V_FLAKY;
    snprintf(t->res.reason, sizeof t->res.reason, "замер не состоялся: адрес не принимал соединения");
    s->sync_pending = 0; rows[0] = '\0';
    (void)d2k_sched_tick(s, 900);
    CHECK(strstr(rows, "outcome=inconclusive path=none") != NULL);
    task_reset(s, t);
}

static void quic_shape_does_not_cancel_tcp_measurement(d2k_sched *s) {
    task *t = fixture(s);
    strcpy(t->name, "pack.cross.example");
    t->transport = 6;
    t->state = T_ASKING;
    uint8_t d1[1500], d2[1500];
    size_t l1 = 0, l2 = 0;
    CHECK(d2k_test_pq_initials(t->name, d1, &l1, d2, &l2) == 0);
    const uint8_t *dg[2] = {d1, d2};
    size_t len[2] = {l1, l2};
    d2k_ev q = {0};
    q.kind = D2K_EV_SHAPE; q.transport = 17; q.family = 4;
    q.shape_len = d2k_qsnap_pack(dg, len, 2, q.shape, sizeof q.shape);
    CHECK(q.shape_len > 0);
    on_shape(s, &q);
    CHECK(!t->stop && !t->snap_len);
    task_reset(s, t);
}

int main(void) {
    d2k_catalog cat = {0};
    d2k_sched *s = d2k_sched_new(&cat, -1, 0x2d);
    CHECK(s != NULL);
    if (!s) return 1;
    d2k_sched_set_say(s, collect, NULL);
    challenge_exclusions_survive_cache_eviction(s);
    tx_ladder_requires_volume_proof(0);
    tx_ladder_requires_volume_proof(1);
    ech_witness_challenge_is_transport_proof(s);
    ech_witness_body_cut_is_rx_cut(s);
    for (int mode = 0; mode < 3; mode++) ech_challenge_witness(s, mode);
    for (int mode = 0; mode < 2; mode++) verify_reselects_witness(s, mode);
    tx_cut_opens_white_ladder(s, 1);
    tx_cut_opens_white_ladder(s, 0);
    quic_shape_does_not_cancel_tcp_measurement(s);
    measurement_absence_is_retryable(s);
    for(int ladder=0;ladder<2;ladder++) {
        task *q=fixture(s);q->transport=17;q->arm.original=1;q->arm_ready=1;
        q->arm.kind=ladder?D2K_QA_COPIES:D2K_QA_UDPLEN;
        q->arm.strategy=ladder?D2K_QS_LADDER:D2K_QS_LENGTH;
        if(ladder){q->arm.bytes[0]=0x40;q->arm.len=1;q->arm.copies=1;}
        else q->arm.udplen=D2K_QUIC_LENGTH_INCREMENT;
        d2k_vres result={.verdict=D2K_V_OPAQUE};
        verdict_to_plans(s,q,&result);CHECK(q->n_plans==1);
        q->next_plan=1;
        CHECK(!strcmp(candidate_path(q),ladder?"перебор":"свойство"));
        search_report(s,q,900,"probe-confirmed",NULL);
        CHECK(strstr(rows,ladder?"path=fallback":"path=property"));
    }
    task *t = fixture(s);
    /* Real launch → pthread_create failure → reset used to lose the report. */
    CHECK(launch_task(s, t) == 0);
    CHECK(strstr(rows, "итог поиска:") != NULL);
    CHECK(strstr(rows, "elapsed_ms=800 queue_ms=150") != NULL);

    t = fixture(s);
    task_done(s, t); /* cancellation while requeued, without launch */
    CHECK(strstr(rows, "elapsed_ms=800 queue_ms=150") != NULL);

    t = fixture(s);
    t->state = T_VOICE_MEASURE; t->transport = 17;
    t->voice_res.verdict = D2K_VOICE_CLEAR;
    voice_finish_measure(s, t, s->now_ms);
    CHECK(strstr(rows, "outcome=probe-direct path=direct") != NULL);
    CHECK(strstr(rows, "outcome=failed") == NULL);

    t = fixture(s);
    t->state = T_VOICE_MEASURE; t->transport = 17;
    t->voice_res.verdict = D2K_VOICE_CLEAR;
    t->voice_known_prefix_valid = 1;
    voice_finish_measure(s, t, s->now_ms);
    CHECK(strstr(rows, "outcome=probe-clear path=unknown") != NULL);
    CHECK(strstr(rows, "path=own-plan") == NULL);

    t = fixture(s);
    t->state = T_ASKING; t->rx_volume_only = 1; t->res_ready = 1;
    t->res.verdict = D2K_V_CLEAR; t->vol.rx_cut = 0;
    s->sync_pending = 0;
    (void)d2k_sched_tick(s, 900);
    CHECK(strstr(rows, "outcome=inconclusive path=none") != NULL);
    CHECK(strstr(rows, "outcome=failed") == NULL);

    /* Поле 17.10.2026, LR-rx8-1, rua.gr: позднее закрытие, исходящая лестница
       оборвалась (~19 КБ), RX-проба ничего не измерила (ответ встал на 4,5 КБ).
       Доказанный обрыв лестницы пустым RX не отменяется: поиск продолжается,
       а не уходит в «не подтвердилось» и покой на 10 минут. */
    t = fixture(s);
    t->state = T_ASKING; t->rx_volume_only = 1; t->res_ready = 1;
    t->res.verdict = D2K_V_INCONCLUSIVE;
    t->vol.verdict = D2K_VOL_CUT; t->vol.at_kb = 19; t->vol.rx_cut = 0;
    s->sync_pending = 0;
    (void)d2k_sched_tick(s, 900);
    CHECK(strstr(rows, "позднее закрытие не подтвердилось") == NULL);
    CHECK(strstr(rows, "исходящая лестница оборвалась около 19 КБ") != NULL);
    CHECK(strstr(rows, "пакетный бюджет потока: identity") == NULL);
    if (fails) fprintf(stderr, "%s\n", rows);
    task_reset(s, t);

    /* Поздний RX без подтверждённого 2xx не даёт исхода probe-direct. */
    t = fixture(s);
    t->state = T_ASKING; t->transport = 6;
    t->trigger_code = D2K_SUSPECT_RST_AFTER_APP; t->res_ready = 1;
    t->res.verdict = D2K_V_CLEAR; t->vol.verdict = D2K_VOL_PASSED;
    t->vol.rx_unmeasured = 1;
    s->sync_pending = 0; rows[0] = '\0';
    (void)d2k_sched_tick(s, 900);
    CHECK(strstr(rows, "outcome=inconclusive path=none") != NULL);
    CHECK(strstr(rows, "outcome=probe-direct") == NULL);
    CHECK(strstr(rows, "объём ответа измерить не удалось; прямой замер не подтверждён") != NULL);
    task_reset(s, t);

    /* Завершённый не-2xx выше полосы тоже не подтверждает прямой прикладной успех. */
    t = fixture(s);
    t->state = T_ASKING; t->transport = 6;
    t->trigger_code = D2K_SUSPECT_RST_AFTER_APP; t->res_ready = 1;
    t->res.verdict = D2K_V_CLEAR; t->vol.verdict = D2K_VOL_PASSED;
    s->sync_pending = 0; rows[0] = '\0';
    (void)d2k_sched_tick(s, 900);
    CHECK(strstr(rows, "outcome=inconclusive path=none") != NULL);
    CHECK(strstr(rows, "outcome=probe-direct") == NULL);
    CHECK(strstr(rows, "прямой ответ не подтвердил прикладной успех; прямой замер не подтверждён") != NULL);
    task_reset(s, t);

    /* RX-пара с завершённым прикладным 2xx подтверждает прямой проход. */
    t = fixture(s);
    t->state = T_ASKING; t->transport = 6;
    t->trigger_code = D2K_SUSPECT_RST_AFTER_APP; t->res_ready = 1;
    t->res.verdict = D2K_V_CLEAR; t->vol.verdict = D2K_VOL_PASSED;
    t->vol.rx_direct_complete = 1;
    s->sync_pending = 0; rows[0] = '\0';
    (void)d2k_sched_tick(s, 900);
    CHECK(strstr(rows, "outcome=probe-direct path=direct") != NULL);
    task_reset(s, t);

    /* ЗАДАЧА 26, П.3: ДОКАЗАННЫЙ ПУТЬ ПЕРЕЖИВАЕТ ЭПИЗОД. Поле 12.10.2026,
       style.sndcdn.com: обрыв доказывает повтор зонда по /css/soehne-*.css, а
       следующий эпизод снова просил «/» и получал завершённый 403 на 243
       байта — измерения не было, цель уходила в покой. Сохранённый
       ДОКАЗАННЫЙ путь обязан идти первым и не вытесняться более поздней
       HTML-подсказкой того же имени: подсказка — только упоминание, а здесь
       обрыв ИЗМЕРЕН. */
    {
        const char *name = "style.cdn-vol.test";
        t = fixture(s);
        snprintf(t->ip, sizeof t->ip, "8.8.8.8");
        snprintf(t->name, sizeof t->name, "%s", name);
        t->port = 443; t->transport = 6; t->family = 4;
        t->state = T_ASKING; t->res_ready = 1; t->rx_volume_only = 1;
        t->res.verdict = D2K_V_CLEAR;
        t->vol.rx_cut = 1; t->vol.rx_at_kb = 15; t->vol.rx_compressed_complete = 1;
        snprintf(t->vol.measured_path, sizeof t->vol.measured_path, "/css/soehne-web.css");
        snprintf(t->measure_path, sizeof t->measure_path, "/css/soehne-web.css");
        s->sync_pending = 0;
        (void)d2k_sched_tick(s, 900); /* главный поток разбирает исход замера */
        /* Ни подсказок, ни подтверждённой привязки: единственное, что известно
           об этом имени, — доказанный обрыв на названном пути. Начинать заново
           с «/» значит выбросить измерение. */
        task *again = fixture(s);
        snprintf(again->ip, sizeof again->ip, "8.8.8.8");
        snprintf(again->name, sizeof again->name, "%s", name);
        again->port = 443; again->transport = 6; again->family = 4;
        select_resource_path(s, again);
        CHECK(!strcmp(again->measure_path, "/css/soehne-web.css"));
        if (strcmp(again->measure_path, "/css/soehne-web.css"))
            fprintf(stderr, "без подсказок эпизод спрашивает \"%s\" (пусто — «/») "
                            "вместо доказанного /css/soehne-web.css\n", again->measure_path);
        /* Позже HTML соседнего хоста назвал этот же хост другим ресурсом. */
        d2k_resource hint;
        memset(&hint, 0, sizeof hint);
        snprintf(hint.host, sizeof hint.host, "%s", name);
        snprintf(hint.path, sizeof hint.path, "/mentioned/only.css");
        remember_resources(s, &hint, 1);
        /* Следующий эпизод того же имени. */
        task *next = fixture(s);
        snprintf(next->ip, sizeof next->ip, "8.8.8.8");
        snprintf(next->name, sizeof next->name, "%s", name);
        next->port = 443; next->transport = 6; next->family = 4;
        select_resource_path(s, next);
        CHECK(!strcmp(next->measure_path, "/css/soehne-web.css"));
        if (strcmp(next->measure_path, "/css/soehne-web.css"))
            fprintf(stderr, "следующий эпизод спрашивает \"%s\" вместо "
                            "доказанного /css/soehne-web.css\n", next->measure_path);
    }

    /* ЗАДАЧА 26, П.4: ПОДСКАЗКА ИЗ ПАМЯТИ ПЛАНИРОВЩИКА. Хост, отдающий 403/401
       на любой путь, подсказку о своих ресурсах не даёт НИКОГДА: verify.c
       собирает их только из завершённого 2xx text/html. Значит путь берётся из
       уже наблюдавшихся по этой цели — здесь свидетель привязки (/witness.css)
       успел устареть и тоже ничего не измерил, а в памяти лежит ресурс
       /observed.css, увиденный в чужом HTML. Один повтор по названной причине
       «мерить было нечем», только наблюдавшийся путь, и тот же
       d2k_resource_path_ok. */
    {
        const char *name = "assets.cdn-vol.test";
        cat.boxes = calloc(1, sizeof *cat.boxes);
        CHECK(cat.boxes != NULL);
        if (cat.boxes) {
            cat.n_boxes = 1;
            snprintf(cat.boxes[0].id, sizeof cat.boxes[0].id, "box-vol-26");
            cat.boxes[0].binds = calloc(1, sizeof *cat.boxes[0].binds);
            CHECK(cat.boxes[0].binds != NULL);
            cat.boxes[0].n_binds = cat.boxes[0].binds ? 1 : 0;
        }
        if (cat.n_boxes && cat.boxes[0].n_binds) {
            d2k_cat_binding *bd = &cat.boxes[0].binds[0];
            snprintf(bd->kind, sizeof bd->kind, "name");
            snprintf(bd->target, sizeof bd->target, "%s", name);
            snprintf(bd->plan_id, sizeof bd->plan_id, "00000000000000000000000000000026");
            snprintf(bd->probe_path, sizeof bd->probe_path, "/witness.css");
            bd->level = 3; bd->enabled = 1; bd->confirmed = 100;
            bd->transport = 6; bd->family = 4; bd->shape = (uint8_t)D2K_SHAPE_MODERN;
        }
        d2k_resource seen;
        memset(&seen, 0, sizeof seen);
        snprintf(seen.host, sizeof seen.host, "%s", name);
        snprintf(seen.path, sizeof seen.path, "/observed.css");
        remember_resources(s, &seen, 1);
        t = fixture(s);
        snprintf(t->ip, sizeof t->ip, "8.8.8.8");
        snprintf(t->name, sizeof t->name, "%s", name);
        t->port = 443; t->transport = 6; t->family = 4;
        CHECK(d2k_hello_from_profile(D2K_SHAPE_MODERN, name, t->trig,
                                     sizeof t->trig, &t->trig_len) == 0);
        select_resource_path(s, t);
        CHECK(!strcmp(t->measure_path, "/witness.css"));
        d2k_sched_vol_path_hook = stub_vol_path;
        d2k_sched_vol_hook = stub_vol_root;
        vol_cut_path = "/observed.css";
        vol_asks = 0;
        d2k_hello trig;
        trig.bytes = t->trig; trig.len = t->trig_len;
        worker_volume(s, t, trig);
        CHECK(vol_asks == 2 && !strcmp(vol_asked[0], "/witness.css") &&
              !strcmp(vol_asked[1], "/observed.css"));
        CHECK(t->vol.rx_cut && !strcmp(t->measure_path, "/observed.css"));
        if (vol_asks != 2 || !t->vol.rx_cut)
            fprintf(stderr, "замеров %d (первый \"%s\", второй \"%s\"), rx_cut=%d, "
                            "путь кандидата \"%s\"\n",
                    vol_asks, vol_asked[0], vol_asks > 1 ? vol_asked[1] : "-",
                    t->vol.rx_cut, t->measure_path);
        d2k_sched_vol_path_hook = d2k_volume_probe_path;
        d2k_sched_vol_hook = d2k_volume_probe;
        vol_cut_path = NULL;
    }
    /* ЗАЩИТА ОТ ВБРОШЕННОГО СБРОСА ПРОСИТСЯ ПО ИЗМЕРЕННОМУ ПОВОДУ.
     * Поле 13.10.2026, forum.ru-board.com: рукопожатие снято, план применён
     * ко всем 133 потокам, сервер ответил всем, и коробка вбросила сброс в
     * 132 — TTL 127 против 55–57 у сервера, каждый В ОКНО. Строку
     * `guard rst_alien` не выдавал ни один сборщик, и реализованная в
     * датапате защита не включалась никогда. */
    {
        char text[512];
        task probe;
        memset(&probe, 0, sizeof probe);
        probe.transport = 6;
        probe.trigger_code = D2K_SUSPECT_RST;
        CHECK(rst_guard_wanted(&probe));
        probe.trigger_code = D2K_SUSPECT_RST_AFTER_APP;
        CHECK(rst_guard_wanted(&probe));
        probe.trigger_code = D2K_SUSPECT_RST_CUT;
        CHECK(rst_guard_wanted(&probe));
        /* Тишина и объём поводом не являются. */
        probe.trigger_code = D2K_SUSPECT_SILENT;
        CHECK(!rst_guard_wanted(&probe));
        /* QUIC — другой транспорт: там нет TCP-сброса. */
        probe.trigger_code = D2K_SUSPECT_RST; probe.transport = 17;
        CHECK(!rst_guard_wanted(&probe));

        snprintf(text, sizeof text, "d2k-plan 1 5\nproto tcp tls\n");
        CHECK(plan_arm_rst_guard(text, sizeof text) == 1);
        CHECK(strstr(text, "guard rst_alien\n") != NULL);
        /* Второй раз не дописывается. */
        CHECK(plan_arm_rst_guard(text, sizeof text) == 0);
        /* Текст остаётся годным планом: защита уезжает в провод записью. */
        uint8_t tlv[D2K_PLAN_TLV_MAX]; size_t tlv_len = 0; char err[200];
        CHECK(d2k_plan_text_to_tlv(text, tlv, sizeof tlv, &tlv_len, err, sizeof err) == 0);
        int found = 0;
        for (size_t at = 12; at + 4 <= tlv_len;) {
            unsigned rec = ((unsigned)tlv[at] << 8) | tlv[at + 1];
            size_t sz = ((size_t)tlv[at + 2] << 8) | tlv[at + 3];
            at += 4;
            if (sz > tlv_len - at) { break; }
            if (rec == 0x0104 && sz == 1 && tlv[at] == 1) { found = 1; }
            at += sz;
        }
        CHECK(found);
        /* ПОВОД ДЛЯ КЛИЕНТСКИХ ПРИВЯЗОК — ИЗМЕРЕННАЯ ПРИМЕТА КОРОБКИ.
         * Зонд судит по своему триггеру, а привязка в каталоге живёт дольше
         * задачи: её повод — примета «rst» в отпечатке коробки, записанная
         * тем же замером. */
        d2k_cat_box box;
        memset(&box, 0, sizeof box);
        CHECK(!box_injects_rst(&box));
        box.fp.n_sig = 2;
        snprintf(box.fp.sig[0].kind, sizeof box.fp.sig[0].kind, "%s", "volume");
        snprintf(box.fp.sig[1].kind, sizeof box.fp.sig[1].kind, "%s", "silent");
        CHECK(!box_injects_rst(&box));
        snprintf(box.fp.sig[1].kind, sizeof box.fp.sig[1].kind, "%s", "rst");
        CHECK(box_injects_rst(&box));
        CHECK(!box_injects_rst(NULL));

        /* Не поместилась — план идёт как был, а не теряется. */
        char tight[40];
        snprintf(tight, sizeof tight, "d2k-plan 1 5\nproto tcp tls\n");
        CHECK(plan_arm_rst_guard(tight, strlen(tight) + 4) == 0);
    }

    d2k_sched_free(s);
    d2k_catalog_free(&cat);
    if (fails) fprintf(stderr, "summary: %d failures\n", fails);
    return fails ? 1 : 0;
}
