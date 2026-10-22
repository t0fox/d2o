/* Exercise production TX/RX sequencing. TCP is localhost-only; TLS and
 * baseline replies are deterministic, so no public service is probed. */
#include "volume.c"

static int failures, legacy_calls, modern_calls, baseline_calls;
static int expected_legacy;
static const char *expected_path;
static size_t expected_wire;
static int mark_calls;
static int repeat_missing, opaque_reply, unmeasured_rx, early_rx, full_non_2xx;
/* Поле 12.10.2026, www.tampermonkey.net: /style.css обрывается на линии восемь
   раз из восьми (15963 против 30182 с VPS), но ОДИН повтор зонда дошёл до
   конца. Шум линии не опровергает обрыв; третий прогон решает. */
static int noisy_second, third_also_full;
/* Поле 12.10.2026, CDN-хосты soundcloud: на единственный «/» style.sndcdn.com
   отдаёт завершённый 403 с телом 243 байта (то же и с VPS — так отвечает сам
   сервер), api-v2.soundcloud.com — 401 с пустым телом. До измеряемой полосы
   12 КБ таким ответам не хватает двух порядков, а НАСТОЯЩИЙ ресурс того же
   имени режется: /css/soehne-*.css — 301328 байт с VPS против 15985 с линии. */
static int short_then_hint, hint_status;
/* Что отдаёт подсказанный ресурс: 0 — обрыв, 1 — нет TLS, 2 — завершённый
   ответ ВЫШЕ полосы (настоящее отрицательное измерение). */
static int retry_outcome;
static const char *hint_host, *hint_for_path, *cut_path, *last_path;
static int expected_gzip_call = 2;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "volume-context:%d: %s\n", __LINE__, #c); failures++; } } while (0)

static int mark_ok(int fd, uint32_t mark) {
    (void)fd; CHECK(mark == 0x2f); mark_calls++; return 0;
}
d2k_mark_fn d2k_mark_hook = mark_ok;

int d2k_tls_connect(int fd, const char *sni, int ms, size_t wire,
                    d2k_tls **out, char *err, size_t cap) {
    (void)fd; (void)sni; (void)ms; *out = NULL;
    CHECK(!expected_legacy && wire == expected_wire); modern_calls++;
    snprintf(err, cap, "TX reset"); return -1;
}
int d2k_tls12_connect(int fd, const char *sni, int ms, size_t wire,
                      d2k_tls12 **out, char *err, size_t cap) {
    (void)fd; (void)sni; (void)ms; *out = NULL;
    CHECK(expected_legacy && wire == expected_wire); legacy_calls++;
    snprintf(err, cap, "TX reset"); return -1;
}
int d2k_tls_write(d2k_tls *t, const uint8_t *b, size_t n, char *e, size_t c) {
    (void)t; (void)b; (void)n; (void)e; (void)c; CHECK(0); return -1;
}
int d2k_tls12_write(d2k_tls12 *t, const uint8_t *b, size_t n, char *e, size_t c) {
    (void)t; (void)b; (void)n; (void)e; (void)c; CHECK(0); return -1;
}
long d2k_tls_read(d2k_tls *t, uint8_t *b, size_t n, int ms, char *e, size_t c) {
    (void)t; (void)b; (void)n; (void)ms; (void)e; (void)c; CHECK(0); return -1;
}
long d2k_tls12_read(d2k_tls12 *t, uint8_t *b, size_t n, int ms, char *e, size_t c) {
    (void)t; (void)b; (void)n; (void)ms; (void)e; (void)c; CHECK(0); return -1;
}
void d2k_tls_free(d2k_tls *t) { (void)t; CHECK(0); }
void d2k_tls12_free(d2k_tls12 *t) { (void)t; CHECK(0); }

d2k_ver_result d2k_verify_probe_baseline(const char *ip, uint16_t port,
    const char *sni, int ms, size_t wire, int legacy, int encoding, uint32_t mark) {
    (void)ip; (void)port; (void)ms;
    CHECK(strcmp(sni, "context.test") == 0 && legacy == expected_legacy &&
          wire == expected_wire && mark == 0x2f);
    CHECK(encoding == (baseline_calls == expected_gzip_call));
    d2k_ver_result r = {0};
    if (unmeasured_rx || early_rx) {
        r.fd = -1; r.level = D2K_VER_HANDSHAKE; r.name_ok = 1;
        r.negotiated_tls = expected_legacy ? 0x0303 : 0x0304;
        r.rx_tls_wire_bytes = 1400;
        if (early_rx) {
            r.status = 200; r.body_bytes = 4000;
        }
        baseline_calls++;
        return r;
    }
    if (full_non_2xx) {
        r.fd = -1; r.level = D2K_VER_APPLICATION; r.name_ok = 1;
        r.negotiated_tls = expected_legacy ? 0x0303 : 0x0304;
        r.status = 403; r.body_has_length = 1; r.body_framing_valid = 1;
        r.body_complete = 1; r.body_bytes = r.body_expected = 20000;
        r.rx_tls_wire_bytes = 20500;
        baseline_calls++;
        return r;
    }
    r.fd = -1; r.status = 200; r.body_has_length = 1;
    r.body_framing_valid = 1; r.body_expected = 96460;
    r.body_bytes = 23900 + baseline_calls * 10;
    if (encoding) {
        r.body_bytes = r.body_expected = 18000;
        r.body_complete = 1; r.body_encoding = 1;
    }
    if (noisy_second) {
        memset(&r, 0, sizeof r); r.fd = -1;
        r.status = 200; r.body_framing_valid = 1; r.body_chunked = 1;
        if (encoding) {
            r.body_bytes = r.body_expected = 6000;
            r.body_complete = 1; r.body_encoding = 1;
        } else if (baseline_calls == 1) {
            r.body_bytes = r.body_expected = 22094; r.body_complete = 1;
        } else {
            r.body_bytes = baseline_calls == 0 ? 15627 : 15963;
            if (third_also_full && baseline_calls == 2) {
                r.body_complete = 1; r.body_expected = r.body_bytes;
            }
        }
    }
    if (opaque_reply) {
        if (!encoding) {
            memset(&r, 0, sizeof r); r.fd = -1;
            r.level = D2K_VER_HANDSHAKE; r.name_ok = 1;
            r.negotiated_tls = expected_legacy ? 0x0303 : 0x0304;
            r.rx_tls_wire_bytes = 14005 + baseline_calls * 20;
            r.rx_tls_record_missing = 2384 - baseline_calls * 20;
        } else {
            r.level = D2K_VER_APPLICATION; r.name_ok = 1;
            r.negotiated_tls = expected_legacy ? 0x0303 : 0x0304;
            r.body_expected = r.body_bytes = 4000; r.rx_tls_wire_bytes = 4500;
        }
    }
    if (repeat_missing && baseline_calls == 1) {
        memset(&r, 0, sizeof r); r.fd = -1;
        snprintf(r.reason, sizeof r.reason, "incomplete TLS record");
    }
    if (short_then_hint) {
        /* Обрыв отдаёт только подсказанный ресурс (cut_path); на любом другом
           пути — завершённый ответ на два порядка меньше полосы. */
        int cut = cut_path && last_path && !strcmp(last_path, cut_path);
        memset(&r, 0, sizeof r); r.fd = -1;
        r.level = D2K_VER_APPLICATION; r.name_ok = 1; r.body_framing_valid = 1;
        r.status = 200;
        if (!cut) {
            r.status = hint_status; r.body_has_length = 1; r.body_complete = 1;
            r.body_bytes = r.body_expected = 243;
            if (hint_host) {
                snprintf(r.resources[0].host, sizeof r.resources[0].host, "%s", hint_host);
                snprintf(r.resources[0].path, sizeof r.resources[0].path, "%s", hint_for_path);
                r.n_resources = 1;
            }
        } else if (retry_outcome == 1) {
            r.status = 0; r.level = D2K_VER_TRANSPORT; r.body_framing_valid = 0;
            snprintf(r.reason, sizeof r.reason, "нет TLS: сброс");
        } else if (retry_outcome == 2) {
            r.body_has_length = 1; r.body_complete = 1;
            r.body_bytes = r.body_expected = 30182;
        } else if (encoding) {
            r.body_chunked = 1; r.body_encoding = 1; r.body_complete = 1;
            r.body_bytes = r.body_expected = 6000;
        } else {
            r.body_chunked = 1;
            r.body_bytes = baseline_calls == 1 ? 15985 : 15968;
        }
    }
    baseline_calls++;
    return r;
}
void d2k_verify_close(d2k_ver_result *r) { CHECK(r->fd == -1); }

d2k_ver_result d2k_verify_probe_path_on(int fd, const char *ip, uint16_t port,
    const char *sni, int ms, size_t wire, int legacy, int encoding,
    uint32_t mark, const char *path) {
    /* В опыте с подсказкой путь меняется по ходу замера, и сверять его с
       одним ожидаемым нельзя: он сам и есть предмет проверки (last_path). */
    CHECK(fd == -1 && (short_then_hint ||
          (expected_path ? path && !strcmp(path, expected_path) : !path)));
    last_path = path;
    return d2k_verify_probe_baseline(ip, port, sni, ms, wire, legacy, encoding, mark);
}

int main(void) {
    for (int family = 4; family <= 6; family += 2) {
    for (int legacy = 0; legacy <= 1; legacy++) {
    for (int resource = 0; resource <= 1; resource++) {
        int fd = socket(family == 6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
        struct sockaddr_storage addr = {0};
        socklen_t len;
        const char *ip;
        if (family == 6) {
            struct sockaddr_in6 *a = (struct sockaddr_in6 *)&addr;
            a->sin6_family = AF_INET6; a->sin6_addr = in6addr_loopback;
            len = sizeof *a; ip = "::1";
        } else {
            struct sockaddr_in *a = (struct sockaddr_in *)&addr;
            a->sin_family = AF_INET; a->sin_addr.s_addr = htonl(0x7f000001u);
            len = sizeof *a; ip = "127.0.0.1";
        }
        CHECK(fd >= 0 && bind(fd, (struct sockaddr *)&addr, len) == 0);
        CHECK(getsockname(fd, (struct sockaddr *)&addr, &len) == 0 && listen(fd, 2) == 0);
        uint16_t port = family == 6
            ? ntohs(((struct sockaddr_in6 *)&addr)->sin6_port)
            : ntohs(((struct sockaddr_in *)&addr)->sin_port);
        expected_legacy = legacy; expected_wire = legacy ? 512 : 1489;
        baseline_calls = 0;
        expected_path = resource ? "/public/main.css" : NULL;
        d2k_vol_result r = resource
            ? d2k_volume_probe_path(ip, port, "context.test", 0, legacy,
                                    expected_wire, 0x2f, expected_path)
            : d2k_volume_probe(ip, port, "context.test", 0, legacy, expected_wire, 0x2f);
        CHECK(r.verdict == D2K_VOL_UNREACHABLE && r.rx_cut &&
              baseline_calls == 3 && r.rx_at_kb == 23);
        /* Задача 26: доказанный обрыв обязан назвать свой путь наверх. Мерили
           по названному ресурсу — он и в результате; мерили по «/» — поле
           пусто, выдумывать «/» нечем. */
        CHECK(resource ? !strcmp(r.measured_path, expected_path) : !r.measured_path[0]);
        if (resource && strcmp(r.measured_path, expected_path))
            fprintf(stderr, "measured_path=\"%s\", ожидался \"%s\"\n",
                    r.measured_path, expected_path);
        close(fd);
    }
    }
    }
    CHECK(modern_calls == 4 && legacy_calls == 4 && mark_calls == 8);
    baseline_calls = 0; repeat_missing = 1; expected_legacy = 0;
    expected_wire = 1536; expected_path = NULL;
    d2k_vol_result partial = {0};
    probe_response_volume(&partial, "127.0.0.1", 443, "context.test", 0, 1536, 0x2f, NULL);
    CHECK(!partial.rx_cut && !partial.rx_direct_complete && baseline_calls == 2);
    CHECK(!partial.rx_unmeasured);
    CHECK(partial.rx_partial_bytes == 23900);
    CHECK(strstr(partial.rx_reason, "23900") && strstr(partial.rx_reason, "identity-2"));
    repeat_missing = 0; opaque_reply = 1;
    for (int legacy = 0; legacy < 2; legacy++) {
        expected_legacy = legacy; baseline_calls = 0;
        d2k_vol_result wire = {0};
        probe_response_volume(&wire, "127.0.0.1", 443, "context.test", legacy, 1536, 0x2f, NULL);
        CHECK(baseline_calls == 3 && wire.rx_cut && wire.rx_wire_basis);
        CHECK(!wire.rx_partial_bytes && wire.rx_partial_wire_bytes == 14005);
        CHECK(strstr(wire.rx_reason, "14005/14025/4500") != NULL);
    }
    opaque_reply = 0; unmeasured_rx = 1; baseline_calls = 0;
    expected_legacy = 0; expected_wire = 1536; expected_path = NULL;
    d2k_vol_result mute = {0};
    probe_response_volume(&mute, "127.0.0.1", 443, "context.test", 0, 1536, 0x2f, NULL);
    CHECK(baseline_calls == 2 && mute.rx_unmeasured && !mute.rx_tls_unavailable &&
          !mute.rx_direct_complete && !mute.rx_cut);
    unmeasured_rx = 0;
    early_rx = 1; baseline_calls = 0;
    d2k_vol_result early = {0};
    probe_response_volume(&early, "127.0.0.1", 443, "context.test", 0, 1536, 0x2f, NULL);
    CHECK(baseline_calls == 2 && early.rx_unmeasured && !early.rx_cut);
    early_rx = 0;
    full_non_2xx = 1; baseline_calls = 0;
    d2k_vol_result fn2 = {0};
    probe_response_volume(&fn2, "127.0.0.1", 443, "context.test", 0, 1536, 0x2f, NULL);
    CHECK(baseline_calls == 1 && !fn2.rx_cut && !fn2.rx_short &&
          !fn2.rx_unmeasured && !fn2.rx_direct_complete);
    full_non_2xx = 0;
    /* ПОЛЕ 12.10.2026, www.tampermonkey.net. /style.css: 30182 байта с VPS
       против 15963 с линии, восемь прогонов байт в байт, без RST и FIN. Зонд
       видел «identity-1 partial=15627; identity-2 HTTP 200 body=22094
       complete=1» и возвращался ни с чем — три эпизода подряд ушли в покой на
       десять минут. Дошедшее измерение расходится с оборванным, а не
       опровергает его: третий identity-прогон подтверждает обрыв, и пара
       считается сошедшейся на двух обрывах, не на одном. */
    opaque_reply = 0; noisy_second = 1; expected_gzip_call = 3;
    expected_legacy = 0; expected_wire = 1536; expected_path = NULL;
    baseline_calls = 0;
    d2k_vol_result noisy = {0};
    probe_response_volume(&noisy, "127.0.0.1", 443, "context.test", 0, 1536, 0x2f, NULL);
    CHECK(baseline_calls == 4);
    CHECK(noisy.rx_cut && !noisy.rx_wire_basis && noisy.rx_at_kb == 15);
    CHECK(noisy.rx_compressed_complete && noisy.rx_partial_bytes == 15627);
    CHECK(strstr(noisy.rx_reason, "15627/15963") != NULL);
    CHECK(strstr(noisy.rx_reason, "identity-3") != NULL);
    /* Третий прогон тоже дошёл до конца: обрыв не воспроизвёлся, вердикта
       НЕТ, и gzip-контроль не запрашивается — один обрыв ничего не доказывает. */
    third_also_full = 1; baseline_calls = 0;
    d2k_vol_result unconfirmed = {0};
    probe_response_volume(&unconfirmed, "127.0.0.1", 443, "context.test", 0, 1536, 0x2f, NULL);
    CHECK(baseline_calls == 3 && !unconfirmed.rx_cut);
    CHECK(strstr(unconfirmed.rx_reason, "identity-3") != NULL);
    noisy_second = third_also_full = 0; expected_gzip_call = 2;
    /* ПОЛЕ 12.10.2026, style.sndcdn.com и api-v2.soundcloud.com. Зонд объёма
       просит единственный «/», а эти хосты отдают на него страницу отказа
       доступа: завершённый 403 с телом 243 байта и 401 с пустым телом (то же
       самое и с VPS — честное поведение сервера). До измеряемой полосы 12 КБ
       зонд не доходит на два порядка, и класс остаётся НЕизмеренным, хотя
       настоящие ресурсы тех же имён режутся: /css/soehne-*.css — 301328 байт
       с VPS против 15985 с линии (три прогона, зависание на таймаут).
       Публичный путь ресурса приходит вместе с тем же ответом — по нему и
       мерим, ОДИН раз и по названной причине «мерить было нечем». */
    short_then_hint = 1; expected_gzip_call = 3;
    hint_host = "context.test"; hint_for_path = "/css/soehne-web.css";
    cut_path = hint_for_path;
    for (int code = 0; code < 2; code++) {
        /* Страница отказа доступа и просто короткий документ — один случай:
           ответ завершён и меньше полосы, мерить по нему нечего. */
        hint_status = code ? 200 : 403;
        baseline_calls = 0; last_path = NULL;
        d2k_vol_result hinted = {0};
        probe_response_volume(&hinted, "127.0.0.1", 443, "context.test", 0, 1536, 0x2f, NULL);
        CHECK(baseline_calls == 4);
        CHECK(hinted.rx_cut && !hinted.rx_wire_basis && hinted.rx_at_kb == 15);
        CHECK(hinted.rx_compressed_complete && hinted.rx_partial_bytes == 15985);
        CHECK(!hinted.rx_short && !hinted.rx_short_bytes);
        CHECK(strstr(hinted.rx_reason, "/css/soehne-web.css") != NULL);
        CHECK(strstr(hinted.rx_reason, "15985/15968") != NULL);
        CHECK(strstr(hinted.rx_reason, "243") != NULL);
        /* ЗАДАЧА 26: ПУТЬ ПОВТОРА — ЧАСТЬ ИЗМЕРЕНИЯ, А НЕ ТОЛЬКО ЖУРНАЛА.
           Причина читается человеком; наверх путь обязан идти полем, иначе
           кандидат проверяется по «/» (403, 243 байта) и доказанный обрыв не
           превращается в подтверждённое решение. */
        CHECK(!strcmp(hinted.measured_path, "/css/soehne-web.css"));
        if (strcmp(hinted.measured_path, "/css/soehne-web.css"))
            fprintf(stderr, "повтор доказал обрыв на /css/soehne-web.css, "
                            "а measured_path=\"%s\"\n", hinted.measured_path);
        /* Подсказка завершённого ответа по-прежнему уходит планировщику. */
        CHECK(hinted.n_resources == (size_t)code);
    }
    /* Повтор не дошёл до TLS — он не сказал ничего, и непроверенный бюджет
       первого ответа остаётся в силе: ложного «обрыв не воспроизвёлся» здесь
       быть не должно. */
    retry_outcome = 1; baseline_calls = 0; last_path = NULL; hint_status = 403;
    d2k_vol_result lost = {0};
    probe_response_volume(&lost, "127.0.0.1", 443, "context.test", 0, 1536, 0x2f, NULL);
    CHECK(baseline_calls == 2 && !lost.rx_cut && lost.rx_tls_unavailable);
    CHECK(lost.rx_short && lost.rx_short_bytes == 243);
    CHECK(strstr(lost.rx_reason, "/css/soehne-web.css") != NULL);
    /* Повтор не измерил ничего — пути измерения нет: спрашивать кандидата по
       этому пути было бы выдумкой, а не замером. */
    CHECK(!lost.measured_path[0]);
    /* Подсказанный ресурс дошёл ЦЕЛИКОМ и сам прошёл полосу — это настоящее
       отрицательное измерение, и подменять его непроверенным бюджетом нельзя. */
    retry_outcome = 2; baseline_calls = 0; last_path = NULL;
    d2k_vol_result passed = {0};
    probe_response_volume(&passed, "127.0.0.1", 443, "context.test", 0, 1536, 0x2f, NULL);
    CHECK(baseline_calls == 2 && !passed.rx_cut && !passed.rx_short);
    CHECK(strstr(passed.rx_reason, "30182") != NULL);
    /* Отрицательное измерение — тоже не обрыв: пути обрыва нет. */
    CHECK(!passed.measured_path[0]);
    retry_outcome = 0;
    /* Подсказки нет — честный непроверенный бюджет остаётся как есть, без
       выдумок, и лишнего зонда не заказываем. */
    hint_host = NULL; hint_status = 403; baseline_calls = 0; last_path = NULL;
    d2k_vol_result bare = {0};
    probe_response_volume(&bare, "127.0.0.1", 443, "context.test", 0, 1536, 0x2f, NULL);
    CHECK(baseline_calls == 1 && !bare.rx_cut);
    CHECK(bare.rx_short && bare.rx_short_bytes == 243);
    CHECK(strstr(bare.rx_reason, "повтор") == NULL);
    /* Подсказка на ЧУЖОЕ имя — это другая цель: адрес и SNI у зонда свои, и
       спросили бы мы чужой путь не у того сервера. */
    hint_host = "other.cdn"; baseline_calls = 0; last_path = NULL;
    d2k_vol_result foreign = {0};
    probe_response_volume(&foreign, "127.0.0.1", 443, "context.test", 0, 1536, 0x2f, NULL);
    CHECK(baseline_calls == 1 && !foreign.rx_cut && foreign.rx_short);
    /* Подсказка совпала с уже измеренным путём — повторять нечего. */
    hint_host = "context.test"; cut_path = NULL; baseline_calls = 0; last_path = NULL;
    d2k_vol_result same = {0};
    probe_response_volume(&same, "127.0.0.1", 443, "context.test", 0, 1536, 0x2f, hint_for_path);
    CHECK(baseline_calls == 1 && !same.rx_cut && same.rx_short);
    short_then_hint = 0; hint_host = NULL; expected_gzip_call = 2;
    if (failures) return 1;
    puts("test_volume_context: OK"); return 0;
}
