/* test_wire.c — сборка пакета на провод.
 *
 * Порча проверяется не тем, что «флаг выставлен», а тем, что получившийся
 * пакет ДЕЙСТВИТЕЛЬНО таков: сумма неверна, TTL мал, идентификатор нулевой.
 * Проверять флаг значило бы проверять собственное намерение, а не результат.
 */
#include <stdio.h>
#include <string.h>
#include "d2k_wire.h"

static int fails;
#define CHECK(cond, msg)                                   \
    do {                                                   \
        if (!(cond)) {                                     \
            printf("ПРОВАЛ: %s\n", msg);                   \
            fails++;                                       \
        }                                                  \
    } while (0)

static uint16_t rd16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}

static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
           (uint32_t)p[2] << 8 | (uint32_t)p[3];
}


/* Эталонный чистый пакет, собранный этим кодом и СВЕРЕННЫЙ СТОРОННЕЙ
 * реализацией контрольных сумм. Лежит здесь именно потому, что собственный
 * проверяльщик однажды уже согласился с собственным сборщиком, когда оба
 * ошибались одинаково: адреса клались в псевдозаголовок как числа, а лежат они
 * в сетевом порядке, и на little-endian это переворачивало адрес. Сумма была
 * неверна у всех пакетов, включая чистые, и на проводе это означало бы, что
 * фальшивку выбрасывают и коробка, и сервер.
 *
 * Эталон ловит возврат этой ошибки без всякого внешнего инструмента.
 */
static const uint8_t golden_clean[] = {
    0x45, 0x00, 0x00, 0x2d, 0x10, 0x01, 0x40, 0x00, 0x40, 0x06, 0x64, 0xd9,
    0xc0, 0xa8, 0x01, 0x43, 0x01, 0x02, 0x03, 0x04, 0x9c, 0x40, 0x01, 0xbb,
    0x00, 0x00, 0x03, 0xe8, 0x11, 0x22, 0x33, 0x44, 0x50, 0x18, 0xfa, 0xf0,
    0x59, 0xfe, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x11,
};

static void check_golden(void) {
    d2k_conn c;
    memset(&c, 0, sizeof c);
    uint8_t s[4] = {192, 168, 1, 67}, d[4] = {1, 2, 3, 4};
    memcpy(&c.src_ip, s, 4);
    memcpy(&c.dst_ip, d, 4);
    uint8_t sp[2] = {0x9c, 0x40}, dp[2] = {0x01, 0xbb};
    memcpy(&c.src_port, sp, 2);
    memcpy(&c.dst_port, dp, 2);
    c.ack = 0x11223344;
    c.window = 64240;
    c.ttl = 64;
    c.ip_id = 0x1000;

    static const uint8_t body[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x11};
    d2k_emit e;
    memset(&e, 0, sizeof e);
    e.seq = 1000;
    e.bytes = body;
    e.len = sizeof body;

    uint8_t pkt[256];
    size_t n = d2k_wire_build(&c, &e, pkt, sizeof pkt);
    CHECK(n == sizeof golden_clean, "длина разошлась с эталоном");
    if (n == sizeof golden_clean) {
        CHECK(memcmp(pkt, golden_clean, n) == 0, "пакет разошёлся с эталоном побайтово");
    }
}

int main(void) {
    /* --- tcp_ts_up: МЕТКА ВРЕМЕНИ ПЕРВОЙ В ОПЦИЯХ ------------------------
     * Документация zapret2, standard fooling: «поднять tcp timestamp опцию в
     * самое начало, если она есть», и там же объяснение — «если есть tcp опция
     * timestamp, linux стабильно отбрасывает пакеты с валидным seq и
     * инвалидным ack ТОЛЬКО ЕСЛИ ОПЦИЯ ИДЁТ ПЕРВОЙ. nfqws1 не соблюдал
     * порядок tcp опций, timestamp получался первым всегда. Поэтому
     * оказалось, что старая версия работает стабильно, а новая нет».
     *
     * Профиль tcp-template-v1 копирует опции потока КАК ЕСТЬ, то есть условие
     * срабатывания наших tcpts-планов зависит от того, где клиент поставил
     * метку, и от нас это скрыто. Приём поднимает её в начало. */
    {
        /* Опции клиента: SACK-permitted, затем метка времени (не первая). */
        static const uint8_t opts[] = {1, 1, 4, 2, 8, 10, 0x11, 0x22, 0x33, 0x44,
                                       0, 0, 0, 0, 1, 1};
        const uint8_t data[] = {7, 8, 9};
        uint8_t out[128];
        d2k_conn c = {.family = 4, .ttl = 64, .window = 1024};
        memcpy(c.tcp_options, opts, sizeof opts);
        c.tcp_options_len = sizeof opts;
        d2k_emit e = {.bytes = data, .len = sizeof data, .seq = 9,
                      .wire_profile = D2K_WIRE_TCP_TEMPLATE,
                      .poison = D2K_POISON_TCPTS_BACK, .ts_up = 1};
        size_t n = d2k_wire_build(&c, &e, out, sizeof out);
        CHECK(n > 40, "tcp_ts_up: посылка не собралась");
        if (n > 40) {
            const uint8_t *o = out + 20 + 20;
            CHECK(o[0] == 8 && o[1] == 10,
                  "tcp_ts_up: метка времени не поднята в начало опций");
            /* Значение по-прежнему сдвинуто назад: приём не отменяет порчу. */
            uint32_t ts = (uint32_t)o[2] << 24 | (uint32_t)o[3] << 16 |
                          (uint32_t)o[4] << 8 | o[5];
            CHECK(ts == 0x11223344u - 1000u,
                  "tcp_ts_up: сдвиг метки назад потерян");
            /* Длина опций не изменилась — заголовок тот же размер. */
            CHECK(((size_t)(out[20 + 12] >> 4) * 4 - 20) == sizeof opts,
                  "tcp_ts_up: длина опций изменилась");
            /* Остальные опции не потеряны: SACK-permitted на месте. */
            int sack = 0;
            for (size_t i = 0; i + 1 < sizeof opts; i++) {
                if (o[i] == 4 && o[i + 1] == 2) { sack = 1; }
            }
            CHECK(sack, "tcp_ts_up: прочие опции клиента потеряны");
        }
        /* Без признака порядок опций клиента не меняется. */
        e.ts_up = 0;
        n = d2k_wire_build(&c, &e, out, sizeof out);
        CHECK(n > 40 && out[40] == 1 && out[40 + 1] == 1,
              "tcp_ts_up: без признака порядок опций всё равно изменён");
    }
    /* --- ip_autottl: TTL ИЗ ИЗМЕРЕННОГО ПУТИ ------------------------------
     * Документация zapret2, standard fooling: «изменить TTL в ipv4 заголовке
     * на автоматически определяемый по шаблону autottl delta,min-max. При
     * невозможности определения TTL берётся ip_ttl, если есть. Иначе TTL не
     * меняется», и «autottl производит эвристическую догадку о длине в хопах
     * на базе TTL входящих пакетов». Константа приметна сама: у донора жёсткий
     * ip_ttl=8 палился с роутера в 50 хопах от назначения. */
    {
        const uint8_t data[] = {1, 2, 3};
        uint8_t out[128];
        /* Сервер ответил с TTL 57: исходный 64, значит путь 7 хопов.
           delta=+1 → 8, в диапазоне [2,12] → TTL фальшивки 8. */
        d2k_conn c = {.family = 4, .ttl = 64, .rev_ttl = 57, .window = 1024};
        d2k_emit e = {.bytes = data, .len = sizeof data, .seq = 9,
                      .autottl = 1, .autottl_delta = 1,
                      .autottl_min = 2, .autottl_max = 12};
        CHECK(d2k_wire_build(&c, &e, out, sizeof out) == 43 && out[8] == 8,
              "autottl: TTL не вычислен по пути (ждали 8)");
        /* Исходный 128 (Windows-сервер): 128-120 = 8 хопов, +1 → 9. */
        c.rev_ttl = 120;
        CHECK(d2k_wire_build(&c, &e, out, sizeof out) && out[8] == 9,
              "autottl: догадка об исходном TTL 128 не сработала");
        /* Исходный 255: 255-250 = 5 хопов, +1 → 6. */
        c.rev_ttl = 250;
        CHECK(d2k_wire_build(&c, &e, out, sizeof out) && out[8] == 6,
              "autottl: догадка об исходном TTL 255 не сработала");
        /* Диапазон зажимает: путь 30 хопов, +1 = 31 > max 12 → 12. */
        c.rev_ttl = 34;
        CHECK(d2k_wire_build(&c, &e, out, sizeof out) && out[8] == 12,
              "autottl: верхняя граница диапазона не применена");
        /* И снизу: путь 0 хопов, +1 = 1 < min 2 → 2. */
        c.rev_ttl = 64;
        CHECK(d2k_wire_build(&c, &e, out, sizeof out) && out[8] == 2,
              "autottl: нижняя граница диапазона не применена");
        /* Ответа не было (rev_ttl 0): берём заданный ttl. */
        c.rev_ttl = 0; e.ttl = 5;
        CHECK(d2k_wire_build(&c, &e, out, sizeof out) && out[8] == 5,
              "autottl: без ответа не взят заданный ttl");
        /* Ответа не было и ttl не задан: TTL не меняется (как обычно). */
        e.ttl = 0;
        CHECK(d2k_wire_build(&c, &e, out, sizeof out) && out[8] == 64,
              "autottl: без ответа и без ttl TTL всё равно подменён");
        /* IPv6: то же поле hop limit. */
        d2k_conn c6 = {.family = 6, .ttl = 64, .rev_ttl = 57, .window = 1024,
            .src_ip6 = {0x20,1,0xdb,8,0,0,0,0,0,0,0,0,0,0,0,1},
            .dst_ip6 = {0x20,1,0xdb,8,0,0,0,0,0,0,0,0,0,0,0,2}};
        d2k_emit e6 = {.bytes = data, .len = sizeof data, .seq = 9,
                       .autottl = 1, .autottl_delta = 1,
                       .autottl_min = 2, .autottl_max = 12};
        CHECK(d2k_wire_build(&c6, &e6, out, sizeof out) && out[7] == 8,
              "autottl: IPv6 hop limit не вычислен по пути");
    }
    {
        d2k_conn v6 = {.family = 6, .ttl = 57, .window = 1024,
            .src_ip6 = {0x20,1,0xdb,8,0,0,0,0,0,0,0,0,0,0,0,1},
            .dst_ip6 = {0x20,1,0xdb,8,0,0,0,0,0,0,0,0,0,0,0,2}};
        const uint8_t data[] = {1,2,3};
        d2k_emit emit = {.bytes = data, .len = sizeof data, .seq = 9};
        uint8_t out[128];
        size_t n6 = d2k_wire_build(&v6, &emit, out, sizeof out);
        CHECK(n6 == 63 && out[0] == 0x60 && rd16(out + 4) == 23 &&
              out[6] == 6 && out[7] == 57, "IPv6 TCP header");
        CHECK(!memcmp(out + 8, v6.src_ip6, 16) && !memcmp(out + 24, v6.dst_ip6, 16),
              "IPv6 TCP full addresses");
        CHECK(!memcmp(out + 60, data, sizeof data) && d2k_wire_tcp_checksum_ok(out, n6),
              "IPv6 TCP payload/checksum");
        out[9] ^= 1;
        CHECK(!d2k_wire_tcp_checksum_ok(out, n6), "IPv6 checksum omitted upper address bits");
        CHECK(d2k_wire_build(&v6, &emit, out, 62) == 0, "IPv6 TCP capacity");
        emit.poison = D2K_POISON_BADSUM;
        n6 = d2k_wire_build(&v6, &emit, out, sizeof out);
        CHECK(n6 == 63 && !d2k_wire_tcp_checksum_ok(out, n6), "IPv6 badsum effect");
        emit.poison = D2K_POISON_IPID_ZERO;
        CHECK(d2k_wire_build(&v6, &emit, out, sizeof out) == 0,
              "IPv4-only IPID effect silently ignored for IPv6");
    }
    d2k_conn c;
    memset(&c, 0, sizeof c);
    /* 192.168.1.67 -> 1.2.3.4, порты 40000 -> 443 */
    uint8_t s[4] = {192, 168, 1, 67}, d[4] = {1, 2, 3, 4};
    memcpy(&c.src_ip, s, 4);
    memcpy(&c.dst_ip, d, 4);
    uint8_t sp[2] = {0x9c, 0x40}, dp[2] = {0x01, 0xbb};
    memcpy(&c.src_port, sp, 2);
    memcpy(&c.dst_port, dp, 2);
    c.ack = 0x11223344;
    c.window = 64240;
    c.ttl = 64;
    c.ip_id = 0x1000;

    static const uint8_t body[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x11};
    uint8_t pkt[256];

    /* --- чистая посылка ------------------------------------------------- */
    d2k_emit e;
    memset(&e, 0, sizeof e);
    e.seq = 1000;
    e.bytes = body;
    e.len = sizeof body;

    size_t n = d2k_wire_build(&c, &e, pkt, sizeof pkt);
    CHECK(n == 20 + 20 + sizeof body, "длина чистого пакета неверна");
    CHECK((pkt[0] >> 4) == 4, "не IPv4");
    CHECK(rd16(pkt + 2) == n, "поле длины не совпало с фактической");
    CHECK(pkt[8] == 64, "TTL не унаследован от соединения");
    CHECK(pkt[9] == 6, "протокол не TCP");
    CHECK(rd32(pkt + 20 + 4) == 1000, "номер последовательности не тот");
    CHECK(memcmp(pkt + 40, body, sizeof body) == 0, "полезная нагрузка не на месте");
    CHECK(d2k_wire_tcp_checksum_ok(pkt, n), "контрольная сумма чистого пакета неверна");

    /* Один TCP urgent byte: флаг, указатель и сумма должны попасть в сам
       сформированный wire-пакет, а не остаться только в модели действия. */
    {
        static const uint8_t urgent_byte = 0x0f;
        memset(&e, 0, sizeof e);
        e.seq = 2000;
        e.bytes = &urgent_byte;
        e.len = 1;
        e.urgent = 1;
        e.urgent_ptr = 1;
        n = d2k_wire_build(&c, &e, pkt, sizeof pkt);
        CHECK(n == 41 && pkt[33] == 0x38 && rd16(pkt + 38) == 1,
              "TCP URG flag/pointer missing from wire header");
        CHECK(pkt[40] == urgent_byte && d2k_wire_tcp_checksum_ok(pkt, n),
              "TCP urgent-byte payload or checksum invalid");
        e.urgent_ptr = 2;
        CHECK(d2k_wire_build(&c, &e, pkt, sizeof pkt) == 0,
              "urgent pointer beyond emitted urgent payload accepted");
    }

    /* Сумма IP тоже обязана сходиться: свёртка заголовка даёт ноль. */
    {
        uint32_t acc = 0;
        for (size_t i = 0; i < 20; i += 2) {
            acc += rd16(pkt + i);
        }
        while (acc >> 16) {
            acc = (acc & 0xffff) + (acc >> 16);
        }
        CHECK((uint16_t)~acc == 0, "контрольная сумма IP неверна");
    }

    /* --- испорченная сумма ---------------------------------------------- */
    memset(&e, 0, sizeof e);
    e.seq = 1000;
    e.bytes = body;
    e.len = sizeof body;
    e.poison = D2K_POISON_BADSUM;
    n = d2k_wire_build(&c, &e, pkt, sizeof pkt);
    CHECK(n > 0, "пакет с испорченной суммой не собрался");
    CHECK(!d2k_wire_tcp_checksum_ok(pkt, n),
          "сумма обязана быть неверной: сервер должен выбросить фальшивку");

    /* Испорченная сумма обязана быть ПРЕДСКАЗУЕМОЙ: эталоны иначе не сойдутся
       от прогона к прогону. */
    {
        uint8_t again[256];
        size_t m = d2k_wire_build(&c, &e, again, sizeof again);
        CHECK(m == n && memcmp(pkt, again, n) == 0,
              "порча суммы не воспроизводима — эталон не сойдётся");
    }

    /* --- малый TTL ------------------------------------------------------- */
    memset(&e, 0, sizeof e);
    e.seq = 1000; e.bytes = body; e.len = sizeof body; e.ttl = 3;
    n = d2k_wire_build(&c, &e, pkt, sizeof pkt);
    CHECK(pkt[8] == 3, "TTL порчи не доехал до заголовка");
    CHECK(d2k_wire_tcp_checksum_ok(pkt, n), "TTL не должен ломать сумму TCP");

    /* --- нулевой идентификатор ------------------------------------------- */
    memset(&e, 0, sizeof e);
    e.seq = 1000; e.bytes = body; e.len = sizeof body;
    e.poison = D2K_POISON_IPID_ZERO;
    n = d2k_wire_build(&c, &e, pkt, sizeof pkt);
    CHECK(rd16(pkt + 4) == 0, "идентификатор IP не обнулён");

    /* Без порчи идентификатор обязан ОТЛИЧАТЬСЯ от исходного: совпадение —
       известная ловушка, сборщик фрагментов на той стороне может счесть
       пакеты частями одной дейтаграммы. */
    memset(&e, 0, sizeof e);
    e.seq = 1000; e.bytes = body; e.len = sizeof body;
    n = d2k_wire_build(&c, &e, pkt, sizeof pkt);
    CHECK(rd16(pkt + 4) != c.ip_id, "идентификатор совпал с исходным");

    /* --- сдвиг номера последовательности --------------------------------- */
    memset(&e, 0, sizeof e);
    e.seq = 1000; e.bytes = body; e.len = sizeof body; e.seq_shift = -10000;
    n = d2k_wire_build(&c, &e, pkt, sizeof pkt);
    CHECK(rd32(pkt + 20 + 4) == (uint32_t)(1000 - 10000), "сдвиг seq не применён");
    CHECK(d2k_wire_tcp_checksum_ok(pkt, n), "сдвиг seq не должен ломать сумму");

    /* --- метка времени со сдвигом ---------------------------------------- */
    memset(&e, 0, sizeof e);
    e.seq = 1000; e.bytes = body; e.len = sizeof body;
    e.poison = D2K_POISON_TCPTS_BACK;
    n = d2k_wire_build(&c, &e, pkt, sizeof pkt);
    CHECK((pkt[20 + 12] >> 4) == 8, "длина заголовка TCP не выросла под опцию");
    CHECK(pkt[20 + 20 + 2] == 8 && pkt[20 + 20 + 3] == 10, "опция метки времени не та");
    CHECK(d2k_wire_tcp_checksum_ok(pkt, n), "опции не должны ломать сумму");
    CHECK(memcmp(pkt + 20 + 20 + 12, body, sizeof body) == 0,
          "нагрузка сместилась не туда при наличии опций");

    /* --- буфер не резиновый ----------------------------------------------- */
    memset(&e, 0, sizeof e);
    e.seq = 1000; e.bytes = body; e.len = sizeof body;
    CHECK(d2k_wire_build(&c, &e, pkt, 10) == 0, "сборка в маленький буфер должна отказать");

    /* --- приставка перекрытия едет впереди нагрузки и входит в сумму ----- */
    {
        d2k_emit e;
        memset(&e, 0, sizeof e);
        const uint8_t pre[] = {0xAA, 0xBB};
        const uint8_t pay[] = {0x16, 0x03, 0x01, 0x00};
        e.kind = D2K_EMIT_PAYLOAD;
        e.seq = 998;
        e.pre = pre;
        e.pre_len = sizeof pre;
        e.bytes = pay;
        e.len = sizeof pay;

        uint8_t out[128];
        size_t n = d2k_wire_build(&c, &e, out, sizeof out);
        CHECK(n == 20 + 20 + sizeof pre + sizeof pay,
              "длина пакета не учла приставку");
        if (n) {
            CHECK(out[40] == 0xAA && out[41] == 0xBB, "приставка не впереди");
            CHECK(out[42] == 0x16 && out[45] == 0x00, "нагрузка съехала");
            CHECK(d2k_wire_tcp_checksum_ok(out, n),
                  "сумма не сошлась: приставка не попала в подсчёт");
        }
    }

    /* Recovered manual profile: preserve negotiated timestamps on real
     * split packets and subtract exactly 1000 only on fake packets. */
    {
        d2k_conn c = {0};
        d2k_emit e = {0};
        uint8_t out[128], data[] = {0x16, 3};
        const uint8_t options[] = {1,1,8,10,0,0,0x13,0x88,0,0,0x23,0x28};
        c.ttl = 63; c.window = 2061; c.ip_id = 7;
        memcpy(c.tcp_options, options, sizeof options);
        c.tcp_options_len = sizeof options;
        e.bytes = data; e.len = sizeof data;
        e.wire_profile = D2K_WIRE_TCP_TEMPLATE;
        e.kind = D2K_EMIT_FAKE; e.poison = D2K_POISON_TCPTS_BACK;
        size_t n = d2k_wire_build(&c, &e, out, sizeof out);
        CHECK(n == 54 && rd32(out + 44) == 4000 && rd32(out + 48) == 9000,
              "native fake не повторил TS-1000/echo ручного эталона");
        CHECK(n && out[8] == 63 && rd16(out + 34) == 2061 && rd16(out + 4) == 7,
              "native fake изменил TTL/window/IPID исходного потока");
        CHECK(n && d2k_wire_tcp_checksum_ok(out, n), "native fake checksum");
        e.kind = D2K_EMIT_PAYLOAD; e.poison = 0;
        n = d2k_wire_build(&c, &e, out, sizeof out);
        CHECK(n == 54 && memcmp(out + 40, options, sizeof options) == 0,
              "real split потерял TCP options");
        c.tcp_options_len = 0; e.poison = D2K_POISON_TCPTS_BACK;
        CHECK(d2k_wire_build(&c, &e, out, sizeof out) == 0,
              "PAWS fake без исходного timestamp выдан за применимый");
    }
    check_golden();

    if (fails) {
        printf("ПРОВАЛОВ: %d\n", fails);
        return 1;
    }
    printf("провод: все проверки прошли\n");
    return 0;
}
