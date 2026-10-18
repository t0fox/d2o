/* test_quicsnap.c — пачка Initial-датаграмм клиента (задача 66).
 *
 * Поле 15.10.2026: Chrome с постквантовым key_share шлёт ClientHello двумя
 * Initial, и снимок из одной датаграммы — обрывок. Стенд двух датаграмм общий
 * с задачей 40 (test_quic_pq.h): имя лежит во ВТОРОЙ датаграмме, как у Chrome
 * с его перестановкой расширений.
 */
#include <stdio.h>
#include <string.h>

#include "d2k_quicsnap.h"
#include "d2k_quic.h"
#include "d2k_quicwire.h"
#include "test_quic_pq.h"

static int fails;
#define CHECK(c, m) do { if (!(c)) { printf("ПРОВАЛ: %s (строка %d)\n", m, __LINE__); fails++; } } while (0)

int main(void) {
    uint8_t d1[1500], d2[1500];
    size_t l1 = 0, l2 = 0;
    CHECK(d2k_test_pq_initials("rutracker.org", d1, &l1, d2, &l2) == 0, "стенд двух датаграмм");
    const uint8_t *dg[2] = {d1, d2};
    size_t len[2] = {l1, l2};

    /* --- упаковка и разбор --------------------------------------------- */
    uint8_t blob[D2K_SHAPE_MAX];
    size_t bl = d2k_qsnap_pack(dg, len, 2, blob, sizeof blob);
    CHECK(bl == 4 + 2 + l1 + 2 + l2, "длина пачки: магия, число, по длине на датаграмму");
    CHECK(d2k_qsnap_is(blob, bl), "магия пачки не узнана");
    /* Одиночная датаграмма пачкой не притворяется: у длинного заголовка QUIC
       обязателен бит 0x80, и с 'Q' она начаться не может. */
    CHECK(!d2k_qsnap_is(d1, l1), "одиночная датаграмма принята за пачку");

    d2k_qsnap s;
    CHECK(d2k_qsnap_parse(blob, bl, &s) == 0, "разбор пачки");
    CHECK(s.n == 2 && s.len[0] == l1 && s.len[1] == l2, "число и длины датаграмм");
    CHECK(!memcmp(s.dg[0], d1, l1) && !memcmp(s.dg[1], d2, l2), "байты датаграмм не те");

    /* --- приветствие и имя ---------------------------------------------- */
    uint8_t ch[8192];
    size_t chl = 0;
    CHECK(d2k_quic_dgrams_hello(dg, len, 2, ch, sizeof ch, &chl) == 0,
          "ClientHello из двух датаграмм");
    CHECK(chl > 4 && ch[0] == 0x01, "собрано не ClientHello");
    CHECK(chl == 4 + ((size_t)ch[1] << 16 | (size_t)ch[2] << 8 | ch[3]),
          "собрано не до заявленной длины");

    uint8_t ch_s[8192];
    size_t ch_sl = 0;
    CHECK(d2k_qsnap_client_hello(&s, ch_s, sizeof ch_s, &ch_sl) == 0 &&
          ch_sl == chl && !memcmp(ch_s, ch, chl), "пачка даёт тот же ClientHello");

    char name[256];
    CHECK(d2k_qsnap_sni(&s, name, sizeof name) == 0 && !strcmp(name, "rutracker.org"),
          "имя из второй датаграммы");

    /* Первая датаграмма в одиночку — обрывок, а не приветствие. */
    d2k_qsnap one = s;
    one.n = 1;
    CHECK(d2k_qsnap_client_hello(&one, ch_s, sizeof ch_s, &ch_sl) != 0,
          "половина приветствия принята за целое");
    CHECK(d2k_qsnap_sni(&one, name, sizeof name) != 0, "имя выдумано из обрывка");

    /* --- перезапечатка --------------------------------------------------- */
    uint8_t re[D2K_SHAPE_MAX];
    size_t rl = 0;
    CHECK(d2k_qsnap_recid(&s, re, sizeof re, &rl) == 0, "перезапечатка пачки");
    CHECK(rl == bl, "перезапечатка изменила длину пачки");
    d2k_qsnap r;
    CHECK(d2k_qsnap_parse(re, rl, &r) == 0 && r.n == 2 &&
          r.len[0] == l1 && r.len[1] == l2, "перезапечатанное — та же форма");
    /* DCID лежит с 6-го байта длинного заголовка: 1 тип + 4 версия + 1 длина. */
    CHECK(memcmp(r.dg[0] + 6, s.dg[0] + 6, 8) != 0, "DCID не обновлён");
    CHECK(!memcmp(r.dg[0] + 6, r.dg[1] + 6, 8), "у датаграмм пачки разные DCID");
    uint8_t ch_r[8192];
    size_t ch_rl = 0;
    CHECK(d2k_qsnap_client_hello(&r, ch_r, sizeof ch_r, &ch_rl) == 0 &&
          ch_rl == chl && !memcmp(ch_r, ch, chl),
          "перезапечатанная пачка не раскрывается в тот же ClientHello");
    uint8_t re2[D2K_SHAPE_MAX];
    size_t rl2 = 0;
    CHECK(d2k_qsnap_recid(&s, re2, sizeof re2, &rl2) == 0 && rl2 == rl &&
          memcmp(re2, re, rl) != 0, "две перезапечатки дали один DCID");

    /* Сдвоенный Initial нельзя перезапечатать только наполовину. */
    {
        uint8_t combined[1500], second[256], body[20]={1}, secret[32];
        d2k_qw_hdr first; d2k_qw_keys keys;
        CHECK(d2k_qw_hdr_parse(d1,l1,0,&first)==0,"разбор исходного заголовка");
        CHECK(d2k_qw_initial_secret(first.version,d1+first.dcid_off,first.dcid_len,D2K_QW_CLIENT,secret)==0,"секрет ключа второго Initial");
        CHECK(d2k_qw_keys_from_secret(first.version,secret,&keys)==0,"ключи второго Initial");
        size_t hl=d2k_qw_long_hdr(second,sizeof second,first.version,D2K_QW_LT_INITIAL,
            d1+first.dcid_off,first.dcid_len,d1+first.scid_off,first.scid_len,4,sizeof body);
        size_t n2=d2k_qw_seal(&keys,1,second,hl,1,4,body,sizeof body,second,sizeof second);
        CHECK(n2>0 && l1+n2<=sizeof combined,"второй корректный Initial");
        memcpy(combined,d1,l1);memcpy(combined+l1,second,n2);
        d2k_qsnap coal={0};coal.n=1;coal.dg[0]=combined;coal.len[0]=l1+n2;
        size_t outlen=0;uint8_t output[D2K_SHAPE_MAX];
        int rc=d2k_qsnap_recid(&coal,output,sizeof output,&outlen);
        int coherent=0;
        if(rc==0) {
            d2k_qsnap parsed;d2k_qw_hdr a,b;
            CHECK(d2k_qsnap_parse(output,outlen,&parsed)==0,"разбор перезапечатанного снимка");
            CHECK(d2k_qw_hdr_parse(parsed.dg[0],parsed.len[0],0,&a)==0,"разбор первого пакета результата");
            CHECK(d2k_qw_hdr_parse(parsed.dg[0]+a.packet_len,parsed.len[0]-a.packet_len,0,&b)==0,"разбор второго пакета результата");
            coherent=a.dcid_len==b.dcid_len && !memcmp(parsed.dg[0]+a.dcid_off,parsed.dg[0]+a.packet_len+b.dcid_off,a.dcid_len);
            printf("склейка recid: код=%d, DCID совпадает=%d, второй пакет без изменений=%d\n",
                   rc,coherent,!memcmp(parsed.dg[0]+a.packet_len,second,n2));
        }
        CHECK(rc!=0 || coherent,"recid должен отклонить склейку или обновить все Initial");
    }

    /* --- 4-байтный varint длины (форма Chrome 150) ----------------------- */
    /* Chrome выделяет 4 байта под поле Length в Initial. d2k_qsnap_recid
       обязан сохранять ширину поля и длину датаграммы без сжатия varint. */
    d2k_qw_hdr h1;
    CHECK(d2k_qw_hdr_parse(d1, l1, 0, &h1) == 0, "разбор d1 для теста 4-байтного varint");
    uint8_t plain1[1500]; size_t plain1_len = 0; uint64_t pn1 = 0;
    uint8_t sec1[32]; d2k_qw_keys k1;
    CHECK(d2k_qw_initial_secret(h1.version, d1 + h1.dcid_off, h1.dcid_len, D2K_QW_CLIENT, sec1) == 0, "секрет для d1");
    CHECK(d2k_qw_keys_from_secret(h1.version, sec1, &k1) == 0, "ключи для d1");
    CHECK(d2k_qw_open(&k1, &h1, d1, 0, plain1, &plain1_len, &pn1) == 0, "открытие d1");
    size_t pn1_len = h1.length_claimed - plain1_len - 16;
    if (plain1_len > 2) {
        plain1_len -= 2;
        uint8_t d1_4w[1500];
        size_t hl_4w = d2k_qw_long_hdr_w(d1_4w, sizeof d1_4w, h1.version, D2K_QW_LT_INITIAL,
                                         d1 + h1.dcid_off, h1.dcid_len, d1 + h1.scid_off, h1.scid_len,
                                         pn1_len, plain1_len, 4);
        CHECK(hl_4w > 0, "сборка заголовка с 4-байтным varint длины");
        size_t sealed_4w = d2k_qw_seal(&k1, 1, d1_4w, hl_4w, pn1, pn1_len, plain1, plain1_len,
                                       d1_4w, sizeof d1_4w);
        CHECK(sealed_4w == l1, "длина запечатанного пакета с 4-байтным varint совпала с l1");
        d2k_qw_hdr h_test;
        CHECK(d2k_qw_hdr_parse(d1_4w, sealed_4w, 0, &h_test) == 0, "разбор пакета с 4-байтным varint");
        CHECK(h_test.length_width == 4, "длина определена как 4-байтный varint");
        const uint8_t *dg_4w[2] = {d1_4w, d2};
        size_t len_4w[2] = {sealed_4w, l2};
        uint8_t blob_4w[D2K_SHAPE_MAX];
        size_t bl_4w = d2k_qsnap_pack(dg_4w, len_4w, 2, blob_4w, sizeof blob_4w);
        CHECK(bl_4w > 0, "упаковка пачки с 4-байтным varint");
        d2k_qsnap s_4w;
        CHECK(d2k_qsnap_parse(blob_4w, bl_4w, &s_4w) == 0, "разбор пачки с 4-байтным varint");
        uint8_t re_4w[D2K_SHAPE_MAX]; size_t rl_4w = 0;
        CHECK(d2k_qsnap_recid(&s_4w, re_4w, sizeof re_4w, &rl_4w) == 0,
              "перезапечатка пачки с 4-байтным varint длины");
        CHECK(rl_4w == bl_4w, "перезапечатка пачки с 4-байтным varint сохранила точную длину");
    }

    /* --- форма ------------------------------------------------------------ */
    d2k_quic_form f;
    CHECK(d2k_qsnap_form(&s, &f) == 0 && f.n == 2 && f.dgram_len == (uint16_t)l1 &&
          f.ch_len == (uint16_t)chl, "форма пачки");

    /* --- отказы ----------------------------------------------------------- */
    /* Датаграммы разных соединений (Retry посреди полёта, чужой поток в
       кольце датапата) не склеиваются в одно приветствие. */
    const uint8_t *mdg[2] = {d1, r.dg[1]};
    uint8_t mixed[D2K_SHAPE_MAX];
    size_t ml = d2k_qsnap_pack(mdg, len, 2, mixed, sizeof mixed);
    d2k_qsnap m;
    CHECK(ml > 0 && d2k_qsnap_parse(mixed, ml, &m) == 0, "упаковка смешанной пачки");
    CHECK(d2k_qsnap_client_hello(&m, ch_s, sizeof ch_s, &ch_sl) != 0,
          "датаграммы разных DCID склеены в одно приветствие");
    CHECK(d2k_qsnap_recid(&m, re, sizeof re, &rl) != 0, "смешанная пачка перезапечатана");

    /* Любое усечение отвергается целиком, а не разбирается наполовину. */
    for (size_t k = 0; k < bl; k++) {
        d2k_qsnap t;
        CHECK(d2k_qsnap_parse(blob, k, &t) != 0, "усечённая пачка принята");
    }
    /* Лишние байты в хвосте — тоже отказ: это не та пачка, что слал клиент. */
    uint8_t longer[D2K_SHAPE_MAX];
    memcpy(longer, blob, bl);
    longer[bl] = 0;
    {
        d2k_qsnap t;
        CHECK(d2k_qsnap_parse(longer, bl + 1, &t) != 0, "пачка с хвостом принята");
    }

    /* Мусор нужной длины — не приветствие и не перезапечатывается. */
    uint8_t junk[64];
    memset(junk, 0x5a, sizeof junk);
    const uint8_t *jdg[1] = {junk};
    size_t jlen[1] = {sizeof junk};
    uint8_t jb[128];
    size_t jbl = d2k_qsnap_pack(jdg, jlen, 1, jb, sizeof jb);
    d2k_qsnap j;
    CHECK(jbl > 0 && d2k_qsnap_parse(jb, jbl, &j) == 0, "упаковка мусора");
    CHECK(d2k_qsnap_client_hello(&j, ch_s, sizeof ch_s, &ch_sl) != 0,
          "мусор принят за приветствие");
    CHECK(d2k_qsnap_recid(&j, re, sizeof re, &rl) != 0, "мусор перезапечатан");

    /* Пределы упаковки. */
    CHECK(d2k_qsnap_pack(dg, len, 0, blob, sizeof blob) == 0, "пустая пачка собрана");
    CHECK(d2k_qsnap_pack(dg, len, D2K_QSNAP_MAX_DGRAMS + 1, blob, sizeof blob) == 0,
          "пачка сверх предела собрана");
    CHECK(d2k_qsnap_pack(dg, len, 2, blob, 16) == 0, "пачка собрана в тесный буфер");

    if (fails) { printf("test_quicsnap: провалов %d\n", fails); return 1; }
    printf("test_quicsnap: все проверки прошли\n");
    return 0;
}
