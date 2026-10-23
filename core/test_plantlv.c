/* test_plantlv.c — перевод текста плана в байты провода.
 *
 * ГЛАВНАЯ ПРОВЕРКА: для КАЖДОЙ формы, которую умеет собирать compose.c, текст,
 * пропущенный через d2k_plan_text_to_tlv, обязан дать РОВНО те же байты, что
 * собирает прямой TLV-сборщик рядом. Это не сверка перевода с представлением
 * теста о нём: обе формы одной фигуры уже существуют в дереве и уже проверены
 * planlab'ом (test_compose), поэтому равенство между ними — настоящий эталон.
 *
 * Вторая проверка: план, собранный d2k_compose (тот, что реально едет от
 * планировщика), после перевода принимается НАСТОЯЩИМ исполнителем датапата —
 * planlab гоняет d2k_plan_load + d2k_plan_apply, те же, что в проде. Без неё
 * равенство с сборщиком доказывало бы лишь внутреннюю согласованность. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "d2k_compose.h"
#include "d2k_compose_internal.h"
#include "d2k_hello.h"
#include "d2k_plantlv.h"
#include "d2k_plan.h"
#include "d2k_wire.h"

static int fails;
#define CHECK(cond, msg) do { if (!(cond)) { printf("ПРОВАЛ: %s\n", (msg)); fails++; } } while (0)

static void show_diff(const char *what, const uint8_t *a, size_t an,
                      const uint8_t *b, size_t bn) {
    printf("  %s: прямой сборщик %zu байт, перевод %zu байт\n", what, an, bn);
    size_t n = an < bn ? an : bn;
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) {
            printf("  первое расхождение в байте %zu: %02x против %02x\n", i, a[i], b[i]);
            return;
        }
    }
}

static void same(const char *what, const char *text,
                 const uint8_t *want, size_t want_len) {
    uint8_t got[D2K_PLAN_TLV_MAX];
    size_t got_len = 0;
    char err[200];
    if (d2k_plan_text_to_tlv(text, got, sizeof got, &got_len, err, sizeof err) != 0) {
        printf("ПРОВАЛ: %s: перевод отказал: %s\n", what, err);
        fails++;
        return;
    }
    if (got_len != want_len || memcmp(got, want, want_len) != 0) {
        printf("ПРОВАЛ: %s: перевод текста дал НЕ те байты, что прямой сборщик\n", what);
        show_diff(what, want, want_len, got, got_len);
        fails++;
    }
}

static int write_file_bytes(const char *path, const uint8_t *b, size_t n) {
    FILE *f = fopen(path, "wb");
    if (!f) { return -1; }
    size_t wr = n ? fwrite(b, 1, n, f) : 0;
    int ok = (wr == n) && (fclose(f) == 0);
    return ok ? 0 : -1;
}

static int write_file_text(const char *path, const char *s) {
    FILE *f = fopen(path, "wb");
    if (!f) { return -1; }
    int ok = fputs(s, f) >= 0;
    return (fclose(f) == 0 && ok) ? 0 : -1;
}

/* AUTOTTL СКВОЗЬ ВЕСЬ ПУТЬ: текст → TLV → разбор → посылка (замысел
 * 2026-10-23 «приёмы без настроек клиентской ОС», п. 6.1). Документация
 * zapret2, standard fooling: ip_autottl меняет TTL «на автоматически
 * определяемый по шаблону autottl delta,min-max». Проверяем, что число
 * считает ДАТАПАТ по TTL ответной стороны, а не контроллер константой. */
static void autottl_end_to_end(void) {
    static const char text[] =
        "d2k-plan 1 13\nid 00000000000000000000000000000000\n"
        "proto tcp tls\npayload 1 aabbcc\n"
        "poison 1 badsum autottl=1,2-12\n"
        "fake payload=1 poison=1 repeats=1 gap_us=0 place=before\norder forward\n";
    uint8_t tlv[D2K_PLAN_TLV_MAX];
    size_t n = 0;
    char err[200];
    d2k_plan *pl = NULL;
    CHECK(d2k_plan_text_to_tlv(text, tlv, sizeof tlv, &n, err, sizeof err) == 0,
          "autottl: текст не переведён в TLV");
    CHECK(d2k_plan_load(tlv, n, &pl, err, sizeof err) == 0 && pl,
          "autottl: TLV не разобран исполнителем");
    if (!pl) { return; }
    uint8_t hello[64] = {0x16, 3, 1, 0, 5, 1, 0, 0, 1, 0};
    d2k_pkt in = {0};
    in.payload = hello; in.payload_len = sizeof hello; in.seq = 100;
    d2k_actions a = {0};
    CHECK(d2k_plan_apply(pl, NULL, &in, &a) == 0 && a.n >= 1,
          "autottl: план не применился к приветствию");
    if (a.n >= 1) {
        /* Плечо доехало до посылки. */
        CHECK(a.v[0].autottl == 1 && a.v[0].autottl_delta == 1 &&
              a.v[0].autottl_min == 2 && a.v[0].autottl_max == 12,
          "autottl: признак и шаблон не доехали до посылки");
        /* И сборщик считает его по ответу: TTL ответа 57 → путь 7 → +1 = 8. */
        uint8_t wire[256];
        d2k_conn c = {0};
        c.family = 4; c.ttl = 64; c.rev_ttl = 57; c.window = 1024;
        size_t w = d2k_wire_build(&c, &a.v[0], wire, sizeof wire);
        CHECK(w > 20 && wire[8] == 8,
          "autottl: сборщик не посчитал TTL по ответу (ждали 8)");
    }
    d2k_actions_free(&a);
    d2k_plan_free(pl);
    /* Старый исполнитель такой план НЕ берёт: minexec ниже 13. */
    static const char old_text[] =
        "d2k-plan 1 12\nid 00000000000000000000000000000000\n"
        "proto tcp tls\npayload 1 aabbcc\n"
        "poison 1 badsum autottl=1,2-12\n"
        "fake payload=1 poison=1 repeats=1 gap_us=0 place=before\norder forward\n";
    size_t n2 = 0;
    CHECK(d2k_plan_text_to_tlv(old_text, tlv, sizeof tlv, &n2, err, sizeof err) != 0 ||
          d2k_plan_load(tlv, n2, &pl, err, sizeof err) != 0,
          "autottl: план с minexec 12 принят старым исполнителем");
    d2k_plan_free(pl);
    /* Кривой шаблон отвергается с объяснением. */
    size_t n3 = 0;
    CHECK(d2k_plan_text_to_tlv(
        "d2k-plan 1 13\nproto tcp tls\npoison 1 autottl=1,20-2\n",
        tlv, sizeof tlv, &n3, err, sizeof err) != 0,
          "autottl: кривой шаблон min>max принят");
}

int main(void) {
    autottl_end_to_end();
    /* --- перекрытие слева ------------------------------------------------ */
    {
        char text[4096];
        uint8_t tlv[4096];
        size_t tlv_len = 0;
        CHECK(overlap_plan_text(text, sizeof text) == 0, "overlap_plan_text не собрался");
        CHECK(overlap_plan_tlv(tlv, sizeof tlv, &tlv_len) == 0, "overlap_plan_tlv не собрался");
        same("перекрытие слева", text, tlv, tlv_len);
    }

    /* --- порядок сегментов ----------------------------------------------- */
    {
        char text[4096];
        uint8_t tlv[4096];
        size_t tlv_len = 0;
        CHECK(reorder_plan_text(text, sizeof text) == 0, "reorder_plan_text не собрался");
        CHECK(reorder_plan_tlv(tlv, sizeof tlv, &tlv_len) == 0, "reorder_plan_tlv не собрался");
        same("порядок сегментов", text, tlv, tlv_len);
    }

    /* --- контрольная сумма (набивка 64×0x0f) ----------------------------- */
    {
        char text[4096];
        uint8_t tlv[4096];
        size_t tlv_len = 0;
        CHECK(checksum_plan_text(text, sizeof text) == 0, "checksum_plan_text не собрался");
        CHECK(checksum_plan_tlv(tlv, sizeof tlv, &tlv_len) == 0, "checksum_plan_tlv не собрался");
        same("контрольная сумма", text, tlv, tlv_len);
    }

    /* --- фальшивка с повторами и паузой (счёт дубликатов) ---------------- */
    {
        uint8_t payload[300];
        for (size_t i = 0; i < sizeof payload; i++) { payload[i] = (uint8_t)(i * 7 + 3); }
        char text[4096];
        uint8_t tlv[4096];
        size_t tlv_len = 0;
        CHECK(badsum_fake_plan_text(payload, sizeof payload, 2, 20000, text, sizeof text) == 0,
              "badsum_fake_plan_text не собрался");
        CHECK(badsum_fake_plan_tlv(payload, sizeof payload, 2, 20000, tlv, sizeof tlv, &tlv_len) == 0,
              "badsum_fake_plan_tlv не собрался");
        same("счёт дубликатов", text, tlv, tlv_len);
    }

    /* --- delay: выдержка перед единственной посылкой ---------------------
     *
     * Ни pace, ни settle её не выражают (см. d2k_plan_internal.h про
     * delay_us). Требует minexec=6: старый датапат выдержки не знает, и
     * молча выпустить посылку без паузы значит исполнить не тот план. */
    {
        uint8_t out[1024];
        size_t n = 0;
        char err[200];
        static const char *h6 =
            "d2k-plan 1 6\nid 00000000000000000000000000000000\nproto udp quic\n";
        static const char *h1 =
            "d2k-plan 1 1\nid 00000000000000000000000000000000\nproto udp quic\n";
        char text[1024];

        snprintf(text, sizeof text, "%sdelay 15000\n", h6);
        CHECK(d2k_plan_text_to_tlv(text, out, sizeof out, &n, err, sizeof err) == 0,
              "выдержка не собралась");
        {
            static const uint8_t want[4] = { 0x01, 0x0b, 0x00, 0x04 };
            int seen = 0;
            for (size_t i = 0; n >= 4 && i + 4 <= n; i++) {
                if (memcmp(out + i, want, 4) == 0) { seen = 1; break; }
            }
            CHECK(seen, "записи выдержки нет в TLV");
        }

        /* ГЛАВНАЯ ПРОВЕРКА — ЧТО ПЛАН ПРИМЕТ РАЗБОР ДАТАПАТА, а не что байты
           записи где-то лежат. Поле 19.09.2026: запись выдержки собиралась,
           но не попала в СЧЁТЧИК записей заголовка, и служба отвергла план
           целиком — «число записей не совпадает с заявленным». Тест, который
           смотрел только на наличие байтов, этого не поймал. */
        {
            const char *pp = "/tmp/d2k-test-delay.bin";
            const char *sp = "/tmp/d2k-test-delay.scn";
            CHECK(write_file_bytes(pp, out, n) == 0, "план выдержки не записался");
            CHECK(write_file_text(sp, "pkt 1000 11 17 "
                    "16030100200100001c0303000000000000000000000000000000000000"
                    "0000000000000000000000000000\n") == 0, "сценарий не записался");
            char cmd[400];
            snprintf(cmd, sizeof cmd, "../datapath/planlab %s %s 2>&1", pp, sp);
            FILE *pf = popen(cmd, "r");
            CHECK(pf != NULL, "planlab не запустился");
            char o[4096];
            size_t got = 0;
            if (pf) {
                while (got + 1 < sizeof o) {
                    size_t r = fread(o + got, 1, sizeof o - 1 - got, pf);
                    if (r == 0) { break; }
                    got += r;
                }
                pclose(pf);
            }
            o[got] = '\0';
            CHECK(strstr(o, "reject") == NULL,
                  "разбор датапата отверг план с выдержкой");
            remove(pp);
            remove(sp);
        }

        snprintf(text, sizeof text, "%sdelay 15000\n", h1);
        CHECK(d2k_plan_text_to_tlv(text, out, sizeof out, &n, err, sizeof err) != 0,
              "выдержка принята при minexec=1 — старый датапат исполнит не тот план");

        snprintf(text, sizeof text, "%sdelay 0\n", h6);
        CHECK(d2k_plan_text_to_tlv(text, out, sizeof out, &n, err, sizeof err) != 0,
              "delay 0 принят — он неотличим от отсутствия строки");

        snprintf(text, sizeof text, "%sdelay 15ms\n", h6);
        CHECK(d2k_plan_text_to_tlv(text, out, sizeof out, &n, err, sizeof err) != 0,
              "delay принял не-число");

        snprintf(text, sizeof text, "%sdelay 15000 20000\n", h6);
        CHECK(d2k_plan_text_to_tlv(text, out, sizeof out, &n, err, sizeof err) != 0,
              "delay принял два значения");
    }

    {
        uint8_t out[256];size_t n=0;char err[200],text[256];
        const char *bad[]={"ipfrag 0\n","ipfrag 5\n","ipfrag 1 2\n",
            "ipfrag 1\nipfrag 1\n","ipfrag -1\n","ipfrag 1ms\n",
            "ipfrag 1\nsplit payload_start +1\n","ipfrag 1\norder reverse\n"};
        for(size_t i=0;i<sizeof bad/sizeof bad[0];i++) {
            snprintf(text,sizeof text,"d2k-plan 1 7\nproto udp quic\n%s",bad[i]);
            CHECK(d2k_plan_text_to_tlv(text,out,sizeof out,&n,err,sizeof err)!=0,
                  "invalid/conflicting fragment text accepted");
        }
        CHECK(d2k_plan_text_to_tlv("d2k-plan 1 6\nproto udp quic\nipfrag 1\n",
              out,sizeof out,&n,err,sizeof err)!=0,"fragment with old executor");
        CHECK(d2k_plan_text_to_tlv("d2k-plan 1 7\nproto tcp tls\nipfrag 1\n",
              out,sizeof out,&n,err,sizeof err)!=0,"fragment with TCP text");
    }

    /* udplen — «удлинить датаграмму на N нулевых байт» (zapret udplen
       increment=N, донор compose questions.go:331-334). Запись 0x010e, два
       байта, исполнитель 9, только UDP. */
    {
        uint8_t out[256];size_t n=0;char err[200],text[256];
        int rc=d2k_plan_text_to_tlv("d2k-plan 1 9\nproto udp quic\nudplen 100\n",
                                    out,sizeof out,&n,err,sizeof err);
        if(rc)printf("udplen: %s\n",err);
        CHECK(rc==0,"udplen 100 не переведён");
        static const uint8_t rec[]={0x01,0x0e,0x00,0x02,0x00,0x64};
        int found=0;
        for(size_t i=12;i+sizeof rec<=n;i++) if(!memcmp(out+i,rec,sizeof rec)) found=1;
        CHECK(rc==0&&found,"udplen 100 не дал записи 010e 0002 0064");
        CHECK(rc==0&&out[7]==9&&out[11]==4,"udplen: заголовок/число записей не те");
        const char *bad[]={"udplen 0\n","udplen +100\n","udplen 100x\n","udplen\n",
            "udplen 100 1\n","udplen 65536\n","udplen 100\nudplen 100\n","udplen -1\n",
            "udplen 100\nipfrag 1\n","udplen 100\nsplit payload_start +1\n",
            "udplen 100\norder reverse\n"};
        for(size_t i=0;i<sizeof bad/sizeof bad[0];i++) {
            snprintf(text,sizeof text,"d2k-plan 1 9\nproto udp quic\n%s",bad[i]);
            CHECK(d2k_plan_text_to_tlv(text,out,sizeof out,&n,err,sizeof err)!=0,
                  "invalid/conflicting udplen text accepted");
        }
        CHECK(d2k_plan_text_to_tlv("d2k-plan 1 8\nproto udp quic\nudplen 100\n",
              out,sizeof out,&n,err,sizeof err)!=0,"udplen with old executor");
        CHECK(d2k_plan_text_to_tlv("d2k-plan 1 9\nproto tcp tls\nudplen 100\n",
              out,sizeof out,&n,err,sizeof err)!=0,"udplen with TCP text");
        /* Комментарий провенанса не меняет байт плана. */
        uint8_t a[256],b[256];size_t an=0,bn=0;
        CHECK(d2k_plan_text_to_tlv("d2k-plan 1 9\nproto udp quic\n# PROFILE\nudplen 100\n",
              a,sizeof a,&an,err,sizeof err)==0 &&
              d2k_plan_text_to_tlv("d2k-plan 1 9\nproto udp quic\nudplen 100\n",
              b,sizeof b,&bn,err,sizeof err)==0 && an==bn && !memcmp(a,b,an),
              "комментарий провенанса изменил TLV");
    }

    /* quicsplit — разрез ClientHello на кадры CRYPTO внутри Initial
       (задача 40). Запись 0x010f, один байт формы (1 — кадры CRYPTO, хвост
       первым), исполнитель 10, только UDP, без фрагментации и удлинения. */
    {
        uint8_t out[256];size_t n=0;char err[200],text[256];
        int rc=d2k_plan_text_to_tlv("d2k-plan 1 10\nproto udp quic\nquicsplit 1\norder forward\n",
                                    out,sizeof out,&n,err,sizeof err);
        if(rc)printf("quicsplit: %s\n",err);
        CHECK(rc==0,"quicsplit 1 не переведён");
        static const uint8_t rec[]={0x01,0x0f,0x00,0x01,0x01};
        int found=0;
        for(size_t i=12;i+sizeof rec<=n;i++) if(!memcmp(out+i,rec,sizeof rec)) found=1;
        CHECK(rc==0&&found,"quicsplit 1 не дал записи 010f 0001 01");
        CHECK(rc==0&&out[7]==10,"quicsplit: исполнитель не 10");
        const char *bad[]={"quicsplit 0\n","quicsplit 2\n","quicsplit\n","quicsplit 1 1\n",
            "quicsplit 1\nquicsplit 1\n","quicsplit 1\nipfrag 1\n","quicsplit 1\nudplen 100\n",
            "quicsplit 1\nsplit payload_start +1\n","quicsplit 1\norder reverse\n"};
        for(size_t i=0;i<sizeof bad/sizeof bad[0];i++) {
            snprintf(text,sizeof text,"d2k-plan 1 10\nproto udp quic\n%s",bad[i]);
            CHECK(d2k_plan_text_to_tlv(text,out,sizeof out,&n,err,sizeof err)!=0,
                  "invalid/conflicting quicsplit text accepted");
        }
        CHECK(d2k_plan_text_to_tlv("d2k-plan 1 9\nproto udp quic\nquicsplit 1\n",
              out,sizeof out,&n,err,sizeof err)!=0,"quicsplit with old executor");
        CHECK(d2k_plan_text_to_tlv("d2k-plan 1 10\nproto tcp tls\nquicsplit 1\n",
              out,sizeof out,&n,err,sizeof err)!=0,"quicsplit with TCP text");
    }

    /* quicdeny — QUIC для имени не пропускается (задача 50, раунд 2):
       запись 0x0110, форма 1, исполнитель 11, только UDP и без воздействий. */
    {
        uint8_t out[256];size_t n=0;char err[200],text[256];
        int rc=d2k_plan_text_to_tlv("d2k-plan 1 11\nproto udp quic\nquicdeny 1\norder forward\n",
                                    out,sizeof out,&n,err,sizeof err);
        if(rc)printf("quicdeny: %s\n",err);
        static const uint8_t rec[]={0x01,0x10,0x00,0x01,0x01};
        int found=0;
        for(size_t i=12;i+sizeof rec<=n;i++) if(!memcmp(out+i,rec,sizeof rec)) found=1;
        CHECK(rc==0&&found&&out[7]==11,"quicdeny 1 не дал записи 0110 0001 01 с исполнителем 11");
        const char *bad[]={"quicdeny 0\n","quicdeny 2\n","quicdeny\n","quicdeny 1\nquicdeny 1\n",
            "quicdeny 1\nudplen 100\n","quicdeny 1\nquicsplit 1\n","quicdeny 1\nipfrag 1\n",
            "quicdeny 1\npayload 1 00ff\nfake 1 0 before 1 0\n","quicdeny 1\norder reverse\n"};
        for(size_t i=0;i<sizeof bad/sizeof bad[0];i++) {
            snprintf(text,sizeof text,"d2k-plan 1 11\nproto udp quic\n%s",bad[i]);
            CHECK(d2k_plan_text_to_tlv(text,out,sizeof out,&n,err,sizeof err)!=0,
                  "invalid/conflicting quicdeny text accepted");
        }
        CHECK(d2k_plan_text_to_tlv("d2k-plan 1 10\nproto udp quic\nquicdeny 1\n",
              out,sizeof out,&n,err,sizeof err)!=0,"quicdeny with old executor");
        CHECK(d2k_plan_text_to_tlv("d2k-plan 1 11\nproto tcp tls\nquicdeny 1\n",
              out,sizeof out,&n,err,sizeof err)!=0,"quicdeny with TCP text");
    }

    /* Строгий разбор: усечённое слово и число вне ширины поля — отказ. */
    {
        uint8_t out[512]; size_t n=0; char err[200], text[512];
        const char *bad[]={
            "poison 1 badsum tcpts ipidzero ttl=5 seqshift=1 extra\n",
            "poison 1 ttl=300\n", "poison 1 ttl=5x\n", "poison 1 ttl=-1\n",
            "poison 1 seqshift=2147483648\n", "poison 1 seqshift=-2147483649\n",
            "poison 65536\n", "payload 65536 aa\n", "payload 1x aa\n",
            "split payload_start +32768\n", "split payload_start -32769\n",
            "split payload_start 1x\n",
            "payload 1 aa\npoison 1\nfake payload=1 poison=1 repeats=70000 gap_us=0 place=before\n",
            "payload 1 aa\npoison 1\nfake payload=1 poison=1 repeats=256 gap_us=0 place=before\n",
            "payload 1 aa\npoison 1\nfake payload=1 poison=1 repeats=1 gap_us=4294967296 place=before\n",
            "payload 1 aa\npoison 1\nfake payload=65536 poison=1 repeats=1 gap_us=0 place=before\n",
            "payload 1 aa\npoison 1\nseqovl payload=1 poison=65536\n",
        };
        for (size_t i=0;i<sizeof bad/sizeof bad[0];i++) {
            snprintf(text,sizeof text,"d2k-plan 1 1\nproto tcp tls\n%s",bad[i]);
            CHECK(d2k_plan_text_to_tlv(text,out,sizeof out,&n,err,sizeof err)!=0,
                  "строгий разбор принял усечённое/внедиапазонное число");
        }
        CHECK(d2k_plan_text_to_tlv("d2k-plan 1 1 1\nproto tcp tls\n",
              out,sizeof out,&n,err,sizeof err)!=0,"d2k-plan с лишним словом");
        CHECK(d2k_plan_text_to_tlv("d2k-plan 65536 1\nproto tcp tls\n",
              out,sizeof out,&n,err,sizeof err)!=0,"schema вне u16");
        /* Границы ширины полей остаются допустимыми. */
        CHECK(d2k_plan_text_to_tlv("d2k-plan 1 1\nproto tcp tls\npayload 65535 aa\n"
              "poison 65535 ttl=255 seqshift=-2147483648\n"
              "split payload_start -32768\nsplit sni_middle +32767\n"
              "fake payload=65535 poison=65535 repeats=255 gap_us=4294967295 place=before\n",
              out,sizeof out,&n,err,sizeof err)==0,"граничные значения отвергнуты");
    }

    {
        static const char good[] =
            "d2k-plan 1 8\nproto tcp tls\nwire detect-tcp-v1\n"
            "input tls-sni\nsegment 1400\noob sni_middle 0f\n";
        uint8_t out[256]; size_t n=0; char err[200];
        CHECK(d2k_plan_text_to_tlv(good,out,sizeof out,&n,err,sizeof err)==0,
              "валидное измеренное TCP URG-плечо не сериализовалось");
        static const uint8_t rec[] = {0x01,0x0d,0x00,0x03,0x00,0x05,0x0f};
        int found=0;
        for(size_t i=0;i+sizeof rec<=n;i++) if(!memcmp(out+i,rec,sizeof rec)) found=1;
        CHECK(found,"OOB TLV потерял якорь SNI или срочный байт");
        static const char *bad[] = {
            "d2k-plan 1 7\nproto tcp tls\nwire detect-tcp-v1\ninput tls-sni\noob sni_middle 0f\n",
            "d2k-plan 1 8\nproto tcp tls\noob sni_middle 0f\n",
            "d2k-plan 1 8\nproto udp quic\noob sni_middle 0f\n",
            "d2k-plan 1 8\nproto tcp tls\nwire detect-tcp-v1\ninput tls-sni\noob sni_middle ff00\n",
            "d2k-plan 1 8\nproto tcp tls\nwire detect-tcp-v1\ninput tls-sni\noob unknown 0f\n"
        };
        for(size_t i=0;i<sizeof bad/sizeof bad[0];i++)
            CHECK(d2k_plan_text_to_tlv(bad[i],out,sizeof out,&n,err,sizeof err)!=0,
                  "неподдержанная форма OOB принята");
        static const char duplicate[] =
            "d2k-plan 1 8\nproto tcp tls\nwire detect-tcp-v1\ninput tls-sni\n"
            "oob sni_middle 0f\noob sni_middle 0e\n";
        CHECK(d2k_plan_text_to_tlv(duplicate,out,sizeof out,&n,err,sizeof err)!=0,
              "повторное OOB-действие принято");
    }

    /* Fallback arm -> text -> TLV -> настоящий datapath executor. */
    {
        d2k_arm arm = { .name = "seqovl-1", .seqovl = 1 };
        uint8_t hello[2048], tlv[D2K_PLAN_TLV_MAX];
        size_t hello_len = 0, sni_off = 0, sni_len = 0, tlv_len = 0;
        char plan_text[4096], err[200];
        CHECK(d2k_hello_from_profile(D2K_SHAPE_LEGACY, "rutracker.org",
                                    hello, sizeof hello, &hello_len) == 0,
              "seqovl wire regression: ClientHello fixture не собрался");
        CHECK(d2k_hello_sni(hello, hello_len, &sni_off, &sni_len) == 0,
              "seqovl wire regression: SNI координаты не извлеклись");
        d2k_arm_input input = {0};
        input.trigger_len = hello_len;
        input.sni_off = sni_off;
        input.sni_len = sni_len;
        CHECK(d2k_arm_plan_measured(&arm, &input, plan_text, sizeof plan_text) == 0,
              "seqovl wire regression: план измеренного seqovl-1 не собрался");
        CHECK(strstr(plan_text, "split payload_start +1\n") == NULL,
              "seqovl wire regression: лишний разрез относительно сырого зонда");
        CHECK(d2k_plan_text_to_tlv(plan_text, tlv, sizeof tlv, &tlv_len,
                                   err, sizeof err) == 0,
              "seqovl wire regression: план не перевёлся в TLV");
        if (hello_len && tlv_len) {
            char *scenario = calloc(1, 3 * hello_len + 128);
            char *output = calloc(1, 8192);
            char *hex = calloc(1, 2 * hello_len + 1);
            char plan_path[128], scenario_path[128], cmd[400];
            CHECK(scenario && output && hex, "seqovl wire regression: память под сценарий не выделилась");
            if (scenario && output && hex) {
                static const char digits[] = "0123456789abcdef";
                for (size_t i = 0; i < hello_len; i++) {
                    hex[2*i] = digits[hello[i] >> 4];
                    hex[2*i+1] = digits[hello[i] & 15];
                }
                snprintf(scenario, 128, "pkt 1000 %zu %zu ", sni_off, sni_len);
                size_t prefix_len = strlen(scenario);
                memcpy(scenario + prefix_len, hex, 2 * hello_len);
                scenario[prefix_len + 2 * hello_len] = '\n';
                snprintf(plan_path, sizeof plan_path, "/tmp/d2k-seqovl-%d.tlv", (int)getpid());
                snprintf(scenario_path, sizeof scenario_path, "/tmp/d2k-seqovl-%d.scn", (int)getpid());
                CHECK(write_file_bytes(plan_path, tlv, tlv_len) == 0,
                      "seqovl wire regression: TLV-файл не записался");
                CHECK(write_file_text(scenario_path, scenario) == 0,
                      "seqovl wire regression: сценарий не записался");
                snprintf(cmd, sizeof cmd, "../datapath/planlab %s %s 2>&1", plan_path, scenario_path);
                FILE *f = popen(cmd, "r");
                CHECK(f != NULL, "seqovl wire regression: planlab не стартовал");
                if (f) {
                    size_t got = fread(output, 1, 8191, f);
                    output[got] = '\0';
                    pclose(f);
                }
                char expected_first[96];
                snprintf(expected_first, sizeof expected_first,
                         "emit payload 0 999 ttl=0 poison=00 0f%02x", hello[0]);
                int emits = 0;
                for (char *p = output; (p = strstr(p, "emit ")) != NULL; p += 5) emits++;
                CHECK(emits == 1,
                      "seqovl wire regression: зонд seqovl-1 шлёт одну посылку");
                CHECK(strstr(output, expected_first) != NULL,
                      "seqovl wire regression: первый сегмент не несёт 0f + первый байт с seq-1");
                CHECK(strstr(output, hex) != NULL,
                      "seqovl wire regression: полное приветствие должно идти после приставки");
                CHECK(strstr(output, "fate drop") != NULL,
                      "seqovl wire regression: исходный пакет не снят при собственной посылке");
                remove(plan_path);
                remove(scenario_path);
            }
            free(hex);
            free(output);
            free(scenario);
        }
    }

    {
        char plan_text[4096], err[200], command[400], output[2048];
        uint8_t tlv[D2K_PLAN_TLV_MAX], hello[64];
        size_t tlv_len=0, used=0;
        int oob_found=0;
        for(size_t i=0;i<d2k_fallback_arms();i++) {
            if(d2k_fallback_plan(i,D2K_SHAPE_MODERN,"rutracker.org",1492,
                                 plan_text,sizeof plan_text)==0 &&
               strstr(plan_text,"oob sni_middle 0f\n")) { oob_found=1; break; }
        }
        CHECK(oob_found,"OOB fallback arm plan не собрался");
        CHECK(d2k_plan_text_to_tlv(plan_text,tlv,sizeof tlv,&tlv_len,err,sizeof err)==0,
              "OOB fallback arm не переводится в TLV");
        memset(hello,0x41,sizeof hello);
        hello[0]=0x16; hello[1]=3; hello[2]=1; hello[3]=0; hello[4]=59;
        hello[5]=1; hello[6]=0; hello[7]=0; hello[8]=55;
        memcpy(hello+20,"rutracker",8);
        char hex[sizeof hello*2+1];
        static const char digits[]="0123456789abcdef";
        for(size_t i=0;i<sizeof hello;i++) {
            hex[2*i]=digits[hello[i]>>4]; hex[2*i+1]=digits[hello[i]&15];
        }
        hex[sizeof hex-1]='\0';
        const char *pp="/tmp/d2k-test-oob.bin", *sp="/tmp/d2k-test-oob.scn";
        char scenario[256];
        snprintf(scenario,sizeof scenario,"pkt 1000 20 8 %s\n",hex);
        CHECK(write_file_bytes(pp,tlv,tlv_len)==0,"OOB TLV файл не создан");
        CHECK(write_file_text(sp,scenario)==0,"OOB сценарий не создан");
        snprintf(command,sizeof command,"../datapath/planlab %s %s 2>&1",pp,sp);
        FILE *f=popen(command,"r");
        CHECK(f!=NULL,"planlab не стартовал для OOB-плеча");
        if(f) {
            used=fread(output,1,sizeof output-1,f); output[used]='\0'; pclose(f);
        } else { output[0]='\0'; }
        int emits=0;
        for(char *p=output;(p=strstr(p,"emit payload"))!=NULL;p+=4) emits++;
        if (strstr(output,"reject ")!=NULL || strstr(output,"refuse")!=NULL || emits!=3) {
            printf("ПРОВАЛ: OOB-план не дал три посылки (emit=%d): %s",emits,output);
            fails++;
        }
        remove(pp); remove(sp);
    }

    /* --- pace: ноль и мусор отвергаются ---------------------------------
     *
     * «pace 0» запрещён нарочно: он и отсутствие строки означали бы одно и то
     * же, а директива, ничего не меняющая, — способ написать план, который
     * читается не так, как исполняется. Здесь же ловится и второе: значение у
     * pace идёт БЕЗ ключа, и разбор не должен принимать "pace pace=12000". */
    {
        uint8_t out[1024];
        size_t n = 0;
        char err[200];
        static const char *head =
            "d2k-plan 1 1\nid 00000000000000000000000000000000\nproto tcp tls\n"
            "split payload_start +1\norder forward\n";
        char text[1024];

        snprintf(text, sizeof text, "%space 0\n", head);
        CHECK(d2k_plan_text_to_tlv(text, out, sizeof out, &n, err, sizeof err) != 0,
              "pace 0 принят — а он неотличим от отсутствия строки");

        snprintf(text, sizeof text, "%space pace=12000\n", head);
        CHECK(d2k_plan_text_to_tlv(text, out, sizeof out, &n, err, sizeof err) != 0,
              "pace принял значение с ключом — у него значение голое");

        snprintf(text, sizeof text, "%space 12ms\n", head);
        CHECK(d2k_plan_text_to_tlv(text, out, sizeof out, &n, err, sizeof err) != 0,
              "pace принял не-число");

        snprintf(text, sizeof text, "%space 12000 15000\n", head);
        CHECK(d2k_plan_text_to_tlv(text, out, sizeof out, &n, err, sizeof err) != 0,
              "pace принял два значения");

        snprintf(text, sizeof text, "%space 12000\n", head);
        CHECK(d2k_plan_text_to_tlv(text, out, sizeof out, &n, err, sizeof err) == 0,
              "правильный pace отвергнут заодно с неправильными");
    }

    /* --- неизвестная директива = ОТКАЗ, а не пропуск (§2.5) -------------- */
    {
        uint8_t out[1024];
        size_t n = 0;
        char err[200];
        const char *bad =
            "d2k-plan 1 1\nid 00000000000000000000000000000000\nproto tcp tls\n"
            "жарить payload=1\norder forward\n";
        CHECK(d2k_plan_text_to_tlv(bad, out, sizeof out, &n, err, sizeof err) != 0,
              "неизвестная директива прошла молча — план на проводе отличался бы от записанного");
        CHECK(strstr(err, "неизвестная директива") != NULL,
              "отказ по неизвестной директиве без внятной причины");
    }

    /* --- текст без заголовка = отказ ------------------------------------- */
    {
        uint8_t out[1024];
        size_t n = 0;
        char err[200];
        CHECK(d2k_plan_text_to_tlv("order forward\n", out, sizeof out, &n, err, sizeof err) != 0,
              "план без заголовка d2k-plan принят");
    }

    /* --- план от d2k_compose принимается НАСТОЯЩИМ исполнителем датапата -- */
    {
        d2k_props pr;
        memset(&pr, 0, sizeof pr);
        char plans[8][4096];
        size_t n = d2k_compose(&pr, D2K_SHAPE_MODERN, "disk.rzd.ru", 0, plans, 8);
        CHECK(n == 1, "пустой вектор обязан дать ровно один запасной план");
        if (n >= 1) {
            uint8_t tlv[D2K_PLAN_TLV_MAX];
            size_t tlv_len = 0;
            char err[200];
            CHECK(d2k_plan_text_to_tlv(plans[0], tlv, sizeof tlv, &tlv_len, err, sizeof err) == 0,
                  "запасной план d2k_compose не переводится в байты провода");
            if (tlv_len > 0) {
                const char *pp = "/tmp/d2k-test-plantlv.bin";
                const char *sp = "/tmp/d2k-test-plantlv.scn";
                /* Сценарий planlab: один пакет, имя на известном смещении —
                   разрезы по якорям sni_middle обязаны во что-то упереться. */
                CHECK(write_file_bytes(pp, tlv, tlv_len) == 0, "план не записался");
                CHECK(write_file_text(sp,
                        "pkt 1000 11 17 "
                        "16030100200100001c0303000000000000000000000000000000000000"
                        "0000000000000000000000000000\n") == 0,
                      "сценарий не записался");
                char cmd[400];
                snprintf(cmd, sizeof cmd, "../datapath/planlab %s %s 2>&1", pp, sp);
                FILE *f = popen(cmd, "r");
                CHECK(f != NULL, "planlab не запустился");
                char out[8192];
                size_t got = 0;
                if (f) {
                    while (got + 1 < sizeof out) {
                        size_t r = fread(out + got, 1, sizeof out - 1 - got, f);
                        if (r == 0) { break; }
                        got += r;
                    }
                    pclose(f);
                }
                out[got] = '\0';
                CHECK(strstr(out, "reject") == NULL && strstr(out, "не принят") == NULL &&
                      strstr(out, "не разобрался") == NULL,
                      "настоящий исполнитель датапата отверг переведённый план");
                CHECK(strstr(out, "emit") != NULL,
                      "исполнитель не выдал ни одной посылки по переведённому плану");
                remove(pp);
                remove(sp);
            }
        }
    }

    if (fails) { printf("ПРОВАЛОВ: %d\n", fails); return 1; }
    printf("перевод плана: все проверки прошли\n");
    return 0;
}
