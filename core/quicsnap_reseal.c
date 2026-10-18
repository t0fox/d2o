/* quicsnap_reseal.c — перезапечатка пачки Initial под новый идентификатор.
 *
 * Отдельный файл от quicsnap.c не ради красоты: датапат пачки только СОБИРАЕТ
 * (d2k_qsnap_pack) и не перезапечатывает их никогда, а перезапечатка тянет за
 * собой генератор случайных чисел и вывод ключей. На роутерах с MIPS каждый
 * килобайт прошивки на счету, и класть в датапат код, который он не зовёт,
 * незачем.
 */
#include <string.h>

#include "d2k_quicsnap.h"
#include "d2k_quicwire.h"
#include "d2k_tls13core.h"


/* Один пакет пачки: открыть старыми ключами, собрать заголовок с новым DCID,
   запечатать новыми. Всё остальное — из снимка: номер пакета и его длина,
   SCID, токен, фиксированный бит, итоговый размер датаграммы.

   Длина номера пакета берётся ИЗ СНИМКА, а не считается заново: клиент
   выбирает её сам (RFC 9000 §17.1), и пересчёт укоротил бы датаграмму — то
   есть изменил бы форму, ради сохранности которой всё это и делается.
   Считается вычитанием: поле Length покрывает номер, тело и тег AEAD. */
static int reseal_one(const uint8_t *in, size_t n,
                      const d2k_qw_keys *old_k, const d2k_qw_keys *new_k,
                      const uint8_t *dcid, size_t dcid_len,
                      uint8_t *out, size_t cap, size_t *out_len) {
    d2k_qw_hdr h;
    if (d2k_qw_hdr_parse(in, n, 0, &h) != 0 || !h.long_hdr ||
        h.type != D2K_QW_LT_INITIAL || h.packet_len != n) {
        return -1;
    }
    uint8_t plain[D2K_QW_MAX_DGRAM];
    size_t plain_len = 0;
    uint64_t pn = 0;
    if (n > sizeof plain || d2k_qw_open(old_k, &h, in, 0, plain, &plain_len, &pn) != 0) {
        return -1;
    }
    if (h.length_claimed < plain_len + 16) {
        return -1;
    }
    size_t pn_len = h.length_claimed - plain_len - 16;
    if (pn_len < 1 || pn_len > 4) {
        return -1;
    }
    uint8_t pkt[D2K_QW_MAX_DGRAM];
    size_t hlen = h.token_len
        ? d2k_qw_long_hdr_token_w(pkt, sizeof pkt, h.version, D2K_QW_LT_INITIAL,
                                  dcid, dcid_len, in + h.scid_off, h.scid_len,
                                  in + h.token_off, h.token_len, pn_len, plain_len,
                                  h.length_width)
        : d2k_qw_long_hdr_w(pkt, sizeof pkt, h.version, D2K_QW_LT_INITIAL,
                            dcid, dcid_len, in + h.scid_off, h.scid_len,
                            pn_len, plain_len, h.length_width);
    if (hlen == 0) {
        return -1;
    }
    /* ФИКСИРОВАННЫЙ БИТ — ИЗ СНИМКА. Сборщик заголовка ставит его всегда (RFC
       9000 §17.2), а клиент вправе его гасить (RFC 9287), и защита заголовка
       его не маскирует. Пересобрать «как положено» значило бы изменить
       форму — и вопрос про погашенный бит никогда бы не подтвердился. */
    pkt[0] = (uint8_t)((pkt[0] & (uint8_t)~0x40u) | (in[0] & 0x40u));
    size_t made = d2k_qw_seal(new_k, 1, pkt, hlen, pn, pn_len, plain, plain_len,
                              pkt, sizeof pkt);
    /* Длина обязана совпасть со снимком: добивка уже внутри расшифрованного
       содержимого, либо хвостовой паддинг/пакет за пределами h.packet_len. */
    if (made == 0 || made != n || n > cap) {
        return -1;
    }
    memcpy(out, pkt, made);
    *out_len = made;
    return 0;
}

int d2k_qsnap_recid(const d2k_qsnap *s, uint8_t *out, size_t cap, size_t *out_len) {
    if (!s || !out || !out_len || s->n == 0 || s->n > D2K_QSNAP_MAX_DGRAMS) {
        return -1;
    }
    d2k_qw_hdr first;
    if (d2k_qw_hdr_parse(s->dg[0], s->len[0], 0, &first) != 0 || !first.long_hdr ||
        first.type != D2K_QW_LT_INITIAL) {
        return -1;
    }
    /* Соль у каждой версии своя (RFC 9001 §5.2, RFC 9369 §3.3.1): версию, для
       которой её нет, перезапечатать нечем. */
    if (first.version != D2K_QW_V1 && first.version != D2K_QW_V2) {
        return -1;
    }

    /* Старые ключи — из DCID ПЕРВОЙ датаграммы: весь полёт идёт под ним. */
    uint8_t sec[32];
    d2k_qw_keys old_k, new_k;
    if (d2k_qw_initial_secret(first.version, s->dg[0] + first.dcid_off, first.dcid_len,
                              D2K_QW_CLIENT, sec) != 0 ||
        d2k_qw_keys_from_secret(first.version, sec, &old_k) != 0) {
        return -1;
    }
    /* Новый DCID — ТОЙ ЖЕ ДЛИНЫ и ОДИН на всю пачку: длина тоже форма, а два
       разных идентификатора сервер принял бы за два соединения с половиной
       приветствия каждое. */
    uint8_t dcid[D2K_QW_CID_MAX];
    size_t dcid_len = (first.dcid_len >= 8 && first.dcid_len <= sizeof dcid)
                      ? first.dcid_len : 8;
    if (d2k_t13_random(dcid, dcid_len) != 0 ||
        d2k_qw_initial_secret(first.version, dcid, dcid_len, D2K_QW_CLIENT, sec) != 0 ||
        d2k_qw_keys_from_secret(first.version, sec, &new_k) != 0) {
        return -1;
    }

    uint8_t made[D2K_QSNAP_MAX_DGRAMS][D2K_QW_MAX_DGRAM];
    const uint8_t *dg[D2K_QSNAP_MAX_DGRAMS];
    size_t len[D2K_QSNAP_MAX_DGRAMS];
    for (size_t i = 0; i < s->n; i++) {
        d2k_qw_hdr h;
        /* Чужая датаграмма в пачке (Retry, другой поток в кольце датапата) —
           отказ целиком: склеенный из двух полётов снимок не слал никто. */
        if (d2k_qw_hdr_parse(s->dg[i], s->len[i], 0, &h) != 0 || !h.long_hdr ||
            h.version != first.version || h.dcid_len != first.dcid_len ||
            memcmp(s->dg[i] + h.dcid_off, s->dg[0] + first.dcid_off, first.dcid_len) != 0) {
            return -1;
        }
        if (reseal_one(s->dg[i], s->len[i], &old_k, &new_k, dcid, dcid_len,
                       made[i], sizeof made[i], &len[i]) != 0) {
            return -1;
        }
        dg[i] = made[i];
    }
    size_t packed = d2k_qsnap_pack(dg, len, s->n, out, cap);
    if (packed == 0) {
        return -1;
    }
    *out_len = packed;
    return 0;
}
