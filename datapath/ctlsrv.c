#define _POSIX_C_SOURCE 200809L
/* ctlsrv.c — смысл команд и событий управляющего сокета.
 *
 * Переносимо: ни NFQUEUE, ни сырых сокетов. Смысл протокола обязан
 * проверяться настоящим клиентом на любой машине, а не только на роутере под
 * root — иначе расхождение двух реализаций найдётся в поле.
 */
#include <stdio.h>
#include <string.h>

#include "d2k_ctlsrv.h"
#include "d2k_quicsnap.h"
#include "../runtime/d2k_runtime.h"

/* Кладёт ключ потока в тело события ПОЛЯМИ, а не наложением структуры на
 * буфер: memcpy(тело, &ключ, sizeof ключ) отправил бы на провод и три байта
 * дыры выравнивания (sizeof(d2k_key) == 16, значащих байт — D2K_KEY_WIRE_LEN
 * == 13), с непредсказуемым содержимым — см. большой комментарий у d2k_key
 * (d2k_track.h) про то, почему на эту дыру нельзя полагаться нигде, кроме
 * зануления внутри d2k_key_make. Тот же приём, каким остальной датапат
 * (wire.c, wire_udp.c) собирает заголовки: поле в поле, явным порядком.
 * Возвращает D2K_KEY_WIRE_LEN — сколько байт записано. */
static size_t put_key(uint8_t *out, const d2k_key *k) {
    memset(out, 0, D2K_KEY_WIRE_LEN);
    out[0] = k->family == 6 ? 6 : 4;
    if (out[0] == 6) {
        memcpy(out + 1, k->low_ip6, 16);
        memcpy(out + 17, k->high_ip6, 16);
    } else {
        memcpy(out + 1, &k->low_ip, 4);
        memcpy(out + 17, &k->high_ip, 4);
    }
    memcpy(out + 33, &k->low_port, 2);
    memcpy(out + 35, &k->high_port, 2);
    out[37] = k->proto;
    return D2K_KEY_WIRE_LEN;
}

int d2k_plan_fits(const d2k_plan *p, uint32_t limits, uint32_t maxlen,
                  char *why, size_t cap) {
    if (limits == 0) {
        return 1;   /* наблюдение: на провод ничего не пойдёт */
    }
    uint8_t used = d2k_plan_poison_used(p);
    if ((used & D2K_POISON_IPID_ZERO) && (limits & D2K_RAW_CANT_IPID)) {
        snprintf(why, cap,
            "план просит нулевой идентификатор IP, а сырой сокет им не "
            "распоряжается: ядро подставит свой");
        return 0;
    }
    /* ДЛИНА ПОСЫЛКИ. Ноль означает «предел не объявлен» — так бывает у стенда
       без сырого сокета, и резать там нечего.

       Сравнение строгое: посылка РОВНО в предел проходит. Перепутав его с
       «больше либо равно», мы отвергали бы полный кадр, который уедет.

       Отказ здесь, а не на отправке, — весь смысл этой проверки: на живой
       пробе 12.09.2026 ядро отвечало «sendto: Message too large» уже после
       того, как команда подтверждена, план встал и событие «план применён»
       ушло контроллеру, — то есть наша собственная неудача записывалась
       коробке в свойства. */
    if (maxlen > 0) {
        size_t need = d2k_plan_max_emit(p);
        if (need > (size_t)maxlen) {
            snprintf(why, cap,
                "самая длинная посылка плана — %zu байт, а способ отправки "
                "унесёт %u", need, (unsigned)maxlen);
            return 0;
        }
    }
    return 1;
}

/* Подтверждает команду. Зовётся ровно один раз на команду — иначе
   контроллер, ждущий подтверждения, дождался бы чужого.
 *
 * reason значим только при ok == 0 (см. D2K_ACK_* в d2k_ctl.h) — успех
 * всегда несёт D2K_ACK_OK, чтобы контроллеру не приходилось смотреть на
 * причину, когда смотреть не на что. Раньше здесь был только признак
 * успеха: контроллер получал одну и ту же «нулевую единицу отказа» что на
 * негодный план, что на переполненную таблицу планов, и не мог отличить
 * своего негодного кандидата от чужой нехватки места (см. большой
 * комментарий у D2K_EV_ACK, d2k_ctl.h). */
static void ack(d2k_ctlsrv *cx, uint16_t type, int ok, uint8_t reason) {
    /* Место под ключ потока есть у всех событий одинаково: подтверждение не
       про поток, но общая раскладка проще и сборке, и разбору. Ключ нулевой. */
    uint8_t body[D2K_KEY_WIRE_LEN + 4 + D2K_TRIAL_ID_LEN + D2K_CTL_BINDING_LEN];
    memset(body, 0, sizeof body);
    body[0] = 4;
    body[D2K_KEY_WIRE_LEN] = (uint8_t)(type >> 8);
    body[D2K_KEY_WIRE_LEN + 1] = (uint8_t)type;
    body[D2K_KEY_WIRE_LEN + 2] = ok ? 1 : 0;
    body[D2K_KEY_WIRE_LEN + 3] = ok ? D2K_ACK_OK : reason;
    if (ok) {
        cx->ok_cmds++;
    } else {
        cx->bad_cmds++;
    }
    if (cx->ctl) {
        size_t len = D2K_KEY_WIRE_LEN+4;
        if ((type >= D2K_CMD_SET_SUFFIX && type <= D2K_CMD_DEL_BYPASS) ||
            type == D2K_CMD_SET_NAME_PROBE || type == D2K_CMD_SET_NAME_BOUND) {
            memcpy(body+len, cx->area_id, D2K_TRIAL_ID_LEN); len += D2K_TRIAL_ID_LEN;
        }
        if(type==D2K_CMD_SET_NAME_BOUND) {
            d2k_ctl_binding_write(body+len,&cx->installed_binding); len+=D2K_CTL_BINDING_LEN;
        }
        d2k_ctl_event(cx->ctl, D2K_EV_ACK, body, len);
    }
}

static void ack_trial(d2k_ctlsrv *cx, uint16_t type, int ok, uint8_t reason,
                      const uint8_t trial_id[D2K_TRIAL_ID_LEN]) {
    uint8_t body[D2K_KEY_WIRE_LEN + 4 + D2K_TRIAL_ID_LEN];
    memset(body, 0, D2K_KEY_WIRE_LEN);
    body[0] = 4;
    body[D2K_KEY_WIRE_LEN] = (uint8_t)(type >> 8);
    body[D2K_KEY_WIRE_LEN + 1] = (uint8_t)type;
    body[D2K_KEY_WIRE_LEN + 2] = (uint8_t)(ok != 0);
    body[D2K_KEY_WIRE_LEN + 3] = ok ? D2K_ACK_OK : reason;
    memcpy(body + D2K_KEY_WIRE_LEN + 4, trial_id, D2K_TRIAL_ID_LEN);
    d2k_ctl_event(cx->ctl, D2K_EV_ACK, body, sizeof body);
}

void d2k_ctlsrv_greet(d2k_ctl *ctl, uint32_t send_maxlen) {
    if (!ctl) { return; }
    /* ПЕРВОЕ, ЧТО СЛЫШИТ КОНТРОЛЛЕР — ВЕРСИЯ ПРОВОДА.
       До неё он не знает, с кем разговаривает, а провод менялся несовместимо
       уже дважды за один день. Смешанная пара при этом не падает и не
       ругается: она молча не даёт подтверждений, и полдня измерений уходит в
       никуда. Событие лосси, как и все прочие, — не дошло, значит контроллер
       версии не увидел и обязан считать это несовпадением. */
    uint8_t body[D2K_KEY_WIRE_LEN + 7 + sizeof(D2K_RELEASE_ID) - 1];
    memset(body, 0, sizeof body);
    body[0] = 4;
    body[D2K_KEY_WIRE_LEN]     = (uint8_t)(D2K_CTL_PROTO_VERSION >> 8);
    body[D2K_KEY_WIRE_LEN + 1] = (uint8_t)D2K_CTL_PROTO_VERSION;
    body[D2K_KEY_WIRE_LEN + 2] = (uint8_t)(send_maxlen >> 24);
    body[D2K_KEY_WIRE_LEN + 3] = (uint8_t)(send_maxlen >> 16);
    body[D2K_KEY_WIRE_LEN + 4] = (uint8_t)(send_maxlen >> 8);
    body[D2K_KEY_WIRE_LEN + 5] = (uint8_t)send_maxlen;
    body[D2K_KEY_WIRE_LEN + 6] = (uint8_t)(sizeof(D2K_RELEASE_ID) - 1);
    memcpy(body + D2K_KEY_WIRE_LEN + 7, D2K_RELEASE_ID, sizeof(D2K_RELEASE_ID) - 1);
    d2k_ctl_event(ctl, D2K_EV_PROTO, body, sizeof body);
}

void d2k_ctlsrv_peer_closed(void *ctx) {
    d2k_ctlsrv *cx = ctx;
    if (cx && cx->sess) d2k_plantab_clear_probes(d2k_session_plans(cx->sess));
}

static int canonical_address(uint8_t family, const uint8_t *ip) {
    if (family == 6) { return 1; }
    if (family != 4) { return 0; }
    for (size_t i = 4; i < 16; i++) { if (ip[i]) { return 0; } }
    return 1;
}

/* Форма адресной привязки (v7): только измеренный протокол. Ноль («не
   объявлено») и дедушкино право (любая форма) по сокету не принимаются —
   иначе один план снова достался бы QUIC, STUN/голосу и TLS одного IP
   (D2K_SPEC §5, задача 16). */
static int addr_shape_valid(uint8_t shape) {
    return shape == D2K_PLAN_SHAPE_MODERN || shape == D2K_PLAN_SHAPE_LEGACY ||
           shape == D2K_PLAN_SHAPE_QUIC || shape == D2K_PLAN_SHAPE_VOICE ||
           shape == D2K_PLAN_SHAPE_ECH_TCP;
}

static int read_probe_flow(const uint8_t *b, d2k_addr_probe_flow *flow) {
    if (b[0] != 4 && b[0] != 6) { return -1; }
    memset(flow, 0, sizeof *flow);
    flow->family = b[0];
    if (b[0] == 6) {
        memcpy(flow->src_ip6, b + 1, 16);
        memcpy(flow->dst_ip6, b + 17, 16);
    } else {
        for (size_t i = 4; i < 16; i++) {
            if (b[1 + i] || b[17 + i]) { return -1; }
        }
        memcpy(flow->src_ip4, b + 1, 4);
        memcpy(flow->dst_ip4, b + 17, 4);
    }
    memcpy(&flow->src_port_be, b + 33, 2);
    memcpy(&flow->dst_port_be, b + 35, 2);
    flow->transport = b[37];
    return 0;
}

void d2k_ctlsrv_command(void *vctx, uint16_t type, const uint8_t *b, size_t len) {
    d2k_ctlsrv *cx = vctx;
    char why[200];
    memset(&cx->installed_binding,0,sizeof cx->installed_binding);
    d2k_plantab *tab = d2k_session_plans(cx->sess);

    /* v8: SET_NAME_PROBE тоже несёт хвостом trial ID опыта. ACK возвращает
       его — и на отказ тоже: контроллер обязан отличить СВОЙ отказ
       исполнителя от чужого подтверждения (задача 19). */
    if ((type >= D2K_CMD_SET_SUFFIX && type <= D2K_CMD_DEL_BYPASS) ||
        type == D2K_CMD_SET_NAME_PROBE || type == D2K_CMD_SET_NAME_BOUND) {
        memset(cx->area_id, 0, sizeof cx->area_id);
        if (len < D2K_TRIAL_ID_LEN) { ack(cx, type, 0, D2K_ACK_BAD_ARGS); return; }
        len -= D2K_TRIAL_ID_LEN;
        memcpy(cx->area_id, b+len, sizeof cx->area_id);
    }

    switch (type) {
    case D2K_CMD_SET_NAME_BOUND:
    case D2K_CMD_SET_NAME:
    case D2K_CMD_SET_SUFFIX:
    case D2K_CMD_SET_NAME_PROBE:
    case D2K_CMD_SET_ADDR: {
        /* v4: [длина имени][имя][форма][family][пробный порт?][план].
           План занимает остаток тела; адресное семейство обязательно. */
        size_t hdr;
        if (type == D2K_CMD_SET_ADDR) {
            hdr = 18u; /* v7: family, address(16), форма протокола */
        } else if (type == D2K_CMD_SET_NAME_PROBE) {
            hdr = len ? 5u + b[0] : 5u;
        } else {
            hdr = len ? 3u + b[0] : 3u;
        }
        if (len < hdr) {
            ack(cx, type, 0, D2K_ACK_BAD_ARGS);
            return;
        }
        if (type == D2K_CMD_SET_ADDR &&
            (!canonical_address(b[0], b + 1) || !addr_shape_valid(b[17]))) {
            ack(cx, type, 0, D2K_ACK_BAD_ARGS);
            return;
        }
        if (type != D2K_CMD_SET_ADDR && b[2u + b[0]] != 4 && b[2u + b[0]] != 6) {
            ack(cx, type, 0, D2K_ACK_BAD_ARGS);
            return;
        }
        d2k_plan *p = NULL;
        if (d2k_plan_load(b + hdr, len - hdr, &p, why, sizeof why) != 0) {
            fprintf(stderr, "d2kd: план от контроллера не принят: %s\n", why);
            ack(cx, type, 0, D2K_ACK_BAD_PLAN);
            return;
        }
        if (!d2k_plan_fits(p, cx->send_limits, cx->send_maxlen, why, sizeof why)) {
            fprintf(stderr, "d2kd: план от контроллера не активирован: %s\n", why);
            d2k_plan_free(p);
            ack(cx, type, 0, D2K_ACK_BAD_PLAN);
            return;
        }
        int rc;
        if (type == D2K_CMD_SET_SUFFIX) {
            rc = d2k_plantab_set_suffix_family(tab, b+1, b[0], cx->now_ns, p,
                b[1u+b[0]], b[2u+b[0]]);
        } else if (type == D2K_CMD_SET_NAME || type == D2K_CMD_SET_NAME_BOUND || type == D2K_CMD_SET_NAME_PROBE) {
            uint16_t sport_be = 0;
            if (type == D2K_CMD_SET_NAME_PROBE) {
                memcpy(&sport_be, b + 3u + b[0], 2);
            }
            if (type == D2K_CMD_SET_NAME_PROBE)
                rc = d2k_plantab_set_name_trial(tab,b+1,b[0],cx->now_ns,p,
                    b[1u+b[0]],sport_be,b[2u+b[0]],cx->area_id);
            else
                rc = d2k_plantab_set_name_family(tab, b + 1, b[0], cx->now_ns, p,
                                                b[1u + b[0]], sport_be, b[2u + b[0]]);
        } else {
            rc = d2k_plantab_set_addr_shaped(tab, b + 1, b[0], cx->now_ns, p, b[17]);
        }
        /* Владение планом перешло таблице в любом случае, включая отказ.
           rc различает ДВЕ разные по вине причины: -1 — таблице планов
           нечего вытеснить (не вина плана, см. d2k_plans.h; с вытеснением
           по давности недостижимо для таблицы ненулевой ёмкости, но
           различение оставлено на случай нарушения этого инварианта), -2 —
           аргументы самой команды негодны (например, пустое имя). Обе
           причины не «план негоден», и путать их с D2K_ACK_BAD_PLAN нельзя:
           контроллер решает по этому коду, жечь ли кандидата. */
        uint8_t reason = D2K_ACK_OK;
        if (rc == -1) {
            reason = D2K_ACK_NO_ROOM;
        } else if (rc != 0) {
            reason = D2K_ACK_BAD_ARGS;
        }
        if(rc==0 && type==D2K_CMD_SET_NAME_BOUND)
            (void)d2k_plantab_binding(tab,p,&cx->installed_binding);
        ack(cx, type, rc == 0, reason);
        return;
    }
    case D2K_CMD_SET_ADDR_PROBE: {
        const size_t fixed = D2K_ADDR_PROBE_FLOW_WIRE_LEN + D2K_TRIAL_ID_LEN + 4u;
        if (len < fixed) {
            ack(cx, type, 0, D2K_ACK_BAD_ARGS);
            return;
        }
        d2k_addr_probe_flow flow = {0};
        if (read_probe_flow(b, &flow) != 0) {
            ack(cx, type, 0, D2K_ACK_BAD_ARGS);
            return;
        }
        const uint8_t *trial_id = b + D2K_ADDR_PROBE_FLOW_WIRE_LEN;
        size_t lease_off = D2K_ADDR_PROBE_FLOW_WIRE_LEN + D2K_TRIAL_ID_LEN;
        uint32_t lease_ms = (uint32_t)b[lease_off] << 24 |
                            (uint32_t)b[lease_off + 1] << 16 |
                            (uint32_t)b[lease_off + 2] << 8 | b[lease_off + 3];
        uint8_t any_id = 0;
        for (size_t i = 0; i < D2K_TRIAL_ID_LEN; i++) { any_id |= trial_id[i]; }
        /* src_port 0 — голосовой опыт «любой клиентский порт» (задача 15);
           подстановка видна только поиску голоса (d2k_plantab_find_voice_probe). */
        if (flow.transport != 17 || !flow.dst_port_be ||
            !lease_ms || lease_ms > D2K_ADDR_PROBE_LEASE_MAX_MS || !any_id ||
            cx->now_ns > UINT64_MAX - (uint64_t)lease_ms * 1000000u) {
            ack_trial(cx, type, 0, D2K_ACK_BAD_ARGS, trial_id);
            return;
        }
        d2k_plan *p = NULL;
        if (d2k_plan_load(b + fixed, len - fixed, &p, why, sizeof why) != 0) {
            fprintf(stderr, "d2kd: адресный probe plan не принят: %s\n", why);
            ack_trial(cx, type, 0, D2K_ACK_BAD_PLAN, trial_id);
            return;
        }
        if (!d2k_plan_fits(p, cx->send_limits, cx->send_maxlen, why, sizeof why)) {
            d2k_plan_free(p);
            ack_trial(cx, type, 0, D2K_ACK_BAD_PLAN, trial_id);
            return;
        }
        uint64_t expires = cx->now_ns + (uint64_t)lease_ms * 1000000u;
        int rc = d2k_plantab_set_addr_probe(tab, &flow, trial_id,
                                            cx->now_ns, expires, p);
        uint8_t reason = rc == -1 ? D2K_ACK_NO_ROOM :
                         rc == 0 ? D2K_ACK_OK : D2K_ACK_BAD_ARGS;
        ack_trial(cx, type, rc == 0, reason, trial_id);
        return;
    }
    case D2K_CMD_ARM_SHAPE: {
        /* Тело: длина имени, имя, ТРАНСПОРТ и семейство по байту. Транспорт
           обязателен: снимок приветствия хранится отдельно на транспорт, и без
           него датапат отдал бы QUIC-задаче байты TLS. Старое тело (без
           последнего байта) отвергается — смешанная пара ловится сверкой
           версии провода, а не молча. */
        if (len < 3 || len != 3u + b[0]) {
            ack(cx, type, 0, D2K_ACK_BAD_ARGS);
            return;
        }
        uint8_t want_tr = b[1u + b[0]];
        uint8_t want_family = b[2u + b[0]];
        if ((want_tr != 6 && want_tr != 17) || (want_family != 4 && want_family != 6)) {
            ack(cx, type, 0, D2K_ACK_BAD_ARGS);
            return;
        }
        if (d2k_session_want_shape_family(cx->sess, b + 1, b[0], want_tr, want_family)) {
            /* Готово прямо сейчас — отдаём, не дожидаясь следующего
               приветствия. */
            size_t slen = 0;
            const uint8_t *sh = d2k_session_shape_family(cx->sess, want_tr, want_family, &slen);
            if (sh && slen > 0 && cx->ctl) {
                uint8_t body[D2K_KEY_WIRE_LEN + D2K_SHAPE_MAX];
                memset(body, 0, D2K_KEY_WIRE_LEN);
                body[0] = want_family;
                /* Транспорт кладётся в ключ, а не рядом: место под него на
                   проводе уже есть, и контроллер разбирает его общим путём. */
                body[D2K_KEY_WIRE_LEN - 1] = want_tr;
                if (slen <= sizeof body - D2K_KEY_WIRE_LEN) {
                    /* Набор опций TCP клиента — ПЕРЕД снимком, тем же ключом
                       (замысел 2026-10-23, п. 5.1). */
                    if (want_tr == 6) {
                        size_t olen = 0;
                        const uint8_t *o = d2k_session_shape_tcp_options_family(
                            cx->sess, want_family, &olen);
                        if (o && olen <= 40) {
                            memcpy(body + D2K_KEY_WIRE_LEN, o, olen);
                            d2k_ctl_event(cx->ctl, D2K_EV_CLIENT_TCP, body,
                                          D2K_KEY_WIRE_LEN + olen);
                        }
                    }
                    memcpy(body + D2K_KEY_WIRE_LEN, sh, slen);
                    d2k_ctl_event(cx->ctl, D2K_EV_SHAPE, body, D2K_KEY_WIRE_LEN + slen);
                }
            }
        }
        ack(cx, type, 1, D2K_ACK_OK);
        return;
    }
    case D2K_CMD_DEL_SUFFIX:
    case D2K_CMD_SET_BYPASS:
    case D2K_CMD_DEL_BYPASS: {
        if (len < 5 || len != 4u+b[0] || !b[0] ||
            (b[3u+b[0]] != 4 && b[3u+b[0]] != 6) ||
            !((b[1u+b[0]] == 6 && (b[2u+b[0]] == 1 || b[2u+b[0]] == 2 || b[2u+b[0]] == 6)) ||
              (b[1u+b[0]] == 17 && b[2u+b[0]] == 3))) {
            ack(cx, type, 0, D2K_ACK_BAD_ARGS); return;
        }
        int rc;
        if (type == D2K_CMD_SET_BYPASS)
            rc = d2k_plantab_set_bypass_family(tab, b+1, b[0], b[1u+b[0]], b[2u+b[0]], b[3u+b[0]]);
        else if (type == D2K_CMD_DEL_SUFFIX)
            rc = d2k_plantab_del_suffix_family(tab, b+1, b[0], b[1u+b[0]], b[2u+b[0]], b[3u+b[0]]);
        else
            rc = d2k_plantab_del_bypass_family(tab, b+1, b[0], b[1u+b[0]], b[2u+b[0]], b[3u+b[0]]);
        ack(cx, type, rc >= 0, rc == -1 ? D2K_ACK_NO_ROOM : rc < 0 ? D2K_ACK_BAD_ARGS : D2K_ACK_OK);
        return;
    }
    case D2K_CMD_DEL_NAME_BOUND: {
        d2k_binding_context expected={0};
        if(len<2+D2K_CTL_BINDING_LEN || !b[0] || len!=2u+b[0]+D2K_CTL_BINDING_LEN ||
           (b[1+b[0]]!=6 && b[1+b[0]]!=17) ||
           d2k_ctl_binding_read(&expected,b+2+b[0],D2K_CTL_BINDING_LEN)) {
            ack(cx,type,0,D2K_ACK_BAD_ARGS); return;
        }
        (void)d2k_plantab_del_name_bound(tab,b+1,b[0],b[1+b[0]],&expected);
        ack(cx,type,1,D2K_ACK_OK); return;
    }
    case D2K_CMD_DEL_NAME:
        /* v9: длина имени, имя, транспорт, форма, family. Снимает ровно
           постоянную запись этого ключа; пробы и другие формы/транспорты
           не трогает (задача 21). Широкого «всё имя» на проводе больше нет. */
        if (len < 4 || len != 4u + b[0] || !b[0] ||
            (b[1u + b[0]] != 6 && b[1u + b[0]] != 17) ||
            b[2u + b[0]] == D2K_PLAN_SHAPE_ANY ||
            (b[3u + b[0]] != 4 && b[3u + b[0]] != 6)) {
            ack(cx, type, 0, D2K_ACK_BAD_ARGS);
            return;
        }
        d2k_plantab_del_name_shaped(tab, b + 1, b[0], b[1u + b[0]], b[2u + b[0]],
                                    b[3u + b[0]]);
        ack(cx, type, 1, D2K_ACK_OK);
        return;
    case D2K_CMD_DEL_NAME_PROBE:
        /* тело: длина имени, имя, форма, family, местный порт */
        if (len < 5 || len != 5u + b[0] ||
            (b[2u + b[0]] != 4 && b[2u + b[0]] != 6)) {
            ack(cx, type, 0, D2K_ACK_BAD_ARGS);
            return;
        }
        uint16_t probe_port;
        memcpy(&probe_port, b + 3u + b[0], 2);
        if (!probe_port) {
            ack(cx, type, 0, D2K_ACK_BAD_ARGS);
            return;
        }
        d2k_plantab_del_name_probe_family(tab, b + 1, b[0], b[1u + b[0]],
                                          probe_port, b[2u + b[0]]);
        ack(cx, type, 1, D2K_ACK_OK);
        return;
    case D2K_CMD_SET_HTTPS: {
        if (len < 1 || len != 1u + b[0] + 4u || !cx->http80) {
            ack(cx, type, 0, D2K_ACK_BAD_ARGS);
            return;
        }
        uint32_t ttl = (uint32_t)b[1u + b[0]] << 24 | (uint32_t)b[2u + b[0]] << 16 |
                       (uint32_t)b[3u + b[0]] << 8 | b[4u + b[0]];
        if (ttl > D2K_HTTPS_TTL_MAX_S) { ttl = D2K_HTTPS_TTL_MAX_S; }
        uint64_t expires = ttl ? cx->now_ns + (uint64_t)ttl * 1000000000ull : 0;
        if (d2k_http80_set_https(cx->http80, (const char *)b + 1, b[0], expires) != 0) {
            ack(cx, type, 0, D2K_ACK_BAD_ARGS);
            return;
        }
        ack(cx, type, 1, D2K_ACK_OK);
        return;
    }
    case D2K_CMD_SET_STALL_BUDGETS: {
        uint16_t bud[D2K_STALL_BUDGETS_MAX];
        if (len < 1 || b[0] > D2K_STALL_BUDGETS_MAX || len != 1u + 2u * b[0]) {
            ack(cx, type, 0, D2K_ACK_BAD_ARGS);
            return;
        }
        for (size_t i = 0; i < b[0]; i++) {
            bud[i] = (uint16_t)(b[1 + 2 * i] << 8 | b[2 + 2 * i]);
        }
        if (d2k_session_set_stall_budgets(cx->sess, bud, b[0]) != 0) {
            ack(cx, type, 0, D2K_ACK_BAD_ARGS);
            return;
        }
        ack(cx, type, 1, D2K_ACK_OK);
        return;
    }
    case D2K_CMD_DEL_ADDR: {
        if (len != 18 || !canonical_address(b[0], b + 1) || !addr_shape_valid(b[17])) {
            ack(cx, type, 0, D2K_ACK_BAD_ARGS);
            return;
        }
        d2k_plantab_del_addr_shaped(tab, b + 1, b[0], b[17]);
        ack(cx, type, 1, D2K_ACK_OK);
        return;
    }
    case D2K_CMD_DEL_ADDR_PROBE: {
        if (len != D2K_ADDR_PROBE_FLOW_WIRE_LEN + D2K_TRIAL_ID_LEN) {
            ack(cx, type, 0, D2K_ACK_BAD_ARGS);
            return;
        }
        d2k_addr_probe_flow flow = {0};
        if (read_probe_flow(b, &flow) != 0) {
            ack(cx, type, 0, D2K_ACK_BAD_ARGS);
            return;
        }
        const uint8_t *trial_id = b + D2K_ADDR_PROBE_FLOW_WIRE_LEN;
        uint8_t any_id = 0;
        for (size_t i = 0; i < D2K_TRIAL_ID_LEN; i++) { any_id |= trial_id[i]; }
        if (flow.transport != 17 || !flow.dst_port_be || !any_id) {
            ack(cx, type, 0, D2K_ACK_BAD_ARGS);
            return;
        }
        /* Idempotent and generation-safe: not finding this exact owner is
           success, but can never remove a different trial or persistent addr. */
        (void)d2k_plantab_del_addr_probe(tab, &flow, trial_id);
        ack(cx, type, 1, D2K_ACK_OK);
        return;
    }
    default:
        /* Незнакомая команда — не повод рвать соединение, но и не повод
           делать вид, что она исполнена. Отвечаем отказом и продолжаем. */
        ack(cx, type, 0, D2K_ACK_BAD_ARGS);
        return;
    }
}

void d2k_ctlsrv_pump(d2k_ctl *ctl, const d2k_session *s, uint64_t *seen) {
    const d2k_journal *j = d2k_session_journal(s);
    uint64_t added = d2k_journal_added(j);
    if (added <= *seen) {
        return;
    }
    size_t have = d2k_journal_count(j);
    uint64_t fresh = added - *seen;
    size_t from = (fresh >= have) ? 0 : (size_t)(have - fresh);
    *seen = added;

    for (size_t i = from; i < have; i++) {
        const d2k_jrn_entry *e = d2k_journal_at(j, i);
        if (!e) {
            continue;
        }
        /* Хватает и на приветствие целиком: форма приезжает сюда же. */
        uint8_t body[D2K_KEY_WIRE_LEN + D2K_SHAPE_MAX + 8 + D2K_PLAN_ID_LEN + D2K_TRIAL_ID_LEN];
        size_t n = put_key(body, &e->key);
        uint16_t type = 0;
        switch (e->kind) {
        case D2K_JRN_HELLO_SNI:
        case D2K_JRN_HELLO_NONAME:
            type = D2K_EV_HELLO;
            body[n++] = e->name_len;
            if (e->name_len) {
                memcpy(body + n, e->name, e->name_len);
                n += e->name_len;
            }
            break;
        case D2K_JRN_SUSPECT:
            type = D2K_EV_SUSPECT;
            body[n++] = e->code;
            /* Подробности — то, ЧЕМ подозрительный пакет отличался от
               остальных в этом же потоке. Из них складывается отпечаток
               коробки; без них в каталоге лежал бы факт «был сброс», по
               которому одну коробку от другой не отличить. */
            body[n++] = e->d_ttl;
            body[n++] = e->d_ref_ttl;
            body[n++] = e->d_tos;
            body[n++] = (uint8_t)(e->d_ipid >> 8);
            body[n++] = (uint8_t)e->d_ipid;
            /* Седьмым байтом — применялся ли план к ЭТОМУ потоку
               (D2K_PLANNED_*, см. d2k_journal.h). Разбор у контроллера длину
               проверяет, а не предполагает: событие без этого байта — законный
               вход от старой службы. */
            body[n++] = e->d_planned;
            body[n++] = e->d_client_shape;
            /* Девятым и десятым (v12) — число при записи, u16 BE: у «TCP
               встал на бюджете» это оценка пакетов с данными обеих сторон к
               началу тишины, по ней контроллер сверяет полосу с бюджетом
               коробки цели. У остальных подозрений ноль. */
            body[n++] = (uint8_t)((e->num > 0xffffu ? 0xffffu : e->num) >> 8);
            body[n++] = (uint8_t)(e->num > 0xffffu ? 0xffffu : e->num);
            break;
        case D2K_JRN_PLAN_APPLIED:
            /* Prepared, not yet sent. Never expose this as positive proof. */
            continue;
        case D2K_JRN_PLAN_DONE:
            type = D2K_EV_APPLIED;
            /* Идентификатор применённого плана — тем же приёмом, что и всё
               остальное здесь: побайтно в тело, без наложения структуры.
               Едет ВСЕГДА, даже когда он нулевой: у плана без записи REC_ID
               нули и есть честный ответ «плану нечем представиться», и
               контроллер читает их так же, как отсутствие поля у старого
               датапата (см. d2k_plan_id, d2k_plan.h). Постоянная длина тела
               к тому же избавляет ту сторону от разбора «есть или нет». */
            memcpy(body + n, e->plan_id, D2K_PLAN_ID_LEN);
            n += D2K_PLAN_ID_LEN;
            memcpy(body + n, e->trial_id, D2K_TRIAL_ID_LEN);
            n += D2K_TRIAL_ID_LEN;
            break;
        case D2K_JRN_PLAN_REFUSED:
            type = D2K_EV_REFUSED;
            /* План НЕ ПРИМЕНЁН. Код записи, а не постоянный ноль: ноль
               (D2K_REFUSE_NONE) значит «плана для цели нет» — такой отказ
               случается на каждом транзитном потоке и ничего не говорит ни о
               коробке, ни о нашей отправке; D2K_REFUSE_NOT_APPLIED значит
               «план найден и отвергнут исполнителем», и для потока своего
               зонда это результат опыта. Прежде здесь стоял ноль константой,
               и отличить одно от другого контроллер не мог вовсе.
               Байт едет ВСЕГДА, а не только когда он ненулевой: постоянная
               длина тела избавляет ту сторону от разбора «есть или нет» —
               тот же приём, что у plan_id в APPLIED выше. */
            body[n++] = e->code;
            memcpy(body + n, e->plan_id, D2K_PLAN_ID_LEN);
            n += D2K_PLAN_ID_LEN;
            memcpy(body + n, e->trial_id, D2K_TRIAL_ID_LEN);
            n += D2K_TRIAL_ID_LEN;
            break;
        case D2K_JRN_PLAN_DAMAGED:
            /* Поток испорчен недоисполнением. Тем же видом события, что отказ
               применить и недоисполнение: для контроллера все три означают
               «измерения не было». Различает их КОД, и у повреждения он свой
               (D2K_REFUSE_DAMAGED): испорченный поток не просто не измерен —
               к нему больше ничего применять нельзя, и путать это с обычным
               «плана для цели нет» (код 0, на каждом транзитном потоке)
               нельзя тем более. Идентификатор плана едет следом, как у
               недоисполнения. */
            type = D2K_EV_REFUSED;
            body[n++] = e->code;
            memcpy(body + n, e->plan_id, D2K_PLAN_ID_LEN);
            n += D2K_PLAN_ID_LEN;
            memcpy(body + n, e->trial_id, D2K_TRIAL_ID_LEN);
            n += D2K_TRIAL_ID_LEN;
            break;
        case D2K_JRN_PLAN_UNSENT:
            /* План применён, но НЕ ДОИСПОЛНЕН: хотя бы одна его посылка не
               покинула машину. Тем же видом события, что и отказ применить,
               и это осознанно: для контроллера оба означают «измерения не
               было». Различает их КОД, и именно ради него он здесь и
               появился — без кода локальная поломка выглядела у контроллера
               ровно как «коробка не поддалась» (docs/decisions/0006). */
            type = D2K_EV_REFUSED;
            body[n++] = e->code;
            memcpy(body + n, e->plan_id, D2K_PLAN_ID_LEN);
            n += D2K_PLAN_ID_LEN;
            memcpy(body + n, e->trial_id, D2K_TRIAL_ID_LEN);
            n += D2K_TRIAL_ID_LEN;
            break;
        case D2K_JRN_SHAPE: {
            /* Байты приветствия лежат не в журнале, а в ловушке сессии:
               запись журнала ограничена, а приветствие бывает в килобайт. */
            size_t slen = 0;
            /* Транспорт берётся из ключа записи журнала: ловушка взводится на
               транспорт, и снимок лежит в его слоте. */
            const uint8_t *sh = d2k_session_shape_family(s, e->key.proto,
                                                         e->key.family == 6 ? 6 : 4, &slen);
            if (!sh || slen == 0 || n + slen > sizeof body) {
                continue;
            }
            /* Набор опций TCP клиента — своим событием ПЕРЕД снимком, тем же
               ключом (замысел 2026-10-23, п. 5.1): контроллер связывает
               набор со снимком до того, как задача возьмёт снимок в замер. */
            if (e->key.proto == 6) {
                size_t olen = 0;
                const uint8_t *o = d2k_session_shape_tcp_options_family(
                    s, e->key.family == 6 ? 6 : 4, &olen);
                if (o && olen <= 40 && n + olen <= sizeof body) {
                    memcpy(body + n, o, olen);
                    d2k_ctl_event(ctl, D2K_EV_CLIENT_TCP, body, n + olen);
                }
            }
            type = D2K_EV_SHAPE;
            memcpy(body + n, sh, slen);
            n += slen;
            break;
        }
        case D2K_JRN_EXCHANGE:
            type = D2K_EV_EXCHANGE;
            body[n++] = e->code;            /* тип первой TLS-записи */
            body[n++] = e->d_tos;           /* набор встреченных типов */
            body[n++] = (uint8_t)(e->num >> 24);
            body[n++] = (uint8_t)(e->num >> 16);
            body[n++] = (uint8_t)(e->num >> 8);
            body[n++] = (uint8_t)e->num;
            /* ПРИЁМКА ВОПРОСА — седьмым байтом, добавлением в хвост.
               Старый контроллер читает шесть первых и седьмой не замечает;
               новый требует его для приёмки. Добавление в хвост выбрано
               вместо бита в маске типов намеренно: маска говорит «такой тип
               записи встречался», а это поле — «запись разобрана и это ответ
               сервера», и складывать их в одно значило бы однажды принять
               алерт за ответ (см. is_server_hello, d2k_tls.h). */
            body[n++] = e->d_server_hello;
            /* ПРИМЕНЯЛСЯ ЛИ ПЛАН — восьмым байтом, тем же приёмом добавления
               в хвост, что и седьмой: старый контроллер читает семь и его не
               замечает; новый по нему гасит замер на рукопожатии для имени,
               которое завершило обмен без плана (медиа VK, 15.10.2026). */
            body[n++] = e->d_planned;
            break;
        default:
            continue;
        }
        if (type == D2K_EV_REFUSED) body[n++] = d2k_session_client_shape(s, &e->key);
        if (type == D2K_EV_APPLIED || type == D2K_EV_REFUSED) {
            /* Snapshot from journal, never the current plan-table entry. */
            for (unsigned b = 0; b < 8; b++)
                body[n++] = (uint8_t)(e->execution_id >> (56 - 8*b));
            d2k_ctl_binding_write(body+n,&e->binding);
            n += D2K_CTL_BINDING_LEN;
        }
        d2k_ctl_event(ctl, type, body, n);
    }
}

/* The same request snapshot encoder is used by d2kd and socket regressions. */
void d2k_ctlsrv_http80_event(d2k_ctl *ctl, const d2k_http80_res *r) {
    if (!ctl) { return; }
    uint8_t body[D2K_KEY_WIRE_LEN + 2 + 255 + 50 + D2K_HTTP80_TARGET_MAX + D2K_CTL_BINDING_LEN + 18];
    size_t hl = strlen(r->host);
    if (hl > 255) { return; }
    memset(body, 0, D2K_KEY_WIRE_LEN);
    body[0] = r->family == 6 ? 6 : 4;
    memcpy(body + 1, r->client, r->family == 6 ? 16 : 4);
    memcpy(body + 17, r->server, r->family == 6 ? 16 : 4);
    body[33] = (uint8_t)(r->client_port >> 8); body[34] = (uint8_t)r->client_port;
    body[35] = (uint8_t)(r->server_port >> 8); body[36] = (uint8_t)r->server_port;
    body[37] = 6;
    body[D2K_KEY_WIRE_LEN] = r->response ? (uint8_t)r->response : (r->answered ? 1 : 0);
    body[D2K_KEY_WIRE_LEN + 1] = (uint8_t)hl;
    memcpy(body + D2K_KEY_WIRE_LEN + 2, r->host, hl);
    size_t off = D2K_KEY_WIRE_LEN + 2 + hl;
    for (size_t i = 0; i < 8; i++)
        body[off + i] = (uint8_t)(r->execution_id >> (56 - i * 8));
    memcpy(body + off + 8, r->plan_id, 16);
    memcpy(body + off + 24, r->trial_id, 16);
    for (size_t i = 0; i < 8; i++)
        body[off + 40 + i] = (uint8_t)(r->request_ms >> (56 - i * 8));
    size_t path_len = strlen(r->request_path);
    body[off + 48] = (uint8_t)(path_len >> 8);
    body[off + 49] = (uint8_t)path_len;
    memcpy(body + off + 50, r->request_path, path_len);
    d2k_ctl_binding_write(body+off+50+path_len,&r->binding);
    size_t end=off+50+path_len+D2K_CTL_BINDING_LEN;
    if(r->response) {
        body[end++]=(uint8_t)(r->status>>8);body[end++]=(uint8_t)r->status;
        for(unsigned i=0;i<8;i++)body[end++]=(uint8_t)(r->body_bytes>>(56-8*i));
        for(unsigned i=0;i<8;i++)body[end++]=(uint8_t)(r->request_no>>(56-8*i));
    }
    d2k_ctl_event(ctl,r->response?D2K_EV_HTTP_RESPONSE:D2K_EV_HTTP_PORTAL,body,end);
}
