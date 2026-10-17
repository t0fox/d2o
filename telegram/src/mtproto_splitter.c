#include "tg_mtproto_splitter.h"

#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>

#define TG_MTPROTO_SPLITTER_RETAIN (64u * 1024u)

static int grow_packet(tg_mtproto_splitter *splitter, size_t extra) {
    if (extra > TG_MTPROTO_MAX_PACKET - splitter->packet_len)
        return TG_MTPROTO_SPLIT_TOO_LARGE;
    size_t need = splitter->packet_len + extra;
    if (need <= splitter->packet_cap) return TG_MTPROTO_SPLIT_OK;
    size_t cap = splitter->packet_cap ? splitter->packet_cap : 256;
    while (cap < need) {
        if (cap > TG_MTPROTO_MAX_PACKET / 2) {
            cap = TG_MTPROTO_MAX_PACKET;
            break;
        }
        cap *= 2;
    }
    if (splitter->memory_budget &&
        tg_memory_budget_reserve(splitter->memory_budget, cap) != 0)
        return TG_MTPROTO_SPLIT_NO_MEMORY;
    uint8_t *packet = realloc(splitter->packet, cap);
    if (!packet) {
        tg_memory_budget_release(splitter->memory_budget, cap);
        return TG_MTPROTO_SPLIT_NO_MEMORY;
    }
    tg_memory_budget_release(splitter->memory_budget, splitter->packet_cap);
    splitter->packet = packet;
    splitter->packet_cap = cap;
    return TG_MTPROTO_SPLIT_OK;
}

static int append_encrypted(tg_mtproto_splitter *splitter,
                            tg_mtproto_ctr *encrypt, uint8_t *data,
                            size_t len) {
    int rc = grow_packet(splitter, len);
    if (rc != TG_MTPROTO_SPLIT_OK) return rc;
    if (tg_mtproto_ctr_xor(encrypt, data, len) != 0)
        return TG_MTPROTO_SPLIT_CIPHER_ERROR;
    if (len) memcpy(splitter->packet + splitter->packet_len, data, len);
    splitter->packet_len += len;
    return TG_MTPROTO_SPLIT_OK;
}

static size_t required_header(const tg_mtproto_splitter *splitter) {
    if (splitter->proto != TG_MTPROTO_ABRIDGED) return 4;
    if (splitter->header_len == 0 ||
        (splitter->header[0] != 0x7f && splitter->header[0] != 0xff))
        return 1;
    return 4;
}

static int parse_total_length(const tg_mtproto_splitter *splitter,
                              size_t *total_len, int *raw_mode) {
    uint32_t payload_len;
    size_t header_len;
    if (splitter->proto == TG_MTPROTO_ABRIDGED) {
        int extended = splitter->header[0] == 0x7f || splitter->header[0] == 0xff;
        header_len = extended ? 4 : 1;
        if (splitter->header_len < header_len) return TG_MTPROTO_SPLIT_INVALID;
        if (extended) {
            payload_len = (uint32_t)splitter->header[1] |
                          ((uint32_t)splitter->header[2] << 8) |
                          ((uint32_t)splitter->header[3] << 16);
        } else {
            payload_len = splitter->header[0] & 0x7f;
        }
        payload_len *= 4;
    } else {
        header_len = 4;
        if (splitter->header_len < header_len) return TG_MTPROTO_SPLIT_INVALID;
        payload_len = (uint32_t)splitter->header[0] |
                      ((uint32_t)splitter->header[1] << 8) |
                      ((uint32_t)splitter->header[2] << 16) |
                      ((uint32_t)splitter->header[3] << 24);
        payload_len &= UINT32_C(0x7fffffff);
    }
    *raw_mode = payload_len == 0;
    if (payload_len > TG_MTPROTO_MAX_PACKET - header_len)
        return TG_MTPROTO_SPLIT_TOO_LARGE;
    *total_len = header_len + (size_t)payload_len;
    return TG_MTPROTO_SPLIT_OK;
}

int tg_mtproto_splitter_init(tg_mtproto_splitter *splitter,
                             tg_mtproto_proto proto) {
    return tg_mtproto_splitter_init_accounted(splitter, proto, NULL);
}

int tg_mtproto_splitter_init_accounted(tg_mtproto_splitter *splitter,
                                       tg_mtproto_proto proto,
                                       tg_memory_budget *memory_budget) {
    if (!splitter || proto < TG_MTPROTO_ABRIDGED ||
        proto > TG_MTPROTO_PADDED_INTERMEDIATE)
        return TG_MTPROTO_SPLIT_INVALID;
    memset(splitter, 0, sizeof(*splitter));
    splitter->proto = proto;
    splitter->memory_budget = memory_budget;
    return TG_MTPROTO_SPLIT_OK;
}

void tg_mtproto_splitter_destroy(tg_mtproto_splitter *splitter) {
    if (!splitter) return;
    OPENSSL_clear_free(splitter->packet, splitter->packet_cap);
    tg_memory_budget_release(splitter->memory_budget, splitter->packet_cap);
    memset(splitter, 0, sizeof(*splitter));
}

static int emit_packet(tg_mtproto_splitter *splitter,
                       tg_mtproto_packet_cb callback, void *callback_ctx) {
    if (callback(callback_ctx, splitter->packet, splitter->packet_len) != 0) {
        splitter->error = TG_MTPROTO_SPLIT_CALLBACK_ERROR;
        return splitter->error;
    }
    splitter->packet_len = 0;
    if (splitter->packet_cap > TG_MTPROTO_SPLITTER_RETAIN) {
        size_t old_cap = splitter->packet_cap;
        OPENSSL_clear_free(splitter->packet, old_cap);
        splitter->packet = NULL;
        splitter->packet_cap = 0;
        tg_memory_budget_release(splitter->memory_budget, old_cap);
    }
    return TG_MTPROTO_SPLIT_OK;
}

int tg_mtproto_splitter_feed(tg_mtproto_splitter *splitter,
                             tg_mtproto_ctr *encrypt, uint8_t *plaintext,
                             size_t len, tg_mtproto_packet_cb callback,
                             void *callback_ctx) {
    if (!splitter || !encrypt || (len && !plaintext) || !callback)
        return TG_MTPROTO_SPLIT_INVALID;
    if (splitter->error) return splitter->error;
    if (len == 0) return TG_MTPROTO_SPLIT_OK;
    if (splitter->disabled) {
        if (len > TG_MTPROTO_MAX_PACKET) {
            splitter->error = TG_MTPROTO_SPLIT_TOO_LARGE;
            return splitter->error;
        }
        if (tg_mtproto_ctr_xor(encrypt, plaintext, len) != 0) {
            splitter->error = TG_MTPROTO_SPLIT_CIPHER_ERROR;
            return splitter->error;
        }
        if (callback(callback_ctx, plaintext, len) != 0) {
            splitter->error = TG_MTPROTO_SPLIT_CALLBACK_ERROR;
            return splitter->error;
        }
        return TG_MTPROTO_SPLIT_OK;
    }

    size_t offset = 0;
    while (offset < len) {
        if (splitter->total_len == 0) {
            size_t required = required_header(splitter);
            size_t take = required - splitter->header_len;
            if (take > len - offset) take = len - offset;
            memcpy(splitter->header + splitter->header_len,
                   plaintext + offset, take);
            int rc = append_encrypted(splitter, encrypt, plaintext + offset, take);
            if (rc != TG_MTPROTO_SPLIT_OK) {
                splitter->error = rc;
                return rc;
            }
            splitter->header_len += take;
            offset += take;
            if (splitter->header_len < required_header(splitter)) continue;

            int raw_mode = 0;
            rc = parse_total_length(splitter, &splitter->total_len, &raw_mode);
            if (rc != TG_MTPROTO_SPLIT_OK) {
                splitter->error = rc;
                return rc;
            }
            if (raw_mode) {
                rc = append_encrypted(splitter, encrypt, plaintext + offset,
                                      len - offset);
                if (rc != TG_MTPROTO_SPLIT_OK) {
                    splitter->error = rc;
                    return rc;
                }
                offset = len;
                splitter->disabled = 1;
                splitter->header_len = 0;
                splitter->total_len = 0;
                rc = emit_packet(splitter, callback, callback_ctx);
                if (rc != TG_MTPROTO_SPLIT_OK) return rc;
                return TG_MTPROTO_SPLIT_OK;
            }
        }

        if (splitter->packet_len < splitter->total_len && offset < len) {
            size_t remaining = splitter->total_len - splitter->packet_len;
            size_t take = remaining < len - offset ? remaining : len - offset;
            int rc = append_encrypted(splitter, encrypt, plaintext + offset, take);
            if (rc != TG_MTPROTO_SPLIT_OK) {
                splitter->error = rc;
                return rc;
            }
            offset += take;
        }
        if (splitter->packet_len == splitter->total_len) {
            int rc = emit_packet(splitter, callback, callback_ctx);
            if (rc != TG_MTPROTO_SPLIT_OK) return rc;
            splitter->header_len = 0;
            splitter->total_len = 0;
        }
    }
    return TG_MTPROTO_SPLIT_OK;
}

int tg_mtproto_splitter_flush(tg_mtproto_splitter *splitter,
                              tg_mtproto_packet_cb callback,
                              void *callback_ctx) {
    if (!splitter || !callback) return TG_MTPROTO_SPLIT_INVALID;
    if (splitter->error) return splitter->error;
    if (!splitter->packet_len) return TG_MTPROTO_SPLIT_OK;
    int rc = emit_packet(splitter, callback, callback_ctx);
    splitter->header_len = 0;
    splitter->total_len = 0;
    return rc;
}

int tg_mtproto_splitter_error(const tg_mtproto_splitter *splitter) {
    return splitter ? splitter->error : TG_MTPROTO_SPLIT_INVALID;
}

const char *tg_mtproto_split_result_text(int result) {
    switch (result) {
    case TG_MTPROTO_SPLIT_OK: return "ошибки нет";
    case TG_MTPROTO_SPLIT_TOO_LARGE: return "пакет MTProto превышает лимит 4 МиБ";
    case TG_MTPROTO_SPLIT_NO_MEMORY: return "недостаточно памяти для пакета MTProto";
    case TG_MTPROTO_SPLIT_CIPHER_ERROR: return "ошибка шифрования потока MTProto";
    case TG_MTPROTO_SPLIT_CALLBACK_ERROR: return "не удалось передать пакет MTProto";
    default: return "неверные параметры кадрирования MTProto";
    }
}
