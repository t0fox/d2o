#ifndef D2K_TG_MTPROTO_DISCOVERY_H
#define D2K_TG_MTPROTO_DISCOVERY_H

#include "tg_dc_map.h"

#include <stddef.h>
#include <stdint.h>

/* После успеха endpoints принадлежат snapshot; освобождаются destroy-функцией. */
int tg_mtproto_config_parse(const uint8_t *data, size_t len, int64_t now,
                            tg_dc_snapshot *out);
/* 0 — найден rpc_result, 1 — только допустимое service-сообщение, -1 — ошибка. */
int tg_mtproto_parse_rpc_result(const uint8_t *body, size_t body_len,
                                uint64_t request_message_id,
                                uint32_t outer_seqno, const uint8_t **result,
                                size_t *result_len);
/* socket_mark=0 отключает SO_MARK; production bootstrap передаёт 0x31. */
int tg_mtproto_discover_config(const char *numeric_address, uint16_t port,
                               uint32_t dc_id, uint32_t timeout_ms,
                               uint32_t socket_mark, int64_t now,
                               tg_dc_snapshot *out);

#endif
