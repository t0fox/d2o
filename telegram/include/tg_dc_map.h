#ifndef D2K_TG_DC_MAP_H
#define D2K_TG_DC_MAP_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include "tg_listener.h"

#define TG_DC_MAP_SCHEMA_VERSION 1u
#define TG_DC_MAP_MAX_ENDPOINTS 512u
#define TG_DC_MAP_MAX_SECRET 256u

typedef struct {
    uint32_t id;
    sa_family_t family;
    uint8_t address[16];
    uint16_t port;
    int media_only;
    int tcpo_only;
    int cdn;
    int is_static;
    int this_port_only;
    uint8_t secret[TG_DC_MAP_MAX_SECRET];
    size_t secret_len;
    int64_t last_seen;
} tg_dc_endpoint;

typedef struct {
    uint32_t schema_version;
    int64_t fetched_at;
    int64_t config_date;
    int64_t config_expires;
    uint32_t this_dc;
    const tg_dc_endpoint *endpoints;
    size_t endpoint_count;
} tg_dc_snapshot;

#define TG_DC_MAP_PATH_MAX 1024u
typedef struct {
    char path[TG_DC_MAP_PATH_MAX];
    tg_dc_snapshot snapshot;
    int has_snapshot;
} tg_dc_map_store;

typedef struct {
    uint8_t bytes[TG_DC_MAP_MAX_SECRET];
    size_t len;
} tg_dc_secret;

typedef enum {
    TG_DC_MAP_OFFICIAL = 1,
    TG_DC_MAP_BUILTIN = 2
} tg_dc_map_source;

typedef enum {
    TG_DC_LOOKUP_OK = 0,
    TG_DC_LOOKUP_NOT_LISTED = -1,
    TG_DC_LOOKUP_PORT = -2,
    TG_DC_LOOKUP_MEDIA = -3,
    TG_DC_LOOKUP_DC = -4,
    TG_DC_LOOKUP_CDN = -5,
    TG_DC_LOOKUP_AMBIGUOUS = -6,
    TG_DC_LOOKUP_INVALID = -7
} tg_dc_lookup_result;

int tg_dc_snapshot_validate(const tg_dc_snapshot *snapshot, int64_t now);
int tg_dc_snapshot_parse_json(const uint8_t *json, size_t len, int64_t now,
                              tg_dc_snapshot *out);
int tg_dc_snapshot_encode_json(const tg_dc_snapshot *snapshot, int64_t now,
                               uint8_t **out, size_t *out_len);
void tg_dc_snapshot_destroy(tg_dc_snapshot *snapshot);
int tg_dc_map_store_init(tg_dc_map_store *store, const char *path);
void tg_dc_map_store_destroy(tg_dc_map_store *store);
int tg_dc_map_store_load(tg_dc_map_store *store, int64_t now);
const tg_dc_snapshot *tg_dc_map_store_current(const tg_dc_map_store *store);
int tg_dc_map_store_refresh_due(const tg_dc_map_store *store, int64_t now,
                                uint64_t refresh_secs);
int tg_dc_map_store_install(tg_dc_map_store *store,
                            const tg_dc_snapshot *incoming, int64_t now);
size_t tg_dc_builtin_endpoint_count(void);
int tg_dc_builtin_endpoint_at(size_t index, int64_t now,
                              tg_dc_endpoint *out);
int tg_dc_map_store_resolve(const tg_dc_map_store *store, int64_t now,
                            const tg_listener_destination *destination,
                            int media_hint, uint32_t dc_hint, int allow_cdn,
                            tg_dc_endpoint *out, tg_dc_map_source *source);
size_t tg_dc_handshake_secrets(const tg_dc_snapshot *snapshot,
                               const tg_listener_destination *destination,
                               int64_t now, tg_dc_secret *out, size_t out_cap);
int tg_dc_write_endpoint_manifest(const char *path,
                                 const tg_dc_snapshot *snapshot,
                                 const uint16_t *allowed_ports,
                                 size_t allowed_port_count, int64_t now);
int tg_dc_resolve(const tg_dc_snapshot *snapshot,
                  const tg_listener_destination *destination,
                  int media_hint, uint32_t dc_hint, int allow_cdn,
                  tg_dc_endpoint *out, tg_dc_map_source *source);
const char *tg_dc_lookup_result_text(int result);

#endif
