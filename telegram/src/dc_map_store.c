#define _POSIX_C_SOURCE 200809L
#include "tg_dc_map.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif

#define TG_DC_CACHE_MAX_BYTES (1024u * 1024u)
#define TG_DC_RETAIN_OLD_SECS (90 * 24 * 60 * 60)

static unsigned long temporary_sequence;

static int copy_snapshot(const tg_dc_snapshot *source, tg_dc_snapshot *out) {
    memset(out, 0, sizeof(*out));
    tg_dc_endpoint *endpoints = calloc(source->endpoint_count, sizeof(*endpoints));
    if (!endpoints) return -1;
    memcpy(endpoints, source->endpoints, source->endpoint_count * sizeof(*endpoints));
    *out = *source;
    out->endpoints = endpoints;
    return 0;
}

static int same_address_port(const tg_dc_endpoint *left,
                             const tg_dc_endpoint *right) {
    size_t len = left->family == AF_INET ? 4 : 16;
    return left->family == right->family && left->port == right->port &&
           memcmp(left->address, right->address, len) == 0;
}

static int same_identity(const tg_dc_endpoint *left,
                         const tg_dc_endpoint *right) {
    return same_address_port(left, right) && left->id == right->id &&
           left->media_only == right->media_only && left->tcpo_only == right->tcpo_only &&
           left->cdn == right->cdn && left->is_static == right->is_static &&
           left->this_port_only == right->this_port_only &&
           left->secret_len == right->secret_len &&
           memcmp(left->secret, right->secret, left->secret_len) == 0;
}

static int replaced_by_incoming(const tg_dc_endpoint *old,
                                const tg_dc_snapshot *incoming) {
    for (size_t i = 0; i < incoming->endpoint_count; ++i) {
        const tg_dc_endpoint *fresh = &incoming->endpoints[i];
        if (same_address_port(fresh, old) &&
            (fresh->id != old->id || fresh->media_only != old->media_only ||
             fresh->cdn != old->cdn))
            return 1;
    }
    return 0;
}

static int endpoint_order(const void *a, const void *b) {
    const tg_dc_endpoint *left = a, *right = b;
    if (left->id != right->id) return left->id < right->id ? -1 : 1;
    if (left->family != right->family) return left->family < right->family ? -1 : 1;
    size_t len = left->family == AF_INET ? 4 : 16;
    int cmp = memcmp(left->address, right->address, len);
    if (cmp) return cmp;
    if (left->port != right->port) return left->port < right->port ? -1 : 1;
    if (left->media_only != right->media_only) return left->media_only - right->media_only;
    if (left->cdn != right->cdn) return left->cdn - right->cdn;
    if (left->this_port_only != right->this_port_only)
        return left->this_port_only - right->this_port_only;
    return 0;
}

static int merge_snapshot(const tg_dc_snapshot *previous,
                          const tg_dc_snapshot *incoming, int64_t now,
                          tg_dc_snapshot *out) {
    if (tg_dc_snapshot_validate(incoming, now) != 0) return -1;
    if (previous && incoming->config_date < previous->config_date) return -1;
    if (copy_snapshot(incoming, out) != 0) return -1;
    if (previous) {
        tg_dc_endpoint *endpoints = (tg_dc_endpoint *)out->endpoints;
        for (size_t i = 0; i < previous->endpoint_count; ++i) {
            const tg_dc_endpoint *old = &previous->endpoints[i];
            if (replaced_by_incoming(old, incoming) ||
                (now > old->last_seen && now - old->last_seen > TG_DC_RETAIN_OLD_SECS))
                continue;
            int duplicate = 0;
            for (size_t j = 0; j < out->endpoint_count; ++j)
                if (same_identity(&endpoints[j], old)) { duplicate = 1; break; }
            if (duplicate) continue;
            if (out->endpoint_count == TG_DC_MAP_MAX_ENDPOINTS) goto fail;
            tg_dc_endpoint *grown = realloc(endpoints,
                (out->endpoint_count + 1) * sizeof(*endpoints));
            if (!grown) goto fail;
            endpoints = grown;
            endpoints[out->endpoint_count++] = *old;
            out->endpoints = endpoints;
        }
    }
    qsort((void *)out->endpoints, out->endpoint_count,
          sizeof(*out->endpoints), endpoint_order);
    if (tg_dc_snapshot_validate(out, now) != 0) goto fail;
    return 0;
fail:
    tg_dc_snapshot_destroy(out);
    return -1;
}

static int read_snapshot_file(const char *path, int64_t now,
                              tg_dc_snapshot *out) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    uint8_t *bytes = NULL;
    int rc = -1;
    if (fd < 0) return -1;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
        (uint64_t)st.st_size > TG_DC_CACHE_MAX_BYTES)
        goto done;
    bytes = malloc(TG_DC_CACHE_MAX_BYTES + 1u);
    if (!bytes) goto done;
    size_t used = 0;
    while (used < TG_DC_CACHE_MAX_BYTES + 1u) {
        ssize_t n = read(fd, bytes + used, TG_DC_CACHE_MAX_BYTES + 1u - used);
        if (n > 0) { used += (size_t)n; continue; }
        if (n == 0) break;
        if (errno == EINTR) continue;
        goto done;
    }
    if (used > TG_DC_CACHE_MAX_BYTES ||
        tg_dc_snapshot_parse_json(bytes, used, now, out) != 0)
        goto done;
    rc = 0;
done:
    free(bytes);
    close(fd);
    return rc;
}

static int make_parent_dirs(const char *path, char dir[TG_DC_MAP_PATH_MAX]) {
    size_t len = strlen(path);
    if (len >= TG_DC_MAP_PATH_MAX) return -1;
    memcpy(dir, path, len + 1);
    char *slash = strrchr(dir, '/');
    if (!slash) {
        strcpy(dir, ".");
        return 0;
    }
    if (slash == dir) slash[1] = '\0';
    else *slash = '\0';
    for (char *p = dir + (dir[0] == '/' ? 1 : 0); *p; ++p) {
        if (*p != '/') continue;
        *p = '\0';
        if (*dir && mkdir(dir, 0755) != 0 && errno != EEXIST) return -1;
        *p = '/';
    }
    if (mkdir(dir, 0755) != 0 && errno != EEXIST) return -1;
    struct stat st;
    return stat(dir, &st) == 0 && S_ISDIR(st.st_mode) ? 0 : -1;
}

static int write_all(int fd, const uint8_t *data, size_t len) {
    size_t offset = 0;
    while (offset < len) {
        ssize_t n = write(fd, data + offset, len - offset);
        if (n > 0) { offset += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        return -1;
    }
    return 0;
}

static int atomic_write(const char *path, const uint8_t *bytes, size_t len) {
    char dir[TG_DC_MAP_PATH_MAX], temporary[TG_DC_MAP_PATH_MAX + 96];
    const char *name;
    if (make_parent_dirs(path, dir) != 0) return -1;
    name = strrchr(path, '/');
    name = name ? name + 1 : path;
    if (!*name) return -1;
    int fd = -1;
    for (unsigned attempt = 0; attempt < 8; ++attempt) {
        unsigned long sequence = temporary_sequence++;
        int n = snprintf(temporary, sizeof(temporary), "%s/.%s.%ld.%lu.tmp",
                         dir, name, (long)getpid(), sequence);
        if (n <= 0 || (size_t)n >= sizeof(temporary)) return -1;
        fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd >= 0 || errno != EEXIST) break;
    }
    if (fd < 0) return -1;
    int ok = write_all(fd, bytes, len) == 0 && fsync(fd) == 0;
    if (close(fd) != 0) ok = 0;
    if (!ok || rename(temporary, path) != 0) {
        unlink(temporary);
        return -1;
    }
    int dirfd = open(dir, O_RDONLY | O_CLOEXEC | O_DIRECTORY);
    if (dirfd < 0) return -1;
    ok = fsync(dirfd) == 0;
    close(dirfd);
    return ok ? 0 : -1;
}

static int save_snapshot(const char *path, const tg_dc_snapshot *snapshot,
                         int64_t now) {
    uint8_t *json = NULL;
    size_t len = 0;
    int rc = tg_dc_snapshot_encode_json(snapshot, now, &json, &len);
    if (rc == 0) rc = atomic_write(path, json, len);
    free(json);
    return rc;
}

int tg_dc_map_store_init(tg_dc_map_store *store, const char *path) {
    if (!store || !path || !*path || strlen(path) >= TG_DC_MAP_PATH_MAX) return -1;
    memset(store, 0, sizeof(*store));
    strcpy(store->path, path);
    return 0;
}

void tg_dc_map_store_destroy(tg_dc_map_store *store) {
    if (!store) return;
    if (store->has_snapshot) tg_dc_snapshot_destroy(&store->snapshot);
    memset(store, 0, sizeof(*store));
}

int tg_dc_map_store_load(tg_dc_map_store *store, int64_t now) {
    char backup[TG_DC_MAP_PATH_MAX + 16];
    tg_dc_snapshot loaded = {0};
    if (!store || !store->path[0] ||
        snprintf(backup, sizeof(backup), "%s.last-good", store->path) >= (int)sizeof(backup))
        return -1;
    if (read_snapshot_file(store->path, now, &loaded) != 0 &&
        read_snapshot_file(backup, now, &loaded) != 0)
        return 0;
    if (store->has_snapshot) tg_dc_snapshot_destroy(&store->snapshot);
    store->snapshot = loaded;
    store->has_snapshot = 1;
    return 0;
}

const tg_dc_snapshot *tg_dc_map_store_current(const tg_dc_map_store *store) {
    return store && store->has_snapshot ? &store->snapshot : NULL;
}

int tg_dc_map_store_refresh_due(const tg_dc_map_store *store, int64_t now,
                                uint64_t refresh_secs) {
    const tg_dc_snapshot *snapshot = tg_dc_map_store_current(store);
    if (!snapshot || now >= snapshot->config_expires) return 1;
    if (now < snapshot->fetched_at) return 0;
    uint64_t age = (uint64_t)(now - snapshot->fetched_at);
    return age >= refresh_secs || age > (uint64_t)TG_DC_RETAIN_OLD_SECS;
}

int tg_dc_map_store_install(tg_dc_map_store *store,
                            const tg_dc_snapshot *incoming, int64_t now) {
    tg_dc_snapshot merged = {0};
    char backup[TG_DC_MAP_PATH_MAX + 16];
    if (!store || !store->path[0] ||
        merge_snapshot(store->has_snapshot ? &store->snapshot : NULL,
                       incoming, now, &merged) != 0)
        return -1;
    if (store->has_snapshot) {
        if (snprintf(backup, sizeof(backup), "%s.last-good", store->path) >=
            (int)sizeof(backup) ||
            save_snapshot(backup, &store->snapshot, now) != 0) {
            tg_dc_snapshot_destroy(&merged);
            return -1;
        }
    }
    if (save_snapshot(store->path, &merged, now) != 0) {
        tg_dc_snapshot_destroy(&merged);
        return -1;
    }
    if (store->has_snapshot) tg_dc_snapshot_destroy(&store->snapshot);
    store->snapshot = merged;
    store->has_snapshot = 1;
    return 0;
}

static int snapshot_is_fresh(const tg_dc_snapshot *snapshot, int64_t now) {
    return snapshot && !(now >= snapshot->fetched_at &&
                         now - snapshot->fetched_at > TG_DC_RETAIN_OLD_SECS);
}

int tg_dc_map_store_resolve(const tg_dc_map_store *store, int64_t now,
                            const tg_listener_destination *destination,
                            int media_hint, uint32_t dc_hint, int allow_cdn,
                            tg_dc_endpoint *out, tg_dc_map_source *source) {
    const tg_dc_snapshot *snapshot = tg_dc_map_store_current(store);
    if (!snapshot_is_fresh(snapshot, now)) snapshot = NULL;
    return tg_dc_resolve(snapshot, destination, media_hint, dc_hint,
                         allow_cdn, out, source);
}

static int destination_equals(const tg_dc_endpoint *endpoint,
                              const tg_listener_destination *destination) {
    const uint8_t mapped_prefix[12] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff
    };
    sa_family_t family = destination->family;
    const uint8_t *address = destination->address;
    if (family == AF_INET6 && memcmp(address, mapped_prefix, sizeof(mapped_prefix)) == 0) {
        family = AF_INET;
        address += 12;
    }
    size_t len = family == AF_INET ? 4 : 16;
    return endpoint->family == family && memcmp(endpoint->address, address, len) == 0;
}

size_t tg_dc_handshake_secrets(const tg_dc_snapshot *snapshot,
                               const tg_listener_destination *destination,
                               int64_t now, tg_dc_secret *out, size_t out_cap) {
    size_t count = 0;
    if (!snapshot || !destination || !out || !out_cap || !snapshot->endpoints ||
        !destination->port || !snapshot_is_fresh(snapshot, now))
        return 0;
    for (size_t i = 0; i < snapshot->endpoint_count; ++i) {
        const tg_dc_endpoint *endpoint = &snapshot->endpoints[i];
        if (!endpoint->tcpo_only || !endpoint->secret_len ||
            (endpoint->this_port_only && endpoint->port != destination->port) ||
            !destination_equals(endpoint, destination))
            continue;
        int duplicate = 0;
        for (size_t j = 0; j < count; ++j)
            if (out[j].len == endpoint->secret_len &&
                memcmp(out[j].bytes, endpoint->secret, endpoint->secret_len) == 0) {
                duplicate = 1;
                break;
            }
        if (duplicate) continue;
        if (count == out_cap) return out_cap + 1;
        memcpy(out[count].bytes, endpoint->secret, endpoint->secret_len);
        out[count].len = endpoint->secret_len;
        ++count;
    }
    return count;
}

typedef struct {
    sa_family_t family;
    uint8_t address[16];
    uint16_t port;
} dc_pair;

static int pair_order(const void *a, const void *b) {
    const dc_pair *left = a, *right = b;
    if (left->family != right->family) return left->family < right->family ? -1 : 1;
    size_t len = left->family == AF_INET ? 4 : 16;
    int cmp = memcmp(left->address, right->address, len);
    if (cmp) return cmp;
    if (left->port != right->port) return left->port < right->port ? -1 : 1;
    return 0;
}

static int port_is_allowed(uint16_t port, const uint16_t *allowed_ports,
                           size_t allowed_port_count) {
    for (size_t i = 0; i < allowed_port_count; ++i)
        if (allowed_ports[i] == port) return 1;
    return 0;
}

int tg_dc_write_endpoint_manifest(const char *path,
                                 const tg_dc_snapshot *snapshot,
                                 const uint16_t *allowed_ports,
                                 size_t allowed_port_count, int64_t now) {
    dc_pair *pairs = NULL;
    char *contents = NULL;
    size_t pair_count = 0, unique_count = 0, used = 0;
    int rc = -1;
    if (!path || !*path || !allowed_ports || allowed_port_count == 0 ||
        allowed_port_count > 32 || tg_dc_snapshot_validate(snapshot, now) != 0)
        return -1;
    if (snapshot->endpoint_count > SIZE_MAX / allowed_port_count) return -1;
    size_t pair_cap = snapshot->endpoint_count * allowed_port_count;
    pairs = calloc(pair_cap, sizeof(*pairs));
    contents = malloc(TG_DC_CACHE_MAX_BYTES);
    if (!pairs || !contents) goto done;
    for (size_t i = 0; i < snapshot->endpoint_count; ++i) {
        const tg_dc_endpoint *endpoint = &snapshot->endpoints[i];
        size_t count = endpoint->this_port_only ? 1 : allowed_port_count;
        for (size_t j = 0; j < count; ++j) {
            uint16_t port = endpoint->this_port_only ? endpoint->port : allowed_ports[j];
            if (!port || port == 80 || !port_is_allowed(port, allowed_ports,
                                                        allowed_port_count))
                continue;
            dc_pair *pair = &pairs[pair_count++];
            pair->family = endpoint->family;
            memcpy(pair->address, endpoint->address, sizeof(pair->address));
            pair->port = port;
        }
    }
    if (!pair_count) goto done;
    qsort(pairs, pair_count, sizeof(*pairs), pair_order);
    int n = snprintf(contents, TG_DC_CACHE_MAX_BYTES,
                     "z2k-tg-dc-options-v1 %lld %lld\n",
                     (long long)snapshot->config_date,
                     (long long)snapshot->fetched_at);
    if (n <= 0 || (size_t)n >= TG_DC_CACHE_MAX_BYTES) goto done;
    used = (size_t)n;
    for (size_t i = 0; i < pair_count; ++i) {
        if (i && pair_order(&pairs[i - 1], &pairs[i]) == 0) continue;
        char address[INET6_ADDRSTRLEN];
        if (!inet_ntop(pairs[i].family, pairs[i].address,
                       address, sizeof(address))) goto done;
        n = snprintf(contents + used, TG_DC_CACHE_MAX_BYTES - used,
                     "%s %u\n", address, pairs[i].port);
        if (n <= 0 || (size_t)n >= TG_DC_CACHE_MAX_BYTES - used) goto done;
        used += (size_t)n;
        ++unique_count;
    }
    if (!unique_count || atomic_write(path, (const uint8_t *)contents, used) != 0)
        goto done;
    rc = 0;
done:
    free(pairs);
    free(contents);
    return rc;
}
