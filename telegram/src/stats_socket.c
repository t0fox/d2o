#define _POSIX_C_SOURCE 200809L
#include "tg_stats_socket.h"

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static const char *route_stage_name(uint8_t stage) {
    switch (stage) {
    case TG_ROUTE_SESSION_STAGE_ROUTING: return "routing";
    case TG_ROUTE_SESSION_STAGE_UPSTREAM_READY: return "upstream_ready";
    case TG_ROUTE_SESSION_STAGE_FIRST_WSS_BINARY_RESPONSE:
        return "first_wss_binary_response";
    default: return "accepted";
    }
}

static const char *route_state_name(uint8_t state) {
    static const char *const names[] = {
        "idle", "connecting", "connected", "selected", "cooldown",
        "failed", "cancelled", "skipped", "first_binary_response"
    };
    return state < sizeof(names) / sizeof(names[0]) ? names[state] : "idle";
}

static const char *route_transport_name(uint8_t transport) {
    switch (transport) {
    case TG_ROUTE_SESSION_TRANSPORT_DIRECT_WSS: return "direct_wss";
    case TG_ROUTE_SESSION_TRANSPORT_CLOUDFLARE_WORKER: return "cloudflare_worker";
    case TG_ROUTE_SESSION_TRANSPORT_CLOUDFLARE_PROXY: return "cloudflare_proxy";
    case TG_ROUTE_SESSION_TRANSPORT_TCP_FALLBACK: return "tcp_fallback";
    case TG_ROUTE_SESSION_TRANSPORT_TCP_PASSTHROUGH: return "tcp_passthrough";
    default: return NULL;
    }
}

static const char *failure_stage_name(uint8_t stage) {
    static const char *const names[TG_EPOLL_FAILURE_STAGE_COUNT] = {
        "none", "dns", "tcp", "tls", "websocket", "mtproto",
        "setup", "route_unavailable", "worker_port"
    };
    return stage < TG_EPOLL_FAILURE_STAGE_COUNT ? names[stage] : "unknown";
}

static int stats_append(char *buffer, size_t capacity, size_t *used,
                        const char *format, ...) {
    if (*used >= capacity) return -1;
    va_list args;
    va_start(args, format);
    int count = vsnprintf(buffer + *used, capacity - *used, format, args);
    va_end(args);
    if (count < 0 || (size_t)count >= capacity - *used) return -1;
    *used += (size_t)count;
    return 0;
}

static int append_active_sessions(char *buffer, size_t capacity, size_t *used,
                                  const tg_epoll_proxy_stats *stats) {
    if (stats_append(buffer, capacity, used,
        "\"process_started_at\":%" PRIu64 ",\"accepted_connections\":%" PRIu64
        ",\"active_sessions\":[", stats->process_started_at,
        stats->accepted_connections) != 0)
        return -1;
    for (size_t i = 0; i < stats->active_sessions_count; ++i) {
        const tg_active_route_session *session = &stats->active_sessions[i];
        const char *direct = route_transport_name(session->direct_transport);
        const char *fallback = route_transport_name(session->fallback_transport);
        const char *selected = route_transport_name(session->selected_transport);
        int rc = session->has_dc
            ? stats_append(buffer, capacity, used,
                "%s{\"id\":%" PRIu64 ",\"dc\":%u", i ? "," : "",
                session->id, session->dc)
            : stats_append(buffer, capacity, used,
                "%s{\"id\":%" PRIu64 ",\"dc\":null", i ? "," : "",
                session->id);
        if (rc != 0 || stats_append(buffer, capacity, used,
            ",\"is_media\":%s,\"stage\":\"%s\",\"direct_state\":\"%s\","
            "\"direct_transport\":%s%s%s,\"fallback_state\":\"%s\","
            "\"fallback_transport\":%s%s%s,\"selected_transport\":%s%s%s,"
            "\"telegram_response_seen\":%s,\"bytes_from_clients\":%" PRIu64
            ",\"bytes_from_upstreams\":%" PRIu64 ",\"events\":[",
            session->has_media ? (session->is_media ? "true" : "false") : "null",
            route_stage_name(session->stage), route_state_name(session->direct_state),
            direct ? "\"" : "null", direct ? direct : "", direct ? "\"" : "",
            route_state_name(session->fallback_state),
            fallback ? "\"" : "null", fallback ? fallback : "", fallback ? "\"" : "",
            selected ? "\"" : "null", selected ? selected : "", selected ? "\"" : "",
            session->telegram_response_seen ? "true" : "false",
            session->bytes_from_clients, session->bytes_from_upstreams) != 0)
            return -1;
        if (stats_append(buffer, capacity, used,
            ",\"client_port\":%u,\"upstream_port\":%u,\"age_ms\":%" PRIu64
            ",\"no_progress_ms\":%" PRIu64 ",\"first_response_latency_ms\":",
            (unsigned)session->client_port, (unsigned)session->upstream_port,
            session->age_ms, session->no_progress_ms) != 0)
            return -1;
        if (session->telegram_response_seen) {
            if (stats_append(buffer, capacity, used, "%" PRIu64,
                             session->first_response_latency_ms) != 0)
                return -1;
        } else if (stats_append(buffer, capacity, used, "null") != 0) {
            return -1;
        }
        if (stats_append(buffer, capacity, used,
            ",\"read_paused\":%s,\"client_queue_bytes\":%" PRIu64
            ",\"upstream_queue_bytes\":%" PRIu64
            ",\"client_queue_capacity_bytes\":%" PRIu64
            ",\"upstream_queue_capacity_bytes\":%" PRIu64
            ",\"ws_rx_capacity_bytes\":%" PRIu64
            ",\"ws_tx_memory_bytes\":%" PRIu64
            ",\"mtproto_packet_capacity_bytes\":%" PRIu64,
            session->read_paused ? "true" : "false",
            session->client_queue_bytes, session->upstream_queue_bytes,
            session->client_queue_capacity_bytes,
            session->upstream_queue_capacity_bytes,
            session->ws_rx_capacity_bytes, session->ws_tx_memory_bytes,
            session->mtproto_packet_capacity_bytes) != 0)
            return -1;
        for (size_t j = 0; j < session->event_count; ++j) {
            const tg_route_session_event *event = &session->events[j];
            const char *transport = route_transport_name(event->transport);
            if (!transport || stats_append(buffer, capacity, used,
            "%s{\"sequence\":%" PRIu64 ",\"age_ms\":%" PRIu64
            ",\"failure_stage\":%u,\"branch\":\"%s\","
            "\"transport\":\"%s\",\"state\":\"%s\"}",
                j ? "," : "", event->sequence,
            stats->monotonic_time_ms >= event->timestamp_ms
                ? stats->monotonic_time_ms - event->timestamp_ms : 0,
            (unsigned)event->failure_stage,
                event->branch ? "fallback" : "direct", transport,
                route_state_name(event->state)) != 0)
                return -1;
        }
        if (stats_append(buffer, capacity, used, "]}") != 0) return -1;
    }
    if (stats_append(buffer, capacity, used,
        "],\"route_sessions_truncated\":%s,\"route_cooldown_ms\":%u"
        ",\"route_cooldowns\":[",
        stats->route_sessions_truncated ? "true" : "false",
        stats->route_cooldown_ms) != 0)
        return -1;
    for (size_t i = 0; i < stats->route_cooldowns_count; ++i) {
        const tg_route_cooldown *cooldown = &stats->route_cooldowns[i];
        const char *transport = route_transport_name(cooldown->transport);
        if (!transport || stats_append(buffer, capacity, used,
            "%s{\"dc\":%u,\"is_media\":%s,\"transport\":\"%s\","
            "\"remaining_ms\":%" PRIu64 ",\"failure_stage\":%u}",
            i ? "," : "", cooldown->dc,
            cooldown->is_media ? "true" : "false", transport,
            cooldown->remaining_ms, (unsigned)cooldown->failure_stage) != 0)
            return -1;
    }
    return stats_append(buffer, capacity, used,
        "],\"route_cooldowns_truncated\":%s,",
        stats->route_cooldowns_truncated ? "true" : "false");
}

static int append_route_stats(char *buffer, size_t capacity, size_t *used,
                              const tg_epoll_proxy_stats *stats) {
    if (stats_append(buffer, capacity, used,
        "\"route_health\":[") != 0) return -1;
    for (size_t i = 0; i < stats->route_health_count; ++i) {
        const tg_route_health_stat *route = &stats->route_health[i];
        const char *transport = route_transport_name(route->transport);
        if (!transport || stats_append(buffer, capacity, used,
            "%s{\"dc\":%u,\"is_media\":%s,\"transport\":\"%s\","
            "\"client_port\":%u,\"upstream_port\":%u,"
            "\"attempts\":%" PRIu64 ",\"failures\":%" PRIu64
            ",\"responses\":%" PRIu64 ",\"cf_responses\":%" PRIu64
            ",\"latency_ms\":%" PRIu64 ",\"last_success_age_ms\":",
            i ? "," : "", route->dc,
            route->is_media ? "true" : "false", transport,
            (unsigned)route->client_port, (unsigned)route->upstream_port,
            route->attempts, route->failures, route->responses,
            route->cf_responses, route->latency_ms) != 0)
            return -1;
        if (route->has_last_success) {
            if (stats_append(buffer, capacity, used, "%" PRIu64,
                             route->last_success_age_ms) != 0) return -1;
        } else if (stats_append(buffer, capacity, used, "null") != 0) return -1;
        if (stats_append(buffer, capacity, used, ",\"last_failure_age_ms\":") != 0)
            return -1;
        if (route->has_last_failure) {
            if (stats_append(buffer, capacity, used, "%" PRIu64,
                             route->last_failure_age_ms) != 0) return -1;
        } else if (stats_append(buffer, capacity, used, "null") != 0) return -1;
        if (stats_append(buffer, capacity, used,
            ",\"cooldown_remaining_ms\":%" PRIu64
            ",\"last_failure_stage\":\"%s\"}",
            route->cooldown_remaining_ms,
            failure_stage_name(route->last_failure_stage)) != 0) return -1;
    }
    if (stats_append(buffer, capacity, used,
        "],\"route_health_truncated\":%s,\"problem_sessions\":[",
        stats->route_health_truncated ? "true" : "false") != 0)
        return -1;
    for (size_t i = 0; i < stats->problem_sessions_count; ++i) {
        const tg_problem_session *problem = &stats->problem_sessions[i];
        const char *transport = route_transport_name(problem->transport);
        if (!transport || stats_append(buffer, capacity, used,
            "%s{\"sequence\":%" PRIu64 ",\"session_id\":%" PRIu64
            ",\"dc\":%u,\"is_media\":%s,\"transport\":\"%s\","
            "\"failure_stage\":\"%s\",\"http_status\":%u,"
            "\"client_port\":%u,\"upstream_port\":%u,\"age_ms\":%" PRIu64
            ",\"bytes_from_clients\":%" PRIu64
            ",\"bytes_from_upstreams\":%" PRIu64 "}",
            i ? "," : "", problem->sequence, problem->session_id,
            problem->dc, problem->is_media ? "true" : "false", transport,
            failure_stage_name(problem->failure_stage),
            (unsigned)problem->http_status, (unsigned)problem->client_port,
            (unsigned)problem->upstream_port, problem->age_ms,
            problem->bytes_from_clients, problem->bytes_from_upstreams) != 0)
            return -1;
    }
    if (stats_append(buffer, capacity, used, "],\"failure_by_stage\":{") != 0)
        return -1;
    for (size_t i = 0; i < TG_EPOLL_FAILURE_STAGE_COUNT; ++i) {
        if (stats_append(buffer, capacity, used, "%s\"%s\":%" PRIu64,
            i ? "," : "", failure_stage_name((uint8_t)i),
            stats->failure_by_stage[i]) != 0)
            return -1;
    }
    return stats_append(buffer, capacity, used, "},");
}

enum { PROC_SMAPS_OK = 1, PROC_SMAPS_UNSUPPORTED, PROC_SMAPS_UNAVAILABLE,
       PROC_SMAPS_PARSE_ERROR };
typedef struct {
    int64_t rss_kib, hwm_kib, anon_kib, vm_data_kib, vm_swap_kib;
    int64_t smaps_kib[8], mem_total_kib, mem_available_kib;
    int64_t fd_count, soft_nofile;
    int smaps_status, smaps_errno, status_ok;
} process_memory;

static int64_t proc_kib(const char *line, const char *key) {
    if (strncmp(line, key, strlen(key)) != 0) return -1;
    const char *p = line + strlen(key);
    while (*p == ' ' || *p == '\t') ++p;
    errno = 0;
    char *end = NULL;
    long long value = strtoll(p, &end, 10);
    if (errno || end == p || value < 0 || strncmp(end, " kB", 3) != 0)
        return -1;
    return (int64_t)value;
}

static void read_process_memory(process_memory *memory) {
    static const char *const status_keys[] = {
        "VmRSS:", "VmHWM:", "RssAnon:", "VmData:", "VmSwap:"
    };
    static const char *const rollup_keys[] = {
        "Rss:", "Pss:", "Anonymous:", "Private_Clean:",
        "Private_Dirty:", "Shared_Clean:", "Shared_Dirty:", "Swap:"
    };
    int64_t *status_values[] = {
        &memory->rss_kib, &memory->hwm_kib, &memory->anon_kib,
        &memory->vm_data_kib, &memory->vm_swap_kib
    };
    memory->rss_kib = memory->hwm_kib = memory->anon_kib = -1;
    memory->vm_data_kib = memory->vm_swap_kib = -1;
    memory->mem_total_kib = memory->mem_available_kib = -1;
    memory->fd_count = memory->soft_nofile = -1;
    memory->smaps_status = PROC_SMAPS_UNAVAILABLE;
    memory->smaps_errno = 0;
    memory->status_ok = 0;
    for (size_t i = 0; i < 8; ++i) memory->smaps_kib[i] = -1;

    FILE *file = fopen("/proc/self/status", "r");
    if (file) {
        char line[256];
        unsigned found = 0;
        while (fgets(line, sizeof(line), file)) {
            for (size_t i = 0; i < sizeof(status_keys) / sizeof(status_keys[0]); ++i) {
                int64_t value = proc_kib(line, status_keys[i]);
                if (value >= 0) { *status_values[i] = value; found |= 1u << i; }
            }
        }
        fclose(file);
        memory->status_ok = found == (1u << 5) - 1u;
    }

    errno = 0;
    file = fopen("/proc/self/smaps_rollup", "r");
    if (!file) {
        memory->smaps_errno = errno;
        memory->smaps_status = errno == ENOENT || errno == ENOTDIR
            ? PROC_SMAPS_UNSUPPORTED : PROC_SMAPS_UNAVAILABLE;
    } else {
        char line[256];
        unsigned found = 0;
        while (fgets(line, sizeof(line), file)) {
            for (size_t i = 0; i < sizeof(rollup_keys) / sizeof(rollup_keys[0]); ++i) {
                int64_t value = proc_kib(line, rollup_keys[i]);
                if (value >= 0) { memory->smaps_kib[i] = value; found |= 1u << i; }
            }
        }
        fclose(file);
        memory->smaps_status = found ? PROC_SMAPS_OK : PROC_SMAPS_PARSE_ERROR;
    }

    file = fopen("/proc/meminfo", "r");
    if (file) {
        char line[256];
        while (fgets(line, sizeof(line), file)) {
            int64_t value = proc_kib(line, "MemTotal:");
            if (value >= 0) memory->mem_total_kib = value;
            value = proc_kib(line, "MemAvailable:");
            if (value >= 0) memory->mem_available_kib = value;
        }
        fclose(file);
    }

    DIR *fd_dir = opendir("/proc/self/fd");
    if (fd_dir) {
        int64_t count = 0;
        struct dirent *entry;
        while ((entry = readdir(fd_dir)) != NULL) {
            if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;
            int numeric = 1;
            for (const char *p = entry->d_name; *p; ++p)
                if (*p < '0' || *p > '9') { numeric = 0; break; }
            if (numeric) ++count;
        }
        closedir(fd_dir);
        memory->fd_count = count > 0 ? count - 1 : 0;
    }
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) == 0 && limit.rlim_cur != RLIM_INFINITY &&
        limit.rlim_cur <= INT64_MAX)
        memory->soft_nofile = (int64_t)limit.rlim_cur;
}

static int append_nullable_i64(char *buffer, size_t capacity, size_t *used,
                               int64_t value) {
    return value < 0 ? stats_append(buffer, capacity, used, "null")
                     : stats_append(buffer, capacity, used, "%" PRId64, value);
}

static const char *smaps_status_name(int status) {
    switch (status) {
    case PROC_SMAPS_OK: return "ok";
    case PROC_SMAPS_UNSUPPORTED: return "unsupported";
    case PROC_SMAPS_PARSE_ERROR: return "parse_error";
    default: return "unavailable";
    }
}

static int append_process_metrics(char *buffer, size_t capacity, size_t *used,
                                 const tg_epoll_proxy_stats *stats,
                                 const process_memory *memory) {
    uint64_t known = stats->buffer_bytes_current + stats->proxy_struct_bytes +
        stats->connection_struct_bytes + stats->retired_connection_struct_bytes +
        stats->worker_pool_struct_bytes;
    if (stats_append(buffer, capacity, used,
        "\"process_id\":%ld,\"process_metrics_status\":\"%s\","
        "\"rss_kib\":", (long)getpid(), memory->status_ok ? "ok" : "unavailable") != 0 ||
        append_nullable_i64(buffer, capacity, used, memory->rss_kib) != 0 ||
        stats_append(buffer, capacity, used, ",\"rss_hwm_kib\":") != 0 ||
        append_nullable_i64(buffer, capacity, used, memory->hwm_kib) != 0 ||
        stats_append(buffer, capacity, used, ",\"rss_anon_kib\":") != 0 ||
        append_nullable_i64(buffer, capacity, used, memory->anon_kib) != 0 ||
        stats_append(buffer, capacity, used, ",\"vm_data_kib\":") != 0 ||
        append_nullable_i64(buffer, capacity, used, memory->vm_data_kib) != 0 ||
        stats_append(buffer, capacity, used, ",\"vm_swap_kib\":") != 0 ||
        append_nullable_i64(buffer, capacity, used, memory->vm_swap_kib) != 0 ||
        stats_append(buffer, capacity, used,
            ",\"smaps_rollup_status\":\"%s\",\"smaps_rollup_errno\":",
            smaps_status_name(memory->smaps_status)) != 0)
        return -1;
    if (memory->smaps_errno) {
        if (stats_append(buffer, capacity, used, "%d", memory->smaps_errno) != 0)
            return -1;
    } else if (stats_append(buffer, capacity, used, "null") != 0) return -1;
    static const char *const rollup_names[] = {
        "smaps_rss_kib", "smaps_pss_kib", "smaps_anonymous_kib",
        "smaps_private_clean_kib", "smaps_private_dirty_kib",
        "smaps_shared_clean_kib", "smaps_shared_dirty_kib", "smaps_swap_kib"
    };
    for (size_t i = 0; i < sizeof(rollup_names) / sizeof(rollup_names[0]); ++i) {
        if (stats_append(buffer, capacity, used, ",\"%s\":", rollup_names[i]) != 0 ||
            append_nullable_i64(buffer, capacity, used, memory->smaps_kib[i]) != 0)
            return -1;
    }
    int64_t residual = memory->rss_kib >= 0 &&
        memory->rss_kib <= INT64_MAX / 1024
        ? memory->rss_kib * 1024 - (known > INT64_MAX ? INT64_MAX : (int64_t)known)
        : -1;
    if (stats_append(buffer, capacity, used,
        ",\"mem_total_kib\":") != 0 ||
        append_nullable_i64(buffer, capacity, used, memory->mem_total_kib) != 0 ||
        stats_append(buffer, capacity, used, ",\"mem_available_kib\":") != 0 ||
        append_nullable_i64(buffer, capacity, used, memory->mem_available_kib) != 0 ||
        stats_append(buffer, capacity, used, ",\"fd_count\":") != 0 ||
        append_nullable_i64(buffer, capacity, used, memory->fd_count) != 0 ||
        stats_append(buffer, capacity, used, ",\"soft_nofile_limit\":") != 0 ||
        append_nullable_i64(buffer, capacity, used, memory->soft_nofile) != 0 ||
        stats_append(buffer, capacity, used,
            ",\"memory_accounted_allocations_bytes\":%" PRIu64
            ",\"rss_minus_known_allocations_bytes\":", known) != 0 ||
        append_nullable_i64(buffer, capacity, used, residual) != 0)
        return -1;
    return 0;
}

static int append_dc_map(char *buffer, size_t capacity, size_t *used,
                         const tg_stats_socket_context *context) {
    const tg_dc_snapshot *snapshot = context && context->dc_map &&
        context->dc_map->has_snapshot ? &context->dc_map->snapshot : NULL;
    int64_t now = (int64_t)time(NULL);
    const char *status = !snapshot ? "unavailable" :
        now < snapshot->fetched_at ? "clock_skew" :
        now >= snapshot->config_expires ? "expired" : "fresh";
    if (stats_append(buffer, capacity, used,
        "\"dc_map_status\":\"%s\",\"dc_map_last_known_good\":%s,"
        "\"dc_map_endpoint_count\":", status,
        context && context->dc_map && context->dc_map->loaded_last_good
            ? "true" : "false") != 0)
        return -1;
    if (snapshot) {
        if (stats_append(buffer, capacity, used, "%zu", snapshot->endpoint_count) != 0)
            return -1;
    } else if (stats_append(buffer, capacity, used, "null") != 0) return -1;
    if (stats_append(buffer, capacity, used, ",\"dc_map_fetched_at\":") != 0)
        return -1;
    if (snapshot && stats_append(buffer, capacity, used, "%" PRId64,
                                 snapshot->fetched_at) != 0) return -1;
    if (!snapshot && stats_append(buffer, capacity, used, "null") != 0) return -1;
    if (stats_append(buffer, capacity, used, ",\"dc_map_config_expires\":") != 0)
        return -1;
    if (snapshot && stats_append(buffer, capacity, used, "%" PRId64,
                                 snapshot->config_expires) != 0) return -1;
    if (!snapshot && stats_append(buffer, capacity, used, "null") != 0) return -1;
    if (stats_append(buffer, capacity, used, ",\"dc_map_age_seconds\":") != 0)
        return -1;
    if (snapshot && stats_append(buffer, capacity, used, "%" PRId64,
            now >= snapshot->fetched_at ? now - snapshot->fetched_at : 0) != 0)
        return -1;
    if (!snapshot && stats_append(buffer, capacity, used, "null") != 0) return -1;
    const char *result = context && context->last_refresh_result
        ? context->last_refresh_result : "never";
    if (stats_append(buffer, capacity, used,
        ",\"dc_map_refreshing\":%s,\"dc_map_last_refresh_result\":\"%s\","
        "\"dc_map_last_attempt_at\":",
        context && context->refreshing ? "true" : "false", result) != 0)
        return -1;
    if (context && context->last_attempt_at > 0 && stats_append(buffer, capacity, used,
        "%" PRId64, context->last_attempt_at) != 0) return -1;
    if ((!context || context->last_attempt_at <= 0) &&
        stats_append(buffer, capacity, used, "null") != 0) return -1;
    if (stats_append(buffer, capacity, used, ",\"dc_map_last_success_at\":") != 0)
        return -1;
    if (context && context->last_success_at > 0 && stats_append(buffer, capacity, used,
        "%" PRId64, context->last_success_at) != 0) return -1;
    if ((!context || context->last_success_at <= 0) &&
        stats_append(buffer, capacity, used, "null") != 0) return -1;
    if (stats_append(buffer, capacity, used, ",\"dc_map_last_failure_at\":") != 0)
        return -1;
    if (context && context->last_failure_at > 0 && stats_append(buffer, capacity, used,
        "%" PRId64, context->last_failure_at) != 0) return -1;
    if ((!context || context->last_failure_at <= 0) &&
        stats_append(buffer, capacity, used, "null") != 0) return -1;
    if (stats_append(buffer, capacity, used, ",\"dc_map_next_refresh_at\":") != 0)
        return -1;
    if (context && context->next_refresh_at > 0 && stats_append(buffer, capacity, used,
        "%" PRId64, context->next_refresh_at) != 0) return -1;
    if ((!context || context->next_refresh_at <= 0) &&
        stats_append(buffer, capacity, used, "null") != 0) return -1;
    if (stats_append(buffer, capacity, used,
        ",\"dc_map_refresh_attempts\":%" PRIu64
        ",\"dc_map_refresh_successes\":%" PRIu64
        ",\"dc_map_refresh_failures\":%" PRIu64
        ",\"dc_map_last_refresh_errno\":",
        context ? context->refresh_attempts : 0,
        context ? context->refresh_successes : 0,
        context ? context->refresh_failures : 0) != 0)
        return -1;
    if (context && context->last_refresh_errno && stats_append(buffer, capacity, used,
        "%d", context->last_refresh_errno) != 0) return -1;
    if ((!context || !context->last_refresh_errno) &&
        stats_append(buffer, capacity, used, "null") != 0) return -1;
    if (stats_append(buffer, capacity, used, ",\"dc_map_last_manifest_errno\":") != 0)
        return -1;
    if (context && context->last_manifest_errno && stats_append(buffer, capacity, used,
        "%d", context->last_manifest_errno) != 0) return -1;
    if ((!context || !context->last_manifest_errno) &&
        stats_append(buffer, capacity, used, "null") != 0) return -1;
    return stats_append(buffer, capacity, used, ",");
}

static int set_socket_flags(int fd) {
    int status_flags = fcntl(fd, F_GETFL, 0);
    int descriptor_flags = fcntl(fd, F_GETFD, 0);
    if (status_flags < 0 || descriptor_flags < 0 ||
        fcntl(fd, F_SETFL, status_flags | O_NONBLOCK) != 0 ||
        fcntl(fd, F_SETFD, descriptor_flags | FD_CLOEXEC) != 0)
        return -1;
    return 0;
}

static int remove_stale_socket(const char *path) {
    struct stat current;
    if (lstat(path, &current) != 0) return errno == ENOENT ? 0 : -1;
    if (!S_ISSOCK(current.st_mode) || current.st_uid != geteuid()) {
        errno = EEXIST;
        return -1;
    }

    int probe = socket(AF_UNIX, SOCK_STREAM, 0);
    if (probe < 0) return -1;
    if (set_socket_flags(probe) != 0) {
        close(probe);
        return -1;
    }
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, strlen(path) + 1);
    int rc = connect(probe, (struct sockaddr *)&address, sizeof(address));
    int saved_errno = errno;
    close(probe);
    if (rc == 0 || (saved_errno != ECONNREFUSED && saved_errno != ENOENT)) {
        errno = EADDRINUSE;
        return -1;
    }
    if (unlink(path) != 0 && errno != ENOENT) return -1;
    return 0;
}

int tg_stats_socket_open(tg_stats_socket *server, const char *path) {
    if (!server || !path || !*path) {
        errno = EINVAL;
        return -1;
    }
    memset(server, 0, sizeof(*server));
    server->fd = -1;
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    size_t path_len = strlen(path);
    if (path_len >= sizeof(address.sun_path) || path_len >= sizeof(server->path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, path_len + 1);
    if (remove_stale_socket(path) != 0) return -1;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (set_socket_flags(fd) != 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    mode_t previous_mask = umask(0077);
    int bind_rc = bind(fd, (struct sockaddr *)&address, sizeof(address));
    int bind_errno = errno;
    (void)umask(previous_mask);
    if (bind_rc != 0 || listen(fd, 8) != 0) {
        int saved_errno = bind_rc != 0 ? bind_errno : errno;
        close(fd);
        if (bind_rc == 0) unlink(path);
        errno = saved_errno;
        return -1;
    }
    struct stat created = {0}, secured = {0};
    int setup_error = 0;
    if (lstat(path, &created) != 0) setup_error = errno;
    else if (!S_ISSOCK(created.st_mode) || created.st_uid != geteuid())
        setup_error = EPERM;
    else if (chmod(path, 0600) != 0) setup_error = errno;
    else if (lstat(path, &secured) != 0) setup_error = errno;
    else if (!S_ISSOCK(secured.st_mode) || secured.st_uid != geteuid() ||
             secured.st_dev != created.st_dev || secured.st_ino != created.st_ino)
        setup_error = ESTALE;
    if (setup_error) {
        close(fd);
        struct stat current;
        if (created.st_ino && lstat(path, &current) == 0 &&
            S_ISSOCK(current.st_mode) && current.st_dev == created.st_dev &&
            current.st_ino == created.st_ino)
            unlink(path);
        errno = setup_error;
        return -1;
    }
    server->fd = fd;
    memcpy(server->path, path, path_len + 1);
    server->device = secured.st_dev;
    server->inode = secured.st_ino;
    return 0;
}

int tg_stats_socket_serve(tg_stats_socket *server,
                          const tg_epoll_proxy *proxy,
                          const tg_stats_socket_context *context) {
    if (!server || server->fd < 0 || !proxy) {
        errno = EINVAL;
        return -1;
    }
    for (;;) {
        int client = accept(server->fd, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            return -1;
        }
        if (set_socket_flags(client) != 0) {
            close(client);
            continue;
        }
        tg_epoll_proxy_stats stats;
        process_memory memory;
        char response[262144];
        int n = tg_epoll_proxy_get_stats(proxy, &stats);
        size_t used = 0;
        read_process_memory(&memory);
        int length = n == 0 ? snprintf(response, sizeof(response),
            "{\"active_connections\":%zu,", stats.active_connections) : -1;
        if (length > 0 && (size_t)length < sizeof(response)) {
            used = (size_t)length;
            if (append_active_sessions(response, sizeof(response), &used,
                                       &stats) == 0 &&
                stats_append(response, sizeof(response), &used,
                    "\"max_connections\":%zu,\"active_wss_connections\":%zu"
                    ",\"max_wss_connections\":%zu"
                    ",\"memory_headroom_bytes\":%zu,\"memory_ceiling_bytes\":%zu"
                    ",\"buffer_bytes_current\":%zu"
                    ",\"buffer_bytes_peak\":%zu"
                    ",\"buffer_bytes_limit\":%zu"
                    ",\"client_queue_bytes\":%zu,\"upstream_queue_bytes\":%zu"
                    ",\"client_queue_capacity_bytes\":%zu"
                    ",\"upstream_queue_capacity_bytes\":%zu"
                    ",\"ws_rx_capacity_bytes\":%zu,\"ws_tx_memory_bytes\":%zu"
                    ",\"mtproto_packet_capacity_bytes\":%zu"
                    ",\"proxy_struct_bytes\":%zu"
                    ",\"connection_struct_bytes\":%zu"
                    ",\"retired_connection_struct_bytes\":%zu"
                    ",\"tls_objects\":%zu,\"worker_pool_tls_objects\":%zu"
                    ",\"client_socket_fds\":%zu,\"upstream_socket_fds\":%zu"
                    ",\"worker_pool_entries\":%zu,\"worker_pool_capacity\":%zu"
                    ",\"worker_pool_struct_bytes\":%zu,\"worker_pool_started\":%s"
                    ",\"accept_limit_rejections\":%" PRIu64
                    ",\"accept_fd_exhaustion\":%" PRIu64
                    ",\"allocation_failures\":%" PRIu64
                    ",\"buffer_budget_rejections\":%" PRIu64
                    ",\"buffer_size_rejections\":%" PRIu64
                    ",\"wss_read_pauses\":%" PRIu64
                    ",\"wss_read_resumes\":%" PRIu64
                    ",\"wss_paused_timeouts\":%" PRIu64
                    ",\"http_403\":%" PRIu64 ",\"http_501\":%" PRIu64
                    ",\"http_502\":%" PRIu64 ",\"last_http_status\":%u"
                    ",\"wss_reads_paused\":%zu"
                    ",\"wss_oldest_pause_ms\":%" PRIu64
                    ",\"connections_started\":%" PRIu64
                    ",\"bytes_from_clients\":%" PRIu64
                    ",\"bytes_from_upstreams\":%" PRIu64
                    ",\"wss_attempts\":%" PRIu64 ",\"wss_failures\":%" PRIu64
                    ",\"wss_responses\":%" PRIu64
                    ",\"cf_wss_responses\":%" PRIu64
                    ",\"last_success_dc\":%u,\"last_success_route\":%u"
                    ",\"last_success_latency_ms\":%" PRIu64
                    ",\"last_success_age_ms\":%" PRIu64
                    ",\"last_failure_dc\":%u,\"last_failure_route\":%u"
                    ",\"last_failure_stage\":%u,\"last_failure_age_ms\":%" PRIu64
                    ",\"worker_pool_hits\":%" PRIu64
                    ",\"worker_pool_misses\":%" PRIu64
                    ",\"worker_pool_responses\":%" PRIu64
                    ",\"client_response_latency_total\":%" PRIu64
                    ",\"client_response_latency_samples\":%zu"
                    ",\"client_response_latency_last_us\":%" PRIu64
                    ",\"client_response_latency_p50_us\":%" PRIu64
                    ",\"client_response_latency_p95_us\":%" PRIu64
                    ",",
                    stats.max_connections, stats.active_wss_connections,
                    stats.max_wss_connections, stats.memory_headroom_bytes,
                    stats.memory_ceiling_bytes, stats.buffer_bytes_current,
                    stats.buffer_bytes_peak, stats.buffer_bytes_limit,
                    stats.client_queue_bytes, stats.upstream_queue_bytes,
                    stats.client_queue_capacity_bytes,
                    stats.upstream_queue_capacity_bytes,
                    stats.ws_rx_capacity_bytes, stats.ws_tx_memory_bytes,
                    stats.mtproto_packet_capacity_bytes,
                    stats.proxy_struct_bytes, stats.connection_struct_bytes,
                    stats.retired_connection_struct_bytes, stats.tls_objects,
                    stats.worker_pool_tls_objects, stats.client_socket_fds,
                    stats.upstream_socket_fds, stats.worker_pool_entries,
                    stats.worker_pool_capacity, stats.worker_pool_struct_bytes,
                    stats.worker_pool_started ? "true" : "false",
                    stats.accept_limit_rejections,
                    stats.accept_fd_exhaustion,
                    stats.allocation_failures,
                    stats.buffer_budget_rejections,
                    stats.buffer_size_rejections,
                    stats.wss_read_pauses,
                    stats.wss_read_resumes,
                    stats.wss_paused_timeouts,
                    stats.http_403, stats.http_501, stats.http_502,
                    stats.last_http_status,
                    stats.wss_reads_paused,
                    stats.wss_oldest_pause_ms,
                    stats.connections_started,
                    stats.bytes_from_clients, stats.bytes_from_upstreams,
                    stats.wss_attempts, stats.wss_failures, stats.wss_responses,
                    stats.cf_wss_responses, stats.last_success_dc,
                    stats.last_success_route, stats.last_success_latency_ms,
                    stats.last_success_age_ms, stats.last_failure_dc,
                    stats.last_failure_route, stats.last_failure_stage,
                    stats.last_failure_age_ms,
                    stats.worker_pool_hits, stats.worker_pool_misses,
                    stats.worker_pool_responses,
                    stats.client_response_latency_total,
                    stats.client_response_latency_samples,
                    stats.client_response_latency_last_us,
                    stats.client_response_latency_p50_us,
                    stats.client_response_latency_p95_us) == 0 &&
                append_route_stats(response, sizeof(response), &used, &stats) == 0 &&
                append_process_metrics(response, sizeof(response), &used,
                                       &stats, &memory) == 0 &&
                stats_append(response, sizeof(response), &used, ",") == 0 &&
                append_dc_map(response, sizeof(response), &used, context) == 0 &&
                stats_append(response, sizeof(response), &used, "}\n") == 0)
                length = (int)used;
            else
                length = -1;
        } else {
            length = -1;
        }
        if (length > 0 && (size_t)length == used) {
            size_t sent = 0;
            while (sent < (size_t)length) {
                ssize_t written = send(client, response + sent,
                                       (size_t)length - sent, MSG_NOSIGNAL);
                if (written > 0) {
                    sent += (size_t)written;
                    continue;
                }
                if (written < 0 && errno == EINTR) continue;
                break;
            }
        }
        close(client);
    }
}

void tg_stats_socket_close(tg_stats_socket *server) {
    if (!server) return;
    if (server->fd >= 0) close(server->fd);
    if (server->path[0]) {
        struct stat current;
        if (lstat(server->path, &current) == 0 && S_ISSOCK(current.st_mode) &&
            current.st_uid == geteuid() && current.st_dev == server->device &&
            current.st_ino == server->inode)
            (void)unlink(server->path);
    }
    memset(server, 0, sizeof(*server));
    server->fd = -1;
}
