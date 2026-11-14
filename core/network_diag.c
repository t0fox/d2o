#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "network_diag.h"
#include "../runtime/d2k_diagnostics_files.h"

#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <time.h>
#include <sys/file.h>
#include <sys/mman.h>
#ifdef __linux__
#include <sys/vfs.h>
#endif

enum { CPU_PROCESSES = 5 };

typedef struct {
    int64_t ticks, start, pid;
} process_cpu;

typedef struct {
    int64_t routes, ifindex, operstate, carrier, rx_errors, tx_errors, rx_dropped, tx_dropped;
} wan_snapshot;

typedef struct {
    uint64_t mono_ms, at;
    d2k_network_controller_message controller;
    d2k_network_datapath_message datapath;
    int64_t cpu_pct[CPU_PROCESSES];
    int64_t backlog, drops, user_drops, netlink_drops;
    int64_t ct_count, ct_max, ct_drop, ct_early_drop, ct_insert_failed;
    wan_snapshot wan[2];
} network_sample;

enum {
    MINUTES = 1440, INCIDENTS = 3, BEFORE_MS = 300000, AFTER_MS = 180000,
    INCIDENT_ROWS = (BEFORE_MS + AFTER_MS) / D2K_NET_DIAG_INTERVAL_MS + 1
};

enum {
    ROUTE4 = 1, ROUTE6 = 2, LINK4 = 4, LINK6 = 8,
    QUEUE_LOSS = 16, CONNTRACK_LOSS = 32
};

typedef struct {
    uint64_t mono_minute, at;
    uint32_t triggers, samples;
    int32_t cpu[CPU_PROCESSES], backlog, ct_pct, verdict_us, queued, mem_kib;
    uint64_t dns_failures;
} minute_sample;

typedef struct {
    uint64_t at, trigger_ms;
    unsigned reasons, count, complete;
    network_sample rows[INCIDENT_ROWS];
} incident;

struct d2k_network_history {
    uint64_t session, total, last_ms, minute_total, incident_total;
    process_cpu prev[CPU_PROCESSES];
    network_sample samples[D2K_NETWORK_HISTORY];
    minute_sample minutes[MINUTES];
    incident incidents[INCIDENTS];
};

/* One page-backed state and one export copy. Reserve covers page/allocator
 * rounding, collector and exporter stack and libc, and bounded socket/stdio
 * buffers. The export lock serializes copies across panel processes. */
enum { IO_RESERVE = 192 * 1024 };
_Static_assert(2 * sizeof(d2k_network_history) + IO_RESERVE <= D2K_NETWORK_BUDGET,
    "network diagnostics exceed the RAM budget");

size_t d2k_network_history_bytes(void) {
    return 2 * sizeof(d2k_network_history) + IO_RESERVE;
}

static FILE *open_path(const char *base, const char *suffix) {
    char path[512];
    int n = snprintf(path, sizeof(path), "%s/%s", base, suffix);
    return n > 0 && (size_t)n < sizeof(path) ? fopen(path, "r") : NULL;
}

static int64_t read_number(const char *base, const char *suffix) {
    FILE *file = open_path(base, suffix);
    int64_t val = -1;
    if (file) {
        if (fscanf(file, "%" SCNd64, &val) != 1 || val < 0) val = -1;
        fclose(file);
    }
    return val;
}

static process_cpu read_cpu(const char *proc, const char *run, const char *pidfile, const char *comm) {
    process_cpu result = {.ticks = -1, .start = -1};
    int64_t pid = read_number(run, pidfile);
    if (pid <= 0 || pid > INT_MAX) return result;
    char suffix[64], line[512];
    snprintf(suffix, sizeof(suffix), "%" PRId64 "/stat", pid);
    FILE *file = open_path(proc, suffix);
    if (!file) return result;
    int ok = fgets(line, sizeof(line), file) != NULL;
    fclose(file);
    if (!ok) return result;

    char *name = strchr(line, '('), *end = strrchr(line, ')');
    if (!name || !end || end <= name) return result;
    *end = '\0';
    if (strcmp(name + 1, comm)) return result;
    char *save = NULL, *token = strtok_r(end + 1, " ", &save);
    int64_t user = -1, sys = -1, start = -1;
    for (unsigned field = 3; token && field <= 22; field++, token = strtok_r(NULL, " ", &save)) {
        if (field != 14 && field != 15 && field != 22) continue;
        char *tail;
        errno = 0;
        int64_t number = strtoll(token, &tail, 10);
        if (errno || tail == token || (*tail != '\0' && *tail != '\n') || number < 0) return result;
        if (field == 14) user = number;
        if (field == 15) sys = number;
        if (field == 22) start = number;
    }
    if (user >= 0 && sys >= 0 && start >= 0 && user <= INT64_MAX - sys) {
        result = (process_cpu){.ticks = user + sys, .start = start, .pid = pid};
    }
    return result;
}

static void sample_cpu(d2k_network_history *h, network_sample *sample, const char *proc, const char *run) {
    static const char *const pids[] = {"d2k.pid", "d2kd.pid", "d2k-panel.pid", "d2kdiag.pid", "d2ktg.pid"};
    static const char *const names[] = {"d2kc", "d2kd", "d2kpanel", "d2kdiag", "d2ktg"};
    long hz = sysconf(_SC_CLK_TCK);
    for (size_t i = 0; i < CPU_PROCESSES; i++) {
        process_cpu current = read_cpu(proc, run, pids[i], names[i]);
        process_cpu prev = h->prev[i];
        sample->cpu_pct[i] = -1;
        if (hz > 0 && prev.pid > 0 && current.pid == prev.pid && current.start == prev.start &&
            current.ticks >= prev.ticks && sample->mono_ms > h->last_ms) {
            uint64_t ticks = (uint64_t)(current.ticks - prev.ticks);
            uint64_t elapsed = sample->mono_ms - h->last_ms;
            if (ticks <= UINT64_MAX / 100000 && elapsed <= UINT64_MAX / (uint64_t)hz)
                sample->cpu_pct[i] = (int64_t)((ticks * 100000) / ((uint64_t)hz * elapsed));
        }
        h->prev[i] = current;
    }
}

static void sample_queue(network_sample *sample, const char *proc) {
    sample->backlog = sample->drops = sample->user_drops = sample->netlink_drops = -1;
    const d2k_network_datapath_message *d = &sample->datapath;
    if (d->header.pid <= 0 || !d->netlink_port) return;
    FILE *file = open_path(proc, "net/netfilter/nfnetlink_queue");
    char line[512];
    if (file) {
        while (fgets(line, sizeof(line), file)) {
            unsigned queue, mode, range;
            uint32_t port, backlog, drops, user_drops;
            int fields = sscanf(line, "%u %" SCNu32 " %" SCNu32 " %u %u %" SCNu32 " %" SCNu32,
                &queue, &port, &backlog, &mode, &range, &drops, &user_drops);
            if (fields != 7 || queue != d->queue || port != d->netlink_port) continue;
            sample->backlog = backlog;
            sample->drops = drops;
            sample->user_drops = user_drops;
            break;
        }
        fclose(file);
    }
    file = open_path(proc, "net/netlink");
    if (file) {
        while (fgets(line, sizeof(line), file)) {
            unsigned protocol;
            uint32_t port;
            int64_t drops;
            int fields = sscanf(line, "%*s %u %" SCNu32 " %*s %*s %*s %*s %*s %" SCNd64,
                &protocol, &port, &drops);
            if (fields == 3 && protocol == 12 && port == d->netlink_port && drops >= 0) {
                sample->netlink_drops = drops;
                break;
            }
        }
        fclose(file);
    }
}

static void sample_conntrack(network_sample *sample, const char *proc) {
    sample->ct_count = read_number(proc, "sys/net/netfilter/nf_conntrack_count");
    sample->ct_max = read_number(proc, "sys/net/netfilter/nf_conntrack_max");
    sample->ct_drop = sample->ct_early_drop = sample->ct_insert_failed = -1;
    FILE *file = open_path(proc, "net/stat/nf_conntrack");
    if (!file) return;
    const char *const names[] = {"drop", "early_drop", "insert_failed"};
    int64_t *const dst[] = {&sample->ct_drop, &sample->ct_early_drop, &sample->ct_insert_failed};
    int columns[] = {-1, -1, -1}, valid[] = {0, 0, 0};
    int64_t totals[] = {0, 0, 0};
    char line[1024];
    unsigned rows = 0;
    if (fgets(line, sizeof(line), file) && strchr(line, '\n')) {
        char *save = NULL;
        int col = 0;
        for (char *p = strtok_r(line, " \t\r\n", &save); p; p = strtok_r(NULL, " \t\r\n", &save), col++) {
            for (size_t i = 0; i < 3; i++) {
                if (!strcmp(p, names[i])) { columns[i] = col; valid[i] = 1; }
            }
        }
        while (fgets(line, sizeof(line), file) && strchr(line, '\n')) {
            rows++;
            unsigned seen = 0;
            col = 0;
            for (char *p = strtok_r(line, " \t\r\n", &save); p; p = strtok_r(NULL, " \t\r\n", &save), col++) {
                for (size_t i = 0; i < 3; i++) {
                    if (!valid[i] || columns[i] != col) continue;
                    char *tail;
                    errno = 0;
                    unsigned long value = strtoul(p, &tail, 16);
                    if (errno || tail == p || *tail || value > UINT32_MAX) valid[i] = 0;
                    else { totals[i] += value; seen |= 1u << i; }
                }
            }
            for (size_t i = 0; i < 3; i++) if (!(seen & (1u << i))) valid[i] = 0;
        }
        if (rows) for (size_t i = 0; i < 3; i++) if (valid[i]) *dst[i] = totals[i];
    }
    fclose(file);
}

static void read_wan_device(wan_snapshot *wan, const char *sys, const char *iface) {
    /* Iface is used only for sysfs lookup; exports use the ifindex. */
    if (!iface[0] || strchr(iface, '/') || !strcmp(iface, ".") || !strcmp(iface, "..")) return;
    char base[512];
    int n = snprintf(base, sizeof(base), "%s/class/net/%s", sys, iface);
    if (n <= 0 || (size_t)n >= sizeof(base)) return;
    wan->ifindex = read_number(base, "ifindex");
    wan->carrier = read_number(base, "carrier");
    wan->rx_errors = read_number(base, "statistics/rx_errors");
    wan->tx_errors = read_number(base, "statistics/tx_errors");
    wan->rx_dropped = read_number(base, "statistics/rx_dropped");
    wan->tx_dropped = read_number(base, "statistics/tx_dropped");
    FILE *file = open_path(base, "operstate");
    if (file) {
        char state[32];
        if (fscanf(file, "%31s", state) == 1) {
            static const char *const states[] = {"unknown", "notpresent", "down",
                "lowerlayerdown", "testing", "dormant", "up"};
            for (size_t i = 0; i < sizeof(states) / sizeof(states[0]); i++) {
                if (!strcmp(state, states[i])) { wan->operstate = (int64_t)i; break; }
            }
        }
        fclose(file);
    }
}

static void sample_wan(wan_snapshot *wan, const char *proc, const char *sys, int ipv6) {
    *wan = (wan_snapshot){-1,-1,-1,-1,-1,-1,-1,-1};
    FILE *file = open_path(proc, ipv6 ? "net/ipv6_route" : "net/route");
    if (!file) return;
    char line[512], best[32] = "";
    unsigned best_metric = UINT_MAX;
    wan->routes = 0;
    while (fgets(line, sizeof(line), file)) {
        char iface[32], dest[33], source[33];
        unsigned prefix, source_prefix, flags, metric, mask;
        int is_default;
        if (ipv6) {
            is_default = sscanf(line, "%32s %x %32s %x %*s %x %*x %*x %x %31s",
                dest, &prefix, source, &source_prefix, &metric, &flags, iface) == 7 &&
                !prefix && !source_prefix && strspn(dest, "0") == 32 && strcmp(iface, "lo");
        } else {
            is_default = sscanf(line, "%31s %32s %*s %x %*u %*u %u %x",
                iface, dest, &flags, &metric, &mask) == 5 &&
                strspn(dest, "0") == 8 && !mask;
        }
        /* RTF_UP, !RTF_REJECT. Exclude IPv6 source-specific defaults. */
        if (!is_default || !(flags & 1u) || (flags & 0x200u)) continue;
        wan->routes++;
        if (!best[0] || metric < best_metric) {
            best_metric = metric;
            strcpy(best, iface);
        }
    }
    fclose(file);
    read_wan_device(wan, sys, best);
}

static int increased(int64_t prev, int64_t now) {
    return prev >= 0 && now > prev;
}

static unsigned incident_signals(const network_sample *prev, const network_sample *s) {
    if (!prev) return 0;
    unsigned result = 0;
    for (unsigned i = 0; i < 2; ++i) {
        const wan_snapshot *a = &prev->wan[i], *b = &s->wan[i];
        if (a->routes > 0 && b->routes == 0) result |= ROUTE4 << i;
        if (a->ifindex > 0 && a->ifindex == b->ifindex && a->carrier == 1 && b->carrier == 0)
            result |= LINK4 << i;
    }
    const d2k_network_datapath_message *a = &prev->datapath, *b = &s->datapath;
    if (a->header.pid > 0 && a->header.pid == b->header.pid && a->generation == b->generation &&
        a->netlink_port == b->netlink_port &&
        (increased(prev->drops, s->drops) || increased(prev->user_drops, s->user_drops) ||
         increased(prev->netlink_drops, s->netlink_drops) || b->counters.enobufs > a->counters.enobufs))
        result |= QUEUE_LOSS;
    if (increased(prev->ct_drop, s->ct_drop) || increased(prev->ct_early_drop, s->ct_early_drop))
        result |= CONNTRACK_LOSS;
    return result;
}

static void record_incident(d2k_network_history *h, const network_sample *s, unsigned triggers) {
    incident *active = h->incident_total ? &h->incidents[(h->incident_total - 1) % INCIDENTS] : NULL;
    if (active && !active->complete) {
        if (s->mono_ms - active->trigger_ms <= AFTER_MS && active->count < INCIDENT_ROWS) {
            active->rows[active->count++] = *s;
            active->reasons |= triggers;
            if (s->mono_ms - active->trigger_ms < AFTER_MS) return;
            active->complete = 1;
            return;
        }
        active->complete = 1;
    }
    if (!triggers) return;
    active = &h->incidents[h->incident_total++ % INCIDENTS];
    active->at = s->at;
    active->trigger_ms = s->mono_ms;
    active->reasons = triggers;
    active->count = active->complete = 0;
    uint64_t start = h->total > D2K_NETWORK_HISTORY ? h->total - D2K_NETWORK_HISTORY : 0;
    for (uint64_t i = start; i < h->total; ++i) {
        const network_sample *prev = &h->samples[i % D2K_NETWORK_HISTORY];
        if (prev->mono_ms > s->mono_ms || s->mono_ms - prev->mono_ms > BEFORE_MS) continue;
        if (active->count >= INCIDENT_ROWS - 1) break;
        active->rows[active->count++] = *prev;
    }
    active->rows[active->count++] = *s;
}

static void peak(int32_t *value, int64_t sample) {
    if (sample > *value) *value = sample > INT32_MAX ? INT32_MAX : (int32_t)sample;
}

static void record_minute(d2k_network_history *h, const network_sample *s,
                          const network_sample *prev, unsigned triggers) {
    uint64_t key = s->mono_ms / 60000;
    minute_sample *m = &h->minutes[(h->minute_total ? h->minute_total - 1 : 0) % MINUTES];
    if (!h->minute_total || m->mono_minute != key) {
        m = &h->minutes[h->minute_total++ % MINUTES];
        *m = (minute_sample){.mono_minute = key, .at = s->at, .backlog = -1, .ct_pct = -1,
            .verdict_us = -1, .queued = -1, .mem_kib = -1, .cpu = {-1,-1,-1,-1,-1}};
    }
    m->samples++;
    m->triggers |= triggers;
    for (unsigned i = 0; i < CPU_PROCESSES; ++i) peak(&m->cpu[i], s->cpu_pct[i]);
    peak(&m->backlog, s->backlog);
    if (s->ct_count >= 0 && s->ct_max > 0 && s->ct_count <= INT64_MAX / 100)
        peak(&m->ct_pct, 100 * s->ct_count / s->ct_max);
    if (s->datapath.header.pid > 0 && s->datapath.counters.verdict_max_us <= INT64_MAX)
        peak(&m->verdict_us, (int64_t)s->datapath.counters.verdict_max_us);
    const d2k_network_controller_message *c = &s->controller;
    if (c->header.pid <= 0) return;
    peak(&m->queued, c->queued);
    if (c->mem_available_kib <= INT32_MAX && (m->mem_kib < 0 || c->mem_available_kib < (uint32_t)m->mem_kib))
        m->mem_kib = (int32_t)c->mem_available_kib;
    if (prev && prev->controller.header.pid == c->header.pid && prev->controller.generation == c->generation &&
        c->counters.dns_failures >= prev->controller.counters.dns_failures) {
        uint64_t delta = c->counters.dns_failures - prev->controller.counters.dns_failures;
        m->dns_failures += delta > UINT64_MAX - m->dns_failures ? UINT64_MAX - m->dns_failures : delta;
    }
}

static int fresh(uint64_t sample, uint64_t now) {
    return sample <= now && now - sample <= 2 * D2K_NET_DIAG_INTERVAL_MS;
}

void d2k_network_history_sample(d2k_network_history *h, uint64_t now,
    const d2k_network_controller_message *controller, const d2k_network_datapath_message *datapath,
    const char *proc, const char *sys, const char *run) {
    if (!h || (h->total && (now <= h->last_ms || now - h->last_ms < D2K_NET_DIAG_INTERVAL_MS))) return;
    network_sample current;
    network_sample *sample = &current;
    *sample = (network_sample){.mono_ms = now, .at = (uint64_t)time(NULL)};
    if (controller->header.pid > 0 && fresh(controller->mono_ms, now)) sample->controller = *controller;
    if (datapath->header.pid > 0 && fresh(datapath->mono_ms, now)) sample->datapath = *datapath;
    sample_cpu(h, sample, proc, run);
    sample_queue(sample, proc);
    sample_conntrack(sample, proc);
    sample_wan(&sample->wan[0], proc, sys, 0);
    sample_wan(&sample->wan[1], proc, sys, 1);
    const network_sample *prev = h->total ? &h->samples[(h->total - 1) % D2K_NETWORK_HISTORY] : NULL;
    unsigned triggers = incident_signals(prev, sample);
    record_incident(h, sample, triggers);
    record_minute(h, sample, prev, triggers);
    h->samples[h->total++ % D2K_NETWORK_HISTORY] = current;
    h->last_ms = now;
}

static void signed_value(FILE *out, int64_t value) {
    if (value < 0) fputs("null", out);
    else fprintf(out, "%" PRId64, value);
}

static void write_wan(FILE *out, const wan_snapshot *w) {
    const int64_t values[] = {w->routes, w->ifindex, w->operstate, w->carrier,
        w->rx_errors, w->tx_errors, w->rx_dropped, w->tx_dropped};
    fputc('[', out);
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
        if (i) fputc(',', out);
        signed_value(out, values[i]);
    }
    fputc(']', out);
}

static void write_datapath(FILE *out, const network_sample *s, uint64_t previous_mono) {
    const d2k_network_datapath_message *d = &s->datapath;
    const d2k_network_datapath *c = &d->counters;
    if (d->header.pid <= 0) { fputs("null", out); return; }
    fprintf(out, "[%ld,%" PRIu64 ",%" PRIu64 ",%u,%u,%u,", d->header.pid, d->generation,
            d->mono_ms, d->queue, d->queue_limit, d->fail_open);
    signed_value(out, s->backlog); fputc(',', out);
    signed_value(out, s->drops); fputc(',', out);
    signed_value(out, s->user_drops); fputc(',', out);
    signed_value(out, s->netlink_drops);
    const uint64_t counts[] = {c->packets, c->enobufs, c->recv_errors, c->verdict_errors, c->kernel_errors,
        c->drop_verdicts, c->replacements, c->raw_send_errors, c->verdict_samples, c->verdict_no_timestamp,
        c->tcp_hold_timeouts, c->udp_hold_timeouts, c->tcp_prior_exchange_actions, c->udp_prior_exchange_actions,
        c->tcp_prior_exchange_packets, c->udp_prior_exchange_packets, c->hold_actions, c->plan_actions,
        c->udp_follow_actions, c->http_actions, c->userspace_verdict_samples, c->conntrack_queries,
        c->conntrack_query_errors, c->routed_flows, c->flow_table_refusals};
    for (size_t i = 0; i < sizeof(counts) / sizeof(counts[0]); i++) fprintf(out, ",%" PRIu64, counts[i]);
    fputc(',', out);
    /* A recently received message can appear in two adjacent collector rows. */
    if (d->mono_ms != previous_mono && c->verdict_max_us != UINT64_MAX)
        fprintf(out, "%" PRIu64, c->verdict_max_us);
    else fputs("null", out);
    fputc(',', out);
    if (d->mono_ms != previous_mono && c->userspace_verdict_max_us != UINT64_MAX)
        fprintf(out, "%" PRIu64, c->userspace_verdict_max_us);
    else fputs("null", out);
    fputc(',', out);
    signed_value(out, d->mono_ms != previous_mono ? (int64_t)c->loop_max_us : -1);
    fputc(',', out);
    signed_value(out, d->mono_ms != previous_mono && c->sweep_max_us ? (int64_t)c->sweep_max_us : -1);
    fputc(']', out);
}

static void write_controller(FILE *out, const d2k_network_controller_message *m) {
    if (m->header.pid <= 0) { fputs("null", out); return; }
    fprintf(out, "[%ld,%" PRIu64 ",%" PRIu64 ",%u,%u,%u,%u,", m->header.pid, m->generation,
            m->mono_ms, m->active, m->queued, m->workers, m->limit);
    signed_value(out, m->cpu_free_pct == UINT32_MAX ? -1 : (int64_t)m->cpu_free_pct);
    fputc(',', out);
    signed_value(out, m->mem_available_kib == UINT32_MAX ? -1 : (int64_t)m->mem_available_kib);
    const d2k_network_controller *c = &m->counters;
    const uint64_t counts[] = {c->measurements, c->measurement_restarts, c->probe_units, c->queue_expired,
        c->phase_deadlines, c->tcp_dial_deadlines, c->dns_checks, c->dns_failures, c->dns_local_failures,
        c->dns_bootstrap_failures, c->dns_config_failures, c->dns_config_max_ms};
    for (size_t i = 0; i < sizeof(counts) / sizeof(counts[0]); i++) fprintf(out, ",%" PRIu64, counts[i]);
    fputc(']', out);
}

static void write_sample(FILE *out, const network_sample *s, uint64_t *previous_mono) {
    fprintf(out, "[%" PRIu64 ",%" PRIu64 ",[", s->at, s->mono_ms);
    for (size_t j = 0; j < CPU_PROCESSES; j++) {
        if (j) fputc(',', out);
        signed_value(out, s->cpu_pct[j]);
    }
    const int64_t ct[] = {s->ct_count, s->ct_max, s->ct_drop, s->ct_early_drop, s->ct_insert_failed};
    fputs("],[", out);
    for (size_t j = 0; j < sizeof(ct) / sizeof(ct[0]); j++) {
        if (j) fputc(',', out);
        signed_value(out, ct[j]);
    }
    fputs("],", out); write_wan(out, &s->wan[0]);
    fputc(',', out); write_wan(out, &s->wan[1]);
    fputc(',', out); write_datapath(out, s, *previous_mono);
    *previous_mono = s->datapath.mono_ms;
    fputc(',', out); write_controller(out, &s->controller);
    fputc(']', out);
}

static void write_minutes(FILE *out, const d2k_network_history *h) {
    fputs(",\"minute_interval_ms\":60000,\"minute_fields\":[\"at\",\"mono_minute\",\"sample_count\","
          "\"triggers\",\"cpu_peak_pct\",\"queue_peak\",\"conntrack_peak_pct\",\"verdict_peak_us\","
          "\"measurements_queued_peak\",\"mem_available_min_kib\",\"observed_dns_failures\"],\"minutes\":[", out);
    uint64_t start = h->minute_total > MINUTES ? h->minute_total - MINUTES : 0;
    int comma = 0;
    for (uint64_t i = start; i < h->minute_total && !ferror(out); ++i) {
        const minute_sample *m = &h->minutes[i % MINUTES];
        if (h->last_ms / 60000 - m->mono_minute >= MINUTES) continue;
        if (comma++) fputc(',', out);
        fprintf(out, "[%" PRIu64 ",%" PRIu64 ",%u,%u,[", m->at, m->mono_minute, m->samples, m->triggers);
        for (size_t j = 0; j < CPU_PROCESSES; ++j) {
            if (j) fputc(',', out);
            signed_value(out, m->cpu[j]);
        }
        fputc(']', out);
        const int values[] = {m->backlog, m->ct_pct, m->verdict_us, m->queued, m->mem_kib};
        for (size_t j = 0; j < sizeof(values) / sizeof(values[0]); ++j) {
            fputc(',', out);
            signed_value(out, values[j]);
        }
        fprintf(out, ",%" PRIu64 "]", m->dns_failures);
    }
    fputc(']', out);
}

static void write_incidents(FILE *out, const d2k_network_history *h) {
    fprintf(out, ",\"incidents_overwritten\":%" PRIu64,
            h->incident_total > INCIDENTS ? h->incident_total - INCIDENTS : 0);
    fputs(",\"incident_signals\":[\"wan4_route_lost\",\"wan6_route_lost\",\"wan4_carrier_lost\","
          "\"wan6_carrier_lost\",\"queue_loss\",\"conntrack_loss\"],\"incidents\":[", out);
    uint64_t start = h->incident_total > INCIDENTS ? h->incident_total - INCIDENTS : 0;
    for (uint64_t i = start; i < h->incident_total && !ferror(out); ++i) {
        const incident *e = &h->incidents[i % INCIDENTS];
        if (i != start) fputc(',', out);
        fprintf(out, "{\"at\":%" PRIu64 ",\"trigger_ms\":%" PRIu64
                ",\"signals\":%u,\"complete\":%s,\"samples\":[",
                e->at, e->trigger_ms, e->reasons, e->complete ? "true" : "false");
        uint64_t previous_mono = UINT64_MAX;
        for (unsigned j = 0; j < e->count && !ferror(out); ++j) {
            if (j) fputc(',', out);
            write_sample(out, &e->rows[j], &previous_mono);
        }
        fputs("]}", out);
    }
    fputc(']', out);
}

void d2k_network_history_write(FILE *out, const d2k_network_history *h) {
    if (!h) { fputs("null", out); return; }
    uint64_t start = h->total > D2K_NETWORK_HISTORY ? h->total - D2K_NETWORK_HISTORY : 0;
    while (start < h->total && h->last_ms - h->samples[start % D2K_NETWORK_HISTORY].mono_ms >= 480000)
        ++start;
    fprintf(out, "{\"interval_ms\":%u,\"capacity\":%u,\"overwritten\":%" PRIu64 ",\"ring_bytes\":%zu,"
            "\"ram_reserved_bytes\":%zu,\"ram_budget_bytes\":%u,",
            D2K_NET_DIAG_INTERVAL_MS, D2K_NETWORK_HISTORY, start, sizeof(*h),
            d2k_network_history_bytes(), D2K_NETWORK_BUDGET);
    fputs("\"fields\":[\"at\",\"mono_ms\",\"cpu_pct_one_core\",\"conntrack\",\"wan4\",\"wan6\",\"nfqueue\",\"controller\"],"
          "\"cpu_fields\":[\"d2kc\",\"d2kd\",\"d2kpanel\",\"d2kdiag\",\"d2ktg\"],"
          "\"conntrack_fields\":[\"count\",\"max\",\"drop\",\"early_drop\",\"insert_failed\"],"
          "\"wan_fields\":[\"default_routes\",\"ifindex\",\"operstate\",\"carrier\",\"rx_errors\",\"tx_errors\",\"rx_dropped\",\"tx_dropped\"],"
          "\"wan_operstate_values\":[\"unknown\",\"notpresent\",\"down\",\"lowerlayerdown\",\"testing\",\"dormant\",\"up\"],"
          "\"nfqueue_fields\":[\"pid\",\"start_ticks\",\"mono_ms\",\"queue\",\"configured_limit\",\"fail_open\",\"backlog\","
          "\"kernel_drops\",\"kernel_user_drops\",\"netlink_socket_drops\",\"packets\",\"enobufs_notifications\","
          "\"recv_errors\",\"verdict_send_errors\",\"kernel_netlink_errors\",\"drop_verdicts_sent\",\"replacement_verdicts_sent\","
          "\"raw_send_errors\",\"verdict_samples\",\"verdict_without_timestamp\",\"tcp_hold_timeout_packets\","
          "\"udp_hold_timeout_packets\",\"tcp_prior_exchange_actions\",\"udp_prior_exchange_actions\","
          "\"tcp_prior_exchange_packets_seen\",\"udp_prior_exchange_packets_seen\",\"hold_actions\",\"plan_actions\","
          "\"udp_follow_actions\",\"http_actions\",\"userspace_verdict_samples\",\"conntrack_queries\","
          "\"conntrack_query_errors\",\"routed_flows\",\"flow_table_refusals\",\"kernel_packet_to_verdict_max_us\","
          "\"userspace_read_to_verdict_max_us\",\"loop_gap_max_us\",\"flow_sweep_max_us\"],"
          "\"controller_fields\":[\"pid\",\"start_ticks\",\"mono_ms\",\"active\",\"queued\",\"workers_running\",\"measurement_limit\","
          "\"cpu_free_pct\",\"mem_available_kib\",\"classifier_workers_started\",\"classifier_restarts_same_task\",\"classifier_completed_probe_units\","
          "\"queue_expired\",\"phase_deadlines\",\"tcp_dial_deadline_results\",\"encrypted_dns_checks_started\","
          "\"encrypted_dns_checks_without_valid_reply\",\"encrypted_dns_local_failures\","
          "\"dns_bootstrap_failures\",\"dns_config_failures\",\"dns_config_max_ms\"],"
          "\"samples\":[", out);
    uint64_t previous_mono = UINT64_MAX;
    for (uint64_t i = start; i < h->total && !ferror(out); i++) {
        const network_sample *s = &h->samples[i % D2K_NETWORK_HISTORY];
        if (i != start) fputc(',', out);
        write_sample(out, s, &previous_mono);
    }
    fputc(']', out);
    write_minutes(out, h);
    write_incidents(out, h);
    fputc('}', out);
}

int d2k_network_memory_ready(const char *proc) {
    FILE *in = open_path(proc, "meminfo");
    if (!in) return 0;
    char line[128];
    unsigned long available;
    unsigned long free_kib = 0;
    while (fgets(line, sizeof(line), in)) {
        if (sscanf(line, "MemAvailable: %lu kB", &available) == 1) {
            fclose(in);
            return available >= 12 * 1024;
        }
        (void)sscanf(line, "MemFree: %lu kB", &free_kib);
    }
    fclose(in);
    return free_kib >= 12 * 1024;
}

uint64_t d2k_network_session(const char *dir) {
#ifdef __linux__
    char path[512];
    struct stat st;
    if (d2k_diag_dir(dir, 0) || d2k_diag_path(path, sizeof(path), dir, D2K_DIAG_NETWORK_FLAG) ||
        lstat(path, &st) || !S_ISREG(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 077))
        return 0;
    /* Identity of the enable marker, even if a disable/enable pair happens
     * between timer ticks and the filesystem reuses the inode. */
    uint64_t stamp = (uint64_t)st.st_ctim.tv_sec * 1000000000 + (uint64_t)st.st_ctim.tv_nsec;
    return (stamp ^ (uint64_t)st.st_ino) | (UINT64_C(1) << 63);
#else
    (void)dir;
    return 0;
#endif
}

int d2k_network_open(const char *dir, const char *name, int create) {
#ifdef __linux__
    char path[512];
    struct statfs fs;
    if (d2k_diag_dir(dir, 0) || statfs(dir, &fs) || fs.f_type != 0x01021994 /* tmpfs */ ||
        d2k_diag_path(path, sizeof(path), dir, name)) return -1;
    int fd = open(path, (create ? O_CREAT | O_RDWR : O_RDONLY) |
                  O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600);
    if (fd < 0) return -1;
    struct stat st;
    if (!fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_uid == geteuid() &&
        !(st.st_mode & 077) && !fstatfs(fd, &fs) && fs.f_type == 0x01021994) /* tmpfs */
        return fd;
    close(fd);
#else
    (void)dir; (void)name; (void)create;
#endif
    return -1;
}

/* The caller holds the state lock. Allocate backing before mmap so a full
 * tmpfs returns an error here instead of raising SIGBUS during sampling. */
d2k_network_history *d2k_network_history_map(int fd, uint64_t session) {
#ifdef __linux__
    if (ftruncate(fd, 0)) return NULL;
    if (!fallocate(fd, 0, 0, sizeof(d2k_network_history))) {
        void *ptr = mmap(NULL, sizeof(d2k_network_history), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (ptr != MAP_FAILED) {
            d2k_network_history *h = ptr;
            h->session = session;
            return h;
        }
    }
    (void)ftruncate(fd, 0);
#else
    (void)fd; (void)session;
#endif
    return NULL;
}

void d2k_network_history_unmap(d2k_network_history *h, int fd) {
    if (h) munmap(h, sizeof(*h));
    (void)ftruncate(fd, 0);
}

d2k_network_history *d2k_network_history_copy(int fd, uint64_t session) {
    struct stat st;
    uint64_t stored_session;
    if (fstat(fd, &st) || st.st_size != sizeof(d2k_network_history) ||
        pread(fd, &stored_session, sizeof(stored_session), 0) != sizeof(stored_session) ||
        stored_session != session) return NULL;
    d2k_network_history *h = malloc(sizeof(*h));
    if (!h) return NULL;
    size_t off = 0;
    while (off < sizeof(*h)) {
        ssize_t n = pread(fd, (char *)h + off, sizeof(*h) - off, (off_t)off);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { free(h); return NULL; }
        off += (size_t)n;
    }
    if (h->session != session || !h->total) { free(h); return NULL; }
    return h;
}
