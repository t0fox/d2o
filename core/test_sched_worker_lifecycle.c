/* Repeated scheduler worker creation and task cleanup without network I/O. */
#define _POSIX_C_SOURCE 200809L
#include "sched.c"
#include <assert.h>

static unsigned synthetic_calls;
static d2k_vres synthetic_tcp(const char *ip, uint16_t port,
    d2k_hello trigger, d2k_hello control, uint32_t mark, int repeats,
    uint32_t gap_us, uint32_t wait_ms, const volatile sig_atomic_t *stop) {
    (void)control; (void)mark; (void)repeats; (void)gap_us; (void)wait_ms; (void)stop;
    d2k_vres result = {0};
    if (!strcmp(ip, "127.0.0.1") && port == 443 && trigger.len == 1024 &&
        trigger.bytes[0] == 0x42 && trigger.bytes[1023] == 0x42)
        synthetic_calls++;
    result.verdict = D2K_V_INCONCLUSIVE;
    return result;
}

static long proc_kib(const char *key) {
#if defined(__linux__)
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return -1;
    char line[256], name[64];
    long value;
    while (fgets(line, sizeof line, f)) {
        if (sscanf(line, "%63[^:]: %ld kB", name, &value) == 2 &&
            strcmp(name, key) == 0) {
            fclose(f);
            return value;
        }
    }
    fclose(f);
#else
    (void)key;
#endif
    return -1;
}

int main(void) {
    enum { CYCLES = 1500, MEMORY_GROWTH_LIMIT_KIB = 5 * 1024 };
    d2k_catalog catalog = {0};
    d2k_sched *sched = d2k_sched_new(&catalog, -1, 0);
    assert(sched);
    d2k_sched_tcp_hook = synthetic_tcp;

    long rss_before = proc_kib("VmRSS");
    long data_before = proc_kib("VmData");
    long rss_warm = -1, data_warm = -1;
    for (unsigned i = 0; i < CYCLES; i++) {
        task *t = &sched->tasks[i % SCHED_MAX_TASKS];
        assert(t->state == T_FREE && !t->th_live);
        snprintf(t->name, sizeof t->name, "worker-%u.example", i);
        strcpy(t->ip, "127.0.0.1"); t->port = 443; t->family = 4; t->transport = 6;
        memset(t->trig, 0x42, 1024); t->trig_len = 1024;
        t->skip_volume_once = 1; t->state = T_ASKING;
        assert(start_worker(sched, t, JOB_CLASSIFY) == 0);
        join_worker(t);
        assert(!t->th_live && !t->worker_owner && t->res_ready);
        task_reset(sched, t);
        if (i + 1 == SCHED_MAX_TASKS) {
            rss_warm = proc_kib("VmRSS");
            data_warm = proc_kib("VmData");
        }
    }

    d2k_diag_counts counts;
    d2k_sched_diagnostic_counts(sched, &counts);
    assert(counts.tasks == 0 && counts.task_states[T_FREE] == SCHED_MAX_TASKS);
    assert(counts.workers_running == 0 && counts.workers_join_pending == 0);
    assert(counts.workers_started == CYCLES && counts.workers_joined == CYCLES);
    assert(counts.worker_start_failures == 0);
    assert(synthetic_calls == CYCLES);

    long rss_after = proc_kib("VmRSS");
    long data_after = proc_kib("VmData");
    printf("1500 mock TCP measurements: VmRSS %ld -> %ld -> %ld KiB, "
           "VmData %ld -> %ld -> %ld KiB (start/warm/end)\n",
           rss_before, rss_warm, rss_after, data_before, data_warm, data_after);
    if (rss_warm >= 0 && rss_after >= 0)
        assert(rss_after <= rss_warm + MEMORY_GROWTH_LIMIT_KIB);
    if (data_warm >= 0 && data_after >= 0)
        assert(data_after <= data_warm + MEMORY_GROWTH_LIMIT_KIB);

    d2k_sched_free(sched);
    d2k_catalog_free(&catalog);
    puts("scheduler TCP worker lifecycle: 1500 mock measurements passed");
    return 0;
}
