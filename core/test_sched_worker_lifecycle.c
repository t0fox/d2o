/* Repeated scheduler worker creation and task cleanup without network I/O. */
#define _GNU_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <pthread.h>
#if defined(__linux__)
static unsigned madvise_calls;
static size_t madvise_bytes;
static int madvise_errno_next;
static int test_madvise(void *addr,size_t length,int advice);
#define madvise test_madvise
#endif
static unsigned fail_next_join;
static int test_pthread_join(pthread_t thread,void **retval);
static int (*native_pthread_join)(pthread_t,void **)=pthread_join;
#define pthread_join test_pthread_join
#include "sched.c"
#include <assert.h>
#if defined(__has_feature)
# if __has_feature(address_sanitizer)
#  define D2K_TEST_WITH_ASAN 1
# endif
#endif
#if defined(__SANITIZE_ADDRESS__)
# define D2K_TEST_WITH_ASAN 1
#endif

static int test_pthread_join(pthread_t thread,void **retval) {
    if(fail_next_join) { fail_next_join=0;return EDEADLK; }
    return native_pthread_join(thread,retval);
}
static unsigned synthetic_calls;
typedef struct { unsigned calls; d2k_diag_counts last; int64_t last_ms; } limit_capture;
static void capture_limit(void *ctx,int64_t now,const d2k_diag_counts *counts) {
    limit_capture *capture=ctx;capture->calls++;capture->last=*counts;capture->last_ms=now;
}
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
    limit_capture limits={0};
    d2k_sched_limit_diagnostics(sched,capture_limit,&limits);
    sched->meas_limit=SCHED_MAX_TASKS;sched->limiter=MEAS_LIM_MEM;sched->now_ms=1000;
    measure_limit_update(sched,0);
    assert(limits.calls==1&&limits.last.measurement_limit==SCHED_DEFAULT_ACTIVE_MEASUREMENTS);
    assert(limits.last_ms==1000&&!limits.last.resources_valid);
    sched->limiter=MEAS_LIM_SLOTS;sched->now_ms=1010;measure_limit_update(sched,0);
    assert(limits.calls==2&&limits.last_ms==1010);

    /* Simulate a pthread_join failure without passing a self/fake handle
       through the ASan pthread interceptor. */
    task *probe=&sched->tasks[0];
    const task_job jobs[]={JOB_CLASSIFY,JOB_CLASSIFY,JOB_VERIFY};
    const uint8_t transports[]={6,17,6};
    const char *types[]={"TCP","QUIC","VERIFY"};
    for(size_t i=0;i<3;i++) {
        probe->th_live=1;probe->worker_owner=sched;
        probe->worker_started_ms=sched_mono_ms()-9000;probe->worker_executing=1;
        probe->job=jobs[i];probe->transport=transports[i];probe->res_ready=0;
        d2k_diag_counts failed_join;
        d2k_sched_diagnostic_counts(sched,&failed_join);
        assert(failed_join.workers_live==1&&failed_join.workers_running==1);
        assert(failed_join.workers_result_pending==1&&failed_join.worker_oldest_age_ms>=9000);
        assert(!strcmp(failed_join.worker_oldest_type,types[i]));
        fail_next_join=1;
        assert(join_worker(probe)!=0&&probe->th_live&&probe->worker_owner==sched);
    }
    assert(sched->workers_joined==0&&sched->worker_join_failures==3);
    probe->th_live=0;probe->worker_owner=NULL;probe->worker_executing=0;
    probe->worker_started_ms=-1;probe->stop=0;

    int diagnostic_memory = getenv("D2K_TEST_DIAG_MEMORY") != NULL;
    d2k_diag_memory_enable(1);
#if defined(__linux__)
    task *memory_reset=&sched->tasks[SCHED_MAX_TASKS-1];
    task_reset(sched,memory_reset);
    assert(madvise_calls==1 && madvise_bytes>0);
    madvise_errno_next=ENOMEM;
    task_reset(sched,memory_reset);
    d2k_diag_madvise madvise_counts;
    d2k_sched_diagnostic_madvise(sched,&madvise_counts);
    assert(madvise_calls==2 && madvise_counts.successes==1 &&
           madvise_counts.failures==1 &&
           madvise_counts.requested_bytes==2*madvise_bytes &&
           madvise_counts.failed_requested_bytes==madvise_bytes &&
           madvise_counts.last_errno==ENOMEM &&
           madvise_counts.errno_hist[0].error==ENOMEM &&
           madvise_counts.errno_hist[0].count==1);
    d2k_sched_diagnostic_madvise_reset(sched);
    d2k_sched_diagnostic_madvise(sched,&madvise_counts);
    assert(madvise_counts.successes==0 && madvise_counts.failures==0 &&
           madvise_counts.requested_bytes==0 && madvise_counts.last_errno==0);
#endif
    d2k_diag_memory_enable(diagnostic_memory);
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
    assert(counts.workers_running == 0 && counts.workers_live == 0 &&
           counts.workers_result_pending == 0 && counts.workers_join_pending == 0);
    assert(counts.workers_started == CYCLES && counts.workers_joined == CYCLES);
    assert(counts.worker_start_failures == 0 && counts.worker_join_failures == 3);
    assert(counts.last_measurement_age_ms >= 0);
    assert(synthetic_calls == CYCLES);
    d2k_diag_mem_site memory_sites[D2K_DIAG_MEMORY_SITE_COUNT];
    d2k_diag_memory_snapshot(memory_sites);
    assert(memory_sites[D2K_DIAG_MEM_SCHED_TCP_WORKER_ARG].live_objects==0);
    assert(memory_sites[D2K_DIAG_MEM_SCHED_TCP_WORKER_ARG].created==
           (diagnostic_memory?CYCLES:0));
    assert(memory_sites[D2K_DIAG_MEM_SCHED_TCP_WORKER_ARG].destroyed==
           (diagnostic_memory?CYCLES:0));

    long rss_after = proc_kib("VmRSS");
    long data_after = proc_kib("VmData");
    printf("1500 mock TCP measurements: VmRSS %ld -> %ld -> %ld KiB, "
           "VmData %ld -> %ld -> %ld KiB (start/warm/end)\n",
           rss_before, rss_warm, rss_after, data_before, data_warm, data_after);
#if !defined(D2K_TEST_WITH_ASAN)
    if (rss_warm >= 0 && rss_after >= 0)
        assert(rss_after <= rss_warm + MEMORY_GROWTH_LIMIT_KIB);
    if (data_warm >= 0 && data_after >= 0)
        assert(data_after <= data_warm + MEMORY_GROWTH_LIMIT_KIB);
#else
    /* ASan quarantines joined pthread stacks, so process RSS is allocator
       retention rather than live worker ownership. Leak and memory-safety
       instrumentation remains enabled for all 1500 cycles. */
    puts("ASan active: RSS delta omitted because joined thread stacks are quarantined");
#endif

    d2k_sched_free(sched);
    d2k_catalog_free(&catalog);
    puts("scheduler TCP worker lifecycle: 1500 mock measurements passed");
    return 0;
}
#if defined(__linux__)
static int test_madvise(void *addr,size_t length,int advice) {
    (void)addr;assert(length>0&&advice==MADV_DONTNEED);
    madvise_calls++;madvise_bytes=length;
    if(madvise_errno_next){int e=madvise_errno_next;madvise_errno_next=0;errno=e;return -1;}
    return 0;
}
#endif
