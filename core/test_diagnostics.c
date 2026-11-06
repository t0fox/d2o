#define _DARWIN_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include "include/d2k_diagnostics.h"
#include "../runtime/d2k_diagnostics_files.h"
static void put(const char *dir,const char *name,const char *text) {
    char p[512];snprintf(p,sizeof p,"%s/%s",dir,name);FILE *f=fopen(p,"w");assert(f);fputs(text,f);assert(!fclose(f));
}
static char *report(d2k_diag *d) {
    FILE *f=tmpfile();assert(f);assert(!d2k_diag_write(d,f));long n=ftell(f);
    assert(n>0 && (unsigned long)n<D2K_DIAG_REPORT_MAX);rewind(f);char *s=malloc((size_t)n+1);assert(s);
    assert(fread(s,1,(size_t)n,f)==(size_t)n);s[n]=0;fclose(f);return s;
}
static int history_epoch_present(const char *json,unsigned epoch) {
    char suffix[40];snprintf(suffix,sizeof suffix,",2,3,1,1,%u]",epoch);
    const char *history=strstr(json,"\"memory_history\":");
    const char *rows=history?strstr(history,"\"samples\":["):NULL;
    return rows&&strstr(rows,suffix)!=NULL;
}
int main(void) {
    d2k_diag *d=NULL;
    d2k_diag_counts c={0};
    c.task_states[0]=62;c.task_states[10]=2;c.snapshot_bytes=4096;c.catalog_bytes=8192;
    c.tasks=2;c.http_bytes=16384;c.tracked_tcp_bytes=512;c.tracked_quic_bytes=1024;
    c.tracked_tls_bytes=1536;
    c.workers_running=2;c.workers_live=3;c.workers_result_pending=1;c.workers_join_pending=1;
    c.worker_oldest_age_ms=600;c.last_measurement_age_ms=1250;strcpy(c.worker_oldest_type,"TCP");
    c.workers_started=12;c.workers_joined=9;c.worker_start_failures=1;c.worker_join_failures=2;
    c.http_failures=3;c.http_bytes=16384;c.http_records_bytes=4096;c.http_queue_bytes=1024;
    c.http_failure_bytes=2048;c.http_failure_limit_hits=4;c.http_failure_record_limit_hits=2;
    c.http_records_limit_bytes=262144;c.http_queue_limit_bytes=32768;
    c.http_failure_limit_bytes=65536;c.http_failure_record_limit_bytes=8192;
    c.http_record_limit_hits=1;c.http_queue_limit_hits=5;c.measurement_limit=1;c.measurement_slots=64;
    c.resources_valid=c.cpu_valid=c.mem_valid=c.conntrack_valid=1;c.cpu_free_pct=75;
    c.mem_avail_kb=8192;c.mem_total_kb=65536;c.mem_reserve_kb=32768;
    c.conntrack_count=100;c.conntrack_max=1000;c.limiter_mask=D2K_DIAG_LIMIT_MEMORY|D2K_DIAG_LIMIT_CONNTRACK;
    c.grow_pending=1;c.resource_sequence=14;c.limit_sequence=12;c.limit_age_ms=3000;
    d2k_diag_event e={.target="a\".example",.protocol="quic",.outcome="failed",.reason="local\nerror"};
    char *all=NULL;
    assert(d2k_diag_bytes(d)==0);
    d2k_diag_record(d,&e);
    for(int round=0;round<10;round++) {
        d=d2k_diag_new(); assert(d && d2k_diag_bytes(d)<=256*1024);
        for(int i=0;i<1000;i++) {e.id=(unsigned)i; d2k_diag_record(d,&e);}
        assert(d2k_diag_event_count(d)==64);
        for(int i=0;i<200;i++) d2k_diag_sample(d,(int64_t)i*60000,&c,"/nonexistent", "/nonexistent");
        assert(d2k_diag_sample_count(d)==120);
        d2k_diag_sample(d,199*60000+1,&c,"/nonexistent","/nonexistent");
        assert(d2k_diag_sample_count(d)==120);
        FILE *f=tmpfile(); assert(f); assert(d2k_diag_write(d,f)==0);
        long size=ftell(f); assert(size>0 && (unsigned long)size<D2K_DIAG_REPORT_MAX); rewind(f);
        char *buf=malloc((size_t)size+1); assert(buf);
        assert(fread(buf,1,(size_t)size,f)==(size_t)size);buf[size]=0;
        assert(strstr(buf,"a\\\".example")); assert(strstr(buf,"local\\nerror"));
        assert(strstr(buf,"\"rss_kib\":null"));
        assert(strstr(buf,"\"catalog_bytes\":8192"));
        assert(strstr(buf,"\"workers_running\":2"));
        assert(strstr(buf,"\"workers_live\":3"));
        assert(strstr(buf,"\"worker_oldest_type\":\"TCP\""));
        assert(strstr(buf,"\"worker_join_failures\":2"));
        assert(strstr(buf,"\"http_failure_limit_hits\":4"));
        assert(strstr(buf,"\"http_failure_bytes\":2048"));
        assert(strstr(buf,"\"http_storage_limits\":{\"records_bytes\":262144,\"queue_bytes\":32768,\"failures_bytes\":65536,\"failure_record_bytes\":8192}"));
        assert(strstr(buf,"\"task_states\":{\"free\":62"));
        assert(strstr(buf,"\"limit_reason\":[\"memory\",\"conntrack\"]"));
        assert(!strstr(buf,"\"id\":935,")); assert(strstr(buf,"\"id\":936,"));
        free(buf);fclose(f);
        for(int i=0;i<40;i++){c.measurement_limit=(uint64_t)i+1;d2k_diag_record_limit(d,(int64_t)i*250,&c);}
        all=report(d);
        assert(strstr(all,"\"limit_transition_capacity\":32"));
        assert(strstr(all,"\"limit_transitions_overwritten\":8"));
        assert(strstr(all,"\"mono_ms\":2000,"));free(all);
        c.measurement_limit=1;
        char full[256];memset(full,'"',sizeof full-1);full[255]=0;
        e.target=full;e.reason=full;
        for(int i=0;i<100000;i++)d2k_diag_record(d,&e);
        if(round==0)for(int i=200;i<=1440;i++)
            d2k_diag_sample(d,(int64_t)i*60000,&c,"/nonexistent","/nonexistent");
        if(round==0)assert(d2k_diag_memory_history_count(d)==1440);
        assert(d2k_diag_sample_count(d)==120);
        f=tmpfile();assert(f);assert(!d2k_diag_write(d,f));long json_size=ftell(f);
        if(json_size>=0&&(unsigned long)json_size>=D2K_DIAG_REPORT_MAX)fprintf(stderr,"diagnostic JSON %ld exceeds %u bytes\n",json_size,(unsigned)D2K_DIAG_REPORT_MAX);
        assert(json_size>0&&(unsigned long)json_size<D2K_DIAG_REPORT_MAX);fclose(f);
        e.target="a\".example";e.reason="local\nerror";
        d2k_diag_free(d);d=NULL;
    }
    char dir[]="/tmp/d2k-diag-proc-XXXXXX",path[512];assert(mkdtemp(dir));
    snprintf(path,sizeof path,"%s/123",dir);assert(!mkdir(path,0700));
    put(dir,"d2k.pid","123\n");put(dir,"123/comm","d2kc\n");
    put(dir,"123/status","VmRSS: 1024 kB\nVmHWM: 2048 kB\nRssAnon: 512 kB\nThreads: 3\n");
    put(dir,"123/smaps","1000-2000 rw-p 00000000 00:00 0 [heap]\nSize: 16 kB\nRss: 8 kB\nPss: 6 kB\nAnonymous: 8 kB\nPrivate_Dirty: 8 kB\nSwap: 0 kB\n2000-3000 rw-p 00000000 00:00 0\nSize: 32 kB\nRss: 24 kB\nPss: 20 kB\nAnonymous: 24 kB\nPrivate_Dirty: 24 kB\nSwap: 1 kB\n3000-4000 r--p 00000000 00:00 1 /private/never-export-me\nSize: 4 kB\nRss: 4 kB\nPss: 4 kB\nAnonymous: 0 kB\nPrivate_Dirty: 0 kB\nSwap: 0 kB\n");
    put(dir,"meminfo","MemTotal: 65536 kB\nMemAvailable: 8192 kB\n");
    d=d2k_diag_new();assert(d);
    d2k_diag_memory_enable(0);assert(!d2k_diag_memory_acquire(D2K_DIAG_MEM_TLS13_SESSION,1536));
    d2k_diag_memory_enable(1);
    int tcp_tracked=d2k_diag_memory_acquire(D2K_DIAG_MEM_SCHED_TCP_WORKER_ARG,512);
    int quic_tracked=d2k_diag_memory_acquire(D2K_DIAG_MEM_QUIC_CONNECTION,1024);
    int tls_tracked=d2k_diag_memory_acquire(D2K_DIAG_MEM_TLS13_SESSION,1536);
    assert(tcp_tracked&&quic_tracked&&tls_tracked);d2k_diag_memory_counts(&c);
    assert(c.tracked_tcp_bytes==512&&c.tracked_quic_bytes==1024&&c.tracked_tls_bytes==1536);
    d2k_diag_madvise madvise={.successes=4,.failures=1,.requested_bytes=20480,
        .failed_requested_bytes=4096,.last_errno=ENOMEM,.errno_hist={{ENOMEM,1}}};
    d2k_diag_set_madvise(d,&madvise);
    {char bad[]={'b','a','d',(char)0xff,'n','a','m','e',0};
     d2k_diag_event invalid={.target=bad,.protocol="tcp",.outcome="failed"};d2k_diag_record(d,&invalid);}
    d2k_diag_sample(d,0,&c,dir,dir);
    put(dir,"123/status","VmRSS: 4096 kB\nVmHWM: 4096 kB\nVmSize: 8192 kB\nVmData: 4096 kB\nVmStk: 128 kB\nVmSwap: 0 kB\nRssAnon: 3072 kB\nThreads: 1\n");
    d2k_diag_sample(d,60000,&c,dir,dir);
    FILE *f=tmpfile();assert(f);assert(!d2k_diag_write(d,f));rewind(f);
    char json[16384];size_t n=fread(json,1,sizeof json-1,f);json[n]=0;
    assert(strstr(json,"\"rss_kib\":1024"));assert(strstr(json,"\"mem_available_kib\":8192"));
    assert(strstr(json,"bad\\ufffdname"));
    assert(strstr(json,"\"vm_data_kib\":4096"));assert(strstr(json,"\"vm_swap_kib\":0"));
    assert(strstr(json,"\"rss_anon_kib\""));assert(strstr(json,"\"anon_kib\":3072"));
    assert(strstr(json,"\"smaps_rollup_status\":\"unsupported\""));
    assert(strstr(json,"\"smaps_rollup_source\":\"unavailable\""));
    assert(strstr(json,"\"smaps_rollup_errno\":null"));
    assert(strstr(json,"\"smaps_rollup\":null"));
    assert(strstr(json,",4,null,null,3072,"));
    assert(strstr(json,"\"smaps_status\":\"not-read\""));
    assert(strstr(json,"\"smaps\":null"));
    fclose(f);
    /* Переполнение кольца не должно терять исходный снимок памяти. */
    for(int i=2;i<125;i++)d2k_diag_sample(d,(int64_t)i*60000,&c,dir,dir);
    all=report(d);const char *detail=strstr(all,"\"memory_details\"");assert(detail);
    assert(strstr(detail,"\"mono_ms\":0,\"rss_kib\":1024"));
    assert(strstr(detail,"\"mono_ms\":7440000,\"rss_kib\":4096"));free(all);
    /* OpenWrt without PROC_PAGE_MONITOR keeps status metrics; diagnostics never walks smaps. */
    put(dir,"123/smaps","1000-2000 rw-p 00000000 00:00 0\nSize: 16 kB\n");
    d2k_diag_sample(d,7500000,&c,dir,dir);all=report(d);
    detail=strstr(all,"\"latest\":");assert(detail && strstr(detail,"\"smaps\":null") &&
        strstr(detail,"\"smaps_status\":\"not-read\""));free(all);
    snprintf(path,sizeof path,"%s/123/smaps",dir);assert(!unlink(path));
    d2k_diag_sample(d,7560000,&c,dir,dir);all=report(d);detail=strstr(all,"\"latest\":");
    assert(detail&&strstr(detail,"\"smaps_status\":\"not-read\"")&&
        strstr(detail,"\"smaps_rollup_status\":\"unsupported\"")&&
        strstr(detail,"\"smaps_rollup_source\":\"unavailable\"")&&
        strstr(detail,"\"smaps_errno\":null")&&strstr(detail,"\"smaps_rollup_errno\":null"));free(all);
    all=report(d);assert(strstr(all,",7560,4096,4096,0,4,null,null,3072,8192,16384,4096,512,1024,1536,2,3,1,1,0]"));free(all);
    put(dir,"123/smaps_rollup","Rss: 120 kB\nPss: 100 kB\nAnonymous: 80 kB\nPrivate_Dirty: 64 kB\nSwap: 2 kB\n");
    put(dir,"123/smaps","1000-2000 rw-p 00000000 00:00 0 [heap]\nSize: 64 kB\nRss: 32 kB\nAnonymous: 32 kB\nPrivate_Dirty: 24 kB\n");
    /* Повторное использование PID новым процессом должно сбросить исходный снимок. */
    put(dir,"123/stat","123 (d2kc) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 12345 0\n");
    snprintf(path,sizeof path,"%s/123/fd",dir);assert(!mkdir(path,0700));put(dir,"123/fd/0","");put(dir,"123/fd/1","");
    d2k_diag_sample(d,7620000,&c,dir,dir);all=report(d);detail=strstr(all,"\"memory_details\"");
    assert(strstr(detail,"\"mono_ms\":7620000,\"rss_kib\":4096"));
    assert(strstr(detail,"\"start_ticks\":12345"));assert(strstr(detail,"\"fd_count\":2"));
    assert(strstr(detail,"\"smaps_rollup_status\":\"ok\""));
    assert(strstr(detail,"\"smaps_rollup_source\":\"smaps_rollup\""));
    assert(strstr(detail,"\"smaps_status\":\"not-read\""));
    assert(strstr(detail,"\"smaps\":null"));
    assert(strstr(detail,"\"private_dirty_kib\":64"));
    free(all);
    for(int i=128;i<=1440;i++){
        if(i==1440){c.catalog_bytes=9625;c.http_bytes=5529;}
        d2k_diag_sample(d,(int64_t)i*60000,&c,dir,dir);
    }
    assert(d2k_diag_memory_history_count(d)==1440);
    d2k_diag_record_write_error(d,"open-temp",EACCES);
    all=report(d);
    assert(strstr(all,"\"memory_history_capacity\":1440"));
    assert(strstr(all,"\"memory_history_overwritten\":1"));
    assert(strstr(all,"\"memory_history\":{\"capacity\":1440"));
    assert(strstr(all,"\"memory_tracking\":{\"enabled\":true"));
    assert(strstr(all,"\"catalog_bytes\",\"http_bytes\",\"snapshot_bytes\",\"tracked_tcp_bytes\",\"tracked_quic_bytes\",\"tracked_tls_bytes\""));
    assert(strstr(all,"\"d2kc_epoch\"]"));
    assert(strstr(all,",9625,5529,"));
    assert(strstr(all,"\"id\":\"tcp.worker_arg\",\"name\":\"TCP worker argument\",\"location\":\"core/sched.c:start_worker\",\"live_bytes\":512"));
    assert(strstr(all,"\"madvise\":{\"successes\":4,\"failures\":1,\"requested_bytes\":20480"));
    assert(strstr(all,"\"kind\":\"diagnostic-json-write-error\""));
    assert(strstr(all,"\"diagnostic_write_failures\":1"));
    const char *export_path=getenv("D2K_TEST_DIAG_JSON");
    if(export_path){FILE *out=fopen(export_path,"w");assert(out);
        assert(fwrite(all,1,strlen(all),out)==strlen(all));assert(!fclose(out));}
    free(all);
    {
        d2k_diag *pid_history=d2k_diag_new();assert(pid_history);
        put(dir,"d2k.pid","123\n");
        put(dir,"123/stat","123 (d2kc) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 12345 0\n");
        d2k_diag_sample(pid_history,0,&c,dir,dir);d2k_diag_sample(pid_history,60000,&c,dir,dir);
        snprintf(path,sizeof path,"%s/124",dir);assert(!mkdir(path,0700));
        put(dir,"124/comm","d2kc\n");put(dir,"124/status","VmRSS: 2048 kB\nRssAnon: 1024 kB\nThreads: 1\n");
        put(dir,"124/stat","124 (d2kc) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 23456 0\n");
        put(dir,"d2k.pid","124\n");d2k_diag_sample(pid_history,120000,&c,dir,dir);
        all=report(pid_history);
        assert(history_epoch_present(all,0)&&history_epoch_present(all,1));
        free(all);d2k_diag_free(pid_history);
        const char *pid_files[]={"124/comm","124/status","124/stat"};
        for(size_t i=0;i<sizeof pid_files/sizeof pid_files[0];i++){snprintf(path,sizeof path,"%s/%s",dir,pid_files[i]);assert(!unlink(path));}
        snprintf(path,sizeof path,"%s/124",dir);assert(!rmdir(path));
        put(dir,"d2k.pid","123\n");
    }
    d2k_diag *growth=d2k_diag_new();assert(growth);
    for(int i=0;i<10;i++){
        char status[160];snprintf(status,sizeof status,"VmRSS: %d kB\nRssAnon: %d kB\nThreads: 1\n",1024+i*220,768+i*180);
        put(dir,"123/status",status);d2k_diag_sample(growth,(int64_t)i*60000,&c,dir,dir);
    }
    all=report(growth);assert(strstr(all,"\"kind\":\"unattributed-rss-growth\""));
    assert(strstr(all,"\"rss_delta_kib\":1980"));assert(strstr(all,"\"accounted_delta_kib\":0"));free(all);d2k_diag_free(growth);
    d2k_diag *accounted_growth=d2k_diag_new();assert(accounted_growth);d2k_diag_counts accounted_counts=c;
    for(int i=0;i<10;i++){
        char status[160];snprintf(status,sizeof status,"VmRSS: %d kB\nRssAnon: %d kB\nThreads: 1\n",1024+i*220,768+i*180);
        accounted_counts.catalog_bytes=(uint64_t)i*22*1024;accounted_counts.http_bytes=(uint64_t)i*22*1024;
        accounted_counts.snapshot_bytes=(uint64_t)i*22*1024;put(dir,"123/status",status);
        d2k_diag_sample(accounted_growth,(int64_t)i*60000,&accounted_counts,dir,dir);
    }
    all=report(accounted_growth);assert(!strstr(all,"unattributed-rss-growth"));free(all);d2k_diag_free(accounted_growth);
    d2k_diag *uptime_wrap=d2k_diag_new();assert(uptime_wrap);
    int64_t mono_before=((int64_t)UINT32_MAX-30)*1000;
    int64_t mono_after=((int64_t)UINT32_MAX+30)*1000;
    d2k_diag_sample(uptime_wrap,mono_before,&c,"/nonexistent","/nonexistent");
    d2k_diag_sample(uptime_wrap,mono_after,&c,"/nonexistent","/nonexistent");
    all=report(uptime_wrap);
    char mono_base[64];snprintf(mono_base,sizeof mono_base,",%llu]",(unsigned long long)UINT32_MAX-30);
    char *time_base=strstr(all,"\"time_base\":[");assert(time_base&&strstr(time_base,mono_base));
    char *memory_rows=strstr(time_base,"\"samples\":[");assert(memory_rows&&strstr(memory_rows,"[0,60,"));
    free(all);d2k_diag_free(uptime_wrap);
    printf("размер кольца: %zu байт\n",d2k_diag_bytes(d));
    d2k_diag_memory_release(D2K_DIAG_MEM_SCHED_TCP_WORKER_ARG,512,tcp_tracked);
    d2k_diag_memory_release(D2K_DIAG_MEM_QUIC_CONNECTION,1024,quic_tracked);
    d2k_diag_memory_release(D2K_DIAG_MEM_TLS13_SESSION,1536,tls_tracked);
    d2k_diag_memory_enable(0);d2k_diag_free(d);
    const char *files[]={"d2k.pid","123/comm","123/status","123/smaps","123/smaps_rollup","123/stat","123/fd/0","123/fd/1","meminfo"};
    for(size_t i=0;i<sizeof files/sizeof files[0];i++){snprintf(path,sizeof path,"%s/%s",dir,files[i]);assert(!unlink(path));}
    snprintf(path,sizeof path,"%s/123/fd",dir);assert(!rmdir(path));
    snprintf(path,sizeof path,"%s/123",dir);assert(!rmdir(path));assert(!rmdir(dir));
    puts("ограниченный отчёт диагностики пройден"); return 0;
}
