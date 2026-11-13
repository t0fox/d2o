#define _DARWIN_C_SOURCE
static char diagnostic_test_dir[]="/tmp/d2k-diag-runtime-XXXXXX";
#define D2K_DIAG_DIR diagnostic_test_dir
#define main d2kc_test_main
#include "d2kc.c"
#undef main
#include <assert.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
typedef struct { char path[sizeof(((struct sockaddr_un *)0)->sun_path)];const char *json;int listener; } stats_fixture;
static void *serve_stats_fixture(void *data) {
    stats_fixture *fixture=data;int client=accept(fixture->listener,NULL,NULL);assert(client>=0);
    size_t length=strlen(fixture->json),sent=0;
    while(sent<length){ssize_t n=write(client,fixture->json+sent,length-sent);assert(n>0);sent+=(size_t)n;}
    close(client);close(fixture->listener);unlink(fixture->path);return NULL;
}
static int path_overflows(const char *dir,const char *name) {
    char out[2];volatile size_t cap=sizeof out;
    return d2k_diag_path(out,cap,dir,name);
}
int main(void) {
    assert(mkdtemp(diagnostic_test_dir));
    errno=0;assert(path_overflows(D2K_DIAG_DIR,"report.json")<0);
    assert(errno==ENAMETOOLONG);
    stats_fixture fixture={.json="{\"rss_kib\":2048,\"active_connections\":3}\n"};
    snprintf(fixture.path,sizeof fixture.path,"%s/stats.sock",D2K_DIAG_DIR);
    fixture.listener=socket(AF_UNIX,SOCK_STREAM,0);assert(fixture.listener>=0);
    struct sockaddr_un stats_address={0};stats_address.sun_family=AF_UNIX;
    memcpy(stats_address.sun_path,fixture.path,strlen(fixture.path)+1);
    assert(bind(fixture.listener,(struct sockaddr *)&stats_address,sizeof stats_address)==0);
    assert(listen(fixture.listener,1)==0);
    pthread_t stats_thread;assert(pthread_create(&stats_thread,NULL,serve_stats_fixture,&fixture)==0);
    telegram_stats_path=fixture.path;char stats_json[256];size_t stats_length=0;
    assert(telegram_stats_read(telegram_stats_path,stats_json,sizeof stats_json,&stats_length)==0);
    assert(pthread_join(stats_thread,NULL)==0);stats_json[stats_length]=0;
    assert(strstr(stats_json,"\"rss_kib\":2048"));
    d2k_catalog cat={0};d2k_sched *s=d2k_sched_new(&cat,-1,0);assert(s);
    d2k_diag_counts counts;
    d2k_sched_diagnostic_counts(s,&counts);
    assert(counts.tasks==0 && counts.task_states[0]==64);
    assert(counts.workers_running==0 && counts.workers_join_pending==0);
    assert(counts.workers_started==0 && counts.workers_joined==0);
    diagnostic_tick(s,1000);assert(!diagnostics);
    for(int i=0;i<10;i++) {
        int64_t now=2000+(int64_t)i*4000;
        assert(d2k_diag_toggle(D2K_DIAG_DIR,1)==0);
        diagnostic_tick(s,now);assert(diagnostics);
        char p[512];assert(!d2k_diag_path(p,sizeof p,D2K_DIAG_DIR,"report.json"));
        struct stat st;assert(!stat(p,&st));assert(st.st_size>0&&st.st_size<D2K_DIAG_REPORT_MAX);
        assert((st.st_mode&077)==0);
        assert(d2k_diag_sample_count(diagnostics)==1);
        diagnostic_tick(s,now+1000);assert(d2k_diag_sample_count(diagnostics)==1);
        assert(d2k_diag_toggle(D2K_DIAG_DIR,0)==0);
        assert(stat(p,&st)<0);
        /* Выгрузка может совпасть с выключением панели; следующий цикл удалит файл. */
        FILE *late=fopen(p,"w");assert(late);fputs("{}",late);assert(!fclose(late));
        diagnostic_tick(s,now+2000);assert(!diagnostics);
        assert(stat(p,&st)<0);
    }
    assert(d2k_diag_toggle(D2K_DIAG_DIR,1)==0);
    assert(d2k_diag_telegram_toggle(D2K_DIAG_DIR,1)==0);
    diagnostic_tick(s,41000);assert(diagnostics&&telegram_diagnostics);
    char report_path[512];assert(!d2k_diag_path(report_path,sizeof report_path,D2K_DIAG_DIR,"report.json"));
    struct stat combined;assert(!stat(report_path,&combined));
    assert(d2k_diag_toggle(D2K_DIAG_DIR,0)==0);
    assert(d2k_diag_telegram_enabled(D2K_DIAG_DIR));assert(!stat(report_path,&combined));
    diagnostic_tick(s,42000);assert(diagnostics&&telegram_diagnostics);
    FILE *f=fopen(report_path,"r");assert(f);assert(fseek(f,0,SEEK_END)==0);
    long report_size=ftell(f);assert(report_size>0);rewind(f);
    char *json=malloc((size_t)report_size+1);assert(json);
    size_t n=fread(json,1,(size_t)report_size,f);assert(n==(size_t)report_size);json[n]=0;fclose(f);
    assert(strstr(json,"\"enabled\":true,\"general_enabled\":false,\"telegram_enabled\":true"));
    free(json);
    assert(d2k_diag_telegram_toggle(D2K_DIAG_DIR,0)==0);
    diagnostic_tick(s,43000);assert(!diagnostics&&!telegram_diagnostics);assert(stat(report_path,&combined)<0);
    d2k_sched_free(s);d2k_catalog_free(&cat);assert(rmdir(D2K_DIAG_DIR)==0);
    puts("переключение, очистка и атомарная выгрузка диагностики пройдены");return 0;
}
