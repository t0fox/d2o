#define _DARWIN_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include "include/d2k_diagnostics.h"
static void put(const char *dir,const char *name,const char *text) {
    char p[512];snprintf(p,sizeof p,"%s/%s",dir,name);FILE *f=fopen(p,"w");assert(f);fputs(text,f);assert(!fclose(f));
}
static char *report(d2k_diag *d) {
    FILE *f=tmpfile();assert(f);assert(!d2k_diag_write(d,f));long n=ftell(f);
    assert(n>0 && n<256*1024);rewind(f);char *s=malloc((size_t)n+1);assert(s);
    assert(fread(s,1,(size_t)n,f)==(size_t)n);s[n]=0;fclose(f);return s;
}
int main(void) {
    d2k_diag *d=NULL;
    d2k_diag_counts c={0};
    d2k_diag_event e={.target="a\".example",.protocol="quic",.outcome="failed",.reason="local\nerror"};
    assert(d2k_diag_bytes(d)==0);
    d2k_diag_record(d,&e);
    for(int round=0;round<10;round++) {
        d=d2k_diag_new(); assert(d && d2k_diag_bytes(d)<=128*1024);
        for(int i=0;i<1000;i++) {e.id=(unsigned)i; d2k_diag_record(d,&e);}
        assert(d2k_diag_event_count(d)==64);
        for(int i=0;i<200;i++) d2k_diag_sample(d,(int64_t)i*60000,&c,"/nonexistent", "/nonexistent");
        assert(d2k_diag_sample_count(d)==120);
        d2k_diag_sample(d,199*60000+1,&c,"/nonexistent","/nonexistent");
        assert(d2k_diag_sample_count(d)==120);
        FILE *f=tmpfile(); assert(f); assert(d2k_diag_write(d,f)==0);
        long size=ftell(f); assert(size>0 && size<256*1024); rewind(f);
        char *buf=malloc((size_t)size+1); assert(buf);
        assert(fread(buf,1,(size_t)size,f)==(size_t)size);buf[size]=0;
        assert(strstr(buf,"a\\\".example")); assert(strstr(buf,"local\\nerror"));
        assert(strstr(buf,"\"rss_kib\":null"));
        assert(!strstr(buf,"\"id\":935,")); assert(strstr(buf,"\"id\":936,"));
        free(buf);fclose(f);
        char full[256];memset(full,'"',sizeof full-1);full[255]=0;
        e.target=full;e.reason=full;
        for(int i=0;i<100000;i++)d2k_diag_record(d,&e);
        f=tmpfile();assert(f);assert(!d2k_diag_write(d,f));assert(ftell(f)<256*1024);fclose(f);
        e.target="a\".example";e.reason="local\nerror";
        d2k_diag_free(d);d=NULL;
    }
    char dir[]="/tmp/d2k-diag-proc-XXXXXX",path[512];assert(mkdtemp(dir));
    snprintf(path,sizeof path,"%s/123",dir);assert(!mkdir(path,0700));
    put(dir,"d2k.pid","123\n");put(dir,"123/comm","d2kc\n");
    put(dir,"123/status","VmRSS: 1024 kB\nVmHWM: 2048 kB\nRssAnon: 512 kB\nThreads: 3\n");
    put(dir,"123/smaps","1000-2000 rw-p 00000000 00:00 0 [heap]\nSize: 16 kB\nRss: 8 kB\nAnonymous: 8 kB\nPrivate_Dirty: 8 kB\n2000-3000 rw-p 00000000 00:00 0\nSize: 32 kB\nRss: 24 kB\nAnonymous: 24 kB\nPrivate_Dirty: 24 kB\n3000-4000 r--p 00000000 00:00 1 /private/never-export-me\nSize: 4 kB\nRss: 4 kB\nAnonymous: 0 kB\nPrivate_Dirty: 0 kB\n");
    put(dir,"meminfo","MemTotal: 65536 kB\nMemAvailable: 8192 kB\n");
    d=d2k_diag_new();assert(d);d2k_diag_sample(d,0,&c,dir,dir);
    put(dir,"123/status","VmRSS: 4096 kB\nVmHWM: 4096 kB\nVmSize: 8192 kB\nVmData: 4096 kB\nVmStk: 128 kB\nVmSwap: 0 kB\nRssAnon: 3072 kB\nThreads: 1\n");
    d2k_diag_sample(d,60000,&c,dir,dir);
    FILE *f=tmpfile();assert(f);assert(!d2k_diag_write(d,f));rewind(f);
    char json[16384];size_t n=fread(json,1,sizeof json-1,f);json[n]=0;
    assert(strstr(json,"\"rss_kib\":1024"));assert(strstr(json,"\"mem_available_kib\":8192"));
    const char *export_path=getenv("D2K_TEST_DIAG_JSON");
    if(export_path){FILE *out=fopen(export_path,"w");assert(out);assert(fwrite(json,1,n,out)==n);assert(!fclose(out));}
    fclose(f);
    /* Переполнение кольца не должно терять исходный снимок памяти. */
    for(int i=2;i<125;i++)d2k_diag_sample(d,(int64_t)i*60000,&c,dir,dir);
    char *all=report(d);const char *detail=strstr(all,"\"memory_details\"");assert(detail);
    assert(strstr(detail,"\"mono_ms\":0,\"rss_kib\":1024"));
    assert(strstr(detail,"\"mono_ms\":7440000,\"rss_kib\":4096"));free(all);
    /* При отсутствии smaps или неполном файле значение неизвестно, а не равно нулю. */
    put(dir,"123/smaps","1000-2000 rw-p 00000000 00:00 0\nSize: 16 kB\n");
    d2k_diag_sample(d,7500000,&c,dir,dir);all=report(d);
    detail=strstr(all,"\"latest\":");assert(detail && strstr(detail,"\"smaps\":null"));free(all);
    /* Повторное использование PID новым процессом должно сбросить исходный снимок. */
    put(dir,"123/stat","123 (d2kc) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 12345 0\n");
    snprintf(path,sizeof path,"%s/123/fd",dir);assert(!mkdir(path,0700));put(dir,"123/fd/0","");put(dir,"123/fd/1","");
    d2k_diag_sample(d,7560000,&c,dir,dir);all=report(d);detail=strstr(all,"\"memory_details\"");
    assert(strstr(detail,"\"mono_ms\":7560000,\"rss_kib\":4096"));
    assert(strstr(detail,"\"start_ticks\":12345"));assert(strstr(detail,"\"fd_count\":2"));free(all);
    printf("размер кольца: %zu байт\n",d2k_diag_bytes(d));d2k_diag_free(d);
    const char *files[]={"d2k.pid","123/comm","123/status","123/smaps","123/stat","123/fd/0","123/fd/1","meminfo"};
    for(size_t i=0;i<sizeof files/sizeof files[0];i++){snprintf(path,sizeof path,"%s/%s",dir,files[i]);assert(!unlink(path));}
    snprintf(path,sizeof path,"%s/123/fd",dir);assert(!rmdir(path));
    snprintf(path,sizeof path,"%s/123",dir);assert(!rmdir(path));assert(!rmdir(dir));
    puts("ограниченный отчёт диагностики пройден"); return 0;
}
