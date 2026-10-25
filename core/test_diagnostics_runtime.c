#define _DARWIN_C_SOURCE
static char diagnostic_test_dir[]="/tmp/d2k-diag-runtime-XXXXXX";
#define D2K_DIAG_DIR diagnostic_test_dir
#define main d2kc_test_main
#include "d2kc.c"
#undef main
#include <assert.h>
int main(void) {
    assert(mkdtemp(diagnostic_test_dir));
    d2k_catalog cat={0};d2k_sched *s=d2k_sched_new(&cat,-1,0);assert(s);
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
    d2k_sched_free(s);d2k_catalog_free(&cat);assert(rmdir(D2K_DIAG_DIR)==0);
    puts("переключение, очистка и атомарная выгрузка диагностики пройдены");return 0;
}
