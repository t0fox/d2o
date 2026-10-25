#ifndef D2K_DIAGNOSTICS_FILES_H
#define D2K_DIAGNOSTICS_FILES_H
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#ifndef D2K_DIAG_DIR
#define D2K_DIAG_DIR "/tmp/d2k-diagnostics"
#endif
#define D2K_DIAG_REPORT_MAX (256u*1024u)
/* Временный закрытый каталог: запрещаем ссылки и доступ для других пользователей. */
static inline int d2k_diag_dir(const char *dir,int create) {
    struct stat st;
    if(create && mkdir(dir,0700)!=0 && errno!=EEXIST)return -1;
    if(lstat(dir,&st)!=0||!S_ISDIR(st.st_mode)||st.st_uid!=geteuid()||(st.st_mode&077))return -1;
    return 0;
}
static inline int d2k_diag_path(char *out,size_t n,const char *dir,const char *name) {
    int z=snprintf(out,n,"%s/%s",dir,name);return z<0||(size_t)z>=n?-1:0;
}
static inline int d2k_diag_enabled(const char *dir) {
    char p[512];struct stat st;
    return d2k_diag_dir(dir,0)==0 && d2k_diag_path(p,sizeof p,dir,"enabled")==0 &&
        lstat(p,&st)==0 && S_ISREG(st.st_mode) && st.st_uid==geteuid() && !(st.st_mode&077);
}
static inline int d2k_diag_toggle(const char *dir,int on) {
    char p[512];
    if(d2k_diag_dir(dir,1)||d2k_diag_path(p,sizeof p,dir,"enabled"))return -1;
    if(on) {
        if(d2k_diag_enabled(dir))return 0;
        int fd=open(p,O_WRONLY|O_CREAT|O_EXCL,0600);if(fd<0)return -1;
        return close(fd);
    }
    if(unlink(p)!=0&&errno!=ENOENT)return -1;
    if(d2k_diag_path(p,sizeof p,dir,"report.json"))return -1;
    if(unlink(p)!=0&&errno!=ENOENT)return -1;
    if(d2k_diag_path(p,sizeof p,dir,"report.new"))return -1;
    if(unlink(p)!=0&&errno!=ENOENT)return -1;
    return 0;
}
#endif
