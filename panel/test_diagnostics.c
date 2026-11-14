#define _DARWIN_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <sys/socket.h>
#include "server.c"
#include <assert.h>
#ifdef __linux__
static void test_network_export(void) {
 char dir[]="/dev/shm/d2k-network-panel-XXXXXX"; assert(mkdtemp(dir));
 d2k_panel_config cfg={.control_enabled=1,.diagnostics_dir=dir};
 int sv[2]; assert(socketpair(AF_UNIX,SOCK_STREAM,0,sv)==0);
 const char *good="POST / HTTP/1.1\r\nHost: localhost\r\nOrigin: http://localhost\r\n\r\n";
 char response[8192];
 assert(api_diagnostics(sv[0],&cfg,good,"POST","network-enable")==0);
 ssize_t n=read(sv[1],response,sizeof(response)-1); assert(n>0); response[n]=0;
 assert(strstr(response,"\"enabled\":false,\"telegram_enabled\":false,\"network_enabled\":true"));
 assert(api_diagnostics(sv[0],&cfg,good,"GET","network-report")==0);
 n=read(sv[1],response,sizeof(response)-1); assert(n>0); response[n]=0;
 assert(strstr(response,"503 Service Unavailable"));
 int state=d2k_network_open(dir,D2K_NETWORK_STATE,1);
 assert(state>=0 && !flock(state,LOCK_EX|LOCK_NB));
 d2k_network_history *history=d2k_network_history_map(state,d2k_network_session(dir)); assert(history);
 d2k_network_history_sample(history,1000,&(d2k_network_controller_message){0},
    &(d2k_network_datapath_message){0},"/nonexistent","/nonexistent","/nonexistent");
 assert(!flock(state,LOCK_UN));

 int other_export=d2k_network_open(dir,D2K_NETWORK_EXPORT_LOCK,1);
 assert(other_export>=0 && !flock(other_export,LOCK_EX|LOCK_NB));
 assert(api_diagnostics(sv[0],&cfg,good,"GET","network-download")==0);
 n=read(sv[1],response,sizeof(response)-1); assert(n>0); response[n]=0;
 assert(strstr(response,"503 Service Unavailable"));
 close(other_export);

 assert(api_diagnostics(sv[0],&cfg,good,"GET","network-download")==0);
 assert(!shutdown(sv[0],SHUT_WR));
 size_t used=0;
 while ((n=read(sv[1],response+used,sizeof(response)-1-used))>0) used+=(size_t)n;
 assert(n==0 && used<sizeof(response)-1); response[used]=0;
 assert(strstr(response,"200 OK") && strstr(response,"d2k-network-diagnostics.json"));
 assert(strstr(response,"\"incidents\":[]}") && strstr(response,"\"minutes\":[["));
 close(sv[0]); close(sv[1]);

 assert(socketpair(AF_UNIX,SOCK_STREAM,0,sv)==0);
 assert(!d2k_diag_toggle(dir,1));
 assert(api_diagnostics(sv[0],&cfg,good,"POST","network-disable")==0);
 n=read(sv[1],response,sizeof(response)-1); assert(n>0); response[n]=0;
 assert(strstr(response,"\"enabled\":true,\"telegram_enabled\":false,\"network_enabled\":false"));
 assert(d2k_diag_enabled(dir));
 assert(api_diagnostics(sv[0],&cfg,good,"GET","network-report")==0);
 n=read(sv[1],response,sizeof(response)-1); assert(n>0); response[n]=0;
 assert(strstr(response,"\r\n\r\nnull"));
 close(sv[0]); close(sv[1]);
 d2k_network_history_unmap(history,state); close(state);
 assert(!d2k_diag_toggle(dir,0));
 char path[512];
 assert(!d2k_diag_path(path,sizeof(path),dir,D2K_NETWORK_STATE) && !unlink(path));
 assert(!d2k_diag_path(path,sizeof(path),dir,D2K_NETWORK_EXPORT_LOCK) && !unlink(path));
 assert(!rmdir(dir));
}
#endif

int main(void) {
#ifdef __linux__
 test_network_export();
#endif
 char dir[]="/tmp/d2k-diag-panel-XXXXXX";assert(mkdtemp(dir));
 d2k_panel_config c={.control_enabled=1,.diagnostics_dir=dir};
 int sv[2];assert(socketpair(AF_UNIX,SOCK_STREAM,0,sv)==0);
 const char *good="POST / HTTP/1.1\r\nHost: localhost\r\nOrigin: http://localhost\r\n\r\n";
 assert(api_diagnostics(sv[0],&c,good,"POST","enable")==0);
 char buf[2048];ssize_t n=read(sv[1],buf,sizeof buf-1);assert(n>0);buf[n]=0;assert(strstr(buf,"200 OK"));assert(d2k_diag_enabled(dir));
 assert(api_diagnostics(sv[0],&c,good,"POST","telegram-enable")==0);
 n=read(sv[1],buf,sizeof buf-1);assert(n>0);buf[n]=0;assert(strstr(buf,"\"telegram_enabled\":true"));assert(d2k_diag_telegram_enabled(dir));
 char report[512];assert(!d2k_diag_path(report,sizeof report,dir,"report.json"));FILE *saved=fopen(report,"w");assert(saved);fputs("{}",saved);assert(!fclose(saved));
 assert(api_diagnostics(sv[0],&c,"POST / HTTP/1.1\r\nHost: localhost\r\n\r\n","POST","disable")==0);
 n=read(sv[1],buf,sizeof buf-1);assert(n>0);buf[n]=0;assert(strstr(buf,"403"));assert(d2k_diag_enabled(dir));
 assert(api_diagnostics(sv[0],&c,good,"POST","disable")==0);
 n=read(sv[1],buf,sizeof buf-1);assert(n>0);buf[n]=0;assert(strstr(buf,"\"enabled\":false,\"telegram_enabled\":true"));
 struct stat st;assert(!stat(report,&st));
 assert(api_diagnostics(sv[0],&c,good,"POST","telegram-disable")==0);
 n=read(sv[1],buf,sizeof buf-1);assert(n>0);buf[n]=0;assert(strstr(buf,"\"enabled\":false,\"telegram_enabled\":false"));
 assert(!d2k_diag_telegram_enabled(dir));assert(stat(report,&st)<0);
 close(sv[0]);close(sv[1]);rmdir(dir);puts("управление диагностикой панели прошло");
}
