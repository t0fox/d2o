#define _DARWIN_C_SOURCE
static char diagnostic_test_dir[]="/tmp/d2k-diag-runtime-XXXXXX";
#define D2K_DIAG_DIR diagnostic_test_dir
static char diagnostic_test_socket[108];
#define D2K_DIAG_INPUT diagnostic_test_socket
#define main d2kc_test_main
#include "d2kc.c"
#undef main
#include <assert.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
static int path_overflows(const char *dir,const char *name) {
    char out[2];volatile size_t cap=sizeof out;
    return d2k_diag_path(out,cap,dir,name);
}
int main(void) {
    assert(mkdtemp(diagnostic_test_dir));
    errno=0;assert(path_overflows(D2K_DIAG_DIR,"report.json")<0);
    assert(errno==ENAMETOOLONG);
    char *path = diagnostic_test_socket;
    assert(d2k_diag_path(path, sizeof(diagnostic_test_socket), D2K_DIAG_DIR, "input.sock") == 0);
    struct sockaddr_un address;
    assert(d2k_diag_address(&address, path) == 0);
    int receiver = socket(AF_UNIX, SOCK_DGRAM, 0);
    assert(receiver >= 0);
    assert(bind(receiver, (struct sockaddr *)&address, sizeof(address)) == 0);
    diagnostic_sender = d2k_diag_sender();
    diagnostic_pid = getpid();
    assert(diagnostic_sender >= 0);
    d2k_catalog cat = {0};
    d2k_sched *s = d2k_sched_new(&cat, -1, 0);
    assert(s);
    diagnostic_tick(s, 1000);
    d2k_diag_counts_message message;
    assert(recv(receiver, &message, sizeof(message), MSG_DONTWAIT) < 0);
    assert(d2k_diag_toggle(D2K_DIAG_DIR, 1) == 0);
    diagnostic_tick(s, 2000);
    assert(recv(receiver, &message, sizeof(message), MSG_DONTWAIT) == sizeof(message));
    assert(message.header.kind == D2K_DIAG_IPC_COUNTS);
    assert(message.counts.tasks == 0);
    /* Leave the receiver stalled until its bounded queue fills. */
    for (int i = 3; i <= 200; ++i) diagnostic_tick(s, 1000 * i);
    close(receiver);
    assert(unlink(path) == 0);
    diagnostic_tick(s, 201000);
    assert(d2k_diag_toggle(D2K_DIAG_DIR, 0) == 0);
    diagnostic_tick(s, 202000);
    assert(!diagnostic_enabled);
    close(diagnostic_sender);
    d2k_sched_free(s);
    d2k_catalog_free(&cat);
    assert(rmdir(D2K_DIAG_DIR) == 0);
    puts("diagnostic sender: bounded, nonblocking, optional");
    return 0;
}
