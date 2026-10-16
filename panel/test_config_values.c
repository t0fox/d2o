#define _POSIX_C_SOURCE 200809L
#define main panel_main_for_config_test
#include "main.c"
#undef main
#include <assert.h>

static int parse(const char *text) {
    char path[] = "/tmp/d2k-config-XXXXXX";
    int fd = mkstemp(path); assert(fd >= 0);
    assert(write(fd, text, strlen(text)) == (ssize_t)strlen(text)); close(fd);
    char mode[32] = "observe", listen[128] = "", state[128] = "";
    char unknown[UNKNOWN_MAX][UNKNOWN_KEY_MAX]; size_t count = 0;
    int queue = 0, exists = 0;
    int rc = read_config(path, mode, sizeof mode, listen, sizeof listen,
                         state, sizeof state, &queue, 0, 0, 0, 0, unknown, &count, &exists);
    unlink(path); return rc;
}
int main(void) {
    assert(known_key("TG_MODE") && known_key("TG_DC_MAP_PATH"));
    assert(parse("SCHEMA='1'\nMODE='apply'\nSTATE_DIR='/opt/d2k/state'\nQUEUE_NUM=\"2000\"\nPANEL_LISTEN='0.0.0.0:8080'\n") == 0);
    assert(parse("SCHEMA=1\nMODE=apply\nSTATE_DIR=/opt/d2k/state\nQUEUE_NUM=2000\n") == 0);
    assert(parse("QUEUE_NUM=\n") == -1);
    assert(parse("SCHEMA=\n") == -1);
    assert(parse("QUEUE_NUM='2000\n") == -1);
    assert(parse("MODE=apply'\n") == -1);
    assert(parse("QUEUE_NUM=2000junk\n") == -1);
    assert(parse("QUEUE_NUM=999999999999999999999999\n") == -1);
    assert(parse("QUEUE_NUM=65536\n") == -1);
    assert(parse("QUEUE_NUM=0\n") == 0);
    assert(parse("SCHEMA=+1\n") == -1);
    assert(parse("QUEUE_NUM='+2000'\n") == -1);
    assert(parse("QUEUE_NUM=' 2000'\n") == -1);
    assert(parse("QUEUE_NUM=-0\n") == -1);
    assert(parse("MODE=apply # active mode\nQUEUE_NUM=2000\t# queue\nSCHEMA='1' # schema\n") == 0);
    assert(parse("MODE=\"apply\" # active mode\nSTATE_DIR='/opt/d2k/#state' # keep literal hash\n") == 0);
    assert(parse("STATE_DIR=/opt/d2k/state#backup\n") == 0);
    assert(parse("QUEUE_NUM=2000#not-a-comment\n") == -1);
    assert(parse("MODE='apply'#not-a-comment\n") == -1);
    assert(parse("QUEUE_NUM= # missing number\n") == -1);
    assert(parse("MODE='apply # unterminated quote\n") == -1);
    char value[] = "'/opt/d2k/#state' # comment";
    assert(normalize_shell_value(value) == 0);
    assert(strcmp(value, "/opt/d2k/#state") == 0);
    puts("panel config: quoted values and strict numbers PASS"); return 0;
}
