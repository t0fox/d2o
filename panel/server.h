#ifndef D2K_PANEL_SERVER_H
#define D2K_PANEL_SERVER_H

#include <stddef.h>

typedef struct {
    const char *live_path;
    const char *asset_dir;
    const char *version;
    const char *commit;
    const char *built;
    const char *mode;
    const char *panel_listen;
    const char *config_path;
    const char *state_dir;
    const char *state_dir_note;
    const char *service_path;
    const char *update_state_path; /* state/update.json, written by d2k-update.sh */
    const char *updater_path;      /* d2k-update.sh: absent means no auto-update */
    const char *engine_pid_path;
    const char *controller_pid_path;
    const char *telegram_pid_path;
    const char *telegram_status_path;
    const char *telegram_stats_path;
    const char *const *unknown_keys;
    size_t unknown_key_count;
    long long started_epoch;
    int queue_num;
    int config_exists;
    int dirty;
    int control_enabled;
    int listener_fd;
} d2k_panel_config;

/* Reap the bounded background service command without blocking HTTP. */
void d2k_panel_control_tick(void);

/* Serve one bounded HTTP/1.1 request on an already accepted socket. */
int d2k_panel_handle_fd(int fd, const d2k_panel_config *cfg);

/* Install process-wide handling so a disconnected HTTP client cannot kill the server. */
int d2k_panel_ignore_sigpipe(void);

#endif
