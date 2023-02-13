#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <limits.h>
#include <errno.h>
#include <libgen.h>

#include <uv.h>

#include "utlist.h"

#include "forever.h"
#include "process.h"
#include "logrotate.h"
#include "logpipe.h"
#include "config.h"

#define DEFAULT_CFG_NAME "forever.toml"
#define DEFAULT_LOG_NAME "forever.log"

static char forever_name[NAME_MAX] = {'\0'};
static char forever_dir[PATH_MAX] = {'\0'};

static char cfg_path[PATH_MAX] = {'\0'};
static char pid_path[PATH_MAX] = {'\0'};
static char log_path[PATH_MAX] = {'\0'};
static int daemonize = 0;

static ForeverProcess_t *cur_process_list = NULL;
static uv_timer_t mem_check_timer;

static void make_daemon() {
    pid_t pid;

    pid = fork();
    if (pid < 0)
        exit(EXIT_FAILURE);
    if (pid > 0)
        exit(EXIT_SUCCESS);
    if (setsid() < 0)
        exit(EXIT_FAILURE);

    pid = fork();

    if (pid < 0)
        exit(EXIT_FAILURE);
    if (pid > 0)
        exit(EXIT_SUCCESS);

    umask(0);
    if (chdir("/") < 0) {
        mfprintf(stderr, "ERROR: chdir(/) failed %s", strerror(errno));
    }

    int  fd = open("/dev/null", O_RDWR);
    if (fd < 0) {
        exit(EXIT_FAILURE);
    }

    dup2(fd, STDIN_FILENO);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    close(fd);
}


// http://stackoverflow.com/questions/669438/how-to-get-memory-usage-at-run-time-in-c
static size_t get_rss_by_pid(pid_t pid) {
    long rss = 0L;
    FILE* fp = NULL;
    char path[1024] = {'\0'};
    sprintf(path, "/proc/%d/statm", pid);
    if ((fp = fopen(path, "r")) == NULL)
        return (size_t)0L;      /* Can't open? */
    if (fscanf( fp, "%*s%ld", &rss ) != 1) {
        fclose(fp);
        return (size_t)0L;      /* Can't read? */
    }
    fclose(fp);
    return (size_t)rss * (size_t)sysconf( _SC_PAGESIZE);
}

static void check_mem(uv_timer_t *handle) {
    ForeverProcess_t *process;
    DL_FOREACH(cur_process_list, process) {
        if (process->uv_process && process->maxmem) {
            size_t cmem = get_rss_by_pid(process->uv_process->pid);
            if (cmem > process->maxmem) {
                mfprintf(stderr, "ERROR: %s reach max mem limit, cur:%zu, max:%zu", process->name, cmem, process->maxmem);
                ForeverProcess_Restart(process);
            }
        }
    }
}

static void cleanup(int signal) {
    ForeverProcess_t *process;
    DL_FOREACH(cur_process_list, process) {
        ForeverProcess_Stop(process);
    }
    exit(0);
}

static char *safe_null(char *s) {
    static char *n = "";
    if (s == NULL) {
        return n;
    }
    return s;
}

static void reload(int signal) {
    ForeverProcess_t *cur_process;
    ForeverProcess_t *new_process;
    ForeverProcess_t *tmp;
    ForeverProcess_t *new_process_list = NULL;
    ForeverProcess_t *hard_reload_list = NULL;

    ForeverConfig_t *config = ParseConfig(cfg_path);
    if (!config) {
        return;
    }

    new_process_list = config->process_list;
    LogRotate_SetConfig(config->rotate_config);

    switch (signal) {
        case SIGUSR1:
            mfprintf(stdout, "INFO: soft reload");
            break;
        case SIGUSR2:
            mfprintf(stdout, "INFO: hard reload");
            break;
        default:
            return;
    }

    DL_FOREACH_SAFE(cur_process_list, cur_process, tmp) {
        new_process = ProcessList_FindByName(new_process_list, cur_process->name);
        if (!new_process) {
            mfprintf(stdout, "INFO: remove and stop %s", cur_process->name);
            DL_DELETE(cur_process_list, cur_process);
            ForeverProcess_Free(cur_process);
        } else {
            int need_hard_reload = 0;
            if (strcmp(cur_process->cmd, new_process->cmd) != 0) {
                mfprintf(stdout, "INFO: %s.cmd changed from %s to %s", cur_process->name, cur_process->cmd, new_process->cmd);
                need_hard_reload = 1;
            }

            if (strcmp(safe_null(cur_process->env), safe_null(new_process->env)) != 0) {
                mfprintf(stdout, "INFO: %s.env changed from %s to %s",
                        cur_process->name,
                        safe_null(cur_process->env),
                        safe_null(new_process->env));
                need_hard_reload = 1;
            }

            if (strcmp(safe_null(cur_process->cwd), safe_null(new_process->cwd)) != 0) {
                mfprintf(stdout, "INFO: %s.cwd changed from %s to %s",
                        cur_process->name,
                        safe_null(cur_process->cwd),
                        safe_null(new_process->cwd));
                need_hard_reload = 1;
            }

            if (strcmp(safe_null(cur_process->stdout_path), safe_null(new_process->stdout_path)) != 0) {
                mfprintf(stdout, "INFO: %s.stdout_path changed from %s to %s",
                        cur_process->name,
                        safe_null(cur_process->stdout_path),
                        safe_null(new_process->stdout_path));
                if (cur_process->stdout_path) free(cur_process->stdout_path);
                cur_process->stdout_path = strdup(new_process->stdout_path);
                LogPipe_SetPath(cur_process->stdout_pipe, cur_process->stdout_path);
            }

            if (strcmp(safe_null(cur_process->stderr_path), safe_null(new_process->stderr_path)) != 0) {
                mfprintf(stdout, "INFO: %s.stderr_path changed from %s to %s",
                        cur_process->name,
                        safe_null(cur_process->stderr_path),
                        safe_null(new_process->stderr_path));
                if (cur_process->stderr_path) free(cur_process->stderr_path);
                cur_process->stderr_path = strdup(new_process->stderr_path);
                LogPipe_SetPath(cur_process->stderr_pipe, cur_process->stderr_path);
            }

            if (cur_process->uid != new_process->uid) {
                mfprintf(stdout, "INFO: %s.uid changed from %d to %d", cur_process->name, cur_process->uid, new_process->uid);
                need_hard_reload = 1;
            }

            if (cur_process->gid != new_process->gid) {
                mfprintf(stdout, "INFO: %s.gid changed from %d to %d", cur_process->name, cur_process->gid, new_process->gid);
                need_hard_reload = 1;
            }

            if (cur_process->maxmem != new_process->maxmem) {
                mfprintf(stdout, "INFO: %s.maxmem changed from %zu to %zu", cur_process->name, cur_process->maxmem, new_process->maxmem);
                cur_process->maxmem = new_process->maxmem;
            }

            if (cur_process->restart_delay != new_process->restart_delay) {
                mfprintf(stdout, "INFO: %s.restart_delay changed from %d to %d", cur_process->name, cur_process->restart_delay, new_process->restart_delay);
                cur_process->restart_delay = new_process->restart_delay;
            }

            if (need_hard_reload) {
                if (signal == SIGUSR1) {
                    mfprintf(stdout, "WARN: %s need hard reload !", cur_process->name);
                    DL_DELETE(new_process_list, new_process);
                    ForeverProcess_Free(new_process);new_process = NULL;
                } else {
                    mfprintf(stdout, "INFO: hard reload %s", cur_process->name);

                    DL_DELETE(cur_process_list, cur_process);
                    ForeverProcess_Free(cur_process);

                    DL_DELETE(new_process_list, new_process);
                    DL_APPEND(hard_reload_list, new_process);
                }
            } else {
                DL_DELETE(new_process_list, new_process);
                ForeverProcess_Free(new_process);new_process = NULL;
            }
        }
    }

    DL_FOREACH_SAFE(new_process_list, new_process, tmp) {
        if (!ProcessList_FindByName(cur_process_list, new_process->name)) {
            mfprintf(stdout, "INFO: start %s", new_process->name);
            DL_DELETE(new_process_list, new_process);
            DL_APPEND(cur_process_list, new_process);
            ForeverProcess_Exec(new_process);
        }
    }

    DL_FOREACH_SAFE(hard_reload_list, new_process, tmp) {
        DL_DELETE(hard_reload_list, new_process);
        DL_APPEND(cur_process_list, new_process);
        ForeverProcess_Exec(new_process);
    }

    ProcessList_Free(new_process_list);
}

static int forever_pid() {
    int pid = 0;

    FILE *fp = fopen(pid_path, "r");
    if (fp) {
        fscanf(fp, "%d", &pid);
        fclose(fp);fp = NULL;
    } else {
        fprintf(stderr, "read pid from %s failed", pid_path);
    }

    return pid;
}

static void parse_argv(int argc, char **argv) {
    char tmp_path[PATH_MAX] = {'\0'};
    char *tmpc;
    int c;

    if (argc > 1 && argv[1][0] != '-') {
        argc --;
        argv[1] = argv[0];
        argv ++;
    }

    opterr = 0;
    while ((c = getopt(argc, argv, "c:dl:")) != -1) {
        switch(c) {
            case 'c':
                if (!realpath(optarg, cfg_path)) {
                    fprintf(stderr, "can't resolve %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'l':
                snprintf(log_path, PATH_MAX, "%s", optarg);
                break;
            case 'd':
                daemonize = 1;
                break;
        }
    }

    if (cfg_path[0] == '\0') {
        snprintf(cfg_path, PATH_MAX, "%s/%s", forever_dir, DEFAULT_CFG_NAME);
    }

    if (log_path[0] == '\0') {
        snprintf(log_path, PATH_MAX, "%s/%s", forever_dir, DEFAULT_LOG_NAME);
    }

    strcpy(tmp_path, cfg_path);
    tmpc = tmp_path;
    while (*tmpc != '\0') {
        if (*tmpc == '/' || *tmpc == '.') {
            *tmpc = '_';
        }
        tmpc ++;
    }
    snprintf(pid_path, PATH_MAX, "/tmp/forever%s.pid", tmp_path);
}

static void forever_main() {
    ForeverProcess_t *process;

    FILE *pidfp = fopen(pid_path, "w");
    if (!pidfp) {
        mfprintf(stderr, "ERROR: can't open %s", pid_path);
        exit(EXIT_FAILURE);
    }

    if (flock(fileno(pidfp), LOCK_EX | LOCK_NB) == -1) {
        mfprintf(stderr, "ERROR: can't lock %s", pid_path);
        exit(EXIT_FAILURE);
    }

    ForeverConfig_t *config = ParseConfig(cfg_path);
    if (!config) {
        exit(EXIT_FAILURE);
    }
    cur_process_list = config->process_list;

    FILE *logfp = fopen(log_path, "a+");
    if (!logfp) {
        mfprintf(stderr, "can't open log %s\n", log_path);
        exit(EXIT_FAILURE);
    }

    if (daemonize) {
        make_daemon();
    }

    if (logfp) {
        dup2(fileno(logfp), STDOUT_FILENO);
        dup2(fileno(logfp), STDERR_FILENO);
        fclose(logfp); logfp = NULL;
    }

    do {
        int pid = getpid();

        mfprintf(stdout, "INFO: forever pid:%d", pid);
        mfprintf(stdout, "INFO: pid file:%s", pid_path);

        fprintf(pidfp, "%d", pid);
        fflush(pidfp);
    } while(0);

    DL_FOREACH(cur_process_list, process) {
        ForeverProcess_Exec(process);
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, cleanup);
    signal(SIGUSR1, reload);
    signal(SIGUSR2, reload);

    uv_timer_init(uv_default_loop(), &mem_check_timer);
    uv_timer_start(&mem_check_timer, check_mem, 1000, 5000);

    LogRotate_SetConfig(config->rotate_config);
    LogRotate_Run();

    uv_run(uv_default_loop(), UV_RUN_DEFAULT);
}

void usage() {
    fprintf(stderr,
            "Usage: %s <start|stop|pid|reload|hard_reload>\n"
            " [start] [-c <configure file>] [-d] [-l <log file>] \n"
            "       -c configure file, default:%s/%s\n"
            "       -d daemonize \n"
            "       -l write log file, default:%s/%s\n"
            " stop [-c <configure file>] \n"
            " pid [-c <configure file>] \n"
            " reload [-c <configure file>] \n"
            " hard_reload [-c <configure file>] \n",
            forever_name,
            forever_dir, DEFAULT_CFG_NAME,
            forever_dir, DEFAULT_LOG_NAME
           );
}

int send_signal(int sig) {
    int pid = forever_pid();
    if (pid) {
        uv_kill(pid, sig);
        return 0;
    } else {
        fprintf(stderr, "forever is not running");
        return 1;
    }
}

int main(int argc, char **argv) {
    argv = uv_setup_args(argc, argv);

    char *tmp_path = malloc(PATH_MAX);
    size_t tmpsize = (size_t)PATH_MAX;
    uv_exepath(tmp_path, &tmpsize);
    strcpy(forever_dir, dirname(tmp_path));

    tmpsize = (size_t)PATH_MAX;
    uv_exepath(tmp_path, &tmpsize);
    strcpy(forever_name, basename(tmp_path));

    free(tmp_path); tmp_path = NULL;

    if (argc > 1) {
        if (strcmp(argv[1], "pid") == 0) {
            parse_argv(argc, argv);
            int pid = forever_pid();
            if (pid) {
                printf("%d\n", pid);
                return 0;
            } else {
                return 1;
            }
        } else if (strcmp(argv[1], "stop") == 0) {
            parse_argv(argc, argv);
            return send_signal(SIGTERM);
        } else if (strcmp(argv[1], "reload") == 0) {
            parse_argv(argc, argv);
            return send_signal(SIGUSR1);
        } else if (strcmp(argv[1], "hard_reload") == 0) {
            parse_argv(argc, argv);
            return send_signal(SIGUSR2);
        } else if (strcmp(argv[1], "-h") == 0 || (argv[1][0] != '-' && strcmp(argv[1], "start") != 0)) {
            usage();
            return 1;
        }
    }

    parse_argv(argc, argv);
    forever_main();

    return  0;
}
