#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <limits.h>
#include <errno.h>

#include <uv.h>

#include "utlist.h"

#include "forever.h"
#include "process.h"
#include "logrotate.h"
#include "logpipe.h"
#include "config.h"

static ForeverProcess_t *cur_process_list = NULL;
static char cfg_path[PATH_MAX] = {'\0'};
static uv_timer_t mem_check_timer;

void usage() {
    fprintf(stderr,
            "Usage: forever -c <configure file> [-d] [-p <pid file>] [-l <log file>] \n"
            "       -c read config from file\n"
            "       -d daemonize \n"
            "       -p write pid file\n"
            "       -l write log file\n"
           );
}

void make_daemon() {
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
size_t get_rss_by_pid(pid_t pid) {
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

void check_mem(uv_timer_t *handle) {
    ForeverProcess_t *process;
    DL_FOREACH(cur_process_list, process) {
        if (process->pid && process->maxmem) {
            size_t cmem = get_rss_by_pid(process->pid);
            if (cmem > process->maxmem) {
                mfprintf(stderr, "ERROR: %s reach max mem limit, cur:%zu, max:%zu", process->name, cmem, process->maxmem);
                ForeverProcess_Restart(process);
            }
        }
    }
}

void cleanup(int signal) {
    ForeverProcess_t *process;
    DL_FOREACH(cur_process_list, process) {
        ForeverProcess_Stop(process);
    }
    exit(0);
}

void reload(int signal) {
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
                mfprintf(stdout, "INFO: %s cmd changed from %s to %s", cur_process->name, cur_process->cmd, new_process->cmd);
                need_hard_reload = 1;
            }

            if (strcmp(cur_process->env, new_process->env) != 0) {
                mfprintf(stdout, "INFO: %s env changed from %s to %s", cur_process->name, cur_process->env, new_process->env);
                need_hard_reload = 1;
            }

            if (strcmp(cur_process->stdout_path, new_process->stdout_path) != 0) {
                mfprintf(stdout, "INFO: %s stdout_path changed from %s to %s", cur_process->name, cur_process->stdout_path, new_process->stdout_path);
                if (cur_process->stdout_path) free(cur_process->stdout_path);
                cur_process->stdout_path = strdup(new_process->stdout_path);
                LogPipe_SetPath(cur_process->stdout_pipe, cur_process->stdout_path);
            }

            if (strcmp(cur_process->stderr_path, new_process->stderr_path) != 0) {
                mfprintf(stdout, "INFO: %s stderr_path changed from %s to %s", cur_process->name, cur_process->stderr_path, new_process->stderr_path);
                if (cur_process->stderr_path) free(cur_process->stderr_path);
                cur_process->stderr_path = strdup(new_process->stderr_path);
                LogPipe_SetPath(cur_process->stderr_pipe, cur_process->stderr_path);
            }

            if (cur_process->uid != new_process->uid) {
                mfprintf(stdout, "INFO: %s uid changed from %d to %d", cur_process->name, cur_process->uid, new_process->uid);
                need_hard_reload = 1;
            }

            if (cur_process->gid != new_process->gid) {
                mfprintf(stdout, "INFO: %s gid changed from %d to %d", cur_process->name, cur_process->gid, new_process->gid);
                need_hard_reload = 1;
            }

            if (cur_process->maxmem != new_process->maxmem) {
                mfprintf(stdout, "INFO: %s maxmem changed from %zu to %zu", cur_process->name, cur_process->maxmem, new_process->maxmem);
                cur_process->maxmem = new_process->maxmem;
            }

            if (cur_process->restart_delay != new_process->restart_delay) {
                mfprintf(stdout, "INFO: %s restart_delay changed from %d to %d", cur_process->name, cur_process->restart_delay, new_process->restart_delay);
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

int main(int argc, char **argv) {
    char pid_path[PATH_MAX] = {'\0'};
    char log_path[PATH_MAX] = {'\0'};
    int c;
    ForeverProcess_t    *process = NULL;
    int                 daemonize = 0;

    opterr = 0;
    while ((c = getopt(argc, argv, "c:p:dl:")) != -1) {
        switch(c) {
            case 'c':
                if (!realpath(optarg, cfg_path)) {
                    fprintf(stderr, "can't resolve %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'p':
                snprintf(pid_path, PATH_MAX, "%s", optarg);
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
        usage();exit(EXIT_FAILURE);
    }

    ForeverConfig_t *config = ParseConfig(cfg_path);
    if (!config) {
        exit(EXIT_FAILURE);
    }
    cur_process_list = config->process_list;

    if (log_path[0] != '\0') {
        FILE *fp = fopen(log_path, "a+");
        if (!fp) {
            mfprintf(stderr, "can't open %s\n", log_path);
            exit(EXIT_FAILURE);
        }
        fclose(fp);
    }

    if (daemonize) {
        make_daemon();
    }

    if (log_path[0] != '\0') {
        FILE *fp = fopen(log_path, "a+");
        if (!fp) {
            mfprintf(stderr, "can't open %s\n", log_path);
            exit(EXIT_FAILURE);
        }
        dup2(fileno(fp), STDOUT_FILENO);
        dup2(fileno(fp), STDERR_FILENO);
        fclose(fp);
    }

    char pid_str[255];
    sprintf(pid_str, "%d", getpid());
    mfprintf(stdout, "INFO: forever pid:%s", pid_str);

    if (pid_path[0] != '\0') {
        FILE *fp;
        fp  = fopen(pid_path, "w");
        if (!fp) {
            mfprintf(stderr, "can't open %s\n", pid_path);
            exit(EXIT_FAILURE);
        }
        fwrite(pid_str, sizeof(char), strlen(pid_str), fp);
        fclose(fp);fp = NULL;
    }

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

    return  0;
}
