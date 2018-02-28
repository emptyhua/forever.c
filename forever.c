#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <sys/resource.h>
#include <limits.h>

#include <uv.h>

#include "dictionary.h"
#include "iniparser.h"

#include "forever.h"
#include "parse_args.h"
#include "process.h"

static ProcessList_t *cur_process_list = NULL;
static char ini_path[PATH_MAX] = {'\0'};
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

char **cmd2args(const char *cmd) {
    static char *prefix = "/usr/bin/env ";
    char *tmp = malloc((strlen(prefix) + strlen(cmd) + 1) * sizeof(char));
    tmp[0] = '\0';
    stpcpy(stpcpy(tmp, prefix), cmd);
    char **args = parse_args(tmp);
    free(tmp);
    return args;
}

ProcessList_t *parse_ini(const char *ini_path) {
    int                 sec_count;
    dictionary          *cfg = NULL;
    ProcessList_t       *process_list = ProcessList_New();
    int                 i;

    const char *sec_name = NULL;
    char        key[PATH_MAX];
    char        *value = NULL;
    ForeverProcess_t *process = NULL;


    cfg = iniparser_load(ini_path);
    if (cfg == NULL) {
        mfprintf(stderr, "ERROR: can't open %s", ini_path);
        goto ERROR;
    }

    sec_count = iniparser_getnsec(cfg);
    if (sec_count == 0) {
        mfprintf(stderr, "ERROR: %s have no sections", ini_path);
        goto ERROR;
    }

    for (i = 0; i < sec_count; i ++) {
        sec_name = iniparser_getsecname(cfg, i);
        if (!sec_name) continue;

        snprintf(key, PATH_MAX, "%s:cmd", sec_name);
        value = iniparser_getstring(cfg, key, NULL);
        if (!value) continue;

        process = ForeverProcess_New();
        process->name = strdup(sec_name);

        process->cmd  = strdup(value);
        process->args = cmd2args(value);

        snprintf(key, PATH_MAX, "%s:cwd", sec_name);
        value = iniparser_getstring(cfg, key, NULL);
        if (value)  {
            process->cwd = strdup(value);
        }

        snprintf(key, PATH_MAX, "%s:stdout", sec_name);
        value = iniparser_getstring(cfg, key, NULL);
        if (value)  {
            FILE *fp = fopen(value, "a+");
            if (!fp) {
                mfprintf(stderr, "ERROR: can't open %s", value);
                goto ERROR;
            }
            fclose(fp);fp = NULL;
            process->std_out = strdup(value);
        }

        snprintf(key, PATH_MAX, "%s:stderr", sec_name);
        value = iniparser_getstring(cfg, key, NULL);
        if (value)  {
            FILE *fp = fopen(value, "a+");
            if (!fp) {
                mfprintf(stderr, "ERROR: can't open %s", value);
                goto ERROR;
            }
            fclose(fp);fp = NULL;
            process->std_err = strdup(value);
        }

        snprintf(key, PATH_MAX, "%s:user", sec_name);
        value = iniparser_getstring(cfg, key, NULL);
        if (value)  {
            struct passwd *u;
            u = getpwnam((const char *)value);
            if (u == NULL) {
                mfprintf(stderr, "ERROR: invalid user %s", value);
                goto ERROR;
            }

            if (u->pw_uid != getuid() && getuid() != 0) {
                mfprintf(stderr, "ERROR: you must run as root to set uid");
                goto ERROR;
            }
            process->uid = u->pw_uid;
        }

        snprintf(key, PATH_MAX, "%s:group", sec_name);
        value = iniparser_getstring(cfg, key, NULL);
        if (value)  {
            struct group *grp;
            grp = getgrnam((const char *)value);
            if (grp == NULL) {
                mfprintf(stderr, "ERROR: invalid group %s", value);
                goto ERROR;
            }

            if (grp->gr_gid != getgid() && getuid() != 0) {
                mfprintf(stderr, "ERROR: you must run as root to set gid");
                goto ERROR;
            }
            process->gid = grp->gr_gid;
        }

        snprintf(key, PATH_MAX, "%s:maxmem", sec_name);
        process->maxmem = iniparser_getint(cfg, key, 0) * 1024 * 1024;

        snprintf(key, PATH_MAX, "%s:restart_delay", sec_name);
        process->restart_delay = iniparser_getint(cfg, key, 1);

        ProcessList_Append(process_list, process);
    }

    if (cfg) {
        iniparser_freedict(cfg);cfg = NULL;
    }

    return process_list;

ERROR:
    if (cfg) {
        iniparser_freedict(cfg);cfg = NULL;
    }

    if (process) {
        ForeverProcess_Free(process);process = NULL;
    }

    ProcessList_Free(process_list);process_list = NULL;

    return NULL;
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
    chdir("/");

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
    ForeverProcess_t *process = cur_process_list->head;
    while(process) {
        if (process->pid && process->maxmem) {
            size_t cmem = get_rss_by_pid(process->pid);
            if (cmem > process->maxmem) {
                mfprintf(stderr, "ERROR: %s reach max mem limit, cur:%zu, max:%zu", process->name, cmem, process->maxmem);
                uv_kill(process->pid, SIGTERM);
            }
        }
        process = process->next;
    }
}

void cleanup(int signal) {
    ForeverProcess_t *process = cur_process_list->head;
    while(process) {
        if (process->pid) {
            uv_kill(process->pid, SIGTERM);
        }
        process = process->next;
    }
    exit(0);
}

void reload(int signal) {
    ForeverProcess_t *cur_process;
    ForeverProcess_t *new_process;
    ForeverProcess_t *next;
    ProcessList_t *new_process_list;
    ProcessList_t *hard_reload_list = ProcessList_New();

    new_process_list = parse_ini(ini_path);
    if (!new_process_list) {
        return;
    }

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

    cur_process = cur_process_list->head;
    while(cur_process) {
        new_process = ProcessList_GetProcessByName(new_process_list, cur_process->name);
        if (!new_process) {
            if (cur_process->pid) {
                cur_process->uv_process.data = NULL;
                mfprintf(stdout, "INFO: kill %s", cur_process->name);
                uv_kill(cur_process->pid, SIGTERM);
            }
            next = cur_process->next;
            ProcessList_Remove(cur_process_list, cur_process);
            ForeverProcess_Free(cur_process);
            cur_process = next;
        } else {
            int need_hard_reload = 0;
            if (strcmp(cur_process->cmd, new_process->cmd) != 0) {
                mfprintf(stdout, "INFO: %s cmd changed from %s to %s", cur_process->name, cur_process->cmd, new_process->cmd);
                need_hard_reload = 1;
            }

            if (strcmp(cur_process->std_out, new_process->std_out) != 0) {
                mfprintf(stdout, "INFO: %s std_out changed from %s to %s", cur_process->name, cur_process->std_out, new_process->std_out);
                need_hard_reload = 1;
            }

            if (strcmp(cur_process->std_err, new_process->std_err) != 0) {
                mfprintf(stdout, "INFO: %s std_err changed from %s to %s", cur_process->name, cur_process->std_err, new_process->std_err);
                need_hard_reload = 1;
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
                    ProcessList_Remove(new_process_list, new_process);
                    ForeverProcess_Free(new_process);new_process = NULL;
                    cur_process = cur_process->next;
                } else {
                    mfprintf(stdout, "INFO: restart %s", cur_process->name);

                    if (cur_process->pid) {
                        cur_process->uv_process.data = NULL;
                        mfprintf(stdout, "INFO: kill %s", cur_process->name);
                        uv_kill(cur_process->pid, SIGTERM);
                    }

                    next = cur_process->next;
                    ProcessList_Remove(cur_process_list, cur_process);
                    ForeverProcess_Free(cur_process);

                    ProcessList_Remove(new_process_list, new_process);
                    ProcessList_Append(hard_reload_list, new_process);

                    cur_process = next;
                }
            } else {
                ProcessList_Remove(new_process_list, new_process);
                ForeverProcess_Free(new_process);new_process = NULL;
                cur_process = cur_process->next;
            }
        }
    }

    new_process = new_process_list->head;
    while (new_process) {
        if (!ProcessList_GetProcessByName(cur_process_list, new_process->name)) {
            mfprintf(stdout, "INFO: start %s", new_process->name);
            next = new_process->next;
            ProcessList_Remove(new_process_list, new_process);
            ProcessList_Append(cur_process_list, new_process);
            ForeverProcess_Exec(new_process);
            new_process = next;
        } else {
            new_process = new_process->next;
        }
    }

    new_process = hard_reload_list->head;
    while (new_process) {
        mfprintf(stdout, "INFO: start %s", new_process->name);
        ProcessList_Append(cur_process_list, new_process);
        ForeverProcess_Exec(new_process);
        new_process = new_process->next;
    }

    hard_reload_list->head = NULL;
    hard_reload_list->tail = NULL;
    ProcessList_Free(hard_reload_list);
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
                if (!realpath(optarg, ini_path)) {
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

    if (ini_path[0] == '\0') {
        usage();exit(EXIT_FAILURE);
    }

    cur_process_list = parse_ini(ini_path);
    if (!cur_process_list) {
        exit(EXIT_FAILURE);
    }

    if (log_path[0] != '\0') {
        FILE *fp = fopen(log_path, "a+");
        if (!fp) {
            fprintf(stderr, "can't open %s\n", log_path);
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
            fprintf(stderr, "can't open %s\n", log_path);
            exit(EXIT_FAILURE);
        }
        dup2(fileno(fp), STDOUT_FILENO);
        dup2(fileno(fp), STDERR_FILENO);
        fclose(fp);
    }

    if (pid_path[0] != '\0') {
        char pid_str[255];
        FILE *fp;
        fp  = fopen(pid_path, "w");
        if (!fp) {
            fprintf(stderr, "can't open %s\n", pid_path);
            exit(EXIT_FAILURE);
        }
        sprintf(pid_str, "%d", getpid());
        fwrite(pid_str, sizeof(char), strlen(pid_str), fp);
        fclose(fp);fp = NULL;
    }

    process = cur_process_list->head;
    while(process) {
        ForeverProcess_Exec(process);
        process = process->next;
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, cleanup);
    signal(SIGUSR1, reload);
    signal(SIGUSR2, reload);

    uv_timer_init(uv_default_loop(), &mem_check_timer);
    uv_timer_start(&mem_check_timer, check_mem, 1000, 5000);

    uv_run(uv_default_loop(), UV_RUN_DEFAULT);

    return  0;
}
