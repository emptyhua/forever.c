#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <sys/resource.h>

#include <uv.h>
#include "dictionary.h"
#include "iniparser.h"
#include "parse_args.h"

#define PATH_MAX 4096
#define mfprintf(stream, format, ...) \
    do {\
        time_t timer; \
        char time_buffer[26];\
        struct tm* tm_info;\
        time(&timer);\
        tm_info = localtime(&timer);\
        strftime(time_buffer, 26, "%Y:%m:%d %H:%M:%S", tm_info);\
        fprintf(stream, \
                "%s: "format"\n",\
                time_buffer,\
##__VA_ARGS__);\
    }while(0)

typedef struct ForeverProcess_s ForeverProcess_t;

struct ForeverProcess_s {
    char *cmd;      /* 执行命令 */
    char *std_out;  /* 标准输出 */
    char *std_err;  /* 标准错误输出 */
    int pid;        /* 进程ID */
    uid_t uid;      /* 用户ID */
    gid_t gid;      /* 用户组ID */
    size_t maxmem;  /* 最大内存限制 */
    char **args;
    uv_process_t uv_process;
    ForeverProcess_t *next;
};

void ForeverProcess_Exec(ForeverProcess_t *process);

static void child_close_cb(uv_handle_t* uv_process) {
    ForeverProcess_t *process = (ForeverProcess_t *)uv_process->data;
    ForeverProcess_Exec(process);
}

static void child_exit_cb(uv_process_t *uv_process, int64_t exit_status, int term_signal) {
    ForeverProcess_t *process = (ForeverProcess_t *)uv_process->data;
    process->pid = 0;
    mfprintf(stderr, "ERROR: %s exited, status:%d, signal:%d", process->cmd, (int)exit_status, term_signal);
    uv_close((uv_handle_t*) uv_process, child_close_cb);
}

void ForeverProcess_Exec(ForeverProcess_t *process) {
    uv_stdio_container_t child_stdio[3];
    uv_process_options_t options;
    int is_root = 0;
    int r;

    if (getuid() == 0) {
        is_root = 1;
    }

    options.flags = 0;

    if (process->uid != 0) {
        options.flags |= UV_PROCESS_SETUID;
        options.uid = process->uid;
    }

    if (process->gid != 0) {
        options.flags |= UV_PROCESS_SETGID;
        options.gid = process->gid;
    }

    // 标准输入
    child_stdio[0].flags = UV_IGNORE;

    // 标准输出
    if (process->std_out) {
        int fd = open(process->std_out, O_WRONLY|O_APPEND|O_CREAT, 0644);
        if (fd == -1) {
            child_stdio[1].flags = UV_IGNORE;
            mfprintf(stderr, "ERROR: can't open %s", process->std_out);
        } else {
            child_stdio[1].flags = UV_INHERIT_FD;
            child_stdio[1].data.fd = fd;
            if (is_root) {
                chown(process->std_out, process->uid, process->gid);
            }
        }
    } else {
        child_stdio[1].flags = UV_IGNORE;
    }

    // 错误输出
    if (process->std_err) {
        int fd = open(process->std_err, O_WRONLY|O_APPEND|O_CREAT, 0644);
        if (fd == -1) {
            child_stdio[2].flags = UV_IGNORE;
            mfprintf(stderr, "ERROR: can't open %s", process->std_err);
        } else {
            child_stdio[2].flags = UV_INHERIT_FD;
            child_stdio[2].data.fd = fd;
            if (is_root) {
                chown(process->std_err, process->uid, process->gid);
            }
        }
    } else {
        child_stdio[2].flags = UV_IGNORE;
    }

    options.env = NULL;
    options.cwd = NULL;
    options.stdio_count = 3;
    options.stdio = child_stdio;
    options.args = process->args;
    options.file = process->args[0];
    options.exit_cb = child_exit_cb;

    process->uv_process.data = process;
    r = uv_spawn(uv_default_loop(), &process->uv_process, &options);
    process->pid = process->uv_process.pid;

    if (child_stdio[1].flags == UV_INHERIT_FD) {
        close(child_stdio[1].data.fd);
    }

    if (child_stdio[2].flags == UV_INHERIT_FD) {
        close(child_stdio[2].data.fd);
    }

    if (r < 0) {
        mfprintf(stderr, "ERROR: fork %s failed:%s", process->cmd, uv_strerror(r));
    } else {
        mfprintf(stdout, "INFO: %s started", process->cmd);
    }
}

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
    stpcpy(stpcpy(tmp, prefix), cmd);
    char **args = parse_args(tmp);
    free(tmp);
    return args;
}

void parse_ini(const char *ini_path, ForeverProcess_t **process_list_p) {
    int                 sec_count;
    dictionary          *cfg = NULL;
    ForeverProcess_t    *process_list = NULL;
    ForeverProcess_t    *last_process = NULL;
    int                 i;

    const char *sec_name;
    char        key[PATH_MAX];
    char        *value;
    ForeverProcess_t *process;


    cfg = iniparser_load(ini_path);
    if (cfg == NULL) {
        exit(EXIT_FAILURE);
    }

    sec_count = iniparser_getnsec(cfg);
    if (sec_count == 0) {
        fprintf(stderr, "nothing to do");
        exit(EXIT_FAILURE);
    }

    for (i = 0; i < sec_count; i ++) {
        sec_name = iniparser_getsecname(cfg, i);
        if (!sec_name) continue;

        snprintf(key, PATH_MAX, "%s:cmd", sec_name);
        value = iniparser_getstring(cfg, key, NULL);
        if (!value) continue;

        process = calloc(1, sizeof(ForeverProcess_t));
        process->cmd  = strdup(value);
        process->args = cmd2args(value);

        snprintf(key, PATH_MAX, "%s:stdout", sec_name);
        value = iniparser_getstring(cfg, key, NULL);
        if (value)  {
            FILE *fp = fopen(value, "a+");
            if (!fp) {
                fprintf(stderr, "can't open %s\n", value);
                exit(EXIT_FAILURE);
            }
            fclose(fp);fp = NULL;
            process->std_out = strdup(value);
        }

        snprintf(key, PATH_MAX, "%s:stderr", sec_name);
        value = iniparser_getstring(cfg, key, NULL);
        if (value)  {
            FILE *fp = fopen(value, "a+");
            if (!fp) {
                fprintf(stderr, "can't open %s\n", value);
                exit(EXIT_FAILURE);
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
                fprintf(stderr, "invalid user %s\n", value);
                exit(EXIT_FAILURE);
            }

            if (u->pw_uid != getuid() && getuid() != 0) {
                fprintf(stderr, "must run as root\n");
                exit(EXIT_FAILURE);
            }
            process->uid = u->pw_uid;
        }

        snprintf(key, PATH_MAX, "%s:group", sec_name);
        value = iniparser_getstring(cfg, key, NULL);
        if (value)  {
            struct group *grp;
            grp = getgrnam((const char *)value);
            if (grp == NULL) {
                fprintf(stderr, "invalid group %s\n", value);
                exit(EXIT_FAILURE);
            }

            if (grp->gr_gid != getgid() && getuid() != 0) {
                fprintf(stderr, "must run as root\n");
                exit(EXIT_FAILURE);
            }
            process->gid = grp->gr_gid;
        }

        snprintf(key, PATH_MAX, "%s:maxmem", sec_name);
        process->maxmem = iniparser_getint(cfg, key, 0) * 1024 * 1024;

        if (last_process) {
            last_process->next = process;
            last_process = process;
        } else {
            process_list = process;
            last_process = process;
        }
    }

    if (process_list == NULL) {
        fprintf(stderr, "nothing to do\n");
        exit(EXIT_FAILURE);
    }

    if (cfg) {
        iniparser_freedict(cfg);cfg = NULL;
    }

    *process_list_p     = process_list;
}

void make_daemon()
{
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

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
}

static ForeverProcess_t    *process_list = NULL;

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
    ForeverProcess_t *process = process_list;
    while(process) {
        if (process->pid && process->maxmem) {
            size_t cmem = get_rss_by_pid(process->pid);
            if (cmem > process->maxmem) {
                mfprintf(stderr, "ERROR: %s reach max mem limit, cur:%zu, max:%zu", process->cmd, cmem, process->maxmem);
                uv_kill(process->pid, 9);
            }
        }
        process = process->next;
    }
}

int main(int argc, char **argv) {
    char ini_path[PATH_MAX] = {'\0'};
    char pid_path[PATH_MAX] = {'\0'};
    char log_path[PATH_MAX] = {'\0'};
    char                c;
    ForeverProcess_t    *process = NULL;
    int                 daemonize = 0;
    uv_timer_t timer;

    opterr = 0;
    while ((c = getopt(argc, argv, "c:p:dl:")) != -1) {
        switch(c) {
            case 'c':
                snprintf(ini_path, PATH_MAX, "%s", optarg);
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
        usage();exit(1);
    }

    parse_ini(ini_path, &process_list);

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

    process = process_list;
    while(process) {
        ForeverProcess_Exec(process);
        process = process->next;
    }

    signal(SIGPIPE, SIG_IGN);

    uv_timer_init(uv_default_loop(), &timer);
    uv_timer_start(&timer, check_mem, 1000, 5000);

    uv_run(uv_default_loop(), UV_RUN_DEFAULT);

    return  0;
}
