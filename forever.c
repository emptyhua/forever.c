#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

#define PATH_MAX 4096

#include "dictionary.h"
#include "iniparser.h"

typedef struct ForeverProcess_s ForeverProcess_t;

struct ForeverProcess_s {
    char *cmd;      /* 执行命令 */
    char *std_out;  /* 标准输出 */
    char *std_err;  /* 标准错误输出 */
    int pid;        /* 进程ID */
    ForeverProcess_t *next;
};

void ForeverProcess_Exec(ForeverProcess_t *process) {

    prctl(PR_SET_PDEATHSIG, SIGKILL);

    if (process->std_out) {
        FILE *fp = fopen(process->std_out, "a+");
        if (!fp) {
            fprintf(stderr, "can't open %s\n", process->std_out);
            exit(EXIT_FAILURE);
        }
        dup2(fileno(fp), STDOUT_FILENO);
        fclose(fp);
    }

    if (process->std_err) {
        FILE *fp = fopen(process->std_err, "a+");
        if (!fp) {
            fprintf(stderr, "can't open %s\n", process->std_err);
            exit(EXIT_FAILURE);
        }
        dup2(fileno(fp), STDERR_FILENO);
        fclose(fp);
    }

    if (-1 == execl("/bin/bash", "bash", "-c", process->cmd, NULL)) {
        fprintf(stderr, "can't exec %s, errno:%d\n", process->cmd, errno);
        exit(EXIT_FAILURE);
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

void parse_ini(const char *ini_path, ForeverProcess_t **process_list_p) {
    int                 sec_count;
    dictionary          *cfg = NULL;
    ForeverProcess_t    *process_list = NULL;
    ForeverProcess_t    *last_process = NULL;
    int                 i;

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
        const char *sec_name;
        char        key[PATH_MAX];
        char        *value;
        ForeverProcess_t *process;

        sec_name = iniparser_getsecname(cfg, i);
        if (!sec_name) continue;

        snprintf(key, PATH_MAX, "%s:cmd", sec_name);
        value = iniparser_getstring(cfg, key, NULL);
        if (!value) continue;

        process = calloc(1, sizeof(ForeverProcess_t));
        process->cmd = strdup(value);

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

        if (last_process) {
            last_process->next = process;
            last_process = process;
        } else {
            process_list = process;
            last_process = process;
        }
    }

    if (process_list == NULL) {
        fprintf(stderr, "nothing to do");
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

int main(int argc, char **argv) {
    char ini_path[PATH_MAX] = {'\0'};
    char pid_path[PATH_MAX] = {'\0'};
    char log_path[PATH_MAX] = {'\0'};
    char                c;
    ForeverProcess_t    *process_list = NULL;
    ForeverProcess_t    *process = NULL;
    pid_t               pid;
    int                 daemonize = 0;

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
        pid = fork();
        if (pid < 0) {
            fprintf(stderr, "can't fork()");
            exit(EXIT_FAILURE);
        } else if (pid > 0) {
            process->pid = pid;
        } else {
            ForeverProcess_Exec(process);
            exit(0);
        }
        process = process->next;
    }

    while(1) {
        int status;
        pid = wait(&status);
        process = process_list;
        while(process) {
            if (process->pid == pid) {
                time_t timer;
                char time_buffer[26];
                struct tm* tm_info;

                time(&timer);
                tm_info = localtime(&timer);
                strftime(time_buffer, 26, "%Y:%m:%d %H:%M:%S", tm_info);

                fprintf(stderr, "%s: %s exited, status:%d \n", time_buffer, process->cmd, status);

                usleep(1000 * 100);
                pid = fork();
                if (pid < 0) {
                    fprintf(stderr, "can't fork()");
                    exit(EXIT_FAILURE);
                } else if (pid > 0) {
                    process->pid = pid;
                    break;
                } else {
                    ForeverProcess_Exec(process);
                    exit(EXIT_FAILURE);
                }
            }
            process = process->next;
        }
    }

    return  0;
}
