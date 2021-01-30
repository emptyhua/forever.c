#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#include "forever.h"
#include "parse_args.h"
#include "process.h"

static void child_restart(uv_timer_t *handle);
static void child_close_cb(uv_handle_t* uv_process);
static void child_exit_cb(uv_process_t *uv_process, int64_t exit_status, int term_signal);

static void child_restart(uv_timer_t *handle) {
    ForeverProcess_t *process = (ForeverProcess_t *)handle->data;
    if (!process) return;
    uv_timer_stop(&process->restart_timer);
    ForeverProcess_Exec(process);
}

static void child_close_cb(uv_handle_t* uv_process) {
    ForeverProcess_t *process = (ForeverProcess_t *)uv_process->data;
    if (!process) return;
    uv_timer_init(uv_default_loop(), &process->restart_timer);
    process->restart_timer.data = process;
    uv_timer_start(&process->restart_timer, child_restart, process->restart_delay * 1000, 0);
}

static void child_exit_cb(uv_process_t *uv_process, int64_t exit_status, int term_signal) {
    ForeverProcess_t *process = (ForeverProcess_t *)uv_process->data;
    if (!process) return;
    process->pid = 0;
    mfprintf(stderr, "ERROR: %s exited, status:%d, signal:%d", process->name, (int)exit_status, term_signal);
    uv_close((uv_handle_t*) uv_process, child_close_cb);
}

ForeverProcess_t *ForeverProcess_New() {
    return calloc(1, sizeof(ForeverProcess_t));
}

void ForeverProcess_Free(ForeverProcess_t *process) {
    if (process->name) free(process->name);
    if (process->cmd) free(process->cmd);
    if (process->std_out) free(process->std_out);
    if (process->std_err) free(process->std_err);
    if (process->cwd) free(process->cwd);
    if (process->env) free(process->env);
    free(process);
}

static char **cmd2args(const char *cmd) {
    static char *prefix = "/usr/bin/env ";
    char *tmp = malloc((strlen(prefix) + strlen(cmd) + 1) * sizeof(char));
    tmp[0] = '\0';
    stpcpy(stpcpy(tmp, prefix), cmd);
    char **args = parse_args(tmp);
    free(tmp);
    return args;
}

void ForeverProcess_Exec(ForeverProcess_t *process) {
    uv_stdio_container_t child_stdio[3];
    uv_process_options_t options;
    int is_root = 0;
    int r;
    char **args = NULL;
    char **envs = NULL;

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
            mfprintf(stderr, "ERROR: %s can't open %s %s", process->name,
                    process->std_out, strerror(errno));
        } else {
            child_stdio[1].flags = UV_INHERIT_FD;
            child_stdio[1].data.fd = fd;
            if (is_root) {
                int ret = chown(process->std_out, process->uid, process->gid);
                if (ret < 0) {
                    mfprintf(stderr, "ERROR: %s chown(%s) failed %s", process->name,
                            process->std_out, strerror(errno));
                }
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
            mfprintf(stderr, "ERROR: can't open %s %s", process->std_err, strerror(errno));
        } else {
            child_stdio[2].flags = UV_INHERIT_FD;
            child_stdio[2].data.fd = fd;
            if (is_root) {
                int ret = chown(process->std_err, process->uid, process->gid);
                if (ret < 0) {
                    mfprintf(stderr, "ERROR: %s chown(%s) failed %s", process->name,
                            process->std_err, strerror(errno));
                }
            }
        }
    } else {
        child_stdio[2].flags = UV_IGNORE;
    }

    if (process->cwd) {
        options.cwd = process->cwd;
    } else {
        options.cwd = NULL;
    }

    options.stdio_count = 3;
    options.stdio = child_stdio;

    args = cmd2args(process->cmd);
    options.args = args;
    options.file = args[0];

    if (process->env) {
        envs = cmd2args(process->env);
        options.env = envs;
    }

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
        mfprintf(stderr, "ERROR: %s start failed:'%s' %s", process->name, options.file, uv_strerror(r));
    } else {
        mfprintf(stdout, "INFO: %s started", process->name);
    }

    free_args(args);
    if (envs) free_args(envs);
}

ProcessList_t *ProcessList_New() {
    return calloc(1, sizeof(ProcessList_t));
}

void ProcessList_Free(ProcessList_t *list) {
    ForeverProcess_t *process = list->head;
    ForeverProcess_t *next;
    while (process) {
        next = process->next;
        ForeverProcess_Free(process);
        process = next;
    }
    free(list);
}

void ProcessList_Append(ProcessList_t *list, ForeverProcess_t *process) {
    if (!list->head) {
        list->head = process;
        list->tail = process;
    } else {
        process->prev = list->tail;
        list->tail->next = process;
        list->tail = process;
    }
}

void ProcessList_Remove(ProcessList_t *list, ForeverProcess_t *process) {
    if (process == list->head) {
        list->head = process->next;
    }
    if (process == list->tail) {
        list->tail = process->prev;
    }
    if (process->prev) {
        process->prev->next = process->next;
    }
    if (process->next) {
        process->next->prev = process->prev;
    }
    process->prev = NULL;
    process->next = NULL;
}

ForeverProcess_t *ProcessList_GetProcessByName(ProcessList_t *list, const char *name) {
    ForeverProcess_t *process = list->head;
    while (process) {
        if (strcmp(process->name, name) == 0) {
            return process;
        }
        process = process->next;
    }
    return NULL;
}
