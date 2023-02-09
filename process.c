#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#include "utlist.h"

#include "forever.h"
#include "parse_args.h"
#include "config.h"
#include "process.h"

static void child_restart(uv_timer_t *handle);
static void child_close_cb(uv_handle_t* uv_process);
static void child_exit_cb(uv_process_t *uv_process, int64_t exit_status, int term_signal);

static void free_handle(uv_handle_t *hd) {
    free(hd);
}

static void child_restart(uv_timer_t *handle) {
    ForeverProcess_t *process = (ForeverProcess_t *)handle->data;
    process->restart_ing = 0;

    uv_timer_stop(process->restart_timer);

    if (process->stoped) {
        return;
    }

    ForeverProcess_Exec(process);
}

static void child_close_cb(uv_handle_t* uv_process) {
    ForeverProcess_t *process = (ForeverProcess_t *)uv_process->data;

    free(uv_process);

    if (!process) {
        return;
    }

    process->uv_process = NULL;

    if (process->stoped) {
        return;
    }

    process->restart_ing = 1;

    if (!process->restart_timer) {
        process->restart_timer = (uv_timer_t *) malloc(sizeof(uv_timer_t));
        uv_timer_init(uv_default_loop(), process->restart_timer);
        process->restart_timer->data = process;
    }

    uv_timer_start(process->restart_timer, child_restart, process->restart_delay * 1000, 0);
}

static void child_exit_cb(uv_process_t *uv_process, int64_t exit_status, int term_signal) {
    ForeverProcess_t *process = (ForeverProcess_t *)uv_process->data;

    if (!process) {
        uv_close((uv_handle_t *)uv_process, free_handle);
        return;
    }

    mfprintf(stderr, "ERROR: %s exited, status:%d, signal:%d", process->name, (int)exit_status, term_signal);
    uv_close((uv_handle_t*) uv_process, child_close_cb);
}

ForeverProcess_t *ForeverProcess_New() {
    return calloc(1, sizeof(ForeverProcess_t));
}


void ForeverProcess_Free(ForeverProcess_t *process) {
    ForeverProcess_Stop(process);

    if (process->name) free(process->name);
    if (process->cmd) free(process->cmd);
    if (process->stdout_path) free(process->stdout_path);
    if (process->stdout_pipe) LogPipe_Free(process->stdout_pipe);
    if (process->stderr_path) free(process->stderr_path);
    if (process->stderr_pipe) LogPipe_Free(process->stderr_pipe);
    if (process->cwd) free(process->cwd);
    if (process->env) free(process->env);
    if (process->user) free(process->user);
    if (process->group) free(process->group);
    if (process->restart_timer) uv_close((uv_handle_t *)process->restart_timer, free_handle);

    free(process);
}

void ForeverProcess_Stop(ForeverProcess_t *process) {
    process->stoped = 1;

    if (process->uv_process) {
        process->uv_process->data = NULL;
        uv_kill(process->uv_process->pid, SIGTERM);
        process->uv_process = NULL;
    }

    if (process->restart_ing) {
        uv_timer_stop(process->restart_timer);
    }
}

void ForeverProcess_Restart(ForeverProcess_t *process) {
    if (process->restart_ing) {
        return;
    }

    if (process->uv_process) {
        uv_kill(process->uv_process->pid, SIGTERM);
    }
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
    if (process->stdout_pipe) LogPipe_Free(process->stdout_pipe);
    process->stdout_pipe = LogPipe_New();
    LogPipe_SetPath(process->stdout_pipe, process->stdout_path);
    child_stdio[1].flags = UV_CREATE_PIPE | UV_WRITABLE_PIPE;
    child_stdio[1].data.stream = (uv_stream_t *)process->stdout_pipe->out;

    // 错误输出
    if (process->stderr_pipe) LogPipe_Free(process->stderr_pipe);
    process->stderr_pipe = LogPipe_New();
    LogPipe_SetPath(process->stderr_pipe, process->stderr_path);
    child_stdio[2].flags = UV_CREATE_PIPE | UV_WRITABLE_PIPE;
    child_stdio[2].data.stream = (uv_stream_t *)process->stderr_pipe->out;

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

    if (process->uv_process) {
        uv_close((uv_handle_t *)process->uv_process, free_handle);
    }

    process->uv_process = (uv_process_t *)malloc(sizeof(uv_process_t));
    process->uv_process->data = process;
    r = uv_spawn(uv_default_loop(), process->uv_process, &options);

    if (r < 0) {
        free(process->uv_process);
        process->uv_process = NULL;
        mfprintf(stderr, "ERROR: %s start failed:'%s' %s", process->name, options.file, uv_strerror(r));
    } else {
        mfprintf(stdout, "INFO: %s started", process->name);
        LogPipe_Start(process->stdout_pipe);
        LogPipe_Start(process->stderr_pipe);
    }

    ForeverProcess_Dump(process);

    free_args(args);
    if (envs) free_args(envs);
}

void ProcessList_Free(ForeverProcess_t *list) {
    ForeverProcess_t *el;
    ForeverProcess_t *tmp;
    DL_FOREACH_SAFE(list, el, tmp) {
        DL_DELETE(list, el);
        ForeverProcess_Free(el);
    }
}

ForeverProcess_t *ProcessList_FindByName(ForeverProcess_t *list, const char *name) {
    ForeverProcess_t *el;
    DL_FOREACH(list, el) {
        if (strcmp(el->name, name) == 0) {
            return el;
        }
    }
    return NULL;
}

void ForeverProcess_Dump(ForeverProcess_t *process) {
    mfprintf(stdout, "%s.cmd: %s", process->name, process->cmd);
    if (process->stdout_path) {
        mfprintf(stdout, "%s.stdout: %s", process->name, process->stdout_path);
    }

    if (process->stderr_path) {
        mfprintf(stdout, "%s.stderr: %s", process->name, process->stderr_path);
    }

    if (process->user) {
        mfprintf(stdout, "%s.user: %s", process->name, process->user);
    }

    if (process->group) {
        mfprintf(stdout, "%s.group: %s", process->name, process->group);
    }

    if (process->cwd) {
        mfprintf(stdout, "%s.cwd: %s", process->name, process->cwd);
    }

    if (process->env) {
        mfprintf(stdout, "%s.env: %s", process->name, process->env);
    }

    mfprintf(stdout, "%s.restart_delay: %d", process->name, process->restart_delay);

    if (process->maxmem) {
        char tmp[1024];
        readable_size((double)process->maxmem, tmp);
        mfprintf(stdout, "%s.maxmem: %s", process->name, tmp);
    }
}
