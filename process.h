#ifndef _FOREVER_PROCESS_H
#define _FOREVER_PROCESS_H

#include <unistd.h>
#include <sys/types.h>

#include <uv.h>
#include "logpipe.h"

typedef struct ForeverProcess_s ForeverProcess_t;

struct ForeverProcess_s {
    char *name;     /* 命名 */
    char *cmd;      /* 执行命令 */

    char *stdout_path;  /* 标准输出 */
    char *stderr_path;  /* 标准错误输出 */

    char *user;
    uid_t uid;      /* 用户ID */
    char *group;
    gid_t gid;      /* 用户组ID */

    size_t maxmem;  /* 最大内存限制 */
    char *cwd;      /* 当前路径 */
    char *env;     /* 环境变量 */
    int restart_delay;/* 重启延迟 */

    LogPipe_t *stdout_pipe;
    LogPipe_t *stderr_pipe;

    uv_process_t *uv_process;

    uv_timer_t *restart_timer;/* 重启timer */
    int restart_ing;
    int stoped;

    ForeverProcess_t *prev;
    ForeverProcess_t *next;
};

ForeverProcess_t *ForeverProcess_New();
void ForeverProcess_Free(ForeverProcess_t *process);
void ForeverProcess_Exec(ForeverProcess_t *process);
void ForeverProcess_Stop(ForeverProcess_t *process);
void ForeverProcess_Restart(ForeverProcess_t *process);
void ForeverProcess_Dump(ForeverProcess_t *process);

void ProcessList_Free(ForeverProcess_t *list);
ForeverProcess_t *ProcessList_FindByName(ForeverProcess_t *list, const char *name);

#endif
