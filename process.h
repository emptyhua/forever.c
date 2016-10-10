#ifndef _FOREVER_PROCESS_H
#define _FOREVER_PROCESS_H

#include <unistd.h>
#include <sys/types.h>

#include <uv.h>

typedef struct ForeverProcess_s ForeverProcess_t;
typedef struct ProcessList_s ProcessList_t;

struct ForeverProcess_s {
    char *name;     /* 命名 */
    char *cmd;      /* 执行命令 */
    char *std_out;  /* 标准输出 */
    char *std_err;  /* 标准错误输出 */
    int pid;        /* 进程ID */
    uid_t uid;      /* 用户ID */
    gid_t gid;      /* 用户组ID */
    size_t maxmem;  /* 最大内存限制 */
    char *cwd;      /* 当前路径 */
    char **args;
    uv_process_t uv_process;
    int restart_delay;/* 重启延迟 */
    uv_timer_t restart_timer;/* 重启timer */
    ForeverProcess_t *prev;
    ForeverProcess_t *next;
};

struct ProcessList_s {
    ForeverProcess_t *head;
    ForeverProcess_t *tail;
};

ForeverProcess_t *ForeverProcess_New();
void ForeverProcess_Free(ForeverProcess_t *process);
void ForeverProcess_Exec(ForeverProcess_t *process);

ProcessList_t *ProcessList_New();
void ProcessList_Free(ProcessList_t *list);
void ProcessList_Append(ProcessList_t *list, ForeverProcess_t *process);
void ProcessList_Remove(ProcessList_t *list, ForeverProcess_t *process);
ForeverProcess_t *ProcessList_GetProcessByName(ProcessList_t *list, const char *name);

#endif
