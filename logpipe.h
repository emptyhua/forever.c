#ifndef _FOREVER_LOGPIPE_H
#define _FOREVER_LOGPIPE_H

#include <unistd.h>
#include <sys/types.h>

#include <uv.h>

typedef struct LogPipe_s LogPipe_t;

struct LogPipe_s {
    char *path;     /* log path */
    size_t max_size;

    uv_pipe_t *out;
    uv_pipe_t *file;

    uv_loop_t* loop;

    LogPipe_t *prev;
    LogPipe_t *next;
};

LogPipe_t *LogPipe_New();
void LogPipe_Free(LogPipe_t *lp);
void LogPipe_Start(LogPipe_t *lp);
void LogPipe_SetPath(LogPipe_t *lp, char *new_path);
void LogPipe_ReOpen(LogPipe_t *lp);

#endif
