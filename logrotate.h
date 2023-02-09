#ifndef _FOREVER_LOGROTATE_H
#define _FOREVER_LOGROTATE_H

#include "logpipe.h"

typedef struct LogRotateConfig_s LogRotateConfig_t;

struct LogRotateConfig_s {
    size_t maxsize;
    unsigned int rotate;
    int compress;
};


void LogRotate_SetConfig(LogRotateConfig_t cfg);
void LogRotate_Run();
void LogRotate_Add(LogPipe_t *lp);
void LogRotate_Remove(LogPipe_t *lp);

#endif
