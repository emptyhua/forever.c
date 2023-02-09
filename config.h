#ifndef _EMPTYHUA_FOREVER_CONFIG_H
#define _EMPTYHUA_FOREVER_CONFIG_H

#include "logrotate.h"
#include "process.h"

typedef struct ForeverConfig_s ForeverConfig_t;

struct ForeverConfig_s {
    LogRotateConfig_t rotate_config;
    ForeverProcess_t *process_list;
};

ForeverConfig_t *ParseConfig(const char *cfg_path);

void readable_size(double size, char *buf);
size_t parse_readable_size(char *buf);

#endif
