#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>

#include "toml.h"
#include "utlist.h"
#include "forever.h"

#include "config.h"

void readable_size(double size, char *buf) {
    int i = 0;
    static const char* units[] = {"B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"};
    while (size > 1024) {
        size /= 1024;
        i++;
    }
    sprintf(buf, "%.*f %s", i, size, units[i]);
}

size_t parse_readable_size(char *s) {
    char *endp = s;
    int sh;
    errno = 0;
    long long int x = strtoll(s, &endp, 10);
    if (errno || endp == s) goto error;
    switch(*endp) {
        case 'k':
        case 'K':
            sh=10;
            break;
        case 'm':
        case 'M':
            sh=20;
            break;
        case 'g':
        case 'G':
            sh=30;
            break;
        case 0: sh=0; break;
        default: goto error;
    }
    if (x > SIZE_MAX>>sh) goto error;
    x <<= sh;
    return x;
error:
    return 0;
}

static void parse_logrotate_config(toml_table_t *sec, LogRotateConfig_t *cfg) {
    const char *svalue = NULL;
    int64_t ivalue;

    if (0 != (svalue = toml_raw_in(sec, "maxsize"))) {
        char *maxsize;
        if (toml_rtos(svalue, &maxsize)) {
            mfprintf(stderr, "ERROR: invalid logrotate.maxsize %s", svalue);
        } else {
            cfg->maxsize = parse_readable_size(maxsize);
            free(maxsize); maxsize = NULL;
        }

        if (cfg->maxsize == 0) {
            cfg->maxsize = 100 * 1024 * 1024;
        }
    }

    if (0 != (svalue = toml_raw_in(sec, "rotate"))) {
        if (toml_rtoi(svalue, &ivalue)) {
            mfprintf(stderr, "ERROR: invalid logrotate.rotate %s", svalue);
        } else {
            cfg->rotate = (unsigned int)ivalue;
        }

        if (cfg->rotate == 0) {
            cfg->rotate = 10;
        }
    }

    if (0 != (svalue = toml_raw_in(sec, "compress"))) {
        if (toml_rtoi(svalue, &ivalue)) {
            mfprintf(stderr, "ERROR: invalid logrotate.compress %s", svalue);
        } else {
            cfg->compress = (int)ivalue;
        }
    }
}

static ForeverProcess_t *parse_process_config(toml_table_t *sec) {
    const char *svalue = NULL;
    int64_t ivalue;

    if (0 == (svalue = toml_raw_in(sec, "cmd"))) {
        return NULL;
    }

    ForeverProcess_t *process = ForeverProcess_New();

    char *cmd;
    if (toml_rtos(svalue, &cmd)) {
        mfprintf(stderr, "ERROR: can't parse %s.cmd", process->name);
        goto ERROR;
    }

    process->cmd  = cmd;

    if (0 != (svalue = toml_raw_in(sec, "cwd"))) {
        char *cwd;
        if (toml_rtos(svalue, &cwd)) {
            mfprintf(stderr, "ERROR: can't parse %s.cwd", process->name);
            goto ERROR;
        }

        process->cwd = cwd;
    }

    if (0 != (svalue = toml_raw_in(sec, "env"))) {
        char *env;
        if (toml_rtos(svalue, &env)) {
            mfprintf(stderr, "ERROR: can't parse %s.env", process->name);
            goto ERROR;
        }

        process->env = env;
    }

    if (0 != (svalue = toml_raw_in(sec, "stdout"))) {
        char *p;
        if (toml_rtos(svalue, &p)) {
            mfprintf(stderr, "ERROR: can't parse %s.stdout", process->name);
            goto ERROR;
        }

        FILE *fp = fopen(p, "a+");
        if (!fp) {
            mfprintf(stderr, "ERROR: can't open %s %s", p, strerror(errno));
            goto ERROR;
        }
        fclose(fp);fp = NULL;
        process->stdout_path = p;
    }

    if (0 != (svalue = toml_raw_in(sec, "stderr"))) {
        char *p;
        if (toml_rtos(svalue, &p)) {
            mfprintf(stderr, "ERROR: can't parse %s.stderr", process->name);
            goto ERROR;
        }

        FILE *fp = fopen(p, "a+");
        if (!fp) {
            mfprintf(stderr, "ERROR: can't open %s %s", p, strerror(errno));
            goto ERROR;
        }
        fclose(fp);fp = NULL;
        process->stderr_path = p;
    }

    if (0 != (svalue = toml_raw_in(sec, "user"))) {
        char *user;
        if (toml_rtos(svalue, &user)) {
            mfprintf(stderr, "ERROR: can't parse %s.user", process->name);
            goto ERROR;
        }

        struct passwd *u;
        u = getpwnam(user);
        if (u == NULL) {
            mfprintf(stderr, "ERROR: invalid user %s", user);
            free(user);user = NULL;
            goto ERROR;
        }

        if (u->pw_uid != getuid() && getuid() != 0) {
            mfprintf(stderr, "ERROR: you must run as root to set uid");
            free(user);user = NULL;
            goto ERROR;
        }
        process->user = user;
        process->uid = u->pw_uid;
    }

    if (0 != (svalue = toml_raw_in(sec, "group"))) {
        char *group;
        if (toml_rtos(svalue, &group)) {
            mfprintf(stderr, "ERROR: can't parse %s.group", process->name);
            goto ERROR;
        }

        struct group *grp;
        grp = getgrnam(group);
        if (grp == NULL) {
            mfprintf(stderr, "ERROR: invalid group %s", svalue);
            free(group); group = NULL;
            goto ERROR;
        }

        if (grp->gr_gid != getgid() && getuid() != 0) {
            mfprintf(stderr, "ERROR: you must run as root to set gid");
            free(group); group = NULL;
            goto ERROR;
        }
        process->group = group;
        process->gid = grp->gr_gid;
    }

    if (0 != (svalue = toml_raw_in(sec, "maxmem"))) {
        char *maxmem;
        if (toml_rtos(svalue, &maxmem) == 0) {
            process->maxmem = parse_readable_size(maxmem);
            free(maxmem); maxmem = NULL;
        }

        if (process->maxmem == 0) {
            mfprintf(stderr, "ERROR: invalid maxmem %s", svalue);
            goto ERROR;
        }
    }

    if (0 != (svalue = toml_raw_in(sec, "restart_delay"))) {
        if (toml_rtoi(svalue, &ivalue)) {
            mfprintf(stderr, "ERROR: invalid restart_delay %s", svalue);
            goto ERROR;
        }
        process->restart_delay = (int)ivalue;
    } else {
        process->restart_delay = 2;
    }

    return process;

ERROR:
    if (process) {
        ForeverProcess_Free(process);process = NULL;
    }

    return NULL;
}

ForeverConfig_t *ParseConfig(const char *cfg_path) {
    FILE* fp;
    char errbuf[200];
    toml_table_t *cfg = NULL;
    toml_table_t *sec = NULL;
    int i;
    const char* key = NULL;

    ForeverConfig_t *config = calloc(1, sizeof(ForeverConfig_t));
    // default rotate config
    config->rotate_config.maxsize = 100 * 1024 * 1024; // 100M
    config->rotate_config.rotate = 10;
    config->rotate_config.compress = 1;

    if (0 == (fp = fopen(cfg_path, "r"))) {
        mfprintf(stderr, "ERROR: can't open %s %s", cfg_path, strerror(errno));
        goto ERROR;
    }

    cfg = toml_parse_file(fp, errbuf, sizeof(errbuf));
    if (0 == cfg) {
        mfprintf(stderr, "ERROR: %s", errbuf);
        goto ERROR;
    }

    for (i = 0; 0 != (key = toml_key_in(cfg, i)); i++) {
        if (0 != (sec = toml_table_in(cfg, key))) {
            if (strcmp(key, "logrotate") == 0) {
                parse_logrotate_config(sec, &config->rotate_config);
            } else {
                ForeverProcess_t *process = parse_process_config(sec);
                if (process) {
                    process->name = strdup(key);
                    DL_APPEND(config->process_list, process);
                    // mfprintf(stdout, "XXXXXXXX %s %p %p", process->name, process->prev, process->next);
                }
            }
        }
    }

    if (cfg) {
        toml_free(cfg);cfg = NULL;
    }

    return config;
ERROR:
    if (cfg) {
        toml_free(cfg);cfg = NULL;
    }

    ProcessList_Free(config->process_list);
    free(config);

    return NULL;
}
