#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <dirent.h>
#include <sys/stat.h>
#include <libgen.h>

#include <uv.h>

#include "utlist.h"

#include "forever.h"
#include "config.h"
#include "logrotate.h"

typedef struct LogRotateItem_s LogRotateItem_t;

struct LogRotateItem_s {
    char *path;
    char *renamed_path;

    LogPipe_t *pipes;

    int checking;
    int freed;

    uv_thread_t clean_job;

    LogRotateItem_t *prev;
    LogRotateItem_t *next;
};

typedef struct DirItem_s DirItem_t;

struct DirItem_s {
    char name[NAME_MAX];
    time_t mtime;

    DirItem_t *prev;
    DirItem_t *next;
};

static LogRotateItem_t *paths = NULL;
static uv_timer_t check_timer;
static LogRotateConfig_t config;


static void free_item(LogRotateItem_t *item) {
    free(item->path);
    if (item->renamed_path) free(item->renamed_path);
    free(item);
}

LogRotateItem_t *find_item(char *path) {
    LogRotateItem_t *item;
    DL_FOREACH(paths, item) {
        if (strcmp(item->path, path) == 0) {
            return item;
        }
    }
    return NULL;
}

void LogRotate_Add(LogPipe_t *lp) {
    if (lp->path == NULL) return;
    LogRotateItem_t *item = find_item(lp->path);
    if (item == NULL) {
        item = (LogRotateItem_t *)calloc(1, sizeof(LogRotateItem_t));
        item->path = strdup(lp->path);
        DL_APPEND(paths, item);
        mfprintf(stdout, "INFO: logrotate start watch %s", item->path);
    }

    DL_APPEND(item->pipes, lp);
}

void LogRotate_Remove(LogPipe_t *lp) {
    if (lp->path == NULL) return;
    LogRotateItem_t *item = find_item(lp->path);
    if (item == NULL) return;
    DL_DELETE(item->pipes, lp);

    if (item->pipes == NULL) {
        mfprintf(stdout, "INFO: logrotate stop watch %s", item->path);
        DL_DELETE(paths, item);
        if (item->checking) {
            item->freed = 1;
        } else {
            free_item(item);
        }
    }
}

static void free_handle(uv_handle_t *hd) {
    free(hd);
}

static int cmp_dir_item(DirItem_t *a, DirItem_t *b) {
    return a->mtime - b->mtime;
}

static void clean_job(void *p) {
    LogRotateItem_t *item = (LogRotateItem_t *)p;

    char tmp_path[PATH_MAX];
    char *path0 = strdup(item->path);
    char *path1 = strdup(item->path);
    char *dir_name = dirname(path0);
    char *base_name = basename(path1);

    DIR *dir = NULL;
    struct dirent *dit;

    DirItem_t *list = NULL;
    DirItem_t *tmp;
    DirItem_t *cur;
    int count;

    struct stat statbuf;

    dir = opendir(dir_name);
    if (!dir) {
        goto clean;
    }

    while ((dit = readdir(dir)) != NULL) {
        if (strncmp(base_name, dit->d_name, strlen(base_name)) != 0) {
            continue;
        }

        snprintf(tmp_path, PATH_MAX, "%s/%s", dir_name, dit->d_name);
        if (stat(tmp_path, &statbuf)) {
            mfprintf(stderr, "ERROR: clean_job() stat %s failed", dit->d_name);
            continue;
        }

        if (!S_ISREG(statbuf.st_mode)) {
            continue;
        }

        cur = (DirItem_t *)malloc(sizeof(DirItem_t));
        snprintf(cur->name, NAME_MAX, "%s", dit->d_name);
        cur->mtime = statbuf.st_mtime;
        DL_APPEND(list, cur);
    }

    DL_COUNT(list, cur, count);
    if (count > config.rotate) {
        DL_SORT(list, cmp_dir_item);
        count -= config.rotate;
        DL_FOREACH_SAFE(list, cur, tmp) {
            snprintf(tmp_path, PATH_MAX, "%s/%s", dir_name, cur->name);
            mfprintf(stdout, "INFO: delete %s", tmp_path);

            unlink(tmp_path);
            DL_DELETE(list, cur);
            free(cur);

            count --;
            if (count == 0) {
                break;
            }
        }
    }

clean:
    if (dir) closedir(dir);
    DL_FOREACH_SAFE(list, cur, tmp) {
        DL_DELETE(list, cur);
        free(cur);
    }
    free(path0);
    free(path1);
}

static void gzip_exit(uv_process_t *uv_process, int64_t exit_status, int term_signal) {
    LogRotateItem_t *item = (LogRotateItem_t *)uv_process->data;

    if (exit_status) {
        mfprintf(stderr, "ERROR: compress %s failed, status:%d, signal:%d", item->renamed_path, (int)exit_status, term_signal);
    } else {
        mfprintf(stdout, "INFO: %s compressed", item->renamed_path);
    }

    uv_close((uv_handle_t*) uv_process, free_handle);

    uv_thread_create(&item->clean_job, clean_job, item);
}

static void stat_cb(uv_fs_t* req) {
    LogRotateItem_t *item = (LogRotateItem_t *) req->data;
    int r = req->result;
    item->checking = 0;

    if (item->freed) {
        free_item(item);
        goto clean;
    }

    if (r) {
        mfprintf(stderr, "ERROR: stat %s failed:%s",
                item->path, uv_strerror(r));
        goto clean;
    }

    if (req->statbuf.st_size > config.maxsize) {
        time_t timer;
        char time_buffer[26];
        struct tm* tm_info;
        char newpath[PATH_MAX];
        LogPipe_t *p;

        time(&timer);
        tm_info = localtime(&timer);
        strftime(time_buffer, 26, "%Y%m%d%H%M%S", tm_info);

        snprintf(newpath, PATH_MAX, "%s.%s", item->path, time_buffer);
        int r = rename(item->path, newpath);
        if (r) {
            mfprintf(stderr, "ERROR: rename %s failed:%s", item->path, strerror(errno));
            goto clean;
        }

        if (item->renamed_path) {
            free(item->renamed_path);
        }
        item->renamed_path = strdup(newpath);

        mfprintf(stdout, "INFO: rotate %s size:%llu", newpath, req->statbuf.st_size);
        DL_FOREACH(item->pipes, p) {
            LogPipe_ReOpen(p);
        }

        if (config.compress) {
            uv_process_t *zip = (uv_process_t *)malloc(sizeof(uv_process_t));
            zip->data = item;

            char* args[4];
            args[0] = "/usr/bin/env";
            args[1] = "gzip";
            args[2] = item->renamed_path;
            args[3] = NULL;

            uv_process_options_t options;
            options.exit_cb = gzip_exit;
            options.file = "/usr/bin/env";
            options.args = args;

            int r = uv_spawn(uv_default_loop(), zip, &options);
            if (r) {
                mfprintf(stderr, "ERROR: gzip %s failed:%s", item->renamed_path, uv_strerror(r));
                free(zip);
            }
        } else {
            uv_thread_create(&item->clean_job, clean_job, item);
        }
    }

clean:
    uv_fs_req_cleanup(req);
    free(req);
}

static void check_log(uv_timer_t *handle) {
    LogRotateItem_t *item;
    DL_FOREACH(paths, item) {
        uv_fs_t *req = (uv_fs_t *)malloc(sizeof(uv_fs_t));
        req->data = item;
        item->checking = 1;
        uv_fs_stat(uv_default_loop(), req, item->path, stat_cb);
    }
}

void LogRotate_SetConfig(LogRotateConfig_t cfg) {
    config = cfg;
    char tmp[1024];
    readable_size((double)config.maxsize, tmp);
    mfprintf(stdout, "INFO: logrotate.maxsize: %s", tmp);
    mfprintf(stdout, "INFO: logrotate.rotate: %d", config.rotate);
    mfprintf(stdout, "INFO: logrotate.compress: %d", config.compress);
}

void LogRotate_Run() {
    uv_timer_init(uv_default_loop(), &check_timer);
    uv_timer_start(&check_timer, check_log, 1000, 5000);
}
