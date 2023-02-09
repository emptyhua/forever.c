#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#include "forever.h"
#include "logrotate.h"
#include "logpipe.h"

static void free_handle(uv_handle_t *hd) {
    free(hd);
}

static void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    *buf = uv_buf_init((char *) malloc(suggested_size), suggested_size);
}

static void log_write_cb(uv_write_t *req, int status) {
    free(req->data);
    free(req);
}

static void out_read_cb(uv_stream_t *pipe, ssize_t nread, const uv_buf_t *buf) {
    if (nread < 0) {
        free(buf->base);
        return;
    }

    LogPipe_t *lp = pipe->data;

    if (lp->file == NULL) {
        free(buf->base);
        return;
    }

    uv_write_t *write_req = (uv_write_t *)malloc(sizeof(uv_write_t));
    write_req->data = buf->base;
    uv_buf_t write_buf = uv_buf_init(buf->base, nread);
    uv_write(write_req, (uv_stream_t *)lp->file, &write_buf, 1, log_write_cb);
}

LogPipe_t *LogPipe_New() {
    LogPipe_t *lp = (LogPipe_t *)calloc(1, sizeof(LogPipe_t));

    lp->loop = uv_default_loop();

    lp->out = (uv_pipe_t *)malloc(sizeof(uv_pipe_t));
    uv_pipe_init(lp->loop, lp->out, 0);
    lp->out->data = lp;

    return lp;
}

void LogPipe_Start(LogPipe_t *lp) {
    int r = uv_read_start((uv_stream_t *)lp->out, alloc_buffer, out_read_cb);
    if (r) {
        mfprintf(stderr, "ERROR: uv_read_start() failed:%s", uv_strerror(r));
    }
}

void LogPipe_SetPath(LogPipe_t *lp, char *new_path) {
    if (lp->path != NULL && new_path != NULL && strcmp(lp->path, new_path) == 0) {
        return;
    }

    if (lp->path) {
        LogRotate_Remove(lp);
        free(lp->path);
        lp->path = NULL;
    }

    if (new_path) {
        lp->path = strdup(new_path);
        LogRotate_Add(lp);
    }

    LogPipe_ReOpen(lp);
}

void LogPipe_ReOpen(LogPipe_t *lp) {
    if (lp->file) {
        uv_close((uv_handle_t *)lp->file, free_handle);
        lp->file = NULL;
    }

    if (lp->path == NULL) {
        return;
    }

    int fd = open(lp->path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd == -1) {
         mfprintf(stderr, "ERROR: open %s failed:%s",
                lp->path, strerror(errno));
    } else {
        lp->file = (uv_pipe_t *)malloc(sizeof(uv_pipe_t));
        uv_pipe_init(lp->loop, lp->file, 0);
        uv_pipe_open(lp->file, fd);
    }
}

void LogPipe_Free(LogPipe_t *lp) {
    if (!lp) return;

    LogRotate_Remove(lp);

    if (lp->out) {
        uv_close((uv_handle_t *)lp->out, free_handle);
        lp->out = NULL;
    }

    if (lp->file) {
        uv_close((uv_handle_t *)lp->file, free_handle);
        lp->file = NULL;
    }

    if (lp->path) {
        free(lp->path);
        lp->path = NULL;
    }

    free(lp); lp = NULL;
}
