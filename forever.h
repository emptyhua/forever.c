#ifndef _EMPTYHUA_FOREVER_H
#define _EMPTYHUA_FOREVER_H

#include <stdio.h>
#include <time.h>

#define mfprintf(stream, format, ...) \
    do {\
        time_t timer; \
        char time_buffer[26];\
        struct tm* tm_info;\
        time(&timer);\
        tm_info = localtime(&timer);\
        strftime(time_buffer, 26, "%Y:%m:%d %H:%M:%S", tm_info);\
        fprintf(stream, \
                "%s: "format"\n",\
                time_buffer,\
                ##__VA_ARGS__);\
        fflush(stream);\
    }while(0)


#endif
