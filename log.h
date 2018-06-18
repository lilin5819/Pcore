/*
 * log.h
 * Copyright (C) 2018 lilin <lilin@lilin-VB>
 *
 * Distributed under terms of the MIT license.
 */

#ifndef LOG_H
#define LOG_H
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>

#define _AUTH "lilin"

#ifndef DEBUG

#define LOG_INIT(...)
#define log_tag(...)
#define log_base(...)
#define log(...)
#define log_(...)
#define log_err(...)
#define log_e(...)
#define log_d(...)
#define log_u(...)
#define log_ld(...)
#define log_lu(...)
#define log_f(...)
#define log_s(...)
#define log_p(...)
#define log_mem(...)
#define log_malloc(...)
#define log_free(...)
#define ok(...) __VA_ARGS__

#else /* no DEBUG */

#define _RED_STR "\033[1;31m"
#define _GRE_STR "\033[1;32m"
#define _YEL_STR "\033[1;33m"
#define _FLASH_STR "\033[5m"
#define _COLOR_END "\033[0m"

#define _BLANK_ERR "blank"
#define _NULL_ERR "NULL"
#define _ASSERT_ERR "assert failed !"
#define PR_RED_START() fprintf(stdout, _RED_STR)
#define PR_FLASH_START() fprintf(stdout, _FLASH_STR)
#define PR_COLOR_END() fprintf(stdout, _COLOR_END)

#define _COLOR_MASK 0x03
#define _FLASH_MASK 0x04

typedef enum _COLOR_T
{
    _GRE,
    _RED,
    _YEL,
    _END,
    _FLASH
} COLOR_T;
static char _COLOR[5][16] = {_GRE_STR, _RED_STR, _YEL_STR, _COLOR_END, _FLASH_STR};
static char *_log_tag = NULL;

char *get_appname(void);
void set_appname(char *appname);

#define LOG_INIT(app)                \
    char *_log_app = app;            \
    char *get_appname(void)         \
    {                                \
        return _log_app;             \
    }                                \
    void set_appname(char *appname) \
    {                                \
        _log_app = appname;          \
    }

static inline void log_base(FILE *fp, const char flag, const char *tag, const char *file, const char *fun, const int line, const char *fmt, ...)
{
    static char fmtbuf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(fmtbuf, sizeof(fmtbuf), fmt, ap);
    va_end(ap);
    fprintf(fp, "[%s%s%s]", _COLOR[_YEL], get_appname(), _COLOR[_END]);
    fprintf(fp, "[%-15s > %-15s > %3d]", file, fun, line);
    if (tag)
        fprintf(fp, "[%s%s%s%s]", _COLOR[flag & _FLASH], _COLOR[flag & _COLOR_MASK], tag, _COLOR[_END]);
    fprintf(fp, "[%s%s%s%s]\n", _COLOR[flag & _FLASH], _COLOR[flag & _COLOR_MASK], fmtbuf, _COLOR[_END]);
}

#define log_line(fp, flag, tag, ...)                                            \
    do                                                                          \
    {                                                                           \
        log_base(fp, flag, tag, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__); \
    } while (0)

#define log(...) log_line(stdout, _GRE, NULL, __VA_ARGS__)
#define log_() log_line(stdout, _GRE, NULL, "line")
#define log_tag(tag, ...) log_line(stdout, _GRE, tag, __VA_ARGS__)
#define log_err(MSG, ...) log_line(stderr, _RED | _FLASH, MSG, __VA_ARGS__)
#define log_e(...) log_err("ERROR", __VA_ARGS__)
#define log_d(N) log("%s=%d", #N, N)
#define log_u(N) log("%s=%u", #N, N)
#define log_ld(N) log("%s=%ld", #N, N)
#define log_lu(N) log("%s=%lu", #N, N)
#define log_f(N) log("%s=%f", #N, N)

#define log_p(N)                                \
    do                                          \
    {                                           \
        if (!N)                                 \
            log_err(_NULL_ERR, "%s", #N);       \
        else                                    \
            log_tag("pointer", "%s=%p", #N, N); \
    } while (0)
//     string
#define log_s(STR)                                     \
    do                                                 \
    {                                                  \
        if (!(char *)(STR))                            \
            log_err(_NULL_ERR, "%s", #STR);            \
        else if (!((char *)(STR))[0])                  \
            log_err(_BLANK_ERR, "%s=\"\"", #STR);      \
        else                                           \
            log_tag("string", "%s=\"%s\"", #STR, STR); \
    } while (0)

#define log_mem(P, LEN)                                           \
    do                                                            \
    {                                                             \
        if (!P)                                                   \
            log_err(_NULL_ERR, "%s", #P);                         \
        else                                                      \
            log_tag("MEMORY", "p:%s addr:%p len:%d", #P, P, LEN); \
        fprintf(stdout, "[ ");                                    \
        for (int i = 0; i < LEN; i++)                             \
        {                                                         \
            fprintf(stdout, "%02X", ((char *)P)[i] & 0xFF);       \
        }                                                         \
        fprintf(stdout, " ]\n");                                  \
    } while (0)

//     assert
#define ok(expr)                               \
    do                                         \
    {                                          \
        if (!(expr))                           \
            log_err(_ASSERT_ERR, "%s", #expr); \
    } while (0)

#define log_malloc(_VAR, _SIZE)                             \
    do                                                      \
    {                                                       \
        log_tag("malloc", "%s %p %lu", #_VAR, _VAR, _SIZE); \
    } while (0)

#define log_free(_VAR, _SIZE)                             \
    do                                                    \
    {                                                     \
        log_tag("free", "%s %p %lu", #_VAR, _VAR, _SIZE); \
    } while (0)
#endif /* DEBUG */

#define log_size log_lu
#define log_int log_d
#define log_long log_ld
#define log_str log_s
#define log_string log_s

#endif /* !LOG_H */
