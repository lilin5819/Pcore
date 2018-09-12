#ifndef _COMMON_H_
#define _COMMON_H_

#include <uv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#define FREE zfree
#define MALLOC zfree

#define FCLOSE(stream)      \
    do                      \
    {                       \
        if (stream)         \
            fclose(stream); \
        stream = NULL;      \
    } while (0)

#define CONTAINER_OF(ptr, type, field)                                        \
  ((type *) ((char *) (ptr) - ((char *) &((type *) 0)->field)))

#ifndef container_of
#define container_of(ptr, type, member) \
	((type *)((char *)(ptr) - offsetof(type, member)))
#endif

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#endif