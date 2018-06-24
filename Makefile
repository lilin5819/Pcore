.PHONY: all clean

CONFIG_SERVER = n
CONFIG_CLIENT = n

CC = gcc
STRIP = strip

CORE_DIRS = pcore
CORE_SRCS = $(foreach dir,$(CORE_DIRS),$(wildcard $(dir)/*.c)) src/main.c
CORE_OBJS = $(subst .c,.o,$(CORE_SRCS))
CORE_CFLAGS =  -DDEBUG -I./pcore -I./include
CORE_LDFLAGS = -L/usr/lib/x86_64-linux-gnu -luv
TARGET = pcore_core

# SRCS += msg.c crypto.c sds/sds.c cjson/cJSON.c
SRC_DIRS = $(CORE_DIRS) cjson sds dict src zmalloc #ae
SRCS = $(foreach dir,$(SRC_DIRS),$(wildcard $(dir)/*.c)) ae/ae.c ae/anet.c
OBJS = $(subst .c,.o,$(SRCS))

CFLAGS = $(CORE_CFLAGS) -I./cjson -I./sds -I./zmalloc -I./src -I./ae -I./dict -I./ae
LDFLAGS = $(CORE_LDFLAGS) -lssl -lcrypto -lm

ifeq ($(CONFIG_SERVER),y)
TARGET += pcore_server
CFLAGS += -DCONFIG_MSG
endif

ifeq ($(CONFIG_CLIENT),y)
TARGET += pcore_client
CFLAGS += -DCONFIG_MSG
endif

all:clean $(TARGET) test
	$(STRIP) $(TARGET)

pcore_server:$(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

pcore_client:$(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

pcore_core:$(CORE_SRCS)
	$(CC) -o $@ $^ $(CORE_CFLAGS) -DELINK_MODE_NAME=\"CORE\" -DELINK_MODE=1  $(CORE_LDFLAGS)

%.o:%.c
	$(CC) -c -o $@ $< $(CFLAGS) -DELINK_MODE_NAME=\"EXT\" -DELINK_MODE=1  $(LDFLAGS)

clean:
	rm -rf $(OBJS) $(TARGET)