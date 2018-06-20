.PHONY: all clean

CONFIG_SERVER = y
CONFIG_CLIENT = y
CONFIG_MSG = y

CC = gcc
STRIP = strip

CORE_SRCS = core.c  
CORE_CFLAGS = -I./cjson -I./sds -DDEBUG
CORE_LDFLAGS = -L/usr/lib/x86_64-linux-gnu -luv
TARGET = elink_core

# SRCS += msg.c crypto.c sds/sds.c cjson/cJSON.c
SRC_DIRS = . cjson sds
SRCS = $(foreach dir,$(SRC_DIRS),$(wildcard $(dir)/*.c))
OBJS = $(subst .c,.o,$(SRCS))

CFLAGS = $(CORE_CFLAGS)
LDFLAGS = $(CORE_LDFLAGS) -lssl -lcrypto -lm
ifeq ($(CONFIG_SERVER),y)
TARGET += elink_server
endif

ifeq ($(CONFIG_CLIENT),y)
TARGET += elink_client
endif

ifeq ($(CONFIG_CLIENT),y)
CFLAGS += -DCONFIG_MSG
endif

all:clean $(TARGET)
	$(STRIP) $(TARGET)

elink_server:$(SRCS)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS) -DCONFIG_SERVER -DELINK_MODE_NAME=\"$@\" -DELINK_MODE=1 

elink_client:$(SRCS)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS) -DCONFIG_CLIENT -DELINK_MODE_NAME=\"$@\" -DELINK_MODE=0

elink_core:$(CORE_SRCS)
	$(CC) -o $@ $^ $(CORE_CFLAGS) $(CORE_LDFLAGS) -DELINK_MODE_NAME=\"$@\" -DELINK_MODE=1

%.o:%.c
	$(CC) -c -o $@ $< $(CFLAGS) $(LDFLAGS)

clean:
	rm -rf $(OBJS) $(TARGET)