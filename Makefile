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
# OBJS = $(subst .c,.o,$(SRCS))
SRC_DIRS = . cjson sds
SRCS = $(foreach dir,$(SRC_DIRS),$(wildcard $(dir)/*.c))

CFLAGS = $(CORE_CFLAGS) -DCONFIG_MSG
LDFLAGS = $(CORE_LDFLAGS) -lssl -lcrypto -lm
ifeq ($(CONFIG_SERVER),y)
TARGET += elink_server
endif

ifeq ($(CONFIG_CLIENT),y)
TARGET += elink_client
endif

all:clean $(TARGET)
	$(STRIP) $(TARGET)

elink_server:$(SRCS)
	$(CC) -o $@ $^ -DCONFIG_SERVER $(CFLAGS) $(LDFLAGS) 

elink_client:$(SRCS)
	$(CC) -o $@ $^ -DCONFIG_CLIENT $(CFLAGS) $(LDFLAGS) 

elink_core:$(CORE_SRCS)
	$(CC) -o $@ $^ $(CORE_CFLAGS) $(CORE_LDFLAGS)

%.o:%.c
	$(CC) -c -o $@ $< $(CFLAGS) $(LDFLAGS)

clean:
	rm -rf $(OBJS) $(TARGET)