.PHONY: all clean

CC = gcc
STRIP = strip
CFLAGS = -I./cjson -DDEBUG
LDFLAGS = -L/usr/lib/x86_64-linux-gnu -lssl -lcrypto -luv -lm

SRC_DIRS = . cjson sds
# SRCS = $(wildcard *.c) $(wildcard cjson/*.c)
DEBUG_SERVER = n

ifeq ($(DEBUG_SERVER),y)
SRCS = server.c crypto.c cjson/cJSON.c
else
SRCS = $(foreach dir,$(SRC_DIRS),$(wildcard $(dir)/*.c))
endif
OBJS = $(subst .c,.o,$(SRCS))
TARGET = elink_server elink_client

all:clean $(TARGET)
	$(STRIP) $(TARGET)

elink_server:$(SRCS)
	gcc -o $@ $^ $(CFLAGS) $(LDFLAGS) -DSERVER

elink_client:$(SRCS)
	gcc -o $@ $^ $(CFLAGS) $(LDFLAGS) -DCLIENT

%.o:%.c
	$(CC) -c -o $@ $< $(CFLAGS) $(LDFLAGS)

clean:
	rm -rf $(OBJS) elink_server