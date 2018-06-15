.PHONY: all clean

CC = gcc
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
OBJS = $(subst c,o,$(SRCS))

all:clean elink_server

elink_server:$(SRCS) #$(SRCS)
	@echo $(CC) $(OBJS)
	gcc  -o $@ $^ $(CFLAGS) $(LDFLAGS)
	# gcc $^ -o $@ $(CFLAGS) $(LDFLAGS)
	# @echo $(OBJS)

%.o:%.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c -o $@ $<
	@echo $^
	@echo $<

clean:
	rm -rf $(OBJS) elink_server