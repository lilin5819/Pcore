#ifndef _CORE_H_

#include <stdint.h>
#include <uv.h>
#include "list.h"

#define ELINK_SERVER_IP "0.0.0.0"
#define ELINK_SERVER_PORT 32768


#define ELINK_SERVER_MODE 1

#define CONTAINER_OF(ptr, type, field)                                        \
  ((type *) ((char *) (ptr) - ((char *) &((type *) 0)->field)))

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#define FREE(x)        \
    do                 \
    {                  \
        if (x != NULL) \
        {              \
            free(x);   \
            x = NULL;  \
        }              \
    } while (0);

#define DEFAULT_BACKLOG 128

struct keys_t;
struct elink_cfg_t;
struct elink_server_ctx;
struct elink_client_ctx;
struct elink_ctx;

typedef struct elink_server_ctx
{
  uv_tcp_t tcp_handle;
  struct sockaddr_in addr;
  int flag;
  uint64_t timestamp;
  char *name;
  struct list_head client_list;
  void *data;
#ifdef CONFIG_MSG
  // char *mac;
  // struct list_head msg_list;
  // keys_t keys;
#endif
} elink_server_ctx;

typedef struct elink_client_ctx
{
  uv_tcp_t tcp_handle;
  struct sockaddr_in addr;
  int flag;
  uint64_t timestamp;
  char *name;
  char *mac;
  char *ip;
  uv_connect_t conn;
  int online;
  // uv_timer_t timer_conn;
  struct list_head list;
  void *data;
#ifdef CONFIG_MSG
  // char *mac;
  // struct list_head msg_list;
  // keys_t keys;
#endif
  uv_buf_t *recv_buf;
} elink_client_ctx;

typedef struct elink_cfg_t
{
  char *host;
  char *ip;
  unsigned short port;
  int backlog;
  int mode;
  char* mode_name;
} elink_cfg_t;

typedef struct elink_ctx
{
    elink_cfg_t cfg;
    elink_server_ctx server;
    elink_client_ctx client;
    uv_loop_t *loop;
    uv_tcp_t *tcp_handle;
    uv_idle_t idle_handle;
    uv_signal_t signal_handle;
    uv_check_t check_handle;
    uv_timer_t timer_netcheck_handle;
    int flag;
    int nclient;
    int nmsg;
} elink_ctx;

elink_server_ctx *get_elink_server_ctx(void);
elink_client_ctx *get_elink_client_ctx(void);
// void on_write(uv_write_t *req, int status);
void close_cb(uv_handle_t *handle);
char *get_if_ipstr(char *ifname);
char *get_if_macstr(char *ifname);

// void msg_start_call(elink_client_ctx *client);

#endif // !_CORE_H_
