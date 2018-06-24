#ifndef _CORE_H_

#include <stdint.h>
#include <uv.h>
#include "list.h"

#define ELINK_SERVER_IP "0.0.0.0"
#define ELINK_SERVER_PORT 32768


#define ELINK_SERVER_MODE 1
#define ELINK_CLIENT_MODE 0

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

struct pcore_cfg_t;
struct pcore_server_ctx;
struct pcore_client_ctx;
struct pcore_ctx;

typedef struct pcore_server_ctx
{
  uv_tcp_t tcp_handle;
  struct sockaddr_in addr;
  int flag;
  uint64_t timestamp;
  char *name;
  struct list_head client_list;
  void *data;
} pcore_server_ctx;

typedef struct pcore_client_ctx
{
  uv_tcp_t tcp_handle;
  struct sockaddr_in addr;
  int flag;
  uint64_t timestamp;
  char *name;
  char *mac;
  char *ip;
  char *gw;
  uv_connect_t conn;
  int online;
  // uv_timer_t timer_conn;
  struct list_head list;
  void *data;
  uv_buf_t *recv_buf;
} pcore_client_ctx;

typedef struct pcore_cfg_t
{
  char *host;
  char *ip;
  unsigned short port;
  int backlog;
  int mode;
  char* mode_name;
} pcore_cfg_t;

typedef struct pcore_ctx
{
    pcore_cfg_t cfg;
    pcore_server_ctx server;
    pcore_client_ctx client;
    uv_loop_t *loop;
    uv_tcp_t *tcp_handle;
    uv_idle_t idle_handle;
    uv_signal_t signal_handle;
    uv_check_t check_handle;
    uv_timer_t timer_netcheck_handle;
    int flag;
    int nclient;
    int nmsg;
} pcore_ctx;

pcore_server_ctx *get_pcore_server_ctx(void);
pcore_client_ctx *get_pcore_client_ctx(void);
// void on_write(uv_write_t *req, int status);
void start_pcore(pcore_ctx *pcore);
void close_all(void);
void close_cb(uv_handle_t *handle);
char *get_if_ipstr(char *ifname);
char *get_if_macstr(char *ifname);
int get_pcore_mode(void);
void read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);
void read_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
void msg_ack_cb(uv_work_t* req);
void msg_dev_reg_call(uv_work_t* req);
void msg_dev_reg_cb(uv_work_t* req);

#endif // !_CORE_H_
