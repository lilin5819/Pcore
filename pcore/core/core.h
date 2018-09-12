#ifndef _CORE_H_

#include "common.h"
// #include "list.h"
#include "adlist.h"
#include "log.h"

#include "env.h"
#include "gc.h"
#include "env.h"
#include "session.h"
#include "stastic.h"

#define ELINK_SERVER_IP "0.0.0.0"
#define ELINK_SERVER_PORT 32768


#define ELINK_SERVER_MODE 1
#define ELINK_CLIENT_MODE 0

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
  struct list *client_list;
  struct dict *var;                 // string string
  struct list *log_list;
  void *data;
} pcore_server_ctx;

typedef struct pcore_client_ctx
{
  uv_tcp_t tcp_handle;
  struct sockaddr_in addr;
  int flag;
  uint64_t timestamp;
  char *name;
  struct dict *var;                 // string string
  char *mac;
  char *ip;
  char *gw;
  uv_connect_t conn;
  int online;
  // struct list *list;
  struct list *log_list;
  uv_buf_t *recv_buf;
  void *data;
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

typedef enum LAYER_T{
    LAYER_SIGNAL,
    LAYER_TIMER,
    LAYER_ASYNC,
    LAYER_WORK,
    LAYER_SERVER,
    LAYER_CLIENT,
    LAYER_AGENT
}LAYER_T;

typedef struct pcore_layer_t
{
    LAYER_T type;
    int id;
    char *name;
    uv_handle_t handle;
    union{
      uv_signal_cb signal;
      uv_timer_cb timer;
      uv_check_cb check;
    }cb;
    // uv_work_cb alloc;  
    uv_work_cb free;
    struct list *log_list;
    void *data;
}pcore_layer_t;

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
    struct dict *layer_map;              // layer name to registered layer map
    struct dict *obj_map;              // type name to item function dict alloc free
    struct list *gc_list;                // point to node
    struct list *log_list;                // log_printf list
    int flag;
    void *data;
} pcore_ctx;

pcore_server_ctx *get_pcore_server_ctx(void);
pcore_client_ctx *get_pcore_client_ctx(void);
// void on_write(uv_write_t *req, int status);
void start_pcore(pcore_ctx *pcore);
void close_all(void);
void close_cb(uv_handle_t *handle);
// char *get_if_ipstr(char *ifname);
// char *get_if_macstr(char *ifname);
// char *get_gw(void);
int get_pcore_mode(void);
void read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);
void read_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
void msg_ack_cb(uv_work_t* req);
void msg_dev_reg_call(uv_work_t* req);
void msg_dev_reg_cb(uv_work_t* req);

#endif // !_CORE_H_
