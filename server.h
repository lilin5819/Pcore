#ifndef _SERVER_H_

#include <uv.h>
#include "list.h"
#include "sds.h"
#include "cJSON.h"

// #define CONTAINER_OF(ptr, type, field)                                        \
//   ((type *) ((char *) (ptr) - ((char *) &((type *) 0)->field)))

#define FREE(x)        \
    do                 \
    {                  \
        if (x != NULL) \
        {              \
            free(x);   \
            x = NULL;  \
        }              \
    } while (0);

struct elink_client_ctx;

typedef struct
{
  char *host;
  char *ip;
  unsigned short port;
} elink_net_t;

#ifdef CONFIG_MSG
typedef struct
{
  sds dh_p;      //prime
  sds dh_g;      //gen
  sds dh_pubkey; //pub key
  sds dh_privkey; //private key
  sds dh_sharekey;
  sds dh_serverkey;
  sds dh_clientkey;
} keys_t;
#endif

typedef struct
{
  uv_tcp_t tcp_handle;
  int flag;
  uint32_t timestamp;
  struct list_head *client_list;
  char *name;
  char *ip;
#ifdef CONFIG_MSG
  char *mac;
  char *gw;

  struct list_head msg_list;
  keys_t keys;
#endif
} elink_server_ctx;

typedef struct
{
  uv_tcp_t tcp_handle;
  int flag;
  uint32_t timestamp;
  struct list_head list;
  char *name;
  char *ip;
  uv_buf_t *recv_buf;
#ifdef CONFIG_MSG
  char *mac;
  char *gw;
  // uv_buf_t *send_buf;

  // elink_server_ctx *server;
  struct list_head msg_list;
  keys_t keys;
#endif
} elink_client_ctx;

typedef struct
{
    elink_net_t net;
    elink_server_ctx *server;
    elink_client_ctx *client;
    uv_loop_t *loop;
    uv_tcp_t *tcp_handle;
    uv_idle_t idle_handle;
    uv_signal_t signal_handle;
    uv_check_t check_handle;
    uv_timer_t timer_handle;
    int flag;
} elink_ctx;

elink_ctx *get_elink_ctx(void);
elink_server_ctx *get_elink_server_ctx(void);
// elink_client_ctx *client_ctx_alloc(void);
void on_write(uv_write_t *req, int status);

#endif // !_SERVER_H_
