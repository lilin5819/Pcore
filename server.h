#ifndef _SERVER_H_

#include <uv.h>
#include "list.h"
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

typedef struct
{
  uv_buf_t dh_p;      //prime
  uv_buf_t dh_g;      //gen
  uv_buf_t dh_pubkey; //pub key
  uv_buf_t dh_prikey; //private key
  uv_buf_t dh_sharekey;
} keys_t;

typedef struct
{
  uv_tcp_t tcp_handle;
  int flag;
  char *name;
  char *ip;
  char *mac;
  char *gw;
  struct list_head *client_list;
  struct list_head msg_list;
  keys_t keys;
} elink_server_ctx;

typedef struct
{
  uv_tcp_t tcp_handle;
  int flag;
  char *name;
  char *ip;
  char *mac;
  char *gw;
  uv_buf_t *recv_buf;
  // uv_buf_t *send_buf;
  keys_t keys;
  struct list_head list;
  // elink_server_ctx *server;
  struct list_head msg_list;
} elink_client_ctx;

elink_server_ctx *get_elink_server_ctx(void);
// elink_client_ctx *client_ctx_alloc(void);
void on_write(uv_write_t *req, int status);

#endif // !_SERVER_H_
